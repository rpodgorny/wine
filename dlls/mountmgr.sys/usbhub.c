/*
 * Copyright 2008 - 2011 Alexander Morozov for Etersoft
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include "config.h"
#include "wine/port.h"

#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_POLL_H
#include <poll.h>
#endif
#ifdef HAVE_SYS_POLL_H
#include <sys/poll.h>
#endif

#ifdef HAVE_LIBUSB_1
#include <libusb.h>
#elif defined(HAVE_LIBUSB)
#include <usb.h>
#undef USB_ENDPOINT_TYPE_MASK
#undef USB_ENDPOINT_TYPE_CONTROL
#undef USB_ENDPOINT_TYPE_ISOCHRONOUS
#undef USB_ENDPOINT_TYPE_BULK
#undef USB_ENDPOINT_TYPE_INTERRUPT
#endif
#ifdef HAVE_LIBUDEV
#include <libudev.h>
#endif

#define NONAMELESSUNION
#define NONAMELESSSTRUCT
#define INITGUID

#include "mountmgr.h"
#include "winreg.h"
#include "winsvc.h"
#include "winuser.h"
#include "setupapi.h"
#include "cfgmgr32.h"
#include "devguid.h"
#include "ddk/usbdrivr.h"
#include "ddk/usbioctl.h"
#include "wine/unicode.h"
#include "wine/debug.h"
#include "wine/list.h"

WINE_DEFAULT_DEBUG_CHANNEL(usbhub);

#if defined(HAVE_LIBUSB) || defined(HAVE_LIBUSB_1)

extern NTSTATUS CDECL __wine_add_device( DRIVER_OBJECT *driver, DEVICE_OBJECT *dev );
extern DRIVER_OBJECT * CDECL __wine_get_driver_object( const WCHAR *service );
extern NTSTATUS CDECL __wine_start_device( DEVICE_OBJECT *device );
extern BOOL CDECL __wine_start_service( const WCHAR *name );

#define NUMBER_OF_PORTS 8

static const WCHAR usbW[] = {'U','S','B',0};

static struct list HostControllers = LIST_INIT(HostControllers);
static struct list Devices = LIST_INIT(Devices);

struct HCDInstance
{
    struct list entry;
    DEVICE_OBJECT *dev;
    WCHAR *root_hub_name;
};

struct DeviceInstance
{
    struct list entry;
    USHORT vid;
    USHORT pid;
    char *instance_id;
    WCHAR *service;
    DEVICE_OBJECT *pdo;
#ifdef HAVE_LIBUSB_1
    libusb_device *dev;
#else
    struct usb_device *dev;
#endif
};

struct PdoExtension
{
    struct DeviceInstance *instance;
};

static DRIVER_OBJECT *usbhub_driver;

static CRITICAL_SECTION usbhub_cs;
static CRITICAL_SECTION_DEBUG usbhub_cs_debug =
{
    0, 0, &usbhub_cs,
    { &usbhub_cs_debug.ProcessLocksList, &usbhub_cs_debug.ProcessLocksList },
      0, 0, { (DWORD_PTR)(__FILE__ ": usbhub_cs") }
};
static CRITICAL_SECTION usbhub_cs = { &usbhub_cs_debug, -1, 0, 0, 0, 0 };

static BOOL libusb_initialized;

static BOOL device_exists( DEVICE_OBJECT *device )
{
    struct DeviceInstance *instance;

    LIST_FOR_EACH_ENTRY( instance, &Devices, struct DeviceInstance, entry )
        if (instance->pdo == device)
            return TRUE;
    return FALSE;
}

static struct HCDInstance *get_hcd_instance( DEVICE_OBJECT *device )
{
    struct HCDInstance *instance;

    LIST_FOR_EACH_ENTRY( instance, &HostControllers, struct HCDInstance, entry )
        if (instance->dev == device)
            return instance;
    return NULL;
}

static void add_data( unsigned char **dst, ULONG *dst_size, const void *src, ULONG src_size )
{
    int copy;

    copy = (src_size >= *dst_size) ? *dst_size : src_size;
    memcpy( *dst, src, copy );
    *dst += copy;
    *dst_size -= copy;
}

#ifdef HAVE_LIBUSB_1

struct DeviceInstance *get_device_by_index( libusb_device *device,
        ULONG connection_index, ULONG *addr )
{
    struct DeviceInstance *instance;
    uint8_t bus_number = libusb_get_bus_number( device );
    ULONG index = 0;

    LIST_FOR_EACH_ENTRY( instance, &Devices, struct DeviceInstance, entry )
        if (instance->dev && instance->dev != device &&
            libusb_get_bus_number( instance->dev ) == bus_number &&
            ++index == connection_index)
        {
            if (addr)
                *addr = libusb_get_device_address( instance->dev );
            return instance;
        }
    return NULL;
}

#else  /* HAVE_LIBUSB_1 */

struct DeviceInstance *get_device_by_index( struct usb_device *device,
        ULONG connection_index, ULONG *addr )
{
    struct DeviceInstance *instance;
    ULONG index = 0;

    LIST_FOR_EACH_ENTRY( instance, &Devices, struct DeviceInstance, entry )
        if (instance->dev && instance->dev != device &&
            instance->dev->bus == device->bus && ++index == connection_index)
        {
            if (addr)
                *addr = instance->dev->devnum;
            return instance;
        }
    return NULL;
}

#endif  /* HAVE_LIBUSB_1 */

static NTSTATUS get_root_hub_name( struct HCDInstance *instance, void *buff,
        ULONG size, ULONG_PTR *outsize )
{
    USB_HCD_DRIVERKEY_NAME *name = buff;
    ULONG name_size;

    if (size < sizeof(*name))
        return STATUS_BUFFER_TOO_SMALL;
    RtlZeroMemory( buff, size );
    name_size = (strlenW(instance->root_hub_name) - 4 + 1) * sizeof(WCHAR);
    name->ActualLength = sizeof(*name) - sizeof(WCHAR) + name_size;
    if (size >= name->ActualLength)
    {
        memcpy( name->DriverKeyName, instance->root_hub_name + 4, name_size );
        *outsize = name->ActualLength;
    }
    else
        *outsize = sizeof(*name);
    return STATUS_SUCCESS;
}

static NTSTATUS get_node_info( void *buff, ULONG size, ULONG_PTR *outsize )
{
    USB_NODE_INFORMATION *node_info = buff;

    if (size < sizeof(*node_info))
        return STATUS_BUFFER_TOO_SMALL;
    RtlZeroMemory( node_info, sizeof(*node_info) );
    node_info->u.HubInformation.HubDescriptor.bDescriptorLength = 9;
    node_info->u.HubInformation.HubDescriptor.bDescriptorType = 41;
    node_info->u.HubInformation.HubDescriptor.bNumberOfPorts = NUMBER_OF_PORTS;
    *outsize = sizeof(*node_info);
    return STATUS_SUCCESS;
}

#ifdef HAVE_LIBUSB_1

static NTSTATUS get_node_conn_info( struct DeviceInstance *inst, void *buff,
        ULONG size, ULONG_PTR *outsize )
{
    USB_NODE_CONNECTION_INFORMATION *conn_info = buff;
    ULONG index = 0;
    struct DeviceInstance *instance;
    uint8_t bus_number = libusb_get_bus_number( inst->dev );
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    if (size < sizeof(*conn_info))
        return STATUS_BUFFER_TOO_SMALL;
    if (!conn_info->ConnectionIndex ||
        conn_info->ConnectionIndex > NUMBER_OF_PORTS)
        return STATUS_INVALID_PARAMETER;
    RtlZeroMemory( (ULONG *)conn_info + 1, sizeof(*conn_info) - sizeof(ULONG) );
    LIST_FOR_EACH_ENTRY( instance, &Devices, struct DeviceInstance, entry )
    {
        if (instance->dev && instance->dev != inst->dev &&
            libusb_get_bus_number( instance->dev ) == bus_number &&
            ++index == conn_info->ConnectionIndex)
        {
            struct libusb_device_descriptor desc;
            libusb_device_handle *husb;
            int config, ret;

            if (libusb_get_device_descriptor( instance->dev, &desc ))
                break;
            memcpy( &conn_info->DeviceDescriptor, &desc,
                    sizeof(USB_DEVICE_DESCRIPTOR) );
            ret = libusb_open( instance->dev, &husb );
            if (!ret)
            {
                ret = libusb_get_configuration( husb, &config );
                if (!ret)
                    conn_info->CurrentConfigurationValue = config;
                libusb_close( husb );
            }
            conn_info->ConnectionStatus = 1;
            *outsize = sizeof(*conn_info);
            status = STATUS_SUCCESS;
            break;
        }
    }
    return status;
}

#else  /* HAVE_LIBUSB_1 */

static NTSTATUS get_node_conn_info( struct DeviceInstance *inst, void *buff,
        ULONG size, ULONG_PTR *outsize )
{
    USB_NODE_CONNECTION_INFORMATION *conn_info = buff;
    ULONG index = 0;
    struct DeviceInstance *instance;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    if (size < sizeof(*conn_info))
        return STATUS_BUFFER_TOO_SMALL;
    if (!conn_info->ConnectionIndex ||
        conn_info->ConnectionIndex > NUMBER_OF_PORTS)
        return STATUS_INVALID_PARAMETER;
    RtlZeroMemory( (ULONG *)conn_info + 1, sizeof(*conn_info) - sizeof(ULONG) );
    LIST_FOR_EACH_ENTRY( instance, &Devices, struct DeviceInstance, entry )
    {
        if (instance->dev && instance->dev != inst->dev &&
            instance->dev->bus == inst->dev->bus &&
            ++index == conn_info->ConnectionIndex)
        {
            usb_dev_handle *husb;

            memcpy( &conn_info->DeviceDescriptor, &instance->dev->descriptor,
                    sizeof(USB_DEVICE_DESCRIPTOR) );
            husb = usb_open( inst->dev );
            if (husb)
            {
                usb_control_msg( husb, 1 << 7, USB_REQ_GET_CONFIGURATION,
                        0, 0, (char *)&conn_info->CurrentConfigurationValue,
                        sizeof(UCHAR), 0 );
                usb_close( husb );
            }
            conn_info->ConnectionStatus = 1;
            *outsize = sizeof(*conn_info);
            status = STATUS_SUCCESS;
            break;
        }
    }
    return status;
}

#endif  /* HAVE_LIBUSB_1 */

static NTSTATUS get_node_conn_driverkey_name( struct DeviceInstance *inst,
        void *buff, ULONG size, ULONG_PTR *outsize )
{
    static const WCHAR device_idW[] = {'U','S','B','\\',
                                       'V','i','d','_','%','0','4','x','&',
                                       'P','i','d','_','%','0','4','x','\\',0};

    USB_NODE_CONNECTION_DRIVERKEY_NAME *driver_key_name = buff;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    WCHAR *dev_instance_idW, *bufW;
    struct DeviceInstance *instance;
    HDEVINFO set;
    SP_DEVINFO_DATA devInfo = { sizeof(devInfo), { 0 } };
    ULONG len, index = 0;

    if (size < sizeof(*driver_key_name))
        return STATUS_BUFFER_TOO_SMALL;
    instance = get_device_by_index( inst->dev,
            driver_key_name->ConnectionIndex, NULL );
    if (instance == NULL)
        return STATUS_INVALID_PARAMETER;
    bufW = HeapAlloc( GetProcessHeap(), 0,
            2 * MAX_DEVICE_ID_LEN * sizeof(WCHAR) );
    if (bufW == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;
    dev_instance_idW = bufW + MAX_DEVICE_ID_LEN;
    snprintfW( dev_instance_idW, MAX_DEVICE_ID_LEN, device_idW, instance->vid,
            instance->pid );
    len = strlenW(dev_instance_idW);
    RtlMultiByteToUnicodeN( dev_instance_idW + len,
            (MAX_DEVICE_ID_LEN - len) * sizeof(WCHAR), NULL,
            instance->instance_id, strlen(instance->instance_id) + 1 );
    set = SetupDiGetClassDevsW( NULL, usbW, 0, DIGCF_ALLCLASSES );
    if (set == INVALID_HANDLE_VALUE)
    {
        HeapFree( GetProcessHeap(), 0, bufW );
        return STATUS_UNSUCCESSFUL;
    }
    while (SetupDiEnumDeviceInfo( set, index++, &devInfo ))
    {
        if (!SetupDiGetDeviceInstanceIdW( set, &devInfo, bufW,
                MAX_DEVICE_ID_LEN, NULL ))
            break;
        if (!strcmpiW( dev_instance_idW, bufW ))
        {
            SetupDiGetDeviceRegistryPropertyW( set, &devInfo, SPDRP_DRIVER,
                    NULL, NULL, 0, &len );
            driver_key_name->ActualLength = 2 * sizeof(ULONG) + len;
            if (size < driver_key_name->ActualLength)
            {
                status = STATUS_SUCCESS;
                *outsize = sizeof(*driver_key_name);
            }
            else if (SetupDiGetDeviceRegistryPropertyW( set, &devInfo,
                    SPDRP_DRIVER, NULL, (BYTE *)driver_key_name->DriverKeyName,
                    len, NULL ))
            {
                status = STATUS_SUCCESS;
                *outsize = driver_key_name->ActualLength;
            }
            break;
        }
    }
    SetupDiDestroyDeviceInfoList( set );
    HeapFree( GetProcessHeap(), 0, bufW );
    return status;
}

static NTSTATUS WINAPI usbhub_ioctl( DEVICE_OBJECT *device, IRP *irp )
{
    IO_STACK_LOCATION *irpsp;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    struct DeviceInstance *inst;
    struct HCDInstance *hcd_inst;
    ULONG_PTR info = 0;

    TRACE( "%p, %p\n", device, irp );

    EnterCriticalSection( &usbhub_cs );
    irpsp = IoGetCurrentIrpStackLocation( irp );
    if (device_exists( device ))
    {
        inst = ((struct PdoExtension *)device->DeviceExtension)->instance;
        if (inst->service) goto done;

        switch (irpsp->Parameters.DeviceIoControl.IoControlCode)
        {
        case IOCTL_USB_GET_NODE_INFORMATION:
            status = get_node_info( irp->AssociatedIrp.SystemBuffer,
                    irpsp->Parameters.DeviceIoControl.OutputBufferLength, &info );
            break;
        case IOCTL_USB_GET_NODE_CONNECTION_INFORMATION:
            status = get_node_conn_info( inst, irp->AssociatedIrp.SystemBuffer,
                    irpsp->Parameters.DeviceIoControl.OutputBufferLength, &info );
            break;
        case IOCTL_USB_GET_NODE_CONNECTION_DRIVERKEY_NAME:
            status = get_node_conn_driverkey_name( inst,
                    irp->AssociatedIrp.SystemBuffer,
                    irpsp->Parameters.DeviceIoControl.OutputBufferLength, &info );
            break;
        default:
            FIXME( "IOCTL %08x is not implemented\n",
                    irpsp->Parameters.DeviceIoControl.IoControlCode );
        }
    }
    else if ((hcd_inst = get_hcd_instance( device )))
    {
        switch (irpsp->Parameters.DeviceIoControl.IoControlCode)
        {
        case IOCTL_USB_GET_ROOT_HUB_NAME:
            status = get_root_hub_name( hcd_inst, irp->AssociatedIrp.SystemBuffer,
                    irpsp->Parameters.DeviceIoControl.OutputBufferLength, &info );
            break;
        default:
            FIXME( "IOCTL %08x is not implemented for HCD\n",
                    irpsp->Parameters.DeviceIoControl.IoControlCode );
        }
    }

done:
    LeaveCriticalSection( &usbhub_cs );
    irp->IoStatus.u.Status = status;
    irp->IoStatus.Information = info;
    IoCompleteRequest( irp, IO_NO_INCREMENT );

    return status;
}

#ifdef HAVE_LIBUSB_1

static NTSTATUS WINAPI usbhub_internal_ioctl( DEVICE_OBJECT *device, IRP *irp )
{
    IO_STACK_LOCATION *irpsp;
    URB *urb;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    struct DeviceInstance *inst;

    TRACE( "%p, %p\n", device, irp );

    EnterCriticalSection( &usbhub_cs );
    if (!device_exists( device )) goto done;
    inst = ((struct PdoExtension *)device->DeviceExtension)->instance;
    if (!inst->service) goto done;
    irpsp = IoGetCurrentIrpStackLocation( irp );
    urb = irpsp->Parameters.Others.Argument1;

    switch (irpsp->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_INTERNAL_USB_SUBMIT_URB:
        switch (urb->u.UrbHeader.Function)
        {
        case URB_FUNCTION_SELECT_CONFIGURATION:
            {
                struct _URB_SELECT_CONFIGURATION *request =
                        &urb->u.UrbSelectConfiguration;
                libusb_device_handle *husb;

                TRACE( "URB_FUNCTION_SELECT_CONFIGURATION\n" );

                if (!libusb_open( inst->dev, &husb ))
                {
                    USB_CONFIGURATION_DESCRIPTOR *conf_desc =
                            request->ConfigurationDescriptor;
                    struct libusb_config_descriptor *conf;
                    int ret;

                    ret = libusb_set_configuration( husb, (conf_desc != NULL) ?
                            conf_desc->bConfigurationValue : -1 );
                    if (ret < 0)
                        ;
                    else if (conf_desc == NULL)
                        status = STATUS_SUCCESS;
                    else if (!libusb_get_active_config_descriptor( inst->dev, &conf ))
                    {
                        USBD_INTERFACE_INFORMATION *if_info = &request->Interface;
                        const struct libusb_interface_descriptor *intf;
                        ULONG k, n;

                        /* FIXME: case of num_altsetting > 1 */

                        for (n = 0; n < conf_desc->bNumInterfaces; ++n)
                        {
                            intf = &conf->interface[n].altsetting[0];
                            if_info->Class = intf->bInterfaceClass;
                            if_info->SubClass = intf->bInterfaceSubClass;
                            if_info->Protocol = intf->bInterfaceProtocol;
                            if_info->InterfaceHandle =
                                    (void *)(intf->bInterfaceNumber + 1);
                            for (k = 0; k < if_info->NumberOfPipes; ++k)
                            {
                                if_info->Pipes[k].MaximumPacketSize =
                                        intf->endpoint[k].wMaxPacketSize;
                                if_info->Pipes[k].EndpointAddress =
                                        intf->endpoint[k].bEndpointAddress;
                                if_info->Pipes[k].Interval =
                                        intf->endpoint[k].bInterval;
                                if_info->Pipes[k].PipeType =
                                        intf->endpoint[k].bmAttributes & 3;
                                if_info->Pipes[k].PipeHandle =
                                        (void *)(intf->endpoint[k].bEndpointAddress +
                                        ((intf->bInterfaceNumber + 1) << 8));
                            }
                            if_info = (USBD_INTERFACE_INFORMATION *)
                                    ((char *)if_info + if_info->Length);
                        }
                        libusb_free_config_descriptor( conf );
                        status = STATUS_SUCCESS;
                    }
                    libusb_close( husb );
                }
            }
            break;
        case URB_FUNCTION_SELECT_INTERFACE:
            {
                struct _URB_SELECT_INTERFACE *request =
                        &urb->u.UrbSelectInterface;
                libusb_device_handle *husb;

                TRACE( "URB_FUNCTION_SELECT_INTERFACE\n" );

                if (!libusb_open( inst->dev, &husb ))
                {
                    int ret;

                    ret = libusb_claim_interface( husb,
                            request->Interface.InterfaceNumber );
                    if (!ret)
                    {
                        ret = libusb_set_interface_alt_setting( husb,
                                request->Interface.InterfaceNumber,
                                request->Interface.AlternateSetting );
                        if (!libusb_release_interface( husb,
                                request->Interface.InterfaceNumber ) && !ret)
                            status = STATUS_SUCCESS;
                    }
                    libusb_close( husb );
                }
            }
            break;
        case URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER:
            {
                struct _URB_BULK_OR_INTERRUPT_TRANSFER *request =
                        &urb->u.UrbBulkOrInterruptTransfer;
                unsigned char *buf = request->TransferBuffer;
                libusb_device_handle *husb;

                TRACE( "URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER\n" );

                if (buf == NULL && request->TransferBufferMDL != NULL)
                    buf = request->TransferBufferMDL->MappedSystemVa;
                if (!libusb_open( inst->dev, &husb ))
                {
                    int ret, transferred;

                    ret = libusb_claim_interface( husb,
                            ((int)request->PipeHandle >> 8) - 1 );
                    if (!ret)
                    {
                        /* FIXME: add support for an interrupt transfer */
                        ret = libusb_bulk_transfer( husb,
                                (unsigned int)request->PipeHandle,
                                buf, request->TransferBufferLength,
                                &transferred, 0 );
                        if (!libusb_release_interface( husb,
                                ((int)request->PipeHandle >> 8) - 1 ) && !ret)
                        {
                            request->TransferBufferLength = transferred;
                            status = STATUS_SUCCESS;
                        }
                    }
                    libusb_close( husb );
                }
            }
            break;
        case URB_FUNCTION_GET_DESCRIPTOR_FROM_DEVICE:
            {
                struct _URB_CONTROL_DESCRIPTOR_REQUEST *request =
                        &urb->u.UrbControlDescriptorRequest;
                ULONG size = request->TransferBufferLength;
                unsigned char *buf = request->TransferBuffer;

                TRACE( "URB_FUNCTION_GET_DESCRIPTOR_FROM_DEVICE\n" );

                if (!size)
                {
                    status = STATUS_SUCCESS;
                    break;
                }
                if (buf == NULL && request->TransferBufferMDL != NULL)
                    buf = request->TransferBufferMDL->MappedSystemVa;
                if (buf == NULL)
                {
                    status = STATUS_INVALID_PARAMETER;
                    break;
                }

                switch (request->DescriptorType)
                {
                case USB_DEVICE_DESCRIPTOR_TYPE:
                    TRACE( "USB_DEVICE_DESCRIPTOR_TYPE\n" );
                    {
                        struct libusb_device_descriptor desc;

                        if (libusb_get_device_descriptor( inst->dev, &desc ))
                            break;
                        memcpy( buf, &desc, (size < sizeof(USB_DEVICE_DESCRIPTOR)) ?
                                size : sizeof(USB_DEVICE_DESCRIPTOR) );
                        status = STATUS_SUCCESS;
                    }
                    break;
                case USB_CONFIGURATION_DESCRIPTOR_TYPE:
                    TRACE( "USB_CONFIGURATION_DESCRIPTOR_TYPE\n" );
                    {
                        unsigned int i, k;
                        struct libusb_config_descriptor *conf;
                        const struct libusb_interface_descriptor *intf;
                        const struct libusb_endpoint_descriptor *endp;

                        /* FIXME: case of num_altsetting > 1 */

                        if (libusb_get_active_config_descriptor( inst->dev, &conf ))
                            break;
                        add_data( &buf, &size, conf,
                                sizeof(USB_CONFIGURATION_DESCRIPTOR) );
                        if (size > 0 && conf->extra)
                            add_data( &buf, &size, conf->extra, conf->extra_length );
                        for (i = 0; i < conf->bNumInterfaces; ++i)
                        {
                            intf = &conf->interface[i].altsetting[0];
                            if (size > 0)
                                add_data( &buf, &size, intf,
                                        sizeof(USB_INTERFACE_DESCRIPTOR) );
                            if (size > 0 && intf->extra)
                                add_data( &buf, &size, intf->extra, intf->extra_length );
                            for (k = 0; k < intf->bNumEndpoints; ++k)
                            {
                                endp = &intf->endpoint[k];
                                if (size > 0)
                                    add_data( &buf, &size, endp,
                                            sizeof(USB_ENDPOINT_DESCRIPTOR) );
                                if (size > 0 && endp->extra)
                                    add_data( &buf, &size, endp->extra,
                                            endp->extra_length );
                            }
                        }
                        libusb_free_config_descriptor( conf );
                        status = STATUS_SUCCESS;
                    }
                    break;
                case USB_STRING_DESCRIPTOR_TYPE:
                    TRACE( "USB_STRING_DESCRIPTOR_TYPE\n" );
                    {
                        libusb_device_handle *husb;
                        int ret;

                        if (!libusb_open( inst->dev, &husb ))
                        {
                            ret = libusb_get_string_descriptor( husb, request->Index,
                                    request->LanguageId, buf, size );
                            libusb_close( husb );
                            if (ret < 0) break;
                            status = STATUS_SUCCESS;
                        }
                    }
                }
            }
            break;
        case URB_FUNCTION_GET_STATUS_FROM_DEVICE:
            {
                struct _URB_CONTROL_GET_STATUS_REQUEST *request =
                        &urb->u.UrbControlGetStatusRequest;
                void *buf = request->TransferBuffer;
                libusb_device_handle *husb;
                int ret;

                TRACE( "URB_FUNCTION_GET_STATUS_FROM_DEVICE\n" );

                if (buf == NULL && request->TransferBufferMDL != NULL)
                    buf = request->TransferBufferMDL->MappedSystemVa;
                if (buf == NULL || request->TransferBufferLength < sizeof(USHORT))
                {
                    status = STATUS_INVALID_PARAMETER;
                    break;
                }
                if (!libusb_open( inst->dev, &husb ))
                {
                    ret = libusb_control_transfer( husb, 1 << 7,
                            LIBUSB_REQUEST_GET_STATUS, 0, request->Index, buf,
                            sizeof(USHORT), 0 );
                    libusb_close( husb );
                    if (ret < 0) break;
                    status = STATUS_SUCCESS;
                }
            }
            break;
        case URB_FUNCTION_VENDOR_DEVICE:
        case URB_FUNCTION_VENDOR_INTERFACE:
        case URB_FUNCTION_VENDOR_ENDPOINT:
        case URB_FUNCTION_CLASS_DEVICE:
        case URB_FUNCTION_CLASS_INTERFACE:
        case URB_FUNCTION_CLASS_ENDPOINT:
            {
                libusb_device_handle *husb;
                struct _URB_CONTROL_VENDOR_OR_CLASS_REQUEST *request =
                        &urb->u.UrbControlVendorClassRequest;
                unsigned char *req_buf = request->TransferBuffer;
                ULONG size = request->TransferBufferLength;

                TRACE( "URB_FUNCTION_{VENDOR,CLASS}_*\n" );

                if (req_buf == NULL && request->TransferBufferMDL != NULL)
                    req_buf = request->TransferBufferMDL->MappedSystemVa;
                if (size && req_buf == NULL)
                {
                    status = STATUS_INVALID_PARAMETER;
                    break;
                }
                if (!libusb_open( inst->dev, &husb ))
                {
                    UCHAR req_type = request->RequestTypeReservedBits;
                    unsigned char *buf;
                    int ret;

                    switch (urb->u.UrbHeader.Function)
                    {
                    case URB_FUNCTION_VENDOR_DEVICE:    req_type |= 0x40; break;
                    case URB_FUNCTION_VENDOR_INTERFACE: req_type |= 0x41; break;
                    case URB_FUNCTION_VENDOR_ENDPOINT:  req_type |= 0x42; break;
                    case URB_FUNCTION_CLASS_DEVICE:     req_type |= 0x20; break;
                    case URB_FUNCTION_CLASS_INTERFACE:  req_type |= 0x21; break;
                    case URB_FUNCTION_CLASS_ENDPOINT:   req_type |= 0x22; break;
                    }
                    buf = HeapAlloc( GetProcessHeap(), 0, size );
                    if (buf != NULL)
                    {
                        memcpy( buf, req_buf, size );
                        if (request->TransferFlags & USBD_TRANSFER_DIRECTION_IN)
                            req_type |= (1 << 7);
                        ret = libusb_control_transfer( husb, req_type,
                                request->Request, request->Value, request->Index,
                                buf, size, 0 );
                        if (ret >= 0)
                        {
                            if (request->TransferFlags & USBD_TRANSFER_DIRECTION_IN)
                            {
                                request->TransferBufferLength =
                                        (ret < size) ? ret : size;
                                memcpy( req_buf, buf, request->TransferBufferLength );
                            }
                            status = STATUS_SUCCESS;
                        }
                        HeapFree( GetProcessHeap(), 0, buf );
                    }
                    libusb_close( husb );
                }
            }
            break;
        case URB_FUNCTION_GET_CONFIGURATION:
            {
                struct _URB_CONTROL_GET_CONFIGURATION_REQUEST *request =
                        &urb->u.UrbControlGetConfigurationRequest;
                char *buf = request->TransferBuffer;
                libusb_device_handle *husb;
                int ret, config;

                TRACE( "URB_FUNCTION_GET_CONFIGURATION\n" );

                if (buf == NULL && request->TransferBufferMDL != NULL)
                    buf = request->TransferBufferMDL->MappedSystemVa;
                if (buf == NULL || request->TransferBufferLength < 1)
                {
                    status = STATUS_INVALID_PARAMETER;
                    break;
                }
                if (!libusb_open( inst->dev, &husb ))
                {
                    ret = libusb_get_configuration( husb, &config );
                    libusb_close( husb );
                    if (ret < 0) break;
                    *buf = config;
                    status = STATUS_SUCCESS;
                }
            }
            break;
        default:
            FIXME( "unsupported URB function %x\n", urb->u.UrbHeader.Function );
        }
        urb->u.UrbHeader.Status = status;
        break;
    default:
        FIXME( "IOCTL %08x is not implemented\n",
                irpsp->Parameters.DeviceIoControl.IoControlCode );
    }

done:
    LeaveCriticalSection( &usbhub_cs );
    irp->IoStatus.u.Status = status;
    irp->IoStatus.Information = 0;
    IoCompleteRequest( irp, IO_NO_INCREMENT );

    return status;
}

#else  /* HAVE_LIBUSB_1 */

static NTSTATUS WINAPI usbhub_internal_ioctl( DEVICE_OBJECT *device, IRP *irp )
{
    IO_STACK_LOCATION *irpsp;
    URB *urb;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    struct DeviceInstance *inst;

    TRACE( "%p, %p\n", device, irp );

    EnterCriticalSection( &usbhub_cs );
    if (!device_exists( device )) goto done;
    inst = ((struct PdoExtension *)device->DeviceExtension)->instance;
    if (!inst->service) goto done;
    irpsp = IoGetCurrentIrpStackLocation( irp );
    urb = irpsp->Parameters.Others.Argument1;

    switch (irpsp->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_INTERNAL_USB_SUBMIT_URB:
        switch (urb->u.UrbHeader.Function)
        {
        case URB_FUNCTION_SELECT_CONFIGURATION:
            {
                struct _URB_SELECT_CONFIGURATION *request =
                        &urb->u.UrbSelectConfiguration;
                usb_dev_handle *husb;

                TRACE( "URB_FUNCTION_SELECT_CONFIGURATION\n" );

                husb = usb_open( inst->dev );
                if (husb)
                {
                    USB_CONFIGURATION_DESCRIPTOR *conf_desc =
                            urb->u.UrbSelectConfiguration.ConfigurationDescriptor;
                    int ret;

                    ret = usb_set_configuration( husb, (conf_desc != NULL) ?
                            conf_desc->bConfigurationValue : -1 );
                    if (ret < 0)
                        ;
                    else if (conf_desc == NULL)
                        status = STATUS_SUCCESS;
                    else
                    {
                        USBD_INTERFACE_INFORMATION *if_info = &request->Interface;
                        struct usb_config_descriptor *conf;
                        struct usb_interface_descriptor *intf;
                        ULONG k, n;

                        /* FIXME: case of num_altsetting > 1 */

                        for (n = 0; n < inst->dev->descriptor.bNumConfigurations; ++n)
                            if (inst->dev->config[n].bConfigurationValue ==
                                conf_desc->bConfigurationValue)
                            {
                                conf = &inst->dev->config[n];
                                break;
                            }
                        for (n = 0; n < conf_desc->bNumInterfaces; ++n)
                        {
                            intf = &conf->interface[n].altsetting[0];
                            if_info->Class = intf->bInterfaceClass;
                            if_info->SubClass = intf->bInterfaceSubClass;
                            if_info->Protocol = intf->bInterfaceProtocol;
                            if_info->InterfaceHandle =
                                    (void *)(intf->bInterfaceNumber + 1);
                            for (k = 0; k < if_info->NumberOfPipes; ++k)
                            {
                                if_info->Pipes[k].MaximumPacketSize =
                                        intf->endpoint[k].wMaxPacketSize;
                                if_info->Pipes[k].EndpointAddress =
                                        intf->endpoint[k].bEndpointAddress;
                                if_info->Pipes[k].Interval =
                                        intf->endpoint[k].bInterval;
                                if_info->Pipes[k].PipeType =
                                        intf->endpoint[k].bmAttributes & 3;
                                if_info->Pipes[k].PipeHandle =
                                        (void *)(intf->endpoint[k].bEndpointAddress +
                                        ((intf->bInterfaceNumber + 1) << 8));
                            }
                            if_info = (USBD_INTERFACE_INFORMATION *)
                                    ((char *)if_info + if_info->Length);
                        }
                        status = STATUS_SUCCESS;
                    }
                    usb_close( husb );
                }
            }
            break;
        case URB_FUNCTION_SELECT_INTERFACE:
            {
                struct _URB_SELECT_INTERFACE *request =
                        &urb->u.UrbSelectInterface;
                usb_dev_handle *husb;

                TRACE( "URB_FUNCTION_SELECT_INTERFACE\n" );

                husb = usb_open( inst->dev );
                if (husb)
                {
                    int ret;

                    ret = usb_claim_interface( husb,
                            request->Interface.InterfaceNumber );
                    if (!ret)
                    {
                        ret = usb_set_altinterface( husb,
                                request->Interface.AlternateSetting );
                        if (!usb_release_interface( husb,
                                request->Interface.InterfaceNumber ) && !ret)
                            status = STATUS_SUCCESS;
                    }
                    usb_close( husb );
                }
            }
            break;
        case URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER:
            {
                struct _URB_BULK_OR_INTERRUPT_TRANSFER *request =
                        &urb->u.UrbBulkOrInterruptTransfer;
                char *buf = request->TransferBuffer;
                usb_dev_handle *husb;

                TRACE( "URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER\n" );

                if (buf == NULL && request->TransferBufferMDL != NULL)
                    buf = request->TransferBufferMDL->MappedSystemVa;
                husb = usb_open( inst->dev );
                if (husb)
                {
                    int ret;

                    ret = usb_claim_interface( husb,
                            ((int)request->PipeHandle >> 8) - 1 );
                    if (!ret)
                    {
                        /* FIXME: add support for an interrupt transfer */
                        if (request->TransferFlags & USBD_TRANSFER_DIRECTION_IN)
                            ret = usb_bulk_read( husb, (int)request->PipeHandle & 0xff,
                                    buf, request->TransferBufferLength, 0 );
                        else
                            ret = usb_bulk_write( husb, (int)request->PipeHandle & 0xff,
                                    buf, request->TransferBufferLength, 0 );
                        if (!usb_release_interface( husb,
                                ((int)request->PipeHandle >> 8) - 1 ) && ret >= 0)
                        {
                            request->TransferBufferLength = ret;
                            status = STATUS_SUCCESS;
                        }
                    }
                    usb_close( husb );
                }
            }
            break;
        case URB_FUNCTION_GET_DESCRIPTOR_FROM_DEVICE:
            {
                struct _URB_CONTROL_DESCRIPTOR_REQUEST *request =
                        &urb->u.UrbControlDescriptorRequest;
                ULONG size = request->TransferBufferLength;
                unsigned char *buf = request->TransferBuffer;

                TRACE( "URB_FUNCTION_GET_DESCRIPTOR_FROM_DEVICE\n" );

                if (!size)
                {
                    status = STATUS_SUCCESS;
                    break;
                }
                if (buf == NULL && request->TransferBufferMDL != NULL)
                    buf = request->TransferBufferMDL->MappedSystemVa;
                if (buf == NULL)
                {
                    status = STATUS_INVALID_PARAMETER;
                    break;
                }

                switch (request->DescriptorType)
                {
                case USB_DEVICE_DESCRIPTOR_TYPE:
                    TRACE( "USB_DEVICE_DESCRIPTOR_TYPE\n" );
                    memcpy( buf, &inst->dev->descriptor,
                            (size < sizeof(USB_DEVICE_DESCRIPTOR)) ?
                            size : sizeof(USB_DEVICE_DESCRIPTOR) );
                    status = STATUS_SUCCESS;
                    break;
                case USB_CONFIGURATION_DESCRIPTOR_TYPE:
                    TRACE( "USB_CONFIGURATION_DESCRIPTOR_TYPE\n" );
                    {
                        unsigned int i, k;
                        struct usb_config_descriptor *conf = &inst->dev->config[0];
                        struct usb_interface_descriptor *intf;
                        struct usb_endpoint_descriptor *endp;

                        /* FIXME: case of num_altsetting > 1 */

                        add_data( &buf, &size, conf,
                                sizeof(USB_CONFIGURATION_DESCRIPTOR) );
                        if (size > 0 && conf->extra)
                            add_data( &buf, &size, conf->extra, conf->extralen );
                        for (i = 0; i < conf->bNumInterfaces; ++i)
                        {
                            intf = &conf->interface[i].altsetting[0];
                            if (size > 0)
                                add_data( &buf, &size, intf,
                                        sizeof(USB_INTERFACE_DESCRIPTOR) );
                            if (size > 0 && intf->extra)
                                add_data( &buf, &size, intf->extra, intf->extralen );
                            for (k = 0; k < intf->bNumEndpoints; ++k)
                            {
                                endp = &intf->endpoint[k];
                                if (size > 0)
                                    add_data( &buf, &size, endp,
                                            sizeof(USB_ENDPOINT_DESCRIPTOR) );
                                if (size > 0 && endp->extra)
                                    add_data( &buf, &size, endp->extra,
                                            endp->extralen );
                            }
                        }
                        status = STATUS_SUCCESS;
                    }
                    break;
                case USB_STRING_DESCRIPTOR_TYPE:
                    TRACE( "USB_STRING_DESCRIPTOR_TYPE\n" );
                    {
                        usb_dev_handle *husb;
                        int ret;

                        husb = usb_open( inst->dev );
                        if (husb)
                        {
                            ret = usb_get_string( husb, request->Index,
                                    request->LanguageId, (void *)buf, size );
                            if (ret >= 0)
                                status = STATUS_SUCCESS;
                            usb_close( husb );
                        }
                    }
                }
            }
            break;
        case URB_FUNCTION_GET_STATUS_FROM_DEVICE:
            {
                struct _URB_CONTROL_GET_STATUS_REQUEST *request =
                        &urb->u.UrbControlGetStatusRequest;
                void *buf = request->TransferBuffer;
                usb_dev_handle *husb;
                int ret;

                TRACE( "URB_FUNCTION_GET_STATUS_FROM_DEVICE\n" );

                if (buf == NULL && request->TransferBufferMDL != NULL)
                    buf = request->TransferBufferMDL->MappedSystemVa;
                if (buf == NULL || request->TransferBufferLength < sizeof(USHORT))
                {
                    status = STATUS_INVALID_PARAMETER;
                    break;
                }
                husb = usb_open( inst->dev );
                if (husb)
                {
                    ret = usb_control_msg( husb, 1 << 7, USB_REQ_GET_STATUS, 0,
                            request->Index, buf, sizeof(USHORT), 0 );
                    if (ret >= 0)
                        status = STATUS_SUCCESS;
                    usb_close( husb );
                }
            }
            break;
        case URB_FUNCTION_VENDOR_DEVICE:
        case URB_FUNCTION_VENDOR_INTERFACE:
        case URB_FUNCTION_VENDOR_ENDPOINT:
        case URB_FUNCTION_CLASS_DEVICE:
        case URB_FUNCTION_CLASS_INTERFACE:
        case URB_FUNCTION_CLASS_ENDPOINT:
            {
                usb_dev_handle *husb;
                struct _URB_CONTROL_VENDOR_OR_CLASS_REQUEST *request =
                        &urb->u.UrbControlVendorClassRequest;
                unsigned char *req_buf = request->TransferBuffer;
                ULONG size = request->TransferBufferLength;

                TRACE( "URB_FUNCTION_{VENDOR,CLASS}_*\n" );

                if (req_buf == NULL && request->TransferBufferMDL != NULL)
                    req_buf = request->TransferBufferMDL->MappedSystemVa;
                if (size && req_buf == NULL)
                {
                    status = STATUS_INVALID_PARAMETER;
                    break;
                }
                husb = usb_open( inst->dev );
                if (husb)
                {
                    UCHAR req_type = request->RequestTypeReservedBits;
                    char *buf;
                    int ret;

                    switch (urb->u.UrbHeader.Function)
                    {
                    case URB_FUNCTION_VENDOR_DEVICE:    req_type |= 0x40; break;
                    case URB_FUNCTION_VENDOR_INTERFACE: req_type |= 0x41; break;
                    case URB_FUNCTION_VENDOR_ENDPOINT:  req_type |= 0x42; break;
                    case URB_FUNCTION_CLASS_DEVICE:     req_type |= 0x20; break;
                    case URB_FUNCTION_CLASS_INTERFACE:  req_type |= 0x21; break;
                    case URB_FUNCTION_CLASS_ENDPOINT:   req_type |= 0x22; break;
                    }
                    buf = HeapAlloc( GetProcessHeap(), 0, size );
                    if (buf != NULL)
                    {
                        memcpy( buf, req_buf, size );
                        if (request->TransferFlags & USBD_TRANSFER_DIRECTION_IN)
                            req_type |= (1 << 7);
                        ret = usb_control_msg( husb, req_type, request->Request,
                                request->Value, request->Index, buf, size, 0 );
                        if (ret >= 0)
                        {
                            if (request->TransferFlags & USBD_TRANSFER_DIRECTION_IN)
                            {
                                request->TransferBufferLength =
                                        (ret < size) ? ret : size;
                                memcpy( req_buf, buf, request->TransferBufferLength );
                            }
                            status = STATUS_SUCCESS;
                        }
                        HeapFree( GetProcessHeap(), 0, buf );
                    }
                    usb_close( husb );
                }
            }
            break;
        case URB_FUNCTION_GET_CONFIGURATION:
            {
                struct _URB_CONTROL_GET_CONFIGURATION_REQUEST *request =
                        &urb->u.UrbControlGetConfigurationRequest;
                char *buf = request->TransferBuffer;
                usb_dev_handle *husb;
                int ret;

                TRACE( "URB_FUNCTION_GET_CONFIGURATION\n" );

                if (buf == NULL && request->TransferBufferMDL != NULL)
                    buf = request->TransferBufferMDL->MappedSystemVa;
                if (buf == NULL || request->TransferBufferLength < 1)
                {
                    status = STATUS_INVALID_PARAMETER;
                    break;
                }
                husb = usb_open( inst->dev );
                if (husb)
                {
                    ret = usb_control_msg( husb, 1 << 7,
                            USB_REQ_GET_CONFIGURATION, 0, 0, buf, 1, 0 );
                    if (ret >= 0)
                        status = STATUS_SUCCESS;
                    usb_close( husb );
                }
            }
            break;
        default:
            FIXME( "unsupported URB function %x\n", urb->u.UrbHeader.Function );
        }
        urb->u.UrbHeader.Status = status;
        break;
    default:
        FIXME( "IOCTL %08x is not implemented\n",
                irpsp->Parameters.DeviceIoControl.IoControlCode );
    }

done:
    LeaveCriticalSection( &usbhub_cs );
    irp->IoStatus.u.Status = status;
    irp->IoStatus.Information = 0;
    IoCompleteRequest( irp, IO_NO_INCREMENT );

    return status;
}

#endif  /* HAVE_LIBUSB_1 */

static NTSTATUS WINAPI usbhub_dispatch_pnp( DEVICE_OBJECT *device, IRP *irp )
{
    static const WCHAR device_idW[] = {'U','S','B','\\',
                                       'V','i','d','_','%','0','4','x','&',
                                       'P','i','d','_','%','0','4','x',0};
    static const WCHAR root_hub_idW[] = {'U','S','B','\\',
                                         'R','O','O','T','_','H','U','B',0};

    struct PdoExtension *dx;
    IO_STACK_LOCATION *irpsp;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ULONG_PTR info = 0;

    TRACE( "%p, %p\n", device, irp );

    EnterCriticalSection( &usbhub_cs );
    irpsp = IoGetCurrentIrpStackLocation( irp );
    if (!device_exists( device ))
    {
        if (irpsp->MinorFunction == IRP_MN_SURPRISE_REMOVAL ||
            irpsp->MinorFunction == IRP_MN_REMOVE_DEVICE)
            status = STATUS_SUCCESS;
        goto done;
    }
    dx = device->DeviceExtension;
    switch (irpsp->MinorFunction)
    {
    case IRP_MN_QUERY_DEVICE_RELATIONS:
        /* dx->instance->service is NULL for root hubs */
        if (dx->instance->service)
        {
            status = irp->IoStatus.u.Status;
            info = irp->IoStatus.Information;
        }
        else
        {
            FIXME( "IRP_MN_QUERY_DEVICE_RELATIONS is not implemented for root hubs\n" );
            status = STATUS_NOT_IMPLEMENTED;
        }
        break;
    case IRP_MN_QUERY_ID:
        switch (irpsp->Parameters.QueryId.IdType)
        {
        case BusQueryDeviceID:
        {
            WCHAR *device_id = ExAllocatePool( PagedPool, dx->instance->service ?
                    sizeof(device_idW) : sizeof(root_hub_idW) );

            if (device_id == NULL)
            {
                status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }
            if (dx->instance->service)
                snprintfW( device_id, strlenW(device_idW) + 1, device_idW,
                        dx->instance->vid, dx->instance->pid );
            else
                strcpyW( device_id, root_hub_idW );
            status = STATUS_SUCCESS;
            info = (ULONG_PTR)device_id;
            break;
        }
        case BusQueryInstanceID:
        {
            char *instance_id;
            ULONG len;
            ULONG size;
            WCHAR *instance_idW;

            instance_id = strrchr( dx->instance->instance_id, '&' );
            instance_id = instance_id ? (instance_id + 1) : dx->instance->instance_id;
            len = strlen(instance_id) + 1;
            size = len * sizeof(WCHAR);
            instance_idW = ExAllocatePool( PagedPool, size );
            if (instance_idW == NULL)
            {
                status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }
            RtlMultiByteToUnicodeN( instance_idW, size, NULL, instance_id, len );
            status = STATUS_SUCCESS;
            info = (ULONG_PTR)instance_idW;
            break;
        }
        default:
            FIXME( "IRP_MN_QUERY_ID: IdType %u is not implemented\n",
                    irpsp->Parameters.QueryId.IdType );
            status = STATUS_NOT_IMPLEMENTED;
        }
        break;
    default:
        status = STATUS_SUCCESS;
    }

done:
    LeaveCriticalSection( &usbhub_cs );
    irp->IoStatus.u.Status = status;
    irp->IoStatus.Information = info;
    IoCompleteRequest( irp, IO_NO_INCREMENT );

    return status;
}

static void stop_service( const WCHAR *name )
{
    SC_HANDLE scm, service;
    SERVICE_STATUS ss;

    scm = OpenSCManagerA( NULL, NULL, SC_MANAGER_ALL_ACCESS );
    if (scm == NULL)
        return;

    service = OpenServiceW( scm, name, SERVICE_ALL_ACCESS );
    if (service == NULL)
    {
        CloseServiceHandle( scm );
        return;
    }

    ControlService( service, SERVICE_CONTROL_STOP, &ss );

    CloseServiceHandle( service );
    CloseServiceHandle( scm );
}

static BOOL create_pdo_name( UNICODE_STRING *pdo_name )
{
    static const WCHAR usbpdoW[] = {'\\','D','e','v','i','c','e','\\',
                                     'U','S','B','P','D','O','-','%','u',0};

    static unsigned int last_pdo_num;
    WCHAR *buf = RtlAllocateHeap( GetProcessHeap(), 0, 30 * sizeof(WCHAR) );

    if (buf == NULL) return FALSE;
    snprintfW( buf, 30, usbpdoW, last_pdo_num++ );
    RtlInitUnicodeString( pdo_name, buf );
    return TRUE;
}

static DEVICE_OBJECT *create_pdo( struct DeviceInstance *inst,
        DRIVER_OBJECT *hubdrv, ULONG flags )
{
    UNICODE_STRING pdo_name;
    DEVICE_OBJECT *usbdev = NULL;

    if (!create_pdo_name( &pdo_name )) return NULL;
    if (IoCreateDevice( hubdrv, sizeof(struct PdoExtension), &pdo_name,
        0, 0, FALSE, &usbdev ) == STATUS_SUCCESS)
    {
        ((struct PdoExtension *)usbdev->DeviceExtension)->instance = inst;
        usbdev->Flags |= flags;
        usbdev->Flags &= ~DO_DEVICE_INITIALIZING;
    }
    RtlFreeUnicodeString( &pdo_name );
    return usbdev;
}

static BOOL register_root_hub_device( DEVICE_OBJECT *dev,
        unsigned int instance_id, UNICODE_STRING *link )
{
    static const WCHAR root_hub_idW[] = {'U','S','B',
                                         '\\','R','O','O','T','_','H','U','B',
                                         '\\','%','u',0};

    HDEVINFO set;
    SP_DEVINFO_DATA devInfo;
    WCHAR *devnameW;
    ULONG size;
    BOOL ret;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    size = sizeof(root_hub_idW) + 16 * sizeof(WCHAR);
    devnameW = HeapAlloc( GetProcessHeap(), 0, size );
    if (devnameW == NULL) return FALSE;
    snprintfW( devnameW, size / sizeof(WCHAR), root_hub_idW, instance_id );

    set = SetupDiGetClassDevsW( NULL, usbW, 0, DIGCF_ALLCLASSES );
    if (set == INVALID_HANDLE_VALUE) goto done;
    devInfo.cbSize = sizeof(SP_DEVINFO_DATA);
    ret = SetupDiCreateDeviceInfoW( set, devnameW, &GUID_DEVCLASS_USB,
            NULL, NULL, 0, &devInfo );
    if (ret)
    {
        ret = SetupDiRegisterDeviceInfo( set, &devInfo, 0, NULL, NULL, NULL );
        if (!ret) goto done;
    }
    else if (ERROR_DEVINST_ALREADY_EXISTS != GetLastError()) goto done;

    status = IoRegisterDeviceInterface( dev, &GUID_DEVINTERFACE_USB_HUB,
            NULL, link );
    if (status == STATUS_SUCCESS)
        IoSetDeviceInterfaceState( link, TRUE );
done:
    if (set != INVALID_HANDLE_VALUE)
        SetupDiDestroyDeviceInfoList( set );
    HeapFree( GetProcessHeap(), 0, devnameW );
    return (status == STATUS_SUCCESS) ? TRUE : FALSE;
}

static void create_hcd_device( unsigned int instance_id, DRIVER_OBJECT *hubdrv,
        UNICODE_STRING *link )
{
    static const WCHAR usbfdoW[] = {'\\','D','e','v','i','c','e',
                                    '\\','U','S','B','F','D','O','-','%','u',0};
    static const WCHAR usbhcdW[] = {'\\','D','o','s','D','e','v','i','c','e','s',
                                    '\\','H','C','D','%','u',0};

    WCHAR *fdo_buf = RtlAllocateHeap( GetProcessHeap(), 0, 30 * sizeof(WCHAR) );
    WCHAR *hcd_buf = RtlAllocateHeap( GetProcessHeap(), 0, 30 * sizeof(WCHAR) );
    UNICODE_STRING fdo_name, hcd_name;
    struct HCDInstance *instance = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    if (fdo_buf == NULL || hcd_buf == NULL) goto done;
    instance = HeapAlloc( GetProcessHeap(), 0, sizeof(*instance) );
    if (instance == NULL) goto done;
    instance->root_hub_name = HeapAlloc( GetProcessHeap(), 0,
            link->Length + sizeof(WCHAR) );
    if (instance->root_hub_name == NULL) goto done;
    memcpy( instance->root_hub_name, link->Buffer, link->Length );
    instance->root_hub_name[link->Length / sizeof(WCHAR)] = 0;

    snprintfW( fdo_buf, 30, usbfdoW, instance_id );
    RtlInitUnicodeString( &fdo_name, fdo_buf );
    snprintfW( hcd_buf, 30, usbhcdW, instance_id );
    RtlInitUnicodeString( &hcd_name, hcd_buf );

    status = IoCreateDevice( hubdrv, 0, &fdo_name, 0, 0, FALSE, &instance->dev );
    if (status != STATUS_SUCCESS) goto done;
    IoCreateSymbolicLink( &hcd_name, &fdo_name );
    instance->dev->Flags &= ~DO_DEVICE_INITIALIZING;
    list_add_tail( &HostControllers, &instance->entry );
done:
    if (status != STATUS_SUCCESS && instance != NULL)
    {
        HeapFree( GetProcessHeap(), 0, instance->root_hub_name );
        HeapFree( GetProcessHeap(), 0, instance );
    }
    RtlFreeUnicodeString( &fdo_name );
    RtlFreeUnicodeString( &hcd_name );
}

static void create_root_hub_device( USHORT vid, USHORT pid, void *dev,
        DRIVER_OBJECT *hubdrv )
{
    static unsigned int instance_id;
    struct DeviceInstance *instance = NULL;
    UNICODE_STRING link;

    instance = HeapAlloc( GetProcessHeap(), 0, sizeof(*instance) );
    if (instance == NULL) return;
    instance->instance_id = HeapAlloc( GetProcessHeap(), 0, 16 );
    if (instance->instance_id == NULL) goto fail;
    instance->vid = vid;
    instance->pid = pid;
    snprintf( instance->instance_id, 16, "%u", instance_id );
    instance->service = NULL;
    instance->dev = dev;

    instance->pdo = create_pdo( instance, hubdrv, DO_POWER_PAGABLE );
    if (instance->pdo == NULL) goto fail;
    list_add_tail( &Devices, &instance->entry );
    if (register_root_hub_device( instance->pdo, instance_id, &link ))
    {
        create_hcd_device( instance_id, hubdrv, &link );
        RtlFreeUnicodeString( &link );
    }
    ++instance_id;
    return;
fail:
    HeapFree( GetProcessHeap(), 0, instance->instance_id );
    HeapFree( GetProcessHeap(), 0, instance );
    return;
}

static BOOL enum_reg_usb_devices(void)
{
    SP_DEVINFO_DATA devInfo = { sizeof(devInfo), { 0 } };
    char *instance_id = NULL;
    struct DeviceInstance *instance, *instance2;
    HDEVINFO set;
    DWORD size, i = 0;
    USHORT vid, pid;
    char *str, *buf;
    BOOL ret;

    set = SetupDiGetClassDevsW( NULL, usbW, 0, DIGCF_ALLCLASSES );
    if (set == INVALID_HANDLE_VALUE) return FALSE;

    while (SetupDiEnumDeviceInfo( set, i++, &devInfo ))
    {
        /* get VID, PID and instance ID */
        buf = HeapAlloc( GetProcessHeap(), 0, MAX_DEVICE_ID_LEN );
        if (buf == NULL) goto fail;
        ret = SetupDiGetDeviceInstanceIdA( set, &devInfo, buf,
                MAX_DEVICE_ID_LEN, NULL );
        if (!ret) goto fail;
        str = strstr( buf, "VID_" );
        if (str != NULL)
        {
            str += 4;
            vid = strtol( str, NULL, 16 );
            str = strstr( str, "PID_" );
        }
        if (str == NULL)
        {
            HeapFree( GetProcessHeap(), 0, buf );
            continue;
        }
        str += 4;
        pid = strtol( str, NULL, 16 );
        str = strrchr( str, '\\' );
        if (str != NULL) ++str;
        if (str == NULL || *str == 0)
        {
            ERR( "bad instance ID\n" );
            HeapFree( GetProcessHeap(), 0, buf );
            continue;
        }
        instance_id = HeapAlloc( GetProcessHeap(), 0, strlen(str) + 1 );
        if (instance_id == NULL) goto fail;
        strcpy( instance_id, str );
        HeapFree( GetProcessHeap(), 0, buf );

        /* get service name */
        SetupDiGetDeviceRegistryPropertyW( set, &devInfo, SPDRP_SERVICE,
                NULL, NULL, 0, &size );
        buf = HeapAlloc( GetProcessHeap(), 0, size );
        if (buf == NULL) goto fail;
        ret = SetupDiGetDeviceRegistryPropertyW( set, &devInfo, SPDRP_SERVICE,
                NULL, (BYTE *)buf, size, NULL );
        if (!ret)
        {
            HeapFree( GetProcessHeap(), 0, buf );
            buf = NULL;
        }

        /* add DeviceInstance structure to Devices list */
        instance = HeapAlloc( GetProcessHeap(), 0, sizeof(*instance) );
        if (instance == NULL) goto fail;
        instance->vid = vid;
        instance->pid = pid;
        instance->instance_id = instance_id;
        instance->service = (WCHAR *)buf;
        instance->pdo = NULL;
        instance->dev = NULL;
        list_add_tail( &Devices, &instance->entry );
        instance_id = NULL;
    }

    SetupDiDestroyDeviceInfoList( set );
    return TRUE;
fail:
    HeapFree( GetProcessHeap(), 0, buf );
    HeapFree( GetProcessHeap(), 0, instance_id );
    SetupDiDestroyDeviceInfoList( set );
    LIST_FOR_EACH_ENTRY_SAFE( instance, instance2, &Devices,
            struct DeviceInstance, entry )
    {
        HeapFree( GetProcessHeap(), 0, instance->instance_id );
        HeapFree( GetProcessHeap(), 0, instance->service );
        list_remove( &instance->entry );
        HeapFree( GetProcessHeap(), 0, instance );
    }
    return FALSE;
}

static char *new_instance_id( USHORT vid, USHORT pid )
{
    struct DeviceInstance *instance;
    char *p, *prefix = NULL;
    unsigned int id = 0, n, prefix_len = 0;
    char *ret;

    LIST_FOR_EACH_ENTRY( instance, &Devices, struct DeviceInstance, entry )
    {
        if (vid == instance->vid && pid == instance->pid)
        {
            if (prefix == NULL)
            {
                prefix = instance->instance_id;
                p = strrchr( instance->instance_id, '&' );
                if (p == NULL) prefix_len = 0;
                else prefix_len = p + 1 - prefix;
                id = strtoul( prefix + prefix_len, NULL, 10 ) + 1;
            }
            else
            {
                p = strrchr( instance->instance_id, '&' );
                if (prefix_len)
                {
                    if (p == NULL || p + 1 - instance->instance_id != prefix_len ||
                        strncmp( instance->instance_id, prefix, prefix_len ))
                        continue;
                }
                else if (p != NULL) continue;
                n = strtoul( instance->instance_id + prefix_len, NULL, 10 ) + 1;
                if (n > id) id = n;
            }
        }
    }
    ret = HeapAlloc( GetProcessHeap(), 0, prefix_len + 16 );
    if (ret == NULL) return NULL;
    memcpy( ret, prefix, prefix_len );
    snprintf( ret + prefix_len, prefix_len + 16, "%d", id );
    return ret;
}

static void register_usb_device( USHORT vid, USHORT pid, void *dev )
{
    static const WCHAR id_fmtW[] = {'U','S','B',
                                    '\\','V','i','d','_','%','0','4','x',
                                    '&','P','i','d','_','%','0','4','x',
                                    '\\','%','s',0};

    struct DeviceInstance *instance;
    HDEVINFO set = INVALID_HANDLE_VALUE;
    SP_DEVINFO_DATA devInfo;
    WCHAR *devnameW = NULL, *instance_idW = NULL;
    char *instance_id;
    ULONG size;

    instance_id = new_instance_id( vid, pid );
    if (instance_id == NULL) return;

    instance = HeapAlloc( GetProcessHeap(), 0, sizeof(*instance) );
    if (instance == NULL)
    {
        HeapFree( GetProcessHeap(), 0, instance_id );
        goto done;
    }
    instance->vid = vid;
    instance->pid = pid;
    instance->instance_id = instance_id;
    instance->service = NULL;
    instance->pdo = NULL;
    instance->dev = dev;
    list_add_tail( &Devices, &instance->entry );

    size = (strlen(instance_id) + 1) * sizeof(WCHAR);
    instance_idW = HeapAlloc( GetProcessHeap(), 0, size );
    if (instance_idW == NULL) goto done;
    RtlMultiByteToUnicodeN( instance_idW, size, NULL,
            instance_id, strlen(instance_id) + 1 );

    size = sizeof(id_fmtW) + (strlenW(instance_idW) - 2) * sizeof(WCHAR);
    devnameW = HeapAlloc( GetProcessHeap(), 0, size );
    if (devnameW == NULL) goto done;
    snprintfW( devnameW, size / sizeof(WCHAR), id_fmtW, vid, pid, instance_idW );

    set = SetupDiGetClassDevsW( NULL, usbW, 0, DIGCF_ALLCLASSES );
    if (set == INVALID_HANDLE_VALUE) goto done;
    devInfo.cbSize = sizeof(SP_DEVINFO_DATA);
    if (SetupDiCreateDeviceInfoW( set, devnameW, &GUID_DEVCLASS_USB,
            NULL, NULL, 0, &devInfo ))
        SetupDiRegisterDeviceInfo( set, &devInfo, 0, NULL, NULL, NULL );
done:
    if (set != INVALID_HANDLE_VALUE)
        SetupDiDestroyDeviceInfoList( set );
    HeapFree( GetProcessHeap(), 0, devnameW );
    HeapFree( GetProcessHeap(), 0, instance_idW );
}

static void start_device_drivers( DRIVER_OBJECT *hubdrv )
{
    struct DeviceInstance *instance;
    DRIVER_OBJECT *driver;
    DEVICE_OBJECT *dev;
    NTSTATUS status;

    LIST_FOR_EACH_ENTRY( instance, &Devices, struct DeviceInstance, entry )
    {
        if (instance->service == NULL || instance->dev == NULL ||
            instance->pdo != NULL) continue;
        if (__wine_start_service( instance->service ))
        {
            instance->pdo = create_pdo( instance, hubdrv,
                    DO_BUS_ENUMERATED_DEVICE | DO_POWER_PAGABLE );
            if (instance->pdo == NULL) continue;
            while (!(driver = __wine_get_driver_object( instance->service )))
                Sleep( 100 );
            status = __wine_add_device( driver, instance->pdo );
            dev = instance->pdo->AttachedDevice;
            if (status == STATUS_SUCCESS && dev != NULL)
                __wine_start_device( dev );
        }
    }
}

static NTSTATUS call_pnp_func( DEVICE_OBJECT *device, UCHAR minor_func )
{
    DRIVER_OBJECT *driver = device->DriverObject;
    IO_STACK_LOCATION *irpsp;
    PIRP irp;
    NTSTATUS status;

    if (driver->MajorFunction[IRP_MJ_PNP] == NULL)
        return STATUS_NOT_SUPPORTED;
    irp = IoAllocateIrp( device->StackSize, FALSE );
    if (irp == NULL) return STATUS_NO_MEMORY;

    irpsp = IoGetNextIrpStackLocation( irp );
    irp->RequestorMode = KernelMode;
    irp->IoStatus.u.Status = STATUS_NOT_SUPPORTED;
    irpsp->MajorFunction = IRP_MJ_PNP;
    irpsp->MinorFunction = minor_func;
    irpsp->DeviceObject = device;
    device->CurrentIrp = irp;
    status = IoCallDriver( device, irp );
    IoFreeIrp( irp );
    return status;
}

static void stop_device_driver( struct DeviceInstance *instance )
{
    if (instance->pdo)
    {
        NTSTATUS status;
        DEVICE_OBJECT *attd = instance->pdo->AttachedDevice;
        DEVICE_OBJECT *dev = (attd != NULL) ? attd : instance->pdo;

        status = call_pnp_func( dev, IRP_MN_SURPRISE_REMOVAL );
        if (status != STATUS_SUCCESS)
            WARN( "handling IRP_MN_SURPRISE_REMOVAL failed: %08x\n", status );
        status = call_pnp_func( dev, IRP_MN_REMOVE_DEVICE );
        if (status != STATUS_SUCCESS)
            WARN( "handling IRP_MN_REMOVE_DEVICE failed: %08x\n", status );
        IoDeleteDevice( instance->pdo );
    }
    if (instance->service)
    {
        struct DeviceInstance *it;
        BOOL stop = TRUE;

        EnterCriticalSection( &usbhub_cs );
        LIST_FOR_EACH_ENTRY( it, &Devices, struct DeviceInstance, entry )
            if (it->pdo != NULL && it->service != NULL &&
                !strcmpiW( it->service, instance->service ))
            {
                stop = FALSE;
                break;
            }
        LeaveCriticalSection( &usbhub_cs );
        if (stop)
            stop_service( instance->service );
    }
    else
        HeapFree( GetProcessHeap(), 0, instance->instance_id );
#ifdef HAVE_LIBUSB_1
    libusb_unref_device( instance->dev );
#endif
    list_remove( &instance->entry );
    HeapFree( GetProcessHeap(), 0, instance );
}

static BOOL is_new( void *dev )
{
    struct DeviceInstance *instance;

    LIST_FOR_EACH_ENTRY( instance, &Devices, struct DeviceInstance, entry )
        if (instance->dev == dev)
            return FALSE;
    return TRUE;
}

static int add_to_remove_list( struct DeviceInstance *it, struct list *remove )
{
    struct DeviceInstance *copy;

    if (it->service)
    {
        copy = HeapAlloc( GetProcessHeap(), 0, sizeof(*copy) );
        if (!copy) return 1;
        memcpy( copy, it, sizeof(struct DeviceInstance) );
        copy->pdo = NULL;
        copy->dev = NULL;
        list_add_tail( &Devices, &copy->entry);
    }
    list_remove( &it->entry );
    list_add_tail( remove, &it->entry );
    return 0;
}

#ifdef HAVE_LIBUSB_1

static int initialize_libusb(void)
{
    return libusb_init( NULL );
}

void add_usb_devices(void)
{
    libusb_device **devs, *dev;
    struct libusb_device_descriptor desc;
    unsigned int i = 0;
    struct DeviceInstance *instance;
    BOOL new_device;

    EnterCriticalSection( &usbhub_cs );
    if (!libusb_initialized || libusb_get_device_list( NULL, &devs ) < 0)
        goto end;
    while ((dev = devs[i++]))
    {
        if (!is_new( dev ))
            continue;
        if (libusb_get_device_descriptor( dev, &desc ))
        {
            ERR( "failed to get USB device descriptor\n" );
            continue;
        }
        TRACE( "add %04x:%04x\n", desc.idVendor, desc.idProduct );
        libusb_ref_device( dev );
        if (libusb_get_device_address( dev ) == 1)
        {
            create_root_hub_device( desc.idVendor, desc.idProduct, dev, usbhub_driver );
            continue;
        }
        new_device = TRUE;
        LIST_FOR_EACH_ENTRY( instance, &Devices, struct DeviceInstance, entry )
        {
            if (instance->dev == NULL && desc.idVendor == instance->vid &&
                desc.idProduct == instance->pid)
            {
                instance->dev = dev;
                new_device = FALSE;
                break;
            }
        }
        if (new_device)
            register_usb_device( desc.idVendor, desc.idProduct, dev );
    }
    libusb_free_device_list( devs, 1 );
    start_device_drivers( usbhub_driver );
end:
    LeaveCriticalSection( &usbhub_cs );
}

void remove_usb_devices(void)
{
    struct list remove_list = LIST_INIT(remove_list);
    libusb_device **devs, *dev;
    struct DeviceInstance *it, *next;
    unsigned int i;
    BOOL found;

    EnterCriticalSection( &usbhub_cs );
    if (!libusb_initialized || libusb_get_device_list( NULL, &devs ) < 0)
        goto end;
    LIST_FOR_EACH_ENTRY_SAFE( it, next, &Devices, struct DeviceInstance, entry )
    {
        if (!it->dev)
            continue;
        found = FALSE;
        i = 0;
        while ((dev = devs[i++]))
            if (it->dev == dev)
            {
                found = TRUE;
                break;
            }
        if (!found && add_to_remove_list( it, &remove_list ))
            break;
    }
end:
    LeaveCriticalSection( &usbhub_cs );
    LIST_FOR_EACH_ENTRY_SAFE( it, next, &remove_list, struct DeviceInstance, entry )
    {
        TRACE( "remove %04x:%04x\n", it->vid, it->pid );
        stop_device_driver( it );
    }
}

#else  /* HAVE_LIBUSB_1 */

static int initialize_libusb(void)
{
    usb_init();
    return 0;
}

void add_usb_devices(void)
{
    struct usb_device *dev;
    struct usb_bus *bus;
    struct usb_device_descriptor *desc;
    struct DeviceInstance *instance;
    BOOL new_device;

    EnterCriticalSection( &usbhub_cs );
    if (!libusb_initialized)
        goto end;
    usb_find_busses();
    usb_find_devices();
    for (bus = usb_busses; bus; bus = bus->next)
        for (dev = bus->devices; dev; dev = dev->next)
        {
            if (dev->devnum > 1 || !is_new( dev )) continue;
            desc = &dev->descriptor;
            TRACE( "add %04x:%04x\n", desc->idVendor, desc->idProduct );
            create_root_hub_device( desc->idVendor, desc->idProduct, dev,
                    usbhub_driver );
        }
    for (bus = usb_busses; bus; bus = bus->next)
        for (dev = bus->devices; dev; dev = dev->next)
        {
            if (dev->devnum <= 1 || !is_new( dev )) continue;
            desc = &dev->descriptor;
            TRACE( "add %04x:%04x\n", desc->idVendor, desc->idProduct );
            new_device = TRUE;
            LIST_FOR_EACH_ENTRY( instance, &Devices, struct DeviceInstance, entry )
            {
                if (instance->dev == NULL && desc->idVendor == instance->vid &&
                    desc->idProduct == instance->pid)
                {
                    instance->dev = dev;
                    new_device = FALSE;
                    break;
                }
            }
            if (new_device)
                register_usb_device( desc->idVendor, desc->idProduct, dev );
        }
    start_device_drivers( usbhub_driver );
end:
    LeaveCriticalSection( &usbhub_cs );
}

void remove_usb_devices(void)
{
    struct list remove_list = LIST_INIT(remove_list);
    struct usb_device *dev;
    struct usb_bus *bus;
    struct DeviceInstance *it, *next;
    BOOL found;

    EnterCriticalSection( &usbhub_cs );
    if (!libusb_initialized)
        goto end;
    usb_find_busses();
    usb_find_devices();
    LIST_FOR_EACH_ENTRY_SAFE( it, next, &Devices, struct DeviceInstance, entry )
    {
        if (!it->dev)
            continue;
        found = FALSE;
        for (bus = usb_busses; bus; bus = bus->next)
            for (dev = bus->devices; dev; dev = dev->next)
                if (it->dev == dev)
                {
                    found = TRUE;
                    break;
                }
        if (!found && add_to_remove_list( it, &remove_list ))
            break;
    }
end:
    LeaveCriticalSection( &usbhub_cs );
    LIST_FOR_EACH_ENTRY_SAFE( it, next, &remove_list, struct DeviceInstance, entry )
    {
        TRACE( "remove %04x:%04x\n", it->vid, it->pid );
        stop_device_driver( it );
    }
}

#endif  /* HAVE_LIBUSB_1 */

#else  /* defined(HAVE_LIBUSB) || defined(HAVE_LIBUSB_1) */

void add_usb_devices(void)
{
}

void remove_usb_devices(void)
{
}

#endif  /* defined(HAVE_LIBUSB) || defined(HAVE_LIBUSB_1) */

#if defined(HAVE_LIBUSB) || defined(HAVE_LIBUSB_1)

#ifdef HAVE_LIBUDEV

static void *start_udev(void)
{
    struct udev *udev;
    struct udev_monitor *mon;
    int ret;

    udev = udev_new();
    if (!udev)
        return NULL;

    mon = udev_monitor_new_from_netlink( udev, "udev" );
    if (!mon) goto end;
    ret = udev_monitor_filter_add_match_subsystem_devtype( mon, "usb", "usb_device" );
    if (ret < 0) goto end;
    ret = udev_monitor_enable_receiving( mon );
    if (ret < 0) goto end;
    return mon;
end:
    udev_monitor_unref( mon );
    udev_unref( udev );
    return NULL;
}

static void loop_udev( void *mon )
{
    struct pollfd fds;
    int ret, fd = udev_monitor_get_fd( mon );

    fds.fd = fd;
    fds.events = POLLIN;

    for(;;)
    {
        fds.revents = 0;
        ret = poll( &fds, 1, -1 );
        if (ret == 1 && (fds.revents & POLLIN))
        {
            struct udev_device *dev = udev_monitor_receive_device( mon );

            if (dev)
            {
                const char *action = udev_device_get_action( dev );

                if (action)
                {
                    if (!strcmp( action, "add" ))
                        add_usb_devices();
                    else if (!strcmp( action, "remove" ))
                        remove_usb_devices();
                }
                udev_device_unref( dev );
            }
        }
    }
}

#else  /* HAVE_LIBUDEV */

static void *start_udev(void)
{
    return NULL;
}

static void loop_udev( void *mon )
{
}

#endif  /* HAVE_LIBUDEV */

static DWORD CALLBACK initialize_usbhub( void *arg )
{
    static const WCHAR usbhub_started_eventW[] = {'_','_','w','i','n','e',
                                                  '_','U','s','b','h','u','b',
                                                  'S','t','a','r','t','e','d',0};

    HANDLE event;
    void *monitor;

    EnterCriticalSection( &usbhub_cs );
    if (!enum_reg_usb_devices())
        ERR( "failed to enumerate USB devices\n" );
    else if (initialize_libusb())
        ERR( "failed to initialize libusb\n" );
    else
        libusb_initialized = TRUE;
    LeaveCriticalSection( &usbhub_cs );
    monitor = start_udev();
    add_usb_devices();
    event = CreateEventW( NULL, TRUE, FALSE, usbhub_started_eventW );
    SetEvent( event );
    CloseHandle( event );
    if (monitor)
        loop_udev( monitor );
    return 0;
}

#endif  /* defined(HAVE_LIBUSB) || defined(HAVE_LIBUSB_1) */

NTSTATUS WINAPI usbhub_driver_entry( DRIVER_OBJECT *driver, UNICODE_STRING *path )
{
#if defined(HAVE_LIBUSB) || defined(HAVE_LIBUSB_1)
    HANDLE thread;

    usbhub_driver = driver;
    driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = usbhub_ioctl;
    driver->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL] = usbhub_internal_ioctl;
    driver->MajorFunction[IRP_MJ_PNP] = usbhub_dispatch_pnp;

    thread = CreateThread( NULL, 0, initialize_usbhub, NULL, 0, NULL );
    if (!thread) return STATUS_UNSUCCESSFUL;
    CloseHandle( thread );
#else
    TRACE( "USB support not compiled in\n" );
#endif
    return STATUS_SUCCESS;
}
