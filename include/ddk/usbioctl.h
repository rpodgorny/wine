/*
 * Copyright 2009 Alexander Morozov for Etersoft
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

#ifndef __DDK_USBIOCTL_H__
#define __DDK_USBIOCTL_H__

#define IOCTL_INTERNAL_USB_SUBMIT_URB  \
  CTL_CODE(FILE_DEVICE_USB, USB_SUBMIT_URB, METHOD_NEITHER, FILE_ANY_ACCESS)

#define IOCTL_USB_GET_NODE_INFORMATION               CTL_CODE(FILE_DEVICE_USB, USB_GET_NODE_INFORMATION, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_USB_GET_NODE_CONNECTION_INFORMATION    CTL_CODE(FILE_DEVICE_USB, USB_GET_NODE_CONNECTION_INFORMATION, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_USB_GET_NODE_CONNECTION_DRIVERKEY_NAME CTL_CODE(FILE_DEVICE_USB, USB_GET_NODE_CONNECTION_DRIVERKEY_NAME, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_USB_GET_ROOT_HUB_NAME CTL_CODE(FILE_DEVICE_USB, HCD_GET_ROOT_HUB_NAME, METHOD_BUFFERED, FILE_ANY_ACCESS)

#include <ddk/usb100.h>
#include <ddk/usbiodef.h>
#include <pshpack1.h>

typedef enum _USB_HUB_NODE {
    UsbHub,
    UsbMIParent
} USB_HUB_NODE;

typedef struct _USB_HUB_INFORMATION {
    USB_HUB_DESCRIPTOR HubDescriptor;
    BOOLEAN HubIsBusPowered;
} USB_HUB_INFORMATION, *PUSB_HUB_INFORMATION;

typedef struct _USB_MI_PARENT_INFORMATION {
    ULONG NumberOfInterfaces;
} USB_MI_PARENT_INFORMATION, *PUSB_MI_PARENT_INFORMATION;

typedef struct _USB_NODE_INFORMATION {
    USB_HUB_NODE NodeType;
    union {
        USB_HUB_INFORMATION HubInformation;
        USB_MI_PARENT_INFORMATION MiParentInformation;
    } u;
} USB_NODE_INFORMATION, *PUSB_NODE_INFORMATION;

typedef struct _USB_PIPE_INFO {
    USB_ENDPOINT_DESCRIPTOR EndpointDescriptor;
    ULONG ScheduleOffset;
} USB_PIPE_INFO, *PUSB_PIPE_INFO;

typedef enum _USB_CONNECTION_STATUS {
    NoDeviceConnected,
    DeviceConnected,
    DeviceFailedEnumeration,
    DeviceGeneralFailure,
    DeviceCausedOvercurrent,
    DeviceNotEnoughPower,
    DeviceNotEnoughBandwidth,
    DeviceHubNestedTooDeeply,
    DeviceInLegacyHub
} USB_CONNECTION_STATUS, *PUSB_CONNECTION_STATUS;

typedef struct _USB_NODE_CONNECTION_INFORMATION {
    ULONG ConnectionIndex;
    USB_DEVICE_DESCRIPTOR DeviceDescriptor;
    UCHAR CurrentConfigurationValue;
    BOOLEAN LowSpeed;
    BOOLEAN DeviceIsHub;
    USHORT DeviceAddress;
    ULONG NumberOfOpenPipes;
    USB_CONNECTION_STATUS ConnectionStatus;
    USB_PIPE_INFO PipeList[0];
} USB_NODE_CONNECTION_INFORMATION, *PUSB_NODE_CONNECTION_INFORMATION;

typedef struct _USB_NODE_CONNECTION_DRIVERKEY_NAME {
    ULONG ConnectionIndex;
    ULONG ActualLength;
    WCHAR DriverKeyName[1];
} USB_NODE_CONNECTION_DRIVERKEY_NAME, *PUSB_NODE_CONNECTION_DRIVERKEY_NAME;

typedef struct _USB_HCD_DRIVERKEY_NAME {
    ULONG ActualLength;
    WCHAR DriverKeyName[1];
} USB_HCD_DRIVERKEY_NAME, *PUSB_HCD_DRIVERKEY_NAME;

#include <poppack.h>

#endif /* __DDK_USBIOCTL_H__ */
