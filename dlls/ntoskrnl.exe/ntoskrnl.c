/*
 * ntoskrnl.exe implementation
 *
 * Copyright (C) 2007 Alexandre Julliard
 * Copyright (C) 2010 Damjan Jovanovic
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

#include <stdarg.h>

#define NONAMELESSUNION
#define NONAMELESSSTRUCT
#define INITGUID

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"
#include "winbase.h"
#include "winsvc.h"
#include "winuser.h"
#include "winreg.h"
#include "setupapi.h"
#include "cfgmgr32.h"
#include "excpt.h"
#include "winioctl.h"
#include "ddk/ntddk.h"
#include "ddk/wdmguid.h"
#include "ddk/ntifs.h"
#include "wine/unicode.h"
#include "wine/server.h"
#include "wine/list.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(ntoskrnl);
WINE_DECLARE_DEBUG_CHANNEL(relay);

BOOLEAN KdDebuggerEnabled = FALSE;
ULONG InitSafeBootMode = 0;

extern LONG CALLBACK vectored_handler( EXCEPTION_POINTERS *ptrs );

KSYSTEM_TIME KeTickCount = { 0, 0, 0 };

typedef struct _KSERVICE_TABLE_DESCRIPTOR
{
    PULONG_PTR Base;
    PULONG Count;
    ULONG Limit;
    PUCHAR Number;
} KSERVICE_TABLE_DESCRIPTOR, *PKSERVICE_TABLE_DESCRIPTOR;

KSERVICE_TABLE_DESCRIPTOR KeServiceDescriptorTable[4] = { { 0 } };

typedef void (WINAPI *PCREATE_PROCESS_NOTIFY_ROUTINE)(HANDLE,HANDLE,BOOLEAN);
typedef void (WINAPI *PCREATE_THREAD_NOTIFY_ROUTINE)(HANDLE,HANDLE,BOOLEAN);

static CRITICAL_SECTION cs;
static CRITICAL_SECTION_DEBUG cs_debug =
{
    0, 0, &cs,
    { &cs_debug.ProcessLocksList, &cs_debug.ProcessLocksList },
      0, 0, { (DWORD_PTR)(__FILE__ ": cs") }
};
static CRITICAL_SECTION cs = { &cs_debug, -1, 0, 0, 0, 0 };

static struct list Irps = LIST_INIT(Irps);

struct IrpInstance
{
    struct list entry;
    IRP *irp;
};

/* tid of the thread running client request */
static DWORD request_thread;

/* pid/tid of the client thread */
static DWORD client_tid;
static DWORD client_pid;

static struct list DriverObjExtensions = LIST_INIT(DriverObjExtensions);

struct DriverObjExtension
{
    struct list entry;
    void *ptr;
    DRIVER_OBJECT *driver;
    void *id_addr;
};

static struct list Drivers = LIST_INIT(Drivers);

struct DriverInstance
{
    struct list entry;
    DRIVER_OBJECT *driver;
    const WCHAR *service;
    DWORD driver_thread_id;
    DWORD client_tid;
    DWORD client_pid;
};

static struct list Interfaces = LIST_INIT(Interfaces);

struct InterfaceInstance
{
    struct list entry;
    WCHAR *link;
    UNICODE_STRING target;
    GUID guid;
    int active;
};

static struct list InterfaceChangeNotifications = LIST_INIT(InterfaceChangeNotifications);

struct InterfaceChangeNotification
{
    struct list entry;
    GUID interface_class;
    PDRIVER_NOTIFICATION_CALLBACK_ROUTINE callback;
    void *context;
};

struct callback
{
    struct list entry;
    PDRIVER_NOTIFICATION_CALLBACK_ROUTINE routine;
    void *context;
};

static struct list Handles = LIST_INIT(Handles);

struct HandleInstance
{
    struct list entry;
    void *object;
    HANDLE handle;
    ULONG refs;
};

#ifdef __i386__
#define DEFINE_FASTCALL1_ENTRYPOINT( name ) \
    __ASM_STDCALL_FUNC( name, 4, \
                       "popl %eax\n\t" \
                       "pushl %ecx\n\t" \
                       "pushl %eax\n\t" \
                       "jmp " __ASM_NAME("__regs_") #name __ASM_STDCALL(4))
#define DEFINE_FASTCALL2_ENTRYPOINT( name ) \
    __ASM_STDCALL_FUNC( name, 8, \
                       "popl %eax\n\t" \
                       "pushl %edx\n\t" \
                       "pushl %ecx\n\t" \
                       "pushl %eax\n\t" \
                       "jmp " __ASM_NAME("__regs_") #name __ASM_STDCALL(8))
#define DEFINE_FASTCALL3_ENTRYPOINT( name ) \
    __ASM_STDCALL_FUNC( name, 12, \
                       "popl %eax\n\t" \
                       "pushl %edx\n\t" \
                       "pushl %ecx\n\t" \
                       "pushl %eax\n\t" \
                       "jmp " __ASM_NAME("__regs_") #name __ASM_STDCALL(12))
#endif

static inline LPCSTR debugstr_us( const UNICODE_STRING *us )
{
    if (!us) return "<null>";
    return debugstr_wn( us->Buffer, us->Length / sizeof(WCHAR) );
}

BOOL CDECL __wine_start_service( const WCHAR *name )
{
    SC_HANDLE scm, service;
    BOOL ret;

    scm = OpenSCManagerA( NULL, NULL, SC_MANAGER_ALL_ACCESS );
    if (scm == NULL)
        return FALSE;

    service = OpenServiceW( scm, name, SERVICE_ALL_ACCESS );
    if (service == NULL)
    {
        CloseServiceHandle( scm );
        return FALSE;
    }

    do {
        ret = StartServiceW( service, 0, NULL );
        if (!ret)
        {
            if (ERROR_SERVICE_ALREADY_RUNNING == GetLastError())
                ret = TRUE;
            else if (ERROR_SERVICE_DATABASE_LOCKED == GetLastError())
                Sleep( 100 );
            else
                break;
        }
    } while (!ret);

    CloseServiceHandle( service );
    CloseServiceHandle( scm );

    return ret;
}

/* get name of driver service for device with given id */
static BOOL get_service( WCHAR *device_id, WCHAR **service_name )
{
    SP_DEVINFO_DATA devInfo = { sizeof(devInfo), { 0 } };
    HDEVINFO set;
    WCHAR *ptr, *enum_name, *id = NULL;
    DWORD size, i = 0;
    BOOL ret;

    *service_name = NULL;
    ptr = strchrW( device_id, '\\' );
    if (!ptr) return FALSE;
    size = ptr - device_id + 1;
    enum_name = RtlAllocateHeap( GetProcessHeap(), 0, size * sizeof(WCHAR) );
    if (!enum_name) return FALSE;
    lstrcpynW( enum_name, device_id, size );

    set = SetupDiGetClassDevsW( NULL, enum_name, 0, DIGCF_ALLCLASSES );
    if (set == INVALID_HANDLE_VALUE) goto end;
    while (SetupDiEnumDeviceInfo( set, i++, &devInfo ))
    {
        SetupDiGetDeviceRegistryPropertyW( set, &devInfo, SPDRP_HARDWAREID,
                NULL, NULL, 0, &size );
        if (id) RtlFreeHeap( GetProcessHeap(), 0, id );
        id = RtlAllocateHeap( GetProcessHeap(), 0, size );
        if (!id) break;
        ret = SetupDiGetDeviceRegistryPropertyW( set, &devInfo, SPDRP_HARDWAREID,
                NULL, (BYTE *)id, size, NULL );
        if (!ret) break;
        if (strcmpiW( device_id, id )) continue;
        SetupDiGetDeviceRegistryPropertyW( set, &devInfo, SPDRP_SERVICE,
                NULL, NULL, 0, &size );
        *service_name = RtlAllocateHeap( GetProcessHeap(), 0, size );
        if (!*service_name) break;
        ret = SetupDiGetDeviceRegistryPropertyW( set, &devInfo, SPDRP_SERVICE,
                NULL, (BYTE *)*service_name, size, NULL );
        if (!ret)
        {
            RtlFreeHeap( GetProcessHeap(), 0, *service_name );
            *service_name = NULL;
            break;
        }
    }
    SetupDiDestroyDeviceInfoList( set );
end:
    if (id) RtlFreeHeap( GetProcessHeap(), 0, id );
    if (enum_name) RtlFreeHeap( GetProcessHeap(), 0, enum_name );
    return (*service_name != NULL);
}

static NTSTATUS get_device_id( DEVICE_OBJECT *pdo, BUS_QUERY_ID_TYPE id_type,
                               WCHAR **id )
{
    NTSTATUS status;
    IO_STACK_LOCATION *irpsp;
    IRP *irp;

    *id = NULL;
    irp = IoAllocateIrp( pdo->StackSize, FALSE );
    if (irp == NULL) return STATUS_NO_MEMORY;
    irpsp = IoGetNextIrpStackLocation( irp );
    irpsp->MajorFunction = IRP_MJ_PNP;
    irpsp->MinorFunction = IRP_MN_QUERY_ID;
    irpsp->Parameters.QueryId.IdType = id_type;
    status = IoCallDriver( pdo, irp );
    if (status == STATUS_SUCCESS)
        *id = (WCHAR *)irp->IoStatus.Information;
    IoFreeIrp( irp );
    return status;
}

static BOOL compare_ids( WCHAR *hardware_id, WCHAR *instance_id,
                         WCHAR *device_instance_id )
{
    WCHAR *ptr, *ptr2;

    ptr = strrchrW( device_instance_id, '\\' );
    if (ptr == NULL) return FALSE;
    if (strncmpiW( hardware_id, device_instance_id, ptr - device_instance_id ))
        return FALSE;
    ++ptr;
    ptr2 = strrchrW( ptr, '&' );
    ptr2 = ptr2 ? (ptr2 + 1) : ptr;
    if (strcmpiW( instance_id, ptr2 ))
        return FALSE;
    return TRUE;
}

/* caller is responsible for proper locking to prevent modifying Interfaces list */
static struct InterfaceInstance *get_registered_interface( WCHAR *name, USHORT len )
{
    struct InterfaceInstance *interf;

    LIST_FOR_EACH_ENTRY( interf, &Interfaces, struct InterfaceInstance, entry )
    {
        if (!strncmpW( name, interf->link, len ))
            return interf;
    }
    return NULL;
}

static void call_interface_change_callbacks( const GUID *interface_class,
                                             UNICODE_STRING *link_name )
{
    struct list callbacks = LIST_INIT(callbacks);
    struct InterfaceChangeNotification *notification;
    struct callback *cb, *cb2;
    DEVICE_INTERFACE_CHANGE_NOTIFICATION change_notification;
    NTSTATUS callback_status;

    EnterCriticalSection( &cs );
    LIST_FOR_EACH_ENTRY( notification, &InterfaceChangeNotifications,
            struct InterfaceChangeNotification, entry )
    {
        if (!memcmp( interface_class, &notification->interface_class,
                sizeof(*interface_class) ))
        {
            cb = HeapAlloc( GetProcessHeap(), 0, sizeof(*cb) );
            if (cb == NULL) break;
            cb->routine = notification->callback;
            cb->context = notification->context;
            list_add_tail( &callbacks, &cb->entry );
        }
    }
    LeaveCriticalSection( &cs );

    change_notification.Version = 1;
    change_notification.Size = sizeof(change_notification);
    change_notification.Event = GUID_DEVICE_INTERFACE_ARRIVAL;
    change_notification.InterfaceClassGuid = *interface_class;
    change_notification.SymbolicLinkName = link_name;

    LIST_FOR_EACH_ENTRY_SAFE( cb, cb2, &callbacks, struct callback, entry )
    {
        if (TRACE_ON(relay))
            DPRINTF( "%04x:Call callback %p (notification=%p,context=%p)\n",
                        GetCurrentThreadId(), cb->routine, &change_notification,
                        cb->context );

        callback_status = cb->routine( &change_notification, cb->context );

        if (TRACE_ON(relay))
            DPRINTF( "%04x:Ret  callback %p (notification=%p,context=%p) retval=%08x\n",
                        GetCurrentThreadId(), cb->routine, &change_notification,
                        cb->context, callback_status );

        list_remove( &cb->entry );
        HeapFree( GetProcessHeap(), 0, cb );
    }
}

static HANDLE get_device_manager(void)
{
    static HANDLE device_manager;
    HANDLE handle = 0, ret = device_manager;

    if (!ret)
    {
        SERVER_START_REQ( create_device_manager )
        {
            req->access     = SYNCHRONIZE;
            req->attributes = 0;
            if (!wine_server_call( req )) handle = wine_server_ptr_handle( reply->handle );
        }
        SERVER_END_REQ;

        if (!handle)
        {
            ERR( "failed to create the device manager\n" );
            return 0;
        }
        if (!(ret = InterlockedCompareExchangePointer( &device_manager, handle, 0 )))
            ret = handle;
        else
            NtClose( handle );  /* somebody beat us to it */
    }
    return ret;
}

static NTSTATUS get_autogenerated_device_name( UNICODE_STRING *name )
{
    static const WCHAR autogen_nameW[] = {'\\','D','e','v','i','c','e',
                                          '\\','%','0','8','x',0};

    NTSTATUS status;
    WCHAR *nameW;
    HANDLE handle;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK io;
    unsigned int k = 1;
 
    if (!(nameW = RtlAllocateHeap( GetProcessHeap(), 0, 17 * sizeof(WCHAR) )))
        return STATUS_NO_MEMORY;
 
    attr.Length = sizeof(attr);
    attr.RootDirectory = 0;
    attr.Attributes = OBJ_CASE_INSENSITIVE;
    attr.ObjectName = name;
    attr.SecurityDescriptor = NULL;
    attr.SecurityQualityOfService = NULL;
 
    for (;;)
    {
        sprintfW( nameW, autogen_nameW, k );
        RtlInitUnicodeString( name, nameW );
        status = NtCreateFile( &handle, 0, &attr, &io, NULL, 0, 0,
                FILE_OPEN, 0, NULL, 0 );
        if (status != STATUS_SUCCESS) break;
        NtClose( handle );
        ++k;
    }
    return STATUS_SUCCESS;
}

/* get id of the thread whose request is being handled */
static DWORD get_client_tid(void)
{
    DWORD ret = 0, thread_id = GetCurrentThreadId();
    struct DriverInstance *drv;
 
    EnterCriticalSection( &cs );
    LIST_FOR_EACH_ENTRY( drv, &Drivers, struct DriverInstance, entry )
    {
        if (drv->driver_thread_id == thread_id)
        {
            ret = drv->client_tid;
            break;
        }
    }
    LeaveCriticalSection( &cs );
    return ret;
}

/* get id of the process whose request is being handled */
static DWORD get_client_pid(void)
{
    DWORD ret = 0, thread_id = GetCurrentThreadId();
    struct DriverInstance *drv;
 
    EnterCriticalSection( &cs );
    LIST_FOR_EACH_ENTRY( drv, &Drivers, struct DriverInstance, entry )
    {
        if (drv->driver_thread_id == thread_id)
        {
            ret = drv->client_pid;
            break;
        }
    }
    LeaveCriticalSection( &cs );
    return ret;
}

/* save ids of the thread  whose request is being handled */
static void save_client_ids( DWORD tid, DWORD pid )
{
    DWORD thread_id = GetCurrentThreadId();
    struct DriverInstance *drv;

    EnterCriticalSection( &cs );
    LIST_FOR_EACH_ENTRY( drv, &Drivers, struct DriverInstance, entry )
    {
        if (drv->driver_thread_id == thread_id)
        {
            drv->client_tid = tid;
            drv->client_pid = pid;
            break;
        }
    }
    LeaveCriticalSection( &cs );
}

/* process an ioctl request for a given device */
static NTSTATUS process_ioctl( DEVICE_OBJECT *device, ULONG code, void *in_buff, ULONG in_size,
                               void *out_buff, ULONG *out_size )
{
    IRP irp;
    MDL mdl;
    IO_STACK_LOCATION irpsp;
    PDRIVER_DISPATCH dispatch = device->DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];
    NTSTATUS status;
    LARGE_INTEGER count;

    TRACE( "ioctl %x device %p in_size %u out_size %u\n", code, device, in_size, *out_size );

    /* so we can spot things that we should initialize */
    memset( &irp, 0x55, sizeof(irp) );
    memset( &irpsp, 0x66, sizeof(irpsp) );
    memset( &mdl, 0x77, sizeof(mdl) );

    irp.RequestorMode = UserMode;
    if ((code & 3) == METHOD_BUFFERED)
    {
        irp.AssociatedIrp.SystemBuffer = HeapAlloc( GetProcessHeap(), 0, max( in_size, *out_size ) );
        if (!irp.AssociatedIrp.SystemBuffer)
            return STATUS_NO_MEMORY;
        memcpy( irp.AssociatedIrp.SystemBuffer, in_buff, in_size );
    }
    else
        irp.AssociatedIrp.SystemBuffer = in_buff;
    irp.UserBuffer = out_buff;
    irp.MdlAddress = &mdl;
    irp.Tail.Overlay.s.u2.CurrentStackLocation = &irpsp;
    irp.UserIosb = NULL;

    irpsp.MajorFunction = IRP_MJ_DEVICE_CONTROL;
    irpsp.Parameters.DeviceIoControl.OutputBufferLength = *out_size;
    irpsp.Parameters.DeviceIoControl.InputBufferLength = in_size;
    irpsp.Parameters.DeviceIoControl.IoControlCode = code;
    irpsp.Parameters.DeviceIoControl.Type3InputBuffer = in_buff;
    irpsp.DeviceObject = device;
    irpsp.CompletionRoutine = NULL;

    mdl.Next = NULL;
    mdl.Size = 0;
    mdl.StartVa = out_buff;
    mdl.ByteCount = *out_size;
    mdl.ByteOffset = 0;

    device->CurrentIrp = &irp;

    KeQueryTickCount( &count );  /* update the global KeTickCount */

    if (TRACE_ON(relay))
        DPRINTF( "%04x:Call driver dispatch %p (device=%p,irp=%p)\n",
                 GetCurrentThreadId(), dispatch, device, &irp );

    status = dispatch( device, &irp );

    if (TRACE_ON(relay))
        DPRINTF( "%04x:Ret  driver dispatch %p (device=%p,irp=%p) retval=%08x\n",
                 GetCurrentThreadId(), dispatch, device, &irp, status );

    *out_size = (irp.IoStatus.u.Status >= 0) ? irp.IoStatus.Information : 0;
    if ((code & 3) == METHOD_BUFFERED)
    {
        if (out_buff) memcpy( out_buff, irp.AssociatedIrp.SystemBuffer, *out_size );
        HeapFree( GetProcessHeap(), 0, irp.AssociatedIrp.SystemBuffer );
    }
    return irp.IoStatus.u.Status;
}


/***********************************************************************
 *           wine_ntoskrnl_main_loop   (Not a Windows API)
 */
NTSTATUS CDECL wine_ntoskrnl_main_loop( HANDLE stop_event )
{
    HANDLE manager = get_device_manager();
    obj_handle_t ioctl = 0;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG code = 0;
    void *in_buff, *out_buff = NULL;
    DEVICE_OBJECT *device = NULL;
    ULONG in_size = 4096, out_size = 0;
    HANDLE handles[2];

    request_thread = GetCurrentThreadId();

    if (!(in_buff = HeapAlloc( GetProcessHeap(), 0, in_size )))
    {
        ERR( "failed to allocate buffer\n" );
        return STATUS_NO_MEMORY;
    }

    handles[0] = stop_event;
    handles[1] = manager;

    for (;;)
    {
        SERVER_START_REQ( get_next_device_request )
        {
            req->manager = wine_server_obj_handle( manager );
            req->prev = ioctl;
            req->status = status;
            wine_server_add_data( req, out_buff, out_size );
            wine_server_set_reply( req, in_buff, in_size );
            if (!(status = wine_server_call( req )))
            {
                code       = reply->code;
                ioctl      = reply->next;
                device     = wine_server_get_ptr( reply->user_ptr );
                client_tid = reply->client_tid;
                client_pid = reply->client_pid;
                in_size    = reply->in_size;
                out_size   = reply->out_size;
            }
            else
            {
                ioctl = 0; /* no previous ioctl */
                out_size = 0;
                in_size = reply->in_size;
            }
        }
        SERVER_END_REQ;

        save_client_ids( client_tid, client_pid );

        switch(status)
        {
        case STATUS_SUCCESS:
            HeapFree( GetProcessHeap(), 0, out_buff );
            if (out_size) out_buff = HeapAlloc( GetProcessHeap(), 0, out_size );
            else out_buff = NULL;
            while (device->AttachedDevice)
                device = device->AttachedDevice;
            status = process_ioctl( device, code, in_buff, in_size, out_buff, &out_size );
            break;
        case STATUS_BUFFER_OVERFLOW:
            HeapFree( GetProcessHeap(), 0, in_buff );
            in_buff = HeapAlloc( GetProcessHeap(), 0, in_size );
            /* restart with larger buffer */
            break;
        case STATUS_PENDING:
            if (WaitForMultipleObjects( 2, handles, FALSE, INFINITE ) == WAIT_OBJECT_0)
            {
                HeapFree( GetProcessHeap(), 0, in_buff );
                HeapFree( GetProcessHeap(), 0, out_buff );
                return STATUS_SUCCESS;
            }
            break;
        }
    }
}


/***********************************************************************
 *           IoAcquireCancelSpinLock  (NTOSKRNL.EXE.@)
 */
void WINAPI IoAcquireCancelSpinLock(PKIRQL irql)
{
    FIXME("(%p): stub\n", irql);
}


/***********************************************************************
 *           IoReleaseCancelSpinLock  (NTOSKRNL.EXE.@)
 */
void WINAPI IoReleaseCancelSpinLock(PKIRQL irql)
{
    FIXME("(%p): stub\n", irql);
}


/***********************************************************************
 *           __wine_add_driver_object   (Not a Windows API)
 */
BOOL CDECL __wine_add_driver_object( DRIVER_OBJECT *driver, const WCHAR *service )
{
    struct DriverInstance *drv;

    drv = HeapAlloc( GetProcessHeap(), 0, sizeof(*drv) );
    if (drv == NULL) return FALSE;
    drv->driver = driver;
    drv->service = service;
    drv->driver_thread_id = GetCurrentThreadId();
    drv->client_tid = 0;
    drv->client_pid = 0;
    EnterCriticalSection( &cs );
    list_add_tail( &Drivers, &drv->entry );
    LeaveCriticalSection( &cs );
    return TRUE;
}


/***********************************************************************
 *           __wine_del_driver_object   (Not a Windows API)
 */
void CDECL __wine_del_driver_object( const DRIVER_OBJECT *driver )
{
    struct DriverInstance *drv;

    EnterCriticalSection( &cs );
    LIST_FOR_EACH_ENTRY( drv, &Drivers, struct DriverInstance, entry )
    {
        if (drv->driver == driver)
        {
            list_remove( &drv->entry );
            HeapFree( GetProcessHeap(), 0, drv );
            break;
        }
    }
    LeaveCriticalSection( &cs );
}


/***********************************************************************
 *           __wine_get_driver_object   (Not a Windows API)
 */
DRIVER_OBJECT * CDECL __wine_get_driver_object( const WCHAR *service )
{
    struct DriverInstance *drv;
    DRIVER_OBJECT *driver_obj = NULL;

    EnterCriticalSection( &cs );
    LIST_FOR_EACH_ENTRY( drv, &Drivers, struct DriverInstance, entry )
    {
        if (!strcmpiW( drv->service, service ))
        {
            driver_obj = drv->driver;
            break;
        }
    }
    LeaveCriticalSection( &cs );
    return driver_obj;
}


/***********************************************************************
 *           __wine_add_device   (Not a Windows API)
 */
NTSTATUS CDECL __wine_add_device( DRIVER_OBJECT *driver, DEVICE_OBJECT *dev )
{
    NTSTATUS status;
    NTSTATUS (WINAPI *AddDevice)( PDRIVER_OBJECT, PDEVICE_OBJECT ) =
            driver->DriverExtension->AddDevice;

    if (TRACE_ON(relay))
        DPRINTF( "%04x:Call AddDevice %p (%p,%p)\n",
                 GetCurrentThreadId(), AddDevice, driver, dev );

    status = AddDevice( driver, dev );

    if (TRACE_ON(relay))
        DPRINTF( "%04x:Ret  AddDevice %p (%p,%p) retval=%08x\n",
                 GetCurrentThreadId(), AddDevice, driver, dev, status );

    return status;
}


/***********************************************************************
 *           __wine_start_device   (Not a Windows API)
 */
NTSTATUS CDECL __wine_start_device( DEVICE_OBJECT *device )
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
    irpsp->MinorFunction = IRP_MN_START_DEVICE;
    irpsp->DeviceObject = device;
    device->CurrentIrp = irp;
    status = IoCallDriver( device, irp );
    IoFreeIrp( irp );
    return status;
}


/***********************************************************************
 *           ExAcquireFastMutexUnsafe  (NTOSKRNL.EXE.@)
 */
#ifdef DEFINE_FASTCALL1_ENTRYPOINT
DEFINE_FASTCALL1_ENTRYPOINT( ExAcquireFastMutexUnsafe )
void WINAPI __regs_ExAcquireFastMutexUnsafe( PFAST_MUTEX FastMutex )
#else
void WINAPI ExAcquireFastMutexUnsafe( PFAST_MUTEX FastMutex )
#endif
{
    FIXME( "stub: %p\n", FastMutex );
}


/***********************************************************************
 *           ExReleaseFastMutexUnsafe  (NTOSKRNL.EXE.@)
 */
#ifdef DEFINE_FASTCALL1_ENTRYPOINT
DEFINE_FASTCALL1_ENTRYPOINT( ExReleaseFastMutexUnsafe )
void WINAPI __regs_ExReleaseFastMutexUnsafe( PFAST_MUTEX FastMutex )
#else
void WINAPI ExReleaseFastMutexUnsafe( PFAST_MUTEX FastMutex )
#endif
{
    FIXME( "stub: %p\n", FastMutex );
}


/***********************************************************************
 *           IoAllocateDriverObjectExtension  (NTOSKRNL.EXE.@)
 */
NTSTATUS WINAPI IoAllocateDriverObjectExtension( PDRIVER_OBJECT DriverObject,
                                                 PVOID ClientIdentificationAddress,
                                                 ULONG DriverObjectExtensionSize,
                                                 PVOID *DriverObjectExtension )
{
    struct DriverObjExtension *ext;

    TRACE( "%p, %p, %u, %p\n", DriverObject, ClientIdentificationAddress,
            DriverObjectExtensionSize, DriverObjectExtension );

    *DriverObjectExtension = NULL;
    if (IoGetDriverObjectExtension( DriverObject, ClientIdentificationAddress ))
        return STATUS_OBJECT_NAME_COLLISION;
    ext = ExAllocatePool( NonPagedPool, sizeof(*ext) );
    if (ext == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;
    ext->ptr = ExAllocatePool( NonPagedPool, DriverObjectExtensionSize );
    if (ext->ptr == NULL)
    {
        ExFreePool( ext );
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    ext->driver = DriverObject;
    ext->id_addr = ClientIdentificationAddress;
    EnterCriticalSection( &cs );
    list_add_tail( &DriverObjExtensions, &ext->entry );
    LeaveCriticalSection( &cs );
    *DriverObjectExtension = ext->ptr;
    return STATUS_SUCCESS;
}

/***********************************************************************
 *           IoGetDriverObjectExtension  (NTOSKRNL.EXE.@)
 */
PVOID WINAPI IoGetDriverObjectExtension( PDRIVER_OBJECT DriverObject,
                                         PVOID ClientIdentificationAddress )
{
    struct DriverObjExtension *ext;
    void *ext_ptr = NULL;

    TRACE( "%p, %p\n", DriverObject, ClientIdentificationAddress );

    EnterCriticalSection( &cs );
    LIST_FOR_EACH_ENTRY( ext, &DriverObjExtensions, struct DriverObjExtension, entry )
    {
        if (DriverObject == ext->driver &&
            ClientIdentificationAddress == ext->id_addr)
        {
            ext_ptr = ext->ptr;
            break;
        }
    }
    LeaveCriticalSection( &cs );
    return ext_ptr;
}

/***********************************************************************
 *           IoInitializeIrp  (NTOSKRNL.EXE.@)
 */
void WINAPI IoInitializeIrp( IRP *irp, USHORT size, CCHAR stack_size )
{
    TRACE( "%p, %u, %d\n", irp, size, stack_size );

    RtlZeroMemory( irp, size );

    irp->Type = IO_TYPE_IRP;
    irp->Size = size;
    InitializeListHead( &irp->ThreadListEntry );
    irp->StackCount = stack_size;
    irp->CurrentLocation = stack_size + 1;
    irp->Tail.Overlay.s.u2.CurrentStackLocation =
            (PIO_STACK_LOCATION)(irp + 1) + stack_size;
}


/***********************************************************************
 *           IoInitializeTimer   (NTOSKRNL.EXE.@)
 */
NTSTATUS WINAPI IoInitializeTimer(PDEVICE_OBJECT DeviceObject,
                                  PIO_TIMER_ROUTINE TimerRoutine,
                                  PVOID Context)
{
    FIXME( "stub: %p, %p, %p\n", DeviceObject, TimerRoutine, Context );
    return STATUS_NOT_IMPLEMENTED;
}


/***********************************************************************
 *           IoStartTimer   (NTOSKRNL.EXE.@)
 */
void WINAPI IoStartTimer(PDEVICE_OBJECT DeviceObject)
{
    FIXME( "stub: %p\n", DeviceObject );
}


/***********************************************************************
 *           IoAllocateIrp  (NTOSKRNL.EXE.@)
 */
PIRP WINAPI IoAllocateIrp( CCHAR stack_size, BOOLEAN charge_quota )
{
    SIZE_T size;
    PIRP irp;

    TRACE( "%d, %d\n", stack_size, charge_quota );

    size = sizeof(IRP) + stack_size * sizeof(IO_STACK_LOCATION);
    irp = ExAllocatePool( NonPagedPool, size );
    if (irp == NULL)
        return NULL;
    IoInitializeIrp( irp, size, stack_size );
    irp->AllocationFlags = IRP_ALLOCATED_FIXED_SIZE;
    if (charge_quota)
        irp->AllocationFlags |= IRP_LOOKASIDE_ALLOCATION;
    return irp;
}


/***********************************************************************
 *           IoFreeIrp  (NTOSKRNL.EXE.@)
 */
void WINAPI IoFreeIrp( IRP *irp )
{
    TRACE( "%p\n", irp );

    ExFreePool( irp );
}


/***********************************************************************
 *           IoAllocateErrorLogEntry  (NTOSKRNL.EXE.@)
 */
PVOID WINAPI IoAllocateErrorLogEntry( PVOID IoObject, UCHAR EntrySize )
{
    FIXME( "stub: %p, %u\n", IoObject, EntrySize );
    return NULL;
}


/***********************************************************************
 *           IoAllocateMdl  (NTOSKRNL.EXE.@)
 */
PMDL WINAPI IoAllocateMdl( PVOID VirtualAddress, ULONG Length, BOOLEAN SecondaryBuffer, BOOLEAN ChargeQuota, PIRP Irp )
{
    PMDL mdl;
    ULONG_PTR address = (ULONG_PTR)VirtualAddress;
    ULONG_PTR page_address;
    SIZE_T nb_pages, mdl_size;

    TRACE("(%p, %u, %i, %i, %p)\n", VirtualAddress, Length, SecondaryBuffer, ChargeQuota, Irp);

    if (Irp)
        FIXME("Attaching the MDL to an IRP is not yet supported\n");

    if (ChargeQuota)
        FIXME("Charge quota is not yet supported\n");

    /* FIXME: We suppose that page size is 4096 */
    page_address = address & ~(4096 - 1);
    nb_pages = (((address + Length - 1) & ~(4096 - 1)) - page_address) / 4096 + 1;

    mdl_size = sizeof(MDL) + nb_pages * sizeof(PVOID);

    mdl = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, mdl_size);
    if (!mdl)
        return NULL;

    mdl->Size = mdl_size;
    mdl->Process = IoGetCurrentProcess();
    mdl->StartVa = (PVOID)page_address;
    mdl->ByteCount = Length;
    mdl->ByteOffset = address - page_address;

    return mdl;
}


/***********************************************************************
 *           IoFreeMdl  (NTOSKRNL.EXE.@)
 */
VOID WINAPI IoFreeMdl(PMDL mdl)
{
    HANDLE process;
    SIZE_T bytes_written;
    DWORD process_id = get_client_pid();

    TRACE( "%p\n", mdl );

    if (process_id)
    {
        process = OpenProcess( PROCESS_ALL_ACCESS, FALSE, process_id );
        if (NULL != process)
        {
            NtWriteVirtualMemory( process, mdl->StartVa, mdl->MappedSystemVa,
                    mdl->ByteCount, &bytes_written );
            CloseHandle( process );
        }
        ExFreePool( mdl->MappedSystemVa );
    }
    ExFreePool( mdl );
}


/***********************************************************************
 *           IoAllocateWorkItem  (NTOSKRNL.EXE.@)
 */
PIO_WORKITEM WINAPI IoAllocateWorkItem( PDEVICE_OBJECT DeviceObject )
{
    FIXME( "stub: %p\n", DeviceObject );
    return NULL;
}


/***********************************************************************
 *           IoAttachDeviceToDeviceStack  (NTOSKRNL.EXE.@)
 */
PDEVICE_OBJECT WINAPI IoAttachDeviceToDeviceStack( DEVICE_OBJECT *source,
                                                   DEVICE_OBJECT *target )
{
    TRACE( "%p, %p\n", source, target );
    while (target->AttachedDevice)
        target = target->AttachedDevice;
    target->AttachedDevice = source;
    source->StackSize = target->StackSize + 1;
    return target;
}


/***********************************************************************
 *           IoDetachDevice  (NTOSKRNL.EXE.@)
 */
void WINAPI IoDetachDevice( DEVICE_OBJECT *device )
{
    TRACE( "%p\n", device );
    device->AttachedDevice = NULL;
}


/***********************************************************************
 *           IoBuildDeviceIoControlRequest  (NTOSKRNL.EXE.@)
 */
PIRP WINAPI IoBuildDeviceIoControlRequest( ULONG IoControlCode,
                                           PDEVICE_OBJECT DeviceObject,
                                           PVOID InputBuffer,
                                           ULONG InputBufferLength,
                                           PVOID OutputBuffer,
                                           ULONG OutputBufferLength,
                                           BOOLEAN InternalDeviceIoControl,
                                           PKEVENT Event,
                                           PIO_STATUS_BLOCK IoStatusBlock )
{
    PIRP irp;
    PIO_STACK_LOCATION irpsp;
    struct IrpInstance *instance;
    CHAR *buf = NULL;
    MDL *mdl = NULL;

    TRACE( "%x, %p, %p, %u, %p, %u, %u, %p, %p\n",
           IoControlCode, DeviceObject, InputBuffer, InputBufferLength,
           OutputBuffer, OutputBufferLength, InternalDeviceIoControl,
           Event, IoStatusBlock );

    if (DeviceObject == NULL)
        return NULL;

    irp = IoAllocateIrp( DeviceObject->StackSize, FALSE );
    if (irp == NULL)
        return NULL;

    instance = HeapAlloc( GetProcessHeap(), 0, sizeof(struct IrpInstance) );
    if (instance == NULL)
    {
        IoFreeIrp( irp );
        return NULL;
    }
    instance->irp = irp;
    list_add_tail( &Irps, &instance->entry );

    irpsp = IoGetNextIrpStackLocation( irp );
    irpsp->MajorFunction = InternalDeviceIoControl ?
            IRP_MJ_INTERNAL_DEVICE_CONTROL : IRP_MJ_DEVICE_CONTROL;
    irpsp->Parameters.DeviceIoControl.IoControlCode = IoControlCode;
    irpsp->Parameters.DeviceIoControl.InputBufferLength = InputBufferLength;
    irpsp->Parameters.DeviceIoControl.OutputBufferLength = OutputBufferLength;
    irp->UserIosb = IoStatusBlock;
    irp->UserEvent = Event;

    switch (IoControlCode & 3)
    {
    case METHOD_BUFFERED:
        buf = ExAllocatePool( NonPagedPool, max( OutputBufferLength, InputBufferLength ) );
        if (buf == NULL)
            goto err;
        memcpy( buf, InputBuffer, InputBufferLength );
        irp->AssociatedIrp.SystemBuffer = buf;
        irp->UserBuffer = OutputBuffer;
        break;
    case METHOD_NEITHER:
        irpsp->Parameters.DeviceIoControl.Type3InputBuffer = InputBuffer;
        irp->UserBuffer = OutputBuffer;
        break;
    default:
        irp->AssociatedIrp.SystemBuffer = InputBuffer;
        mdl = ExAllocatePool( NonPagedPool, sizeof(*mdl) );
        if (mdl == NULL)
            goto err;
        mdl->Next = NULL;
        mdl->Size = 0;
        mdl->StartVa = OutputBuffer;
        mdl->MappedSystemVa = OutputBuffer;
        mdl->ByteCount = OutputBufferLength;
        mdl->ByteOffset = 0;
        irp->MdlAddress = mdl;
    }

    instance = HeapAlloc( GetProcessHeap(), 0, sizeof(struct IrpInstance) );
    if (instance == NULL)
        goto err;
    instance->irp = irp;
    EnterCriticalSection( &cs );
    list_add_tail( &Irps, &instance->entry );
    LeaveCriticalSection( &cs );

    return irp;
err:
    if (buf)
        ExFreePool( buf );
    if (mdl)
        ExFreePool( mdl );
    IoFreeIrp( irp );
    return NULL;
}


/***********************************************************************
 *           IoCreateDriver   (NTOSKRNL.EXE.@)
 */
NTSTATUS WINAPI IoCreateDriver( UNICODE_STRING *name, PDRIVER_INITIALIZE init )
{
    DRIVER_OBJECT *driver;
    DRIVER_EXTENSION *extension;
    NTSTATUS status;

    TRACE("(%s, %p)\n", debugstr_us(name), init);

    if (!(driver = RtlAllocateHeap( GetProcessHeap(), HEAP_ZERO_MEMORY,
                                    sizeof(*driver) + sizeof(*extension) )))
        return STATUS_NO_MEMORY;

    if ((status = RtlDuplicateUnicodeString( 1, name, &driver->DriverName )))
    {
        RtlFreeHeap( GetProcessHeap(), 0, driver );
        return status;
    }

    extension = (DRIVER_EXTENSION *)(driver + 1);
    driver->Size            = sizeof(*driver);
    driver->DriverInit      = init;
    driver->DriverExtension = extension;
    extension->DriverObject   = driver;
    extension->ServiceKeyName = driver->DriverName;

    status = driver->DriverInit( driver, name );

    if (status)
    {
        RtlFreeUnicodeString( &driver->DriverName );
        RtlFreeHeap( GetProcessHeap(), 0, driver );
    }
    return status;
}


/***********************************************************************
 *           IoDeleteDriver   (NTOSKRNL.EXE.@)
 */
void WINAPI IoDeleteDriver( DRIVER_OBJECT *driver )
{
    TRACE("(%p)\n", driver);

    RtlFreeUnicodeString( &driver->DriverName );
    RtlFreeHeap( GetProcessHeap(), 0, driver );
}


/***********************************************************************
 *           IoCreateDevice   (NTOSKRNL.EXE.@)
 */
NTSTATUS WINAPI IoCreateDevice( DRIVER_OBJECT *driver, ULONG ext_size,
                                UNICODE_STRING *name, DEVICE_TYPE type,
                                ULONG characteristics, BOOLEAN exclusive,
                                DEVICE_OBJECT **ret_device )
{
    NTSTATUS status;
    DEVICE_OBJECT *device;
    HANDLE handle = 0;
    HANDLE manager = get_device_manager();
    UNICODE_STRING generated_name;

    TRACE( "(%p, %u, %s, %u, %x, %u, %p)\n",
           driver, ext_size, debugstr_us(name), type, characteristics, exclusive, ret_device );

    if (!(device = HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*device) + ext_size )))
        return STATUS_NO_MEMORY;

    if (characteristics & FILE_AUTOGENERATED_DEVICE_NAME)
    {
        status = get_autogenerated_device_name( &generated_name );
        if (status != STATUS_SUCCESS)
        {
            HeapFree( GetProcessHeap(), 0, device );
            return status;
        }
        name = &generated_name;
    }

    SERVER_START_REQ( create_device )
    {
        req->access     = 0;
        req->attributes = 0;
        req->rootdir    = 0;
        req->manager    = wine_server_obj_handle( manager );
        req->user_ptr   = wine_server_client_ptr( device );
        if (name) wine_server_add_data( req, name->Buffer, name->Length );
        if (!(status = wine_server_call( req ))) handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;

    if (status == STATUS_SUCCESS)
    {
        device->Type            = IO_TYPE_DEVICE;
        device->Size            = sizeof(*device) + ext_size;
        device->DriverObject    = driver;
        device->Flags           = DO_DEVICE_INITIALIZING;
        if (name) device->Flags |= DO_DEVICE_HAS_NAME;
        device->DeviceExtension = device + 1;
        device->DeviceType      = type;
        device->StackSize       = 1;
        device->Reserved        = handle;

        device->NextDevice   = driver->DeviceObject;
        driver->DeviceObject = device;

        *ret_device = device;
    }
    else HeapFree( GetProcessHeap(), 0, device );

    if (characteristics & FILE_AUTOGENERATED_DEVICE_NAME)
        RtlFreeUnicodeString( &generated_name );
    return status;
}


/***********************************************************************
 *           IoDeleteDevice   (NTOSKRNL.EXE.@)
 */
void WINAPI IoDeleteDevice( DEVICE_OBJECT *device )
{
    NTSTATUS status;

    TRACE( "%p\n", device );

    SERVER_START_REQ( delete_device )
    {
        req->handle = wine_server_obj_handle( device->Reserved );
        status = wine_server_call( req );
    }
    SERVER_END_REQ;

    if (status == STATUS_SUCCESS)
    {
        DEVICE_OBJECT **prev = &device->DriverObject->DeviceObject;
        while (*prev && *prev != device) prev = &(*prev)->NextDevice;
        if (*prev) *prev = (*prev)->NextDevice;
        NtClose( device->Reserved );
        HeapFree( GetProcessHeap(), 0, device );
    }
}


/***********************************************************************
 *           IoCreateSymbolicLink   (NTOSKRNL.EXE.@)
 */
NTSTATUS WINAPI IoCreateSymbolicLink( UNICODE_STRING *name, UNICODE_STRING *target )
{
    HANDLE handle;
    OBJECT_ATTRIBUTES attr;

    attr.Length                   = sizeof(attr);
    attr.RootDirectory            = 0;
    attr.ObjectName               = name;
    attr.Attributes               = OBJ_CASE_INSENSITIVE | OBJ_OPENIF;
    attr.SecurityDescriptor       = NULL;
    attr.SecurityQualityOfService = NULL;

    TRACE( "%s -> %s\n", debugstr_us(name), debugstr_us(target) );
    /* FIXME: store handle somewhere */
    return NtCreateSymbolicLinkObject( &handle, SYMBOLIC_LINK_ALL_ACCESS, &attr, target );
}


/***********************************************************************
 *           IoInvalidateDeviceRelations  (NTOSKRNL.EXE.@)
 */
void WINAPI IoInvalidateDeviceRelations( PDEVICE_OBJECT DeviceObject,
                                         DEVICE_RELATION_TYPE Type )
{
    TRACE( "%p, %u\n", DeviceObject, Type );

    while (DeviceObject->AttachedDevice)
        DeviceObject = DeviceObject->AttachedDevice;
    if (Type == BusRelations)
    {
        DEVICE_RELATIONS *rel;
        IO_STACK_LOCATION *irpsp;
        IRP *irp;
        NTSTATUS status;

        irp = IoAllocateIrp( DeviceObject->StackSize, FALSE );
        if (irp == NULL) return;
        irpsp = IoGetNextIrpStackLocation( irp );
        irpsp->MajorFunction = IRP_MJ_PNP;
        irpsp->MinorFunction = IRP_MN_QUERY_DEVICE_RELATIONS;
        irpsp->Parameters.QueryDeviceRelations.Type = BusRelations;
        status = IoCallDriver( DeviceObject, irp );
        rel = (DEVICE_RELATIONS *)irp->IoStatus.Information;
        if (status == STATUS_SUCCESS && rel && rel->Count)
        {
            unsigned int k;

            for (k = 0; k < rel->Count; ++k)
            {
                IoFreeIrp( irp );
                irp = IoAllocateIrp( rel->Objects[k]->StackSize, FALSE );
                if (irp == NULL) return;
                irpsp = IoGetNextIrpStackLocation( irp );
                irpsp->MajorFunction = IRP_MJ_PNP;
                irpsp->MinorFunction = IRP_MN_QUERY_ID;
                irpsp->Parameters.QueryId.IdType = BusQueryDeviceID;
                status = IoCallDriver( rel->Objects[k], irp );
                if (status == STATUS_SUCCESS)
                {
                    WCHAR *service;

                    if (get_service( (WCHAR *)irp->IoStatus.Information, &service )
                        && __wine_start_service( service ))
                    {
                        DRIVER_OBJECT *driver;

                        while (!(driver = __wine_get_driver_object( service )))
                            Sleep( 100 );
                        status = __wine_add_device( driver, rel->Objects[k] );
                        if (status == STATUS_SUCCESS &&
                            rel->Objects[k]->AttachedDevice)
                            __wine_start_device( rel->Objects[k]->AttachedDevice );
                    }
                    if (service) RtlFreeHeap( GetProcessHeap(), 0, service );
                }
                ExFreePool( (void *)irp->IoStatus.Information );
            }
            ExFreePool( rel );
        }
        IoFreeIrp( irp );
    }
    else
        FIXME( "DEVICE_RELATION_TYPE %u not implemented\n", Type );
}


/***********************************************************************
 *           IoRegisterDeviceInterface   (NTOSKRNL.EXE.@)
 */
NTSTATUS WINAPI IoRegisterDeviceInterface( PDEVICE_OBJECT PhysicalDeviceObject,
                                           GUID *InterfaceClassGuid,
                                           PUNICODE_STRING ReferenceString,
                                           PUNICODE_STRING SymbolicLinkName )
{
    WCHAR *hardware_id = NULL, *instance_id = NULL, *id = NULL;
    WCHAR *ptr, *target, *enumerator = NULL;
    SP_DEVICE_INTERFACE_DETAIL_DATA_W *detail = NULL;
    HDEVINFO set;
    SP_DEVINFO_DATA devInfo;
    SP_DEVICE_INTERFACE_DATA interfaceData;
    DWORD i = 0;
    NTSTATUS status;
    struct InterfaceInstance *interf;
    DWORD size;

    TRACE( "%p %s %s %p\n", PhysicalDeviceObject,
           debugstr_guid(InterfaceClassGuid), debugstr_us(ReferenceString),
           SymbolicLinkName );

    status = get_device_id( PhysicalDeviceObject, BusQueryInstanceID, &instance_id );
    if (status != STATUS_SUCCESS) goto end;
    status = get_device_id( PhysicalDeviceObject, BusQueryDeviceID, &hardware_id );
    if (status != STATUS_SUCCESS) goto end;
    ptr = strchrW( hardware_id, '\\' ) + 1;
    size = (char *)ptr - (char *)hardware_id;
    enumerator = RtlAllocateHeap( GetProcessHeap(), 0, size );
    id = RtlAllocateHeap( GetProcessHeap(), 0, MAX_DEVICE_ID_LEN );
    if (enumerator == NULL || id == NULL)
    {
        status = STATUS_NO_MEMORY;
        goto end;
    }
    lstrcpynW( enumerator, hardware_id, size / sizeof(WCHAR) );

    status = STATUS_UNSUCCESSFUL;
    set = SetupDiGetClassDevsW( NULL, enumerator, NULL, DIGCF_ALLCLASSES );
    if (INVALID_HANDLE_VALUE == set) goto end;
    devInfo.cbSize = sizeof(devInfo);
    while (SetupDiEnumDeviceInfo( set, i++, &devInfo ))
        if (SetupDiGetDeviceInstanceIdW( set, &devInfo, id, MAX_DEVICE_ID_LEN, NULL )
            && compare_ids( hardware_id, instance_id, id ))
        {
            interfaceData.cbSize = sizeof(interfaceData);
            if (SetupDiCreateDeviceInterfaceW( set, &devInfo,
                    InterfaceClassGuid, NULL, 0, &interfaceData ))
            {
                SetupDiGetDeviceInterfaceDetailW( set, &interfaceData, NULL, 0,
                        &size, NULL );
                detail = RtlAllocateHeap( GetProcessHeap(), 0, size );
                if (detail == NULL) break;
                detail->cbSize = sizeof(*detail);
                if (!SetupDiGetDeviceInterfaceDetailW( set, &interfaceData,
                        detail, size, NULL, NULL ))
                    break;
                interf = RtlAllocateHeap( GetProcessHeap(), 0, sizeof(*interf) );
                if (interf == NULL) break;
                interf->link = RtlAllocateHeap( GetProcessHeap(), 0,
                        (strlenW(detail->DevicePath) + 1) * sizeof(WCHAR) );
                if (interf->link == NULL)
                {
                    RtlFreeHeap( GetProcessHeap(), 0, interf );
                    break;
                }
                detail->DevicePath[1] = '?';
                strcpyW( interf->link, detail->DevicePath );
                target = RtlAllocateHeap( GetProcessHeap(), 0,
                        MAX_PATH * sizeof(WCHAR) );
                if (target == NULL)
                {
                    RtlFreeHeap( GetProcessHeap(), 0, interf->link );
                    RtlFreeHeap( GetProcessHeap(), 0, interf );
                    break;
                }
                status = IoGetDeviceProperty( PhysicalDeviceObject,
                        DevicePropertyPhysicalDeviceObjectName,
                        MAX_PATH * sizeof(WCHAR), target, &size );
                if (status == STATUS_SUCCESS)
                {
                    RtlInitUnicodeString( &interf->target, target );
                    interf->guid = *InterfaceClassGuid;
                    interf->active = 0;
                    EnterCriticalSection( &cs );
                    if (!get_registered_interface( interf->link,
                            strlenW(interf->link) ))
                    {
                        list_add_tail( &Interfaces, &interf->entry );
                        LeaveCriticalSection( &cs );
                        break;
                    }
                    LeaveCriticalSection( &cs );
                }
                RtlFreeHeap( GetProcessHeap(), 0, target );
                RtlFreeHeap( GetProcessHeap(), 0, interf->link );
                RtlFreeHeap( GetProcessHeap(), 0, interf );
            }
            break;
        }
    SetupDiDestroyDeviceInfoList( set );

    if (STATUS_SUCCESS == status)
        RtlCreateUnicodeString( SymbolicLinkName, detail->DevicePath );
end:
    if (detail) RtlFreeHeap( GetProcessHeap(), 0, detail );
    if (id) RtlFreeHeap( GetProcessHeap(), 0, id );
    if (enumerator) RtlFreeHeap( GetProcessHeap(), 0, enumerator );
    if (hardware_id) ExFreePool( hardware_id );
    if (instance_id) ExFreePool( instance_id );
    return status;
}

/***********************************************************************
 *           IoDeleteSymbolicLink   (NTOSKRNL.EXE.@)
 */
NTSTATUS WINAPI IoDeleteSymbolicLink( UNICODE_STRING *name )
{
    HANDLE handle;
    OBJECT_ATTRIBUTES attr;
    NTSTATUS status;

    attr.Length                   = sizeof(attr);
    attr.RootDirectory            = 0;
    attr.ObjectName               = name;
    attr.Attributes               = OBJ_CASE_INSENSITIVE;
    attr.SecurityDescriptor       = NULL;
    attr.SecurityQualityOfService = NULL;

    if (!(status = NtOpenSymbolicLinkObject( &handle, 0, &attr )))
    {
        SERVER_START_REQ( unlink_object )
        {
            req->handle = wine_server_obj_handle( handle );
            status = wine_server_call( req );
        }
        SERVER_END_REQ;
        NtClose( handle );
    }
    return status;
}


/***********************************************************************
 *           IoGetDeviceInterfaces   (NTOSKRNL.EXE.@)
 */
NTSTATUS WINAPI IoGetDeviceInterfaces( const GUID *InterfaceClassGuid,
                                       PDEVICE_OBJECT PhysicalDeviceObject,
                                       ULONG Flags, PWSTR *SymbolicLinkList )
{
    FIXME( "stub: %s %p %x %p\n", debugstr_guid(InterfaceClassGuid),
           PhysicalDeviceObject, Flags, SymbolicLinkList );
    return STATUS_NOT_IMPLEMENTED;
}


/***********************************************************************
 *           IoSetDeviceInterfaceState   (NTOSKRNL.EXE.@)
 */
NTSTATUS WINAPI IoSetDeviceInterfaceState( PUNICODE_STRING SymbolicLinkName,
                                           BOOLEAN Enable )
{
    TRACE( "%s %d\n", debugstr_us(SymbolicLinkName), Enable );

    if (Enable)
    {
        struct InterfaceInstance *interf;
        NTSTATUS status;
        GUID guid;
        int changed = 0;

        status = STATUS_OBJECT_NAME_NOT_FOUND;
        EnterCriticalSection( &cs );
        interf = get_registered_interface( SymbolicLinkName->Buffer,
                SymbolicLinkName->Length / sizeof(WCHAR) );
        if (interf != NULL)
        {
            if (!interf->active)
            {
                guid = interf->guid;
                status = IoCreateSymbolicLink( SymbolicLinkName, &interf->target );
                if (status == STATUS_SUCCESS)
                {
                    interf->active = 1;
                    changed = 1;
                }
            }
            else status = STATUS_SUCCESS;
        }
        LeaveCriticalSection( &cs );
        if (changed) call_interface_change_callbacks( &guid, SymbolicLinkName );
        return status;
    }
    else
    {
        FIXME( "Disabling interface is not supported\n" );
        return STATUS_NOT_IMPLEMENTED;
    }
}


/***********************************************************************
 *           IoGetDeviceObjectPointer   (NTOSKRNL.EXE.@)
 */
NTSTATUS  WINAPI IoGetDeviceObjectPointer( UNICODE_STRING *name, ACCESS_MASK access, PFILE_OBJECT *file, PDEVICE_OBJECT *device )
{
    FIXME( "stub: %s %x %p %p\n", debugstr_us(name), access, file, device );

    return STATUS_NOT_IMPLEMENTED;
}


/***********************************************************************
 *           IoGetDeviceProperty   (NTOSKRNL.EXE.@)
 */
NTSTATUS WINAPI IoGetDeviceProperty( DEVICE_OBJECT *device, DEVICE_REGISTRY_PROPERTY device_property,
                                     ULONG buffer_length, PVOID property_buffer, PULONG result_length )
{
    NTSTATUS status;

    TRACE( "%p %d %u %p %p\n", device, device_property, buffer_length,
           property_buffer, result_length );

    switch (device_property)
    {
    case DevicePropertyHardwareID:
    {
        WCHAR *hardware_id;

        status = get_device_id( device, BusQueryDeviceID, &hardware_id );
        if (status != STATUS_SUCCESS) break;
        *result_length = (strlenW(hardware_id) + 1) * sizeof(WCHAR);
        if (buffer_length >= *result_length)
            strcpyW( property_buffer, hardware_id );
        else
            status = STATUS_BUFFER_TOO_SMALL;
        ExFreePool( hardware_id );
        break;
    }
    case DevicePropertyPhysicalDeviceObjectName:
    {
        static const WCHAR deviceW[] = {'\\','D','e','v','i','c','e','\\',0};
        WCHAR device_name[MAX_PATH];
        data_size_t len;

        SERVER_START_REQ( get_device_name )
        {
            req->handle = wine_server_obj_handle( device->Reserved );
            wine_server_set_reply( req, device_name,
                    sizeof(device_name) - sizeof(WCHAR) );
            status = wine_server_call( req );
            len = wine_server_reply_size( reply );
        }
        SERVER_END_REQ;

        if (status != STATUS_SUCCESS) break;
        *result_length = len + sizeof(deviceW);
        if (buffer_length >= *result_length)
        {
            strcpyW( property_buffer, deviceW );
            device_name[len / sizeof(WCHAR)] = 0;
            strcatW( property_buffer, device_name );
        }
        else status = STATUS_BUFFER_TOO_SMALL;
        break;
    }
    default:
        FIXME( "device property %u is not supported\n", device_property );
        status = STATUS_NOT_IMPLEMENTED;
    }

    return status;
}


static NTSTATUS WINAPI invalid_request_handler( DEVICE_OBJECT *device, IRP *irp )
{
    irp->IoStatus.u.Status = STATUS_INVALID_DEVICE_REQUEST;
    IoCompleteRequest( irp, IO_NO_INCREMENT );
    return STATUS_INVALID_DEVICE_REQUEST;
}


/***********************************************************************
 *           IoCallDriver   (NTOSKRNL.EXE.@)
 */
NTSTATUS WINAPI IoCallDriver( DEVICE_OBJECT *device, IRP *irp )
{
    PDRIVER_DISPATCH dispatch;
    IO_STACK_LOCATION *irpsp;
    NTSTATUS status;

    TRACE( "%p %p\n", device, irp );

    --irp->CurrentLocation;
    irpsp = --irp->Tail.Overlay.s.u2.CurrentStackLocation;
    irpsp->DeviceObject = device;
    dispatch = device->DriverObject->MajorFunction[irpsp->MajorFunction];
    if (!dispatch)
        dispatch = invalid_request_handler;

    if (TRACE_ON(relay))
        DPRINTF( "%04x:Call driver dispatch %p (device=%p,irp=%p)\n",
                 GetCurrentThreadId(), dispatch, device, irp );

    status = dispatch( device, irp );

    if (TRACE_ON(relay))
        DPRINTF( "%04x:Ret  driver dispatch %p (device=%p,irp=%p) retval=%08x\n",
                 GetCurrentThreadId(), dispatch, device, irp, status );

    return status;
}


/***********************************************************************
 *           IofCallDriver   (NTOSKRNL.EXE.@)
 */
#ifdef DEFINE_FASTCALL2_ENTRYPOINT
DEFINE_FASTCALL2_ENTRYPOINT( IofCallDriver )
NTSTATUS WINAPI __regs_IofCallDriver( DEVICE_OBJECT *device, IRP *irp )
#else
NTSTATUS WINAPI IofCallDriver( DEVICE_OBJECT *device, IRP *irp )
#endif
{
    TRACE( "%p %p\n", device, irp );
    return IoCallDriver( device, irp );
}

/***********************************************************************
 *           IoGetAttachedDeviceReference    (NTOSKRNL.EXE.@)
 */
PDEVICE_OBJECT WINAPI IoGetAttachedDeviceReference( PDEVICE_OBJECT obj )
{
    FIXME( "stub: %p\n", obj );
    return obj;
}

/***********************************************************************
 *           IoGetRelatedDeviceObject    (NTOSKRNL.EXE.@)
 */
PDEVICE_OBJECT WINAPI IoGetRelatedDeviceObject( PFILE_OBJECT obj )
{
    FIXME( "stub: %p\n", obj );
    return NULL;
}

static CONFIGURATION_INFORMATION configuration_information;

/***********************************************************************
 *           IoGetConfigurationInformation    (NTOSKRNL.EXE.@)
 */
PCONFIGURATION_INFORMATION WINAPI IoGetConfigurationInformation(void)
{
    FIXME( "partial stub\n" );
    /* FIXME: return actual devices on system */
    return &configuration_information;
}


/***********************************************************************
 *           IoIsWdmVersionAvailable     (NTOSKRNL.EXE.@)
 */
NTSTATUS WINAPI IoIsWdmVersionAvailable(UCHAR MajorVersion, UCHAR MinorVersion)
{
    DWORD version;
    DWORD major;
    DWORD minor;

    TRACE( "%d, 0x%X\n", MajorVersion, MinorVersion );

    version = GetVersion();
    major = LOBYTE(version);
    minor = HIBYTE(LOWORD(version));

    if (MajorVersion == 6 && MinorVersion == 0)
    {
        /* Windows Vista, Windows Server 2008, Windows 7 */
    }
    else if (MajorVersion == 1)
    {
        if (MinorVersion == 0x30)
        {
            /* Windows server 2003 */
            MajorVersion = 6;
            MinorVersion = 0;
        }
        else if (MinorVersion == 0x20)
        {
            /* Windows XP */
            MajorVersion = 5;
            MinorVersion = 1;
        }
        else if (MinorVersion == 0x10)
        {
            /* Windows 2000 */
            MajorVersion = 5;
            MinorVersion = 0;
        }
        else if (MinorVersion == 0x05)
        {
            /* Windows ME */
            MajorVersion = 4;
            MinorVersion = 0x5a;
        }
        else if (MinorVersion == 0x00)
        {
            /* Windows 98 */
            MajorVersion = 4;
            MinorVersion = 0x0a;
        }
        else
        {
            FIXME( "unknown major %d minor 0x%X\n", MajorVersion, MinorVersion );
            return FALSE;
        }
    }
    else
    {
        FIXME( "unknown major %d minor 0x%X\n", MajorVersion, MinorVersion );
        return FALSE;
    }
    return major > MajorVersion || (major == MajorVersion && minor >= MinorVersion);
}


/***********************************************************************
 *           IoQueryDeviceDescription    (NTOSKRNL.EXE.@)
 */
NTSTATUS WINAPI IoQueryDeviceDescription(PINTERFACE_TYPE itype, PULONG bus, PCONFIGURATION_TYPE ctype,
                                     PULONG cnum, PCONFIGURATION_TYPE ptype, PULONG pnum,
                                     PIO_QUERY_DEVICE_ROUTINE callout, PVOID context)
{
    FIXME( "(%p %p %p %p %p %p %p %p)\n", itype, bus, ctype, cnum, ptype, pnum, callout, context);
    return STATUS_NOT_IMPLEMENTED;
}


/***********************************************************************
 *           IoRegisterDriverReinitialization    (NTOSKRNL.EXE.@)
 */
void WINAPI IoRegisterDriverReinitialization( PDRIVER_OBJECT obj, PDRIVER_REINITIALIZE reinit, PVOID context )
{
    FIXME( "stub: %p %p %p\n", obj, reinit, context );
}


/***********************************************************************
 *           IoRegisterPlugPlayNotification    (NTOSKRNL.EXE.@)
 */
NTSTATUS WINAPI IoRegisterPlugPlayNotification( IO_NOTIFICATION_EVENT_CATEGORY
                                                EventCategory,
                                                ULONG EventCategoryFlags,
                                                PVOID EventCategoryData,
                                                PDRIVER_OBJECT DriverObject,
                                                PDRIVER_NOTIFICATION_CALLBACK_ROUTINE
                                                CallbackRoutine, PVOID Context,
                                                PVOID *NotificationEntry )
{
    TRACE( "%u %u %p %p %p %p %p\n", EventCategory, EventCategoryFlags,
           EventCategoryData, DriverObject, CallbackRoutine, Context,
           NotificationEntry );

    if (EventCategory == EventCategoryDeviceInterfaceChange)
    {
        struct InterfaceChangeNotification *notification =
                HeapAlloc( GetProcessHeap(), 0, sizeof(*notification) );
        struct list interfs = LIST_INIT(interfs);
        struct InterfaceInstance *interf, *interf2;
        UNICODE_STRING link;

        if (notification == NULL) return STATUS_NO_MEMORY;
        notification->interface_class = *(GUID *)EventCategoryData;
        notification->callback = CallbackRoutine;
        notification->context = Context;

        EnterCriticalSection( &cs );
        list_add_tail( &InterfaceChangeNotifications, &notification->entry );
        if (EventCategoryFlags & PNPNOTIFY_DEVICE_INTERFACE_INCLUDE_EXISTING_INTERFACES)
        {
            LIST_FOR_EACH_ENTRY( interf, &Interfaces, struct InterfaceInstance, entry )
            {
                if (interf->active && !memcmp( &notification->interface_class,
                        &interf->guid, sizeof(GUID) ))
                {
                    interf2 = HeapAlloc( GetProcessHeap(), 0, sizeof(*interf2) );
                    if (interf2 == NULL) break;
                    interf2->link = HeapAlloc( GetProcessHeap(), 0,
                            (strlenW(interf->link) + 1) * sizeof(WCHAR) );
                    if (interf2->link == NULL) break;
                    strcpyW( interf2->link, interf->link );
                    interf2->guid = interf->guid;
                    list_add_tail( &interfs, &interf2->entry );
                }
            }
        }
        LeaveCriticalSection( &cs );

        LIST_FOR_EACH_ENTRY_SAFE( interf, interf2, &interfs,
                struct InterfaceInstance, entry )
        {
            list_remove( &interf->entry );
            if (interf->link)
            {
                RtlInitUnicodeString( &link, interf->link );
                call_interface_change_callbacks( &interf->guid, &link );
                HeapFree( GetProcessHeap(), 0, interf->link );
            }
            HeapFree( GetProcessHeap(), 0, interf );
        }
        *NotificationEntry = notification;
        return STATUS_SUCCESS;
    }
    else
    {
        FIXME( "event category %u is not supported\n", EventCategory );
        return STATUS_NOT_IMPLEMENTED;
    }
}


/***********************************************************************
 *           IoUnregisterPlugPlayNotification    (NTOSKRNL.EXE.@)
 */
NTSTATUS WINAPI IoUnregisterPlugPlayNotification( PVOID NotificationEntry )
{
    struct InterfaceChangeNotification *notification = NotificationEntry;

    TRACE( "%p\n", NotificationEntry );

    EnterCriticalSection( &cs );
    list_remove( &notification->entry );
    LeaveCriticalSection( &cs );
    HeapFree( GetProcessHeap(), 0, notification );
    return STATUS_SUCCESS;
}


/***********************************************************************
 *           IoRegisterShutdownNotification    (NTOSKRNL.EXE.@)
 */
NTSTATUS WINAPI IoRegisterShutdownNotification( PDEVICE_OBJECT obj )
{
    FIXME( "stub: %p\n", obj );
    return STATUS_SUCCESS;
}


/***********************************************************************
 *           IoUnregisterShutdownNotification    (NTOSKRNL.EXE.@)
 */
VOID WINAPI IoUnregisterShutdownNotification( PDEVICE_OBJECT obj )
{
    FIXME( "stub: %p\n", obj );
}


/***********************************************************************
 *           IoReportResourceUsage    (NTOSKRNL.EXE.@)
 */
NTSTATUS WINAPI IoReportResourceUsage(PUNICODE_STRING name, PDRIVER_OBJECT drv_obj, PCM_RESOURCE_LIST drv_list,
                                      ULONG drv_size, PDRIVER_OBJECT dev_obj, PCM_RESOURCE_LIST dev_list,
                                      ULONG dev_size, BOOLEAN overwrite, PBOOLEAN detected)
{
    FIXME("(%s %p %p %u %p %p %u %d %p) stub\n", debugstr_w(name? name->Buffer : NULL),
          drv_obj, drv_list, drv_size, dev_obj, dev_list, dev_size, overwrite, detected);
    return STATUS_NOT_IMPLEMENTED;
}


/***********************************************************************
 *           IoCompleteRequest   (NTOSKRNL.EXE.@)
 */
VOID WINAPI IoCompleteRequest( IRP *irp, UCHAR priority_boost )
{
    IO_STACK_LOCATION *irpsp;
    PIO_COMPLETION_ROUTINE routine;
    IO_STATUS_BLOCK *iosb;
    struct IrpInstance *instance;
    NTSTATUS status, stat;
    KEVENT *event;
    int call_flag = 0;

    TRACE( "%p %u\n", irp, priority_boost );

    iosb = irp->UserIosb;
    status = irp->IoStatus.u.Status;
    while (irp->CurrentLocation <= irp->StackCount)
    {
        irpsp = irp->Tail.Overlay.s.u2.CurrentStackLocation;
        routine = irpsp->CompletionRoutine;
        call_flag = 0;
        /* FIXME: add SL_INVOKE_ON_CANCEL support */
        if (routine)
        {
            if ((irpsp->Control & SL_INVOKE_ON_SUCCESS) && STATUS_SUCCESS == status)
                call_flag = 1;
            if ((irpsp->Control & SL_INVOKE_ON_ERROR) && STATUS_SUCCESS != status)
                call_flag = 1;
        }
        ++irp->CurrentLocation;
        ++irp->Tail.Overlay.s.u2.CurrentStackLocation;
        if (call_flag)
        {
            TRACE( "calling %p( %p, %p, %p )\n", routine,
                    irpsp->DeviceObject, irp, irpsp->Context );
            stat = routine( irpsp->DeviceObject, irp, irpsp->Context );
            TRACE( "CompletionRoutine returned %x\n", stat );
            if (STATUS_MORE_PROCESSING_REQUIRED == stat)
                return;
        }
    }
    if (iosb && STATUS_SUCCESS == status)
    {
        iosb->u.Status = irp->IoStatus.u.Status;
        iosb->Information = irp->IoStatus.Information;
    }
    event = irp->UserEvent;
    EnterCriticalSection( &cs );
    LIST_FOR_EACH_ENTRY( instance, &Irps, struct IrpInstance, entry )
    {
        if (instance->irp == irp)
        {
            void *buf = irp->AssociatedIrp.SystemBuffer;
            MDL *mdl = irp->MdlAddress;
            struct _FILE_OBJECT *file = irp->Tail.Overlay.OriginalFileObject;

            list_remove( &instance->entry );
            HeapFree( GetProcessHeap(), 0, instance );
            if (mdl)
            {
                ExFreePool( mdl );
            }
            else if (buf)
            {
                memcpy( irp->UserBuffer, buf, irp->IoStatus.Information );
                ExFreePool( buf );
            }
            if (file) ExFreePool( file );
            IoFreeIrp( irp );
            break;
        }
    }
    LeaveCriticalSection( &cs );
    if (event)
        KeSetEvent( event, 0, FALSE );
}


/***********************************************************************
 *           IofCompleteRequest   (NTOSKRNL.EXE.@)
 */
#ifdef DEFINE_FASTCALL2_ENTRYPOINT
DEFINE_FASTCALL2_ENTRYPOINT( IofCompleteRequest )
void WINAPI __regs_IofCompleteRequest( IRP *irp, UCHAR priority_boost )
#else
void WINAPI IofCompleteRequest( IRP *irp, UCHAR priority_boost )
#endif
{
    TRACE( "%p %u\n", irp, priority_boost );
    IoCompleteRequest( irp, priority_boost );
}


/***********************************************************************
 *           InterlockedCompareExchange   (NTOSKRNL.EXE.@)
 */
#ifdef DEFINE_FASTCALL3_ENTRYPOINT
DEFINE_FASTCALL3_ENTRYPOINT( NTOSKRNL_InterlockedCompareExchange )
LONG WINAPI __regs_NTOSKRNL_InterlockedCompareExchange( LONG volatile *dest, LONG xchg, LONG compare )
#else
LONG WINAPI NTOSKRNL_InterlockedCompareExchange( LONG volatile *dest, LONG xchg, LONG compare )
#endif
{
    return InterlockedCompareExchange( dest, xchg, compare );
}


/***********************************************************************
 *           InterlockedDecrement   (NTOSKRNL.EXE.@)
 */
#ifdef DEFINE_FASTCALL1_ENTRYPOINT
DEFINE_FASTCALL1_ENTRYPOINT( NTOSKRNL_InterlockedDecrement )
LONG WINAPI __regs_NTOSKRNL_InterlockedDecrement( LONG volatile *dest )
#else
LONG WINAPI NTOSKRNL_InterlockedDecrement( LONG volatile *dest )
#endif
{
    return InterlockedDecrement( dest );
}


/***********************************************************************
 *           InterlockedExchange   (NTOSKRNL.EXE.@)
 */
#ifdef DEFINE_FASTCALL2_ENTRYPOINT
DEFINE_FASTCALL2_ENTRYPOINT( NTOSKRNL_InterlockedExchange )
LONG WINAPI __regs_NTOSKRNL_InterlockedExchange( LONG volatile *dest, LONG val )
#else
LONG WINAPI NTOSKRNL_InterlockedExchange( LONG volatile *dest, LONG val )
#endif
{
    return InterlockedExchange( dest, val );
}


/***********************************************************************
 *           InterlockedExchangeAdd   (NTOSKRNL.EXE.@)
 */
#ifdef DEFINE_FASTCALL2_ENTRYPOINT
DEFINE_FASTCALL2_ENTRYPOINT( NTOSKRNL_InterlockedExchangeAdd )
LONG WINAPI __regs_NTOSKRNL_InterlockedExchangeAdd( LONG volatile *dest, LONG incr )
#else
LONG WINAPI NTOSKRNL_InterlockedExchangeAdd( LONG volatile *dest, LONG incr )
#endif
{
    return InterlockedExchangeAdd( dest, incr );
}


/***********************************************************************
 *           InterlockedIncrement   (NTOSKRNL.EXE.@)
 */
#ifdef DEFINE_FASTCALL1_ENTRYPOINT
DEFINE_FASTCALL1_ENTRYPOINT( NTOSKRNL_InterlockedIncrement )
LONG WINAPI __regs_NTOSKRNL_InterlockedIncrement( LONG volatile *dest )
#else
LONG WINAPI NTOSKRNL_InterlockedIncrement( LONG volatile *dest )
#endif
{
    return InterlockedIncrement( dest );
}


/***********************************************************************
 *           ExAllocatePool   (NTOSKRNL.EXE.@)
 */
PVOID WINAPI ExAllocatePool( POOL_TYPE type, SIZE_T size )
{
    return ExAllocatePoolWithTag( type, size, 0 );
}


/***********************************************************************
 *           ExAllocatePoolWithQuota   (NTOSKRNL.EXE.@)
 */
PVOID WINAPI ExAllocatePoolWithQuota( POOL_TYPE type, SIZE_T size )
{
    return ExAllocatePoolWithTag( type, size, 0 );
}


/***********************************************************************
 *           ExAllocatePoolWithTag   (NTOSKRNL.EXE.@)
 */
PVOID WINAPI ExAllocatePoolWithTag( POOL_TYPE type, SIZE_T size, ULONG tag )
{
    /* FIXME: handle page alignment constraints */
    void *ret = HeapAlloc( GetProcessHeap(), 0, size );
    TRACE( "%lu pool %u -> %p\n", size, type, ret );
    return ret;
}


/***********************************************************************
 *           ExAllocatePoolWithQuotaTag   (NTOSKRNL.EXE.@)
 */
PVOID WINAPI ExAllocatePoolWithQuotaTag( POOL_TYPE type, SIZE_T size, ULONG tag )
{
    return ExAllocatePoolWithTag( type, size, tag );
}


/***********************************************************************
 *           ExCreateCallback   (NTOSKRNL.EXE.@)
 */
NTSTATUS WINAPI ExCreateCallback(PCALLBACK_OBJECT *obj, POBJECT_ATTRIBUTES attr,
                                 BOOLEAN create, BOOLEAN allow_multiple)
{
    FIXME("(%p, %p, %u, %u): stub\n", obj, attr, create, allow_multiple);

    return STATUS_NOT_IMPLEMENTED;
}


/***********************************************************************
 *           ExFreePool   (NTOSKRNL.EXE.@)
 */
void WINAPI ExFreePool( void *ptr )
{
    ExFreePoolWithTag( ptr, 0 );
}


/***********************************************************************
 *           ExFreePoolWithTag   (NTOSKRNL.EXE.@)
 */
void WINAPI ExFreePoolWithTag( void *ptr, ULONG tag )
{
    TRACE( "%p\n", ptr );
    HeapFree( GetProcessHeap(), 0, ptr );
}


/***********************************************************************
 *           ExInitializeResourceLite   (NTOSKRNL.EXE.@)
 */
NTSTATUS WINAPI ExInitializeResourceLite(PERESOURCE Resource)
{
    FIXME( "stub: %p\n", Resource );
    return STATUS_NOT_IMPLEMENTED;
}


/***********************************************************************
 *           ExInitializeNPagedLookasideList   (NTOSKRNL.EXE.@)
 */
void WINAPI ExInitializeNPagedLookasideList(PNPAGED_LOOKASIDE_LIST Lookaside,
                                            PALLOCATE_FUNCTION Allocate,
                                            PFREE_FUNCTION Free,
                                            ULONG Flags,
                                            SIZE_T Size,
                                            ULONG Tag,
                                            USHORT Depth)
{
    FIXME( "stub: %p, %p, %p, %u, %lu, %u, %u\n", Lookaside, Allocate, Free, Flags, Size, Tag, Depth );
}

/***********************************************************************
 *           ExInitializePagedLookasideList   (NTOSKRNL.EXE.@)
 */
void WINAPI ExInitializePagedLookasideList(PPAGED_LOOKASIDE_LIST Lookaside,
                                           PALLOCATE_FUNCTION Allocate,
                                           PFREE_FUNCTION Free,
                                           ULONG Flags,
                                           SIZE_T Size,
                                           ULONG Tag,
                                           USHORT Depth)
{
    FIXME( "stub: %p, %p, %p, %u, %lu, %u, %u\n", Lookaside, Allocate, Free, Flags, Size, Tag, Depth );
}

/***********************************************************************
 *           ExInitializeZone   (NTOSKRNL.EXE.@)
 */
NTSTATUS WINAPI ExInitializeZone(PZONE_HEADER Zone,
                                 ULONG BlockSize,
                                 PVOID InitialSegment,
                                 ULONG InitialSegmentSize)
{
    FIXME( "stub: %p, %u, %p, %u\n", Zone, BlockSize, InitialSegment, InitialSegmentSize );
    return STATUS_NOT_IMPLEMENTED;
}

/***********************************************************************
*           FsRtlRegisterUncProvider   (NTOSKRNL.EXE.@)
*/
NTSTATUS WINAPI FsRtlRegisterUncProvider(PHANDLE MupHandle, PUNICODE_STRING RedirDevName,
                                         BOOLEAN MailslotsSupported)
{
    FIXME("(%p %p %d): stub\n", MupHandle, RedirDevName, MailslotsSupported);
    return STATUS_NOT_IMPLEMENTED;
}

/***********************************************************************
 *           IoGetCurrentProcess / PsGetCurrentProcess   (NTOSKRNL.EXE.@)
 */
PEPROCESS WINAPI IoGetCurrentProcess(void)
{
    FIXME("() stub\n");
    return NULL;
}

/***********************************************************************
 *           KeGetCurrentThread / PsGetCurrentThread   (NTOSKRNL.EXE.@)
 */
PRKTHREAD WINAPI KeGetCurrentThread(void)
{
    FIXME("() stub\n");
    return NULL;
}


/***********************************************************************
 *           KeDelayExecutionThread   (NTOSKRNL.EXE.@)
 */
NTSTATUS WINAPI KeDelayExecutionThread ( KPROCESSOR_MODE WaitMode,
        BOOLEAN Alertable, PLARGE_INTEGER Interval )
{
    FIXME( "stub: %d %d %p\n", WaitMode, Alertable, Interval );
    return STATUS_SUCCESS;
}


/***********************************************************************
 *           KeInitializeEvent   (NTOSKRNL.EXE.@)
 */
void WINAPI KeInitializeEvent( PRKEVENT Event, EVENT_TYPE Type, BOOLEAN State )
{
    TRACE( "%p %d %d\n", Event, Type, State );
    RtlZeroMemory( Event, sizeof(KEVENT) );
    Event->Header.Type = Type;
    Event->Header.Size = 4;
    if (State)
        Event->Header.SignalState = 1;
    InitializeListHead( &Event->Header.WaitListHead );
}


/***********************************************************************
 *           KeClearEvent   (NTOSKRNL.EXE.@)
 */
void WINAPI KeClearEvent( PRKEVENT Event )
{
    TRACE( "%p\n", Event );
    InterlockedExchange( &Event->Header.SignalState, 0 );
}


 /***********************************************************************
 *           KeInitializeMutex   (NTOSKRNL.EXE.@)
 */
void WINAPI KeInitializeMutex(PRKMUTEX Mutex, ULONG Level)
{
    TRACE( "%p, %u\n", Mutex, Level );
    RtlZeroMemory( Mutex, sizeof(KMUTEX) );
    Mutex->Header.Type = 2;
    Mutex->Header.Size = 8;
    Mutex->Header.SignalState = 1;
    InitializeListHead( &Mutex->Header.WaitListHead );
    Mutex->ApcDisable = 1;
}


 /***********************************************************************
 *           KeWaitForMutexObject   (NTOSKRNL.EXE.@)
 */
NTSTATUS WINAPI KeWaitForMutexObject(PRKMUTEX Mutex, KWAIT_REASON WaitReason, KPROCESSOR_MODE WaitMode,
                                     BOOLEAN Alertable, PLARGE_INTEGER Timeout)
{
    FIXME( "stub: %p, %d, %d, %d, %p\n", Mutex, WaitReason, WaitMode, Alertable, Timeout );
    return STATUS_NOT_IMPLEMENTED;
}


 /***********************************************************************
 *           KeReleaseMutex   (NTOSKRNL.EXE.@)
 */
LONG WINAPI KeReleaseMutex(PRKMUTEX Mutex, BOOLEAN Wait)
{
    FIXME( "stub: %p, %d\n", Mutex, Wait );
    return STATUS_SUCCESS;
}


/***********************************************************************
 *           KeInitializeSemaphore   (NTOSKRNL.EXE.@)
 */
void WINAPI KeInitializeSemaphore( PRKSEMAPHORE Semaphore, LONG Count, LONG Limit )
{
    FIXME( "(%p %d %d) stub\n", Semaphore , Count, Limit );
    RtlZeroMemory( Semaphore, sizeof(KSEMAPHORE) );
    Semaphore->Header.Type = 5;
}


/***********************************************************************
 *           KeInitializeSpinLock   (NTOSKRNL.EXE.@)
 */
void WINAPI KeInitializeSpinLock( PKSPIN_LOCK SpinLock )
{
    FIXME( "stub: %p\n", SpinLock );
}


/***********************************************************************
 *           KeInitializeTimerEx   (NTOSKRNL.EXE.@)
 */
void WINAPI KeInitializeTimerEx( PKTIMER Timer, TIMER_TYPE Type )
{
    FIXME( "stub: %p %d\n", Timer, Type );
    RtlZeroMemory( Timer, sizeof(KTIMER) );
    Timer->Header.Type = Type ? 9 : 8;
}


/***********************************************************************
 *           KeInitializeTimer   (NTOSKRNL.EXE.@)
 */
void WINAPI KeInitializeTimer( PKTIMER Timer )
{
    KeInitializeTimerEx(Timer, NotificationTimer);
}

/***********************************************************************
 *           KeInsertQueue   (NTOSKRNL.EXE.@)
 */
LONG WINAPI KeInsertQueue(PRKQUEUE Queue, PLIST_ENTRY Entry)
{
    FIXME( "stub: %p %p\n", Queue, Entry );
    return 0;
}

/**********************************************************************
 *           KeQueryActiveProcessors   (NTOSKRNL.EXE.@)
 *
 * Return the active Processors as bitmask
 *
 * RETURNS
 *   active Processors as bitmask
 *
 */
KAFFINITY WINAPI KeQueryActiveProcessors( void )
{
    DWORD_PTR AffinityMask;

    GetProcessAffinityMask( GetCurrentProcess(), &AffinityMask, NULL);
    return AffinityMask;
}


/**********************************************************************
 *           KeQueryInterruptTime   (NTOSKRNL.EXE.@)
 *
 * Return the interrupt time count
 *
 */
ULONGLONG WINAPI KeQueryInterruptTime( void )
{
    LARGE_INTEGER totaltime;

    KeQueryTickCount(&totaltime);
    return totaltime.QuadPart;
}


/***********************************************************************
 *           KeQuerySystemTime   (NTOSKRNL.EXE.@)
 */
void WINAPI KeQuerySystemTime( LARGE_INTEGER *time )
{
    NtQuerySystemTime( time );
}


/***********************************************************************
 *           KeQueryTickCount   (NTOSKRNL.EXE.@)
 */
void WINAPI KeQueryTickCount( LARGE_INTEGER *count )
{
    count->QuadPart = NtGetTickCount();
    /* update the global variable too */
    KeTickCount.LowPart   = count->u.LowPart;
    KeTickCount.High1Time = count->u.HighPart;
    KeTickCount.High2Time = count->u.HighPart;
}


/***********************************************************************
 *           KeReleaseSemaphore   (NTOSKRNL.EXE.@)
 */
LONG WINAPI KeReleaseSemaphore( PRKSEMAPHORE Semaphore, KPRIORITY Increment,
                                LONG Adjustment, BOOLEAN Wait )
{
    FIXME("(%p %d %d %d) stub\n", Semaphore, Increment, Adjustment, Wait );
    return 0;
}


/***********************************************************************
 *           KeQueryTimeIncrement   (NTOSKRNL.EXE.@)
 */
ULONG WINAPI KeQueryTimeIncrement(void)
{
    return 10000;
}


/***********************************************************************
 *           KeResetEvent   (NTOSKRNL.EXE.@)
 */
LONG WINAPI KeResetEvent( PRKEVENT Event )
{
    TRACE("(%p)\n", Event);
    return InterlockedExchange( &Event->Header.SignalState, 0 );
}


/***********************************************************************
 *           KeSetEvent   (NTOSKRNL.EXE.@)
 */
LONG WINAPI KeSetEvent( PRKEVENT Event, KPRIORITY Increment, BOOLEAN Wait )
{
    struct HandleInstance *inst;
    LONG ret;

    TRACE("(%p, %d, %d)\n", Event, Increment, Wait);

    ret = InterlockedExchange( &Event->Header.SignalState, 1 );
    EnterCriticalSection( &cs );
    LIST_FOR_EACH_ENTRY( inst, &Handles, struct HandleInstance, entry )
    {
        if (inst->object == Event)
        {
            NtSetEvent( inst->handle, NULL );
            break;
        }
    }
    LeaveCriticalSection( &cs );
    return ret;
}


/***********************************************************************
 *           KeSetPriorityThread   (NTOSKRNL.EXE.@)
 */
KPRIORITY WINAPI KeSetPriorityThread( PKTHREAD Thread, KPRIORITY Priority )
{
    FIXME("(%p %d)\n", Thread, Priority);
    return Priority;
}


/***********************************************************************
 *           KeWaitForSingleObject   (NTOSKRNL.EXE.@)
 */
NTSTATUS WINAPI KeWaitForSingleObject(PVOID Object,
                                      KWAIT_REASON WaitReason,
                                      KPROCESSOR_MODE WaitMode,
                                      BOOLEAN Alertable,
                                      PLARGE_INTEGER Timeout)
{
    DISPATCHER_HEADER *header = Object;
    NTSTATUS status = STATUS_SUCCESS;

    TRACE( "%p, %d, %d, %d, %p\n", Object, WaitReason, WaitMode, Alertable, Timeout );

    switch (header->Type)
    {
    case NotificationEvent:
    case SynchronizationEvent:
    {
        struct HandleInstance *inst;
        HANDLE event_handle = NULL;

        if (InterlockedCompareExchange( &header->SignalState, 0, header->Type ))
        {
            status = STATUS_SUCCESS;
            break;
        }

        EnterCriticalSection( &cs );
        LIST_FOR_EACH_ENTRY( inst, &Handles, struct HandleInstance, entry )
        {
            if (inst->object == Object)
            {
                event_handle = inst->handle;
                ++inst->refs;
                break;
            }
        }
        while (event_handle == NULL)
        {
            OBJECT_ATTRIBUTES attr;

            RtlZeroMemory( &attr, sizeof(attr) );
            attr.Length = sizeof(attr);
            status = NtCreateEvent( &event_handle, EVENT_ALL_ACCESS, &attr,
                    !header->Type, FALSE );
            if (status != STATUS_SUCCESS)
                break;
            inst = HeapAlloc( GetProcessHeap(), 0, sizeof(*inst) );
            if (inst == NULL)
            {
                NtClose( event_handle );
                status = STATUS_NO_MEMORY;
                break;
            }
            inst->object = Object;
            inst->handle = event_handle;
            inst->refs = 1;
            list_add_head( &Handles, &inst->entry );
        }
        LeaveCriticalSection( &cs );
        if (status != STATUS_SUCCESS)
            break;

        status = NtWaitForSingleObject( event_handle, Alertable, Timeout );

        EnterCriticalSection( &cs );
        LIST_FOR_EACH_ENTRY( inst, &Handles, struct HandleInstance, entry )
        {
            if (inst->object == Object)
            {
                if (!--inst->refs)
                {
                    list_remove( &inst->entry );
                    NtClose( inst->handle );
                    HeapFree( GetProcessHeap(), 0, inst );
                }
                break;
            }
        }
        LeaveCriticalSection( &cs );
        break;
    }
    default:
        WARN( "synchronization object %u is not supported\n", header->Type );
    }
    return status;
}

/***********************************************************************
 *           IoRegisterFileSystem   (NTOSKRNL.EXE.@)
 */
VOID WINAPI IoRegisterFileSystem(PDEVICE_OBJECT DeviceObject)
{
    FIXME("(%p): stub\n", DeviceObject);
}

/***********************************************************************
*           IoUnregisterFileSystem   (NTOSKRNL.EXE.@)
*/
VOID WINAPI IoUnregisterFileSystem(PDEVICE_OBJECT DeviceObject)
{
    FIXME("(%p): stub\n", DeviceObject);
}

/***********************************************************************
 *           MmAllocateNonCachedMemory   (NTOSKRNL.EXE.@)
 */
PVOID WINAPI MmAllocateNonCachedMemory( SIZE_T size )
{
    TRACE( "%lu\n", size );
    return VirtualAlloc( NULL, size, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE|PAGE_NOCACHE );
}

/***********************************************************************
 *           MmAllocateContiguousMemory   (NTOSKRNL.EXE.@)
 */
PVOID WINAPI MmAllocateContiguousMemory( SIZE_T size, PHYSICAL_ADDRESS highest_valid_address )
{
    FIXME( "%lu, %s stub\n", size, wine_dbgstr_longlong(highest_valid_address.QuadPart) );
    return NULL;
}

/***********************************************************************
 *           MmAllocateContiguousMemorySpecifyCache   (NTOSKRNL.EXE.@)
 */
PVOID WINAPI MmAllocateContiguousMemorySpecifyCache( SIZE_T size,
                                                     PHYSICAL_ADDRESS lowest_valid_address,
                                                     PHYSICAL_ADDRESS highest_valid_address,
                                                     PHYSICAL_ADDRESS BoundaryAddressMultiple,
                                                     MEMORY_CACHING_TYPE CacheType )
{
    FIXME(": stub\n");
    return NULL;
}

/***********************************************************************
 *           MmAllocatePagesForMdl   (NTOSKRNL.EXE.@)
 */
PMDL WINAPI MmAllocatePagesForMdl(PHYSICAL_ADDRESS lowaddress, PHYSICAL_ADDRESS highaddress,
                                  PHYSICAL_ADDRESS skipbytes, SIZE_T size)
{
    FIXME("%s %s %s %lu: stub\n", wine_dbgstr_longlong(lowaddress.QuadPart), wine_dbgstr_longlong(highaddress.QuadPart),
                                  wine_dbgstr_longlong(skipbytes.QuadPart), size);
    return NULL;
}

/***********************************************************************
 *           MmFreeNonCachedMemory   (NTOSKRNL.EXE.@)
 */
void WINAPI MmFreeNonCachedMemory( void *addr, SIZE_T size )
{
    TRACE( "%p %lu\n", addr, size );
    VirtualFree( addr, 0, MEM_RELEASE );
}

/***********************************************************************
 *           MmIsAddressValid   (NTOSKRNL.EXE.@)
 *
 * Check if the process can access the virtual address without a pagefault
 *
 * PARAMS
 *  VirtualAddress [I] Address to check
 *
 * RETURNS
 *  Failure: FALSE
 *  Success: TRUE  (Accessing the Address works without a Pagefault)
 *
 */
BOOLEAN WINAPI MmIsAddressValid(PVOID VirtualAddress)
{
    TRACE("(%p)\n", VirtualAddress);
    return !IsBadWritePtr(VirtualAddress, 1);
}

/***********************************************************************
 *           MmMapIoSpace   (NTOSKRNL.EXE.@)
 */
PVOID WINAPI MmMapIoSpace( PHYSICAL_ADDRESS PhysicalAddress, DWORD NumberOfBytes, DWORD CacheType )
{
    FIXME( "stub: 0x%08x%08x, %d, %d\n", PhysicalAddress.u.HighPart, PhysicalAddress.u.LowPart, NumberOfBytes, CacheType );
    return NULL;
}


 /***********************************************************************
 *           MmMapLockedPages   (NTOSKRNL.EXE.@)
 */
PVOID WINAPI MmMapLockedPages(PMDL MemoryDescriptorList,
        KPROCESSOR_MODE AccessMode)
{
    TRACE("%p %d\n", MemoryDescriptorList, AccessMode);
    return MemoryDescriptorList->MappedSystemVa;
}

/***********************************************************************
 *           MmLockPagableSectionByHandle  (NTOSKRNL.EXE.@)
 */
VOID WINAPI MmLockPagableSectionByHandle(PVOID ImageSectionHandle)
{
    FIXME("stub %p\n", ImageSectionHandle);
}

/***********************************************************************
 *           MmMapLockedPagesSpecifyCache  (NTOSKRNL.EXE.@)
 */
PVOID WINAPI  MmMapLockedPagesSpecifyCache(PMDLX MemoryDescriptorList, KPROCESSOR_MODE AccessMode, MEMORY_CACHING_TYPE CacheType,
                                           PVOID BaseAddress, ULONG BugCheckOnFailure, MM_PAGE_PRIORITY Priority)
{
    FIXME("(%p, %u, %u, %p, %u, %u): stub\n", MemoryDescriptorList, AccessMode, CacheType, BaseAddress, BugCheckOnFailure, Priority);

    return NULL;
}

/***********************************************************************
 *           MmUnlockPagableImageSection  (NTOSKRNL.EXE.@)
 */
VOID WINAPI MmUnlockPagableImageSection(PVOID ImageSectionHandle)
{
    FIXME("stub %p\n", ImageSectionHandle);
}

/***********************************************************************
 *           MmPageEntireDriver   (NTOSKRNL.EXE.@)
 */
PVOID WINAPI MmPageEntireDriver(PVOID AddrInSection)
{
    TRACE("%p\n", AddrInSection);
    return AddrInSection;
}


/***********************************************************************
 *           MmProbeAndLockPages  (NTOSKRNL.EXE.@)
 */
void WINAPI MmProbeAndLockPages(PMDLX MemoryDescriptorList, KPROCESSOR_MODE AccessMode, LOCK_OPERATION Operation)
{
    FIXME("(%p, %u, %u): stub\n", MemoryDescriptorList, AccessMode, Operation);
}


/***********************************************************************
 *           MmResetDriverPaging   (NTOSKRNL.EXE.@)
 */
void WINAPI MmResetDriverPaging(PVOID AddrInSection)
{
    TRACE("%p\n", AddrInSection);
}


/***********************************************************************
 *           MmUnlockPages  (NTOSKRNL.EXE.@)
 */
void WINAPI  MmUnlockPages(PMDLX MemoryDescriptorList)
{
    FIXME("(%p): stub\n", MemoryDescriptorList);
}


/***********************************************************************
 *           MmUnmapIoSpace   (NTOSKRNL.EXE.@)
 */
VOID WINAPI MmUnmapIoSpace( PVOID BaseAddress, SIZE_T NumberOfBytes )
{
    FIXME( "stub: %p, %lu\n", BaseAddress, NumberOfBytes );
}

/***********************************************************************
 *           ObfReferenceObject   (NTOSKRNL.EXE.@)
 */
VOID WINAPI ObfReferenceObject(PVOID Object)
{
    FIXME("(%p): stub\n", Object);
}

 /***********************************************************************
 *           ObReferenceObjectByHandle    (NTOSKRNL.EXE.@)
 */
NTSTATUS WINAPI ObReferenceObjectByHandle( HANDLE obj, ACCESS_MASK access,
                                           POBJECT_TYPE type,
                                           KPROCESSOR_MODE mode, PVOID* ptr,
                                           POBJECT_HANDLE_INFORMATION info)
{
    FIXME( "stub: %p %x %p %d %p %p\n", obj, access, type, mode, ptr, info);
    return STATUS_NOT_IMPLEMENTED;
}

 /***********************************************************************
 *           ObReferenceObjectByName    (NTOSKRNL.EXE.@)
 */
NTSTATUS WINAPI ObReferenceObjectByName( UNICODE_STRING *ObjectName,
                                         ULONG Attributes,
                                         ACCESS_STATE *AccessState,
                                         ACCESS_MASK DesiredAccess,
                                         POBJECT_TYPE ObjectType,
                                         KPROCESSOR_MODE AccessMode,
                                         void *ParseContext,
                                         void **Object)
{
    FIXME("stub\n");
    return STATUS_NOT_IMPLEMENTED;
}

/***********************************************************************
 *           MmUnmapLockedPages   (NTOSKRNL.EXE.@)
 */
void WINAPI MmUnmapLockedPages(PVOID BaseAddress, PMDL MemoryDescriptorList)
{
    TRACE("%p %p\n", BaseAddress, MemoryDescriptorList);
}


/***********************************************************************
 *           ObReferenceObjectByPointer   (NTOSKRNL.EXE.@)
 */
NTSTATUS WINAPI ObReferenceObjectByPointer( VOID *obj, ACCESS_MASK access,
                                            POBJECT_TYPE type,
                                            KPROCESSOR_MODE mode )
{
    FIXME( "stub: %p %x %p %d\n", obj, access, type, mode );
    return STATUS_NOT_IMPLEMENTED;
}


/***********************************************************************
 *           ObDereferenceObject   (NTOSKRNL.EXE.@)
 */
void WINAPI ObDereferenceObject( VOID *obj )
{
    FIXME( "stub: %p\n", obj );
}


/***********************************************************************
 *           ObfDereferenceObject   (NTOSKRNL.EXE.@)
 */
#ifdef DEFINE_FASTCALL1_ENTRYPOINT
DEFINE_FASTCALL1_ENTRYPOINT( ObfDereferenceObject )
void WINAPI __regs_ObfDereferenceObject( VOID *obj )
#else
void WINAPI ObfDereferenceObject( VOID *obj )
#endif
{
    ObDereferenceObject( obj );
}


/***********************************************************************
 *           PsCreateSystemThread   (NTOSKRNL.EXE.@)
 */
NTSTATUS WINAPI PsCreateSystemThread(PHANDLE ThreadHandle, ULONG DesiredAccess,
				     POBJECT_ATTRIBUTES ObjectAttributes,
			             HANDLE ProcessHandle, PCLIENT_ID ClientId,
                                     PKSTART_ROUTINE StartRoutine, PVOID StartContext)
{
    if (!ProcessHandle) ProcessHandle = GetCurrentProcess();
    return RtlCreateUserThread(ProcessHandle, 0, FALSE, 0, 0,
                               0, StartRoutine, StartContext,
                               ThreadHandle, ClientId);
}

/***********************************************************************
 *           PsGetCurrentProcessId   (NTOSKRNL.EXE.@)
 */
HANDLE WINAPI PsGetCurrentProcessId(void)
{
    if (GetCurrentThreadId() == request_thread)
        return UlongToHandle(client_pid);
    return UlongToHandle(GetCurrentProcessId());
}


/***********************************************************************
 *           PsGetCurrentThreadId   (NTOSKRNL.EXE.@)
 */
HANDLE WINAPI PsGetCurrentThreadId(void)
{
    if (GetCurrentThreadId() == request_thread)
        return UlongToHandle(client_tid);
    return UlongToHandle(GetCurrentThreadId());
}


/***********************************************************************
 *           PsGetVersion   (NTOSKRNL.EXE.@)
 */
BOOLEAN WINAPI PsGetVersion(ULONG *major, ULONG *minor, ULONG *build, UNICODE_STRING *version )
{
    RTL_OSVERSIONINFOEXW info;

    info.dwOSVersionInfoSize = sizeof(info);
    RtlGetVersion( &info );
    if (major) *major = info.dwMajorVersion;
    if (minor) *minor = info.dwMinorVersion;
    if (build) *build = info.dwBuildNumber;

    if (version)
    {
#if 0  /* FIXME: GameGuard passes an uninitialized pointer in version->Buffer */
        size_t len = min( strlenW(info.szCSDVersion)*sizeof(WCHAR), version->MaximumLength );
        memcpy( version->Buffer, info.szCSDVersion, len );
        if (len < version->MaximumLength) version->Buffer[len / sizeof(WCHAR)] = 0;
        version->Length = len;
#endif
    }
    return TRUE;
}


/***********************************************************************
 *           PsImpersonateClient   (NTOSKRNL.EXE.@)
 */
NTSTATUS WINAPI PsImpersonateClient(PETHREAD Thread, PACCESS_TOKEN Token, BOOLEAN CopyOnOpen,
                                    BOOLEAN EffectiveOnly, SECURITY_IMPERSONATION_LEVEL ImpersonationLevel)
{
    FIXME("(%p, %p, %u, %u, %u): stub\n", Thread, Token, CopyOnOpen, EffectiveOnly, ImpersonationLevel);

    return STATUS_NOT_IMPLEMENTED;
}


/***********************************************************************
 *           PsSetCreateProcessNotifyRoutine   (NTOSKRNL.EXE.@)
 */
NTSTATUS WINAPI PsSetCreateProcessNotifyRoutine( PCREATE_PROCESS_NOTIFY_ROUTINE callback, BOOLEAN remove )
{
    FIXME( "stub: %p %d\n", callback, remove );
    return STATUS_SUCCESS;
}


/***********************************************************************
 *           PsSetCreateThreadNotifyRoutine   (NTOSKRNL.EXE.@)
 */
NTSTATUS WINAPI PsSetCreateThreadNotifyRoutine( PCREATE_THREAD_NOTIFY_ROUTINE NotifyRoutine )
{
    FIXME( "stub: %p\n", NotifyRoutine );
    return STATUS_SUCCESS;
}


/***********************************************************************
 *           PsTerminateSystemThread   (NTOSKRNL.EXE.@)
 */
NTSTATUS WINAPI PsTerminateSystemThread(NTSTATUS ExitStatus)
{
    FIXME( "stub: %u\n", ExitStatus );
    return STATUS_NOT_IMPLEMENTED;
}


/***********************************************************************
 *           MmGetSystemRoutineAddress   (NTOSKRNL.EXE.@)
 */
PVOID WINAPI MmGetSystemRoutineAddress(PUNICODE_STRING SystemRoutineName)
{
    HMODULE hMod;
    STRING routineNameA;
    PVOID pFunc = NULL;

    static const WCHAR ntoskrnlW[] = {'n','t','o','s','k','r','n','l','.','e','x','e',0};
    static const WCHAR halW[] = {'h','a','l','.','d','l','l',0};

    if (!SystemRoutineName) return NULL;

    if (RtlUnicodeStringToAnsiString( &routineNameA, SystemRoutineName, TRUE ) == STATUS_SUCCESS)
    {
        /* We only support functions exported from ntoskrnl.exe or hal.dll */
        hMod = GetModuleHandleW( ntoskrnlW );
        pFunc = GetProcAddress( hMod, routineNameA.Buffer );
        if (!pFunc)
        {
           hMod = GetModuleHandleW( halW );
           if (hMod) pFunc = GetProcAddress( hMod, routineNameA.Buffer );
        }
        RtlFreeAnsiString( &routineNameA );
    }

    if (pFunc)
        TRACE( "%s -> %p\n", debugstr_us(SystemRoutineName), pFunc );
    else
        FIXME( "%s not found\n", debugstr_us(SystemRoutineName) );
    return pFunc;
}


/***********************************************************************
 *           MmQuerySystemSize   (NTOSKRNL.EXE.@)
 */
MM_SYSTEMSIZE WINAPI MmQuerySystemSize(void)
{
    FIXME("stub\n");
    return MmLargeSystem;
}

/***********************************************************************
 *           KeInitializeDpc   (NTOSKRNL.EXE.@)
 */
VOID WINAPI KeInitializeDpc(PRKDPC Dpc, PKDEFERRED_ROUTINE DeferredRoutine, PVOID DeferredContext)
{
    FIXME("stub\n");
}

/***********************************************************************
 *           READ_REGISTER_BUFFER_UCHAR   (NTOSKRNL.EXE.@)
 */
VOID WINAPI READ_REGISTER_BUFFER_UCHAR(PUCHAR Register, PUCHAR Buffer, ULONG Count)
{
    FIXME("stub\n");
}

/*****************************************************
 *           PoSetPowerState   (NTOSKRNL.EXE.@)
 */
POWER_STATE WINAPI PoSetPowerState(PDEVICE_OBJECT DeviceObject, POWER_STATE_TYPE Type, POWER_STATE State)
{
    FIXME("(%p %u %u) stub\n", DeviceObject, Type, State.DeviceState);
    return State;
}

/*****************************************************
 *           IoWMIRegistrationControl   (NTOSKRNL.EXE.@)
 */
NTSTATUS WINAPI IoWMIRegistrationControl(PDEVICE_OBJECT DeviceObject, ULONG Action)
{
    FIXME("(%p %u) stub\n", DeviceObject, Action);
    return STATUS_SUCCESS;
}

/*****************************************************
 *           PsSetLoadImageNotifyRoutine   (NTOSKRNL.EXE.@)
 */
NTSTATUS WINAPI PsSetLoadImageNotifyRoutine(PLOAD_IMAGE_NOTIFY_ROUTINE routine)
{
    FIXME("(%p) stub\n", routine);
    return STATUS_SUCCESS;
}

/*****************************************************
 *           PsLookupProcessByProcessId  (NTOSKRNL.EXE.@)
 */
NTSTATUS WINAPI PsLookupProcessByProcessId(HANDLE processid, PEPROCESS *process)
{
    FIXME("(%p %p) stub\n", processid, process);
    return STATUS_NOT_IMPLEMENTED;
}


/*****************************************************
 *           IoSetThreadHardErrorMode  (NTOSKRNL.EXE.@)
 */
BOOLEAN WINAPI IoSetThreadHardErrorMode(BOOLEAN EnableHardErrors)
{
    FIXME("stub\n");
    return FALSE;
}


/*****************************************************
 *           IoInitializeRemoveLockEx  (NTOSKRNL.EXE.@)
 */
VOID WINAPI IoInitializeRemoveLockEx(PIO_REMOVE_LOCK lock, ULONG tag,
                                     ULONG maxmin, ULONG high, ULONG size)
{
    FIXME("(%p %u %u %u %u) stub\n", lock, tag, maxmin, high, size);
}


/*****************************************************
 *           IoAcquireRemoveLockEx  (NTOSKRNL.EXE.@)
 */

NTSTATUS WINAPI IoAcquireRemoveLockEx(PIO_REMOVE_LOCK lock, PVOID tag,
                                      LPCSTR file, ULONG line, ULONG lock_size)
{
    FIXME("(%p, %p, %s, %u, %u): stub\n", lock, tag, debugstr_a(file), line, lock_size);

    return STATUS_NOT_IMPLEMENTED;
}


/*****************************************************
 *           DllMain
 */
BOOL WINAPI DllMain( HINSTANCE inst, DWORD reason, LPVOID reserved )
{
    static void *handler;
    LARGE_INTEGER count;
    struct DriverObjExtension *ext, *ext2;
    struct InterfaceInstance *intf, *intf2;

    switch(reason)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls( inst );
#ifdef __i386__
        handler = RtlAddVectoredExceptionHandler( TRUE, vectored_handler );
#endif
        KeQueryTickCount( &count );  /* initialize the global KeTickCount */
        break;
    case DLL_PROCESS_DETACH:
        if (reserved) break;
        RtlRemoveVectoredExceptionHandler( handler );
        DeleteCriticalSection( &cs );
        LIST_FOR_EACH_ENTRY_SAFE( ext, ext2, &DriverObjExtensions,
                struct DriverObjExtension, entry )
        {
            list_remove( &ext->entry );
            ExFreePool( ext->ptr );
            ExFreePool( ext );
        }
        LIST_FOR_EACH_ENTRY_SAFE( intf, intf2, &Interfaces,
                struct InterfaceInstance, entry )
        {
            list_remove( &intf->entry );
            RtlFreeUnicodeString( &intf->target );
            RtlFreeHeap( GetProcessHeap(), 0, intf->link );
            RtlFreeHeap( GetProcessHeap(), 0, intf );
        }
        break;
    }
    return TRUE;
}

/*****************************************************
 *           Ke386IoSetAccessProcess  (NTOSKRNL.EXE.@)
 */
BOOLEAN WINAPI Ke386IoSetAccessProcess(PEPROCESS *process, ULONG flag)
{
    FIXME("(%p %d) stub\n", process, flag);
    return FALSE;
}

/*****************************************************
 *           Ke386SetIoAccessMap  (NTOSKRNL.EXE.@)
 */
BOOLEAN WINAPI Ke386SetIoAccessMap(ULONG flag, PVOID buffer)
{
    FIXME("(%d %p) stub\n", flag, buffer);
    return FALSE;
}

/*****************************************************
 *           IoCreateSynchronizationEvent (NTOSKRNL.EXE.@)
 */
PKEVENT WINAPI IoCreateSynchronizationEvent(PUNICODE_STRING name, PHANDLE handle)
{
    FIXME("(%p %p) stub\n", name, handle);
    return NULL;
}

/*****************************************************
 *           IoStartNextPacket  (NTOSKRNL.EXE.@)
 */
VOID WINAPI IoStartNextPacket(PDEVICE_OBJECT deviceobject, BOOLEAN cancelable)
{
    FIXME("(%p %d) stub\n", deviceobject, cancelable);
}

/*****************************************************
 *           ObQueryNameString  (NTOSKRNL.EXE.@)
 */
NTSTATUS WINAPI ObQueryNameString(PVOID object, POBJECT_NAME_INFORMATION name, ULONG maxlength, PULONG returnlength)
{
    FIXME("(%p %p %u %p) stub\n", object, name, maxlength, returnlength);
    return STATUS_NOT_IMPLEMENTED;
}

/*****************************************************
 *           IoRegisterPlugPlayNotification  (NTOSKRNL.EXE.@)
 */
NTSTATUS WINAPI IoRegisterPlugPlayNotification(IO_NOTIFICATION_EVENT_CATEGORY category, ULONG flags, PVOID data,
                                               PDRIVER_OBJECT driver, PDRIVER_NOTIFICATION_CALLBACK_ROUTINE callback,
                                               PVOID context, PVOID *notification)
{
    FIXME("(%u %u %p %p %p %p %p) stub\n", category, flags, data, driver, callback, context, notification);
    return STATUS_SUCCESS;
}
