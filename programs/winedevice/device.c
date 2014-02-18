/*
 * Service process to load a kernel driver
 *
 * Copyright 2007 Alexandre Julliard
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

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "winreg.h"
#include "winsvc.h"
#include "ddk/ntddk.h"
#include "wine/unicode.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(winedevice);
WINE_DECLARE_DEBUG_CHANNEL(relay);

extern NTSTATUS CDECL wine_ntoskrnl_main_loop( HANDLE stop_event );
extern BOOL CDECL __wine_add_driver_object( DRIVER_OBJECT *driver, const WCHAR *service );
extern void CDECL __wine_del_driver_object( const DRIVER_OBJECT *driver );
extern HANDLE CDECL __wine_make_process_system(void);

#define EVENT_NAME_LEN (30 * sizeof(WCHAR))

static const WCHAR pipe_nameW[] = {'\\','\\','.','\\','p','i','p','e',
                                   '\\','w','i','n','e','d','e','v','i','c','e',0};
static const WCHAR winedevice_mutexW[] = {'_','_','w','i','n','e','_',
                                          'W','i','n','e','d','e','v','i','c','e',0};

/* these variables are used only by "winedevice driver_name" */
static WCHAR *driver_name;
static SERVICE_STATUS_HANDLE service_handle;
static HANDLE stop_event;

/* find the LDR_MODULE corresponding to the driver module */
static LDR_MODULE *find_ldr_module( HMODULE module )
{
    LIST_ENTRY *entry, *list = &NtCurrentTeb()->Peb->LdrData->InMemoryOrderModuleList;

    for (entry = list->Flink; entry != list; entry = entry->Flink)
    {
        LDR_MODULE *ldr = CONTAINING_RECORD(entry, LDR_MODULE, InMemoryOrderModuleList);
        if (ldr->BaseAddress == module) return ldr;
        if (ldr->BaseAddress > (void *)module) break;
    }
    return NULL;
}

/* load the driver module file */
static HMODULE load_driver_module( const WCHAR *name )
{
    IMAGE_NT_HEADERS *nt;
    const IMAGE_IMPORT_DESCRIPTOR *imports;
    SYSTEM_BASIC_INFORMATION info;
    int i;
    INT_PTR delta;
    ULONG size;
    HMODULE module = LoadLibraryW( name );

    if (!module) return NULL;
    nt = RtlImageNtHeader( module );

    if (!(delta = (char *)module - (char *)nt->OptionalHeader.ImageBase)) return module;

    /* the loader does not apply relocations to non page-aligned binaries or executables,
     * we have to do it ourselves */

    NtQuerySystemInformation( SystemBasicInformation, &info, sizeof(info), NULL );
    if (nt->OptionalHeader.SectionAlignment < info.PageSize ||
        !(nt->FileHeader.Characteristics & IMAGE_FILE_DLL))
    {
        DWORD old;
        IMAGE_BASE_RELOCATION *rel, *end;

        if ((rel = RtlImageDirectoryEntryToData( module, TRUE, IMAGE_DIRECTORY_ENTRY_BASERELOC, &size )))
        {
            WINE_TRACE( "%s: relocating from %p to %p\n",
                        wine_dbgstr_w(name), (char *)module - delta, module );
            end = (IMAGE_BASE_RELOCATION *)((char *)rel + size);
            while (rel < end && rel->SizeOfBlock)
            {
                void *page = (char *)module + rel->VirtualAddress;
                VirtualProtect( page, info.PageSize, PAGE_EXECUTE_READWRITE, &old );
                rel = LdrProcessRelocationBlock( page, (rel->SizeOfBlock - sizeof(*rel)) / sizeof(USHORT),
                                                 (USHORT *)(rel + 1), delta );
                if (old != PAGE_EXECUTE_READWRITE) VirtualProtect( page, info.PageSize, old, NULL );
                if (!rel) goto error;
            }
            /* make sure we don't try again */
            size = FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) + nt->FileHeader.SizeOfOptionalHeader;
            VirtualProtect( nt, size, PAGE_READWRITE, &old );
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0;
            VirtualProtect( nt, size, old, NULL );
        }
    }

    /* make sure imports are relocated too */

    if ((imports = RtlImageDirectoryEntryToData( module, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size )))
    {
        for (i = 0; imports[i].Name && imports[i].FirstThunk; i++)
        {
            char *name = (char *)module + imports[i].Name;
            WCHAR buffer[32], *p = buffer;

            while (p < buffer + 32) if (!(*p++ = *name++)) break;
            if (p <= buffer + 32) FreeLibrary( load_driver_module( buffer ) );
        }
    }

    return module;

error:
    FreeLibrary( module );
    return NULL;
}

/* call the driver init entry point */
static NTSTATUS init_driver( HMODULE module, UNICODE_STRING *keyname,
                             const WCHAR *drv_name, PDRIVER_OBJECT driver_obj,
                             PDRIVER_EXTENSION driver_extension )
{
    unsigned int i;
    NTSTATUS status;
    const IMAGE_NT_HEADERS *nt = RtlImageNtHeader( module );

    if (!nt->OptionalHeader.AddressOfEntryPoint) return STATUS_SUCCESS;

    driver_obj->Size            = sizeof(DRIVER_OBJECT);
    driver_obj->DriverSection   = find_ldr_module( module );
    driver_obj->DriverInit      = (PDRIVER_INITIALIZE)((char *)module + nt->OptionalHeader.AddressOfEntryPoint);
    driver_obj->DriverExtension = driver_extension;

    driver_extension->DriverObject   = driver_obj;
    driver_extension->ServiceKeyName = *keyname;

    if (WINE_TRACE_ON(relay))
        WINE_DPRINTF( "%04x:Call driver init %p (obj=%p,str=%s)\n", GetCurrentThreadId(),
                      driver_obj->DriverInit, driver_obj, wine_dbgstr_w(keyname->Buffer) );

    status = driver_obj->DriverInit( driver_obj, keyname );

    if (WINE_TRACE_ON(relay))
        WINE_DPRINTF( "%04x:Ret  driver init %p (obj=%p,str=%s) retval=%08x\n", GetCurrentThreadId(),
                      driver_obj->DriverInit, driver_obj, wine_dbgstr_w(keyname->Buffer), status );

    WINE_TRACE( "init done for %s obj %p\n", wine_dbgstr_w(drv_name), driver_obj );
    WINE_TRACE( "- DriverInit = %p\n", driver_obj->DriverInit );
    WINE_TRACE( "- DriverStartIo = %p\n", driver_obj->DriverStartIo );
    WINE_TRACE( "- DriverUnload = %p\n", driver_obj->DriverUnload );
    WINE_TRACE( "- AddDevice = %p\n", driver_extension->AddDevice );
    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
        WINE_TRACE( "- MajorFunction[%d] = %p\n", i, driver_obj->MajorFunction[i] );

    return status;
}

/* load the .sys module for a device driver */
static HMODULE load_driver( const WCHAR *drv_name, PDRIVER_OBJECT driver_obj,
                            PDRIVER_EXTENSION driver_extension )
{
    static const WCHAR driversW[] = {'\\','d','r','i','v','e','r','s','\\',0};
    static const WCHAR systemrootW[] = {'\\','S','y','s','t','e','m','R','o','o','t','\\',0};
    static const WCHAR postfixW[] = {'.','s','y','s',0};
    static const WCHAR ntprefixW[] = {'\\','?','?','\\',0};
    static const WCHAR ImagePathW[] = {'I','m','a','g','e','P','a','t','h',0};
    static const WCHAR servicesW[] = {'\\','R','e','g','i','s','t','r','y',
                                      '\\','M','a','c','h','i','n','e',
                                      '\\','S','y','s','t','e','m',
                                      '\\','C','u','r','r','e','n','t','C','o','n','t','r','o','l','S','e','t',
                                      '\\','S','e','r','v','i','c','e','s','\\',0};

    HKEY driver_hkey;
    UNICODE_STRING keypath;
    HMODULE module;
    LPWSTR path = NULL, str;
    DWORD type, size;
    NTSTATUS status;

    str = HeapAlloc( GetProcessHeap(), 0, sizeof(servicesW) + strlenW(drv_name)*sizeof(WCHAR) );
    lstrcpyW( str, servicesW );
    lstrcatW( str, drv_name );

    if (RegOpenKeyW( HKEY_LOCAL_MACHINE, str + 18 /* skip \registry\machine */, &driver_hkey ))
    {
        WINE_ERR( "cannot open key %s, err=%u\n", wine_dbgstr_w(str), GetLastError() );
        HeapFree( GetProcessHeap(), 0, str);
        return NULL;
    }
    RtlInitUnicodeString( &keypath, str );

    /* read the executable path from memory */
    size = 0;
    if (!RegQueryValueExW( driver_hkey, ImagePathW, NULL, &type, NULL, &size ))
    {
        str = HeapAlloc( GetProcessHeap(), 0, size );
        if (!RegQueryValueExW( driver_hkey, ImagePathW, NULL, &type, (LPBYTE)str, &size ))
        {
            size = ExpandEnvironmentStringsW(str,NULL,0);
            path = HeapAlloc(GetProcessHeap(),0,size*sizeof(WCHAR));
            ExpandEnvironmentStringsW(str,path,size);
        }
        HeapFree( GetProcessHeap(), 0, str );
        if (!path) return NULL;

        if (!strncmpiW( path, systemrootW, 12 ))
        {
            WCHAR buffer[MAX_PATH];

            GetWindowsDirectoryW(buffer, MAX_PATH);

            str = HeapAlloc(GetProcessHeap(), 0, (size -11 + strlenW(buffer))
                                                        * sizeof(WCHAR));
            lstrcpyW(str, buffer);
            lstrcatW(str, path + 11);
            HeapFree( GetProcessHeap(), 0, path );
            path = str;
        }
        else if (!strncmpW( path, ntprefixW, 4 ))
            str = path + 4;
        else
            str = path;
    }
    else
    {
        /* default is to use the driver name + ".sys" */
        WCHAR buffer[MAX_PATH];
        GetSystemDirectoryW(buffer, MAX_PATH);
        path = HeapAlloc(GetProcessHeap(),0,
          (strlenW(buffer) + strlenW(driversW) + strlenW(drv_name) + strlenW(postfixW) + 1)
          *sizeof(WCHAR));
        lstrcpyW(path, buffer);
        lstrcatW(path, driversW);
        lstrcatW(path, drv_name);
        lstrcatW(path, postfixW);
        str = path;
    }

    WINE_TRACE( "loading driver %s\n", wine_dbgstr_w(str) );

    module = load_driver_module( str );
    HeapFree( GetProcessHeap(), 0, path );
    if (!module) return NULL;

    status = init_driver( module, &keypath, drv_name, driver_obj, driver_extension );
    if (status != STATUS_SUCCESS)
    {
        FreeLibrary( module );
        return NULL;
    }
    return module;
}

static void unload_driver( HMODULE module, DRIVER_OBJECT *driver_obj )
{
    if (driver_obj->DriverUnload)
    {
        if (WINE_TRACE_ON(relay))
            WINE_DPRINTF( "%04x:Call driver unload %p (obj=%p)\n",
                          GetCurrentThreadId(), driver_obj->DriverUnload, driver_obj );

        driver_obj->DriverUnload( driver_obj );

        if (WINE_TRACE_ON(relay))
            WINE_DPRINTF( "%04x:Ret  driver unload %p (obj=%p)\n",
                          GetCurrentThreadId(), driver_obj->DriverUnload, driver_obj );
    }
    FreeLibrary( module );
}

static DWORD WINAPI service_handler( DWORD ctrl, DWORD event_type, LPVOID event_data, LPVOID context )
{
    SERVICE_STATUS status;

    status.dwServiceType             = SERVICE_WIN32;
    status.dwControlsAccepted        = SERVICE_ACCEPT_STOP;
    status.dwWin32ExitCode           = 0;
    status.dwServiceSpecificExitCode = 0;
    status.dwCheckPoint              = 0;
    status.dwWaitHint                = 0;

    switch(ctrl)
    {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        WINE_TRACE( "shutting down %s\n", wine_dbgstr_w(driver_name) );
        status.dwCurrentState     = SERVICE_STOP_PENDING;
        status.dwControlsAccepted = 0;
        SetServiceStatus( service_handle, &status );
        SetEvent( stop_event );
        return NO_ERROR;
    default:
        WINE_FIXME( "got service ctrl %x for %s\n", ctrl,
                    wine_dbgstr_w(driver_name) );
        status.dwCurrentState = SERVICE_RUNNING;
        SetServiceStatus( service_handle, &status );
        return NO_ERROR;
    }
}

static int loading_request( WCHAR *event_name )
{
    static WCHAR winedeviceW[] = {'\\','w','i','n','e','d','e','v','i','c','e','.','e','x','e',0};

    WCHAR *driver_process_cmd;
    PROCESS_INFORMATION pi;
    STARTUPINFOW si;
    HANDLE pipe;
    DWORD count, len;
    BOOL ret, loaded;

    /* create winedevice.exe process which will load drivers */

    len = GetSystemDirectoryW( NULL, 0 );
    driver_process_cmd = HeapAlloc( GetProcessHeap(), 0, sizeof(winedeviceW)
            + sizeof(WCHAR) * len );
    if (!driver_process_cmd) return 1;
    GetSystemDirectoryW( driver_process_cmd, len );
    strcpyW( driver_process_cmd + len - 1, winedeviceW );

    RtlZeroMemory( &si, sizeof(STARTUPINFOW) );
    si.cb = sizeof(STARTUPINFOW);
    ret = CreateProcessW( NULL, driver_process_cmd, NULL, NULL, FALSE, 0,
            NULL, NULL, &si, &pi );
    HeapFree( GetProcessHeap(), 0, driver_process_cmd );
    if (!ret) return 1;
    CloseHandle( pi.hThread );
    CloseHandle( pi.hProcess );

    /* send driver and event names and receive loading result */

    do {
        WaitNamedPipeW( pipe_nameW, NMPWAIT_WAIT_FOREVER );
        pipe = CreateFileW( pipe_nameW, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
    } while (pipe == INVALID_HANDLE_VALUE);
    len = (strlenW(driver_name) + 1) * sizeof(WCHAR);
    ret = WriteFile( pipe, &len, sizeof(DWORD), &count, NULL );
    if (!ret || count != sizeof(DWORD)) goto fail;
    ret = WriteFile( pipe, driver_name, len, &count, NULL );
    if (!ret || count != len) goto fail;
    ret = WriteFile( pipe, event_name, EVENT_NAME_LEN, &count, NULL );
    if (!ret || count != EVENT_NAME_LEN) goto fail;
    ret = ReadFile( pipe, &loaded, sizeof(BOOL), &count, NULL );
    if (!ret || count != sizeof(BOOL)) goto fail;
    if (loaded)
    {
        CloseHandle( pipe );
        return 0;
    }
fail:
    CloseHandle( pipe );
    return 1;
}

static HMODULE handle_loading_request( HANDLE pipe, DRIVER_OBJECT *driver_obj,
                                       DRIVER_EXTENSION *driver_extension,
                                       WCHAR **drv_name, WCHAR **event_name )
{
    HMODULE module = NULL;
    BOOL ret, loaded = FALSE;
    DWORD count, len;

    *drv_name = NULL;
    *event_name = NULL;
    ret = ReadFile( pipe, &len, sizeof(DWORD), &count, NULL );
    if (!ret || count != sizeof(DWORD)) goto end;
    *drv_name = HeapAlloc( GetProcessHeap(), 0, len );
    if (!*drv_name) goto end;
    ret = ReadFile( pipe, *drv_name, len, &count, NULL );
    if (!ret || count != len) goto end;
    *event_name = HeapAlloc( GetProcessHeap(), 0, EVENT_NAME_LEN );
    if (!*event_name) goto end;
    ret = ReadFile( pipe, *event_name, EVENT_NAME_LEN, &count, NULL );
    if (!ret || count != EVENT_NAME_LEN) goto end;
    module = load_driver( *drv_name, driver_obj, driver_extension );
    if (module) loaded = TRUE;
    ret = WriteFile( pipe, &loaded, sizeof(BOOL), &count, NULL );
    if (module && (!ret || count != sizeof(BOOL)))
    {
        unload_driver( module, driver_obj );
        module = NULL;
    }
end:
    DisconnectNamedPipe( pipe );
    CloseHandle( pipe );
    if (!module)
    {
        if (*drv_name) HeapFree( GetProcessHeap(), 0, *drv_name );
        if (*event_name) HeapFree( GetProcessHeap(), 0, *drv_name );
    }
    return module;
}

static HANDLE create_named_event( WCHAR **event_name )
{
    static const WCHAR event_nameW[] = {'_','_','w','i','n','e','_',
                                        'W','i','n','e','d','e','v','i','c','e','_','%','u',0};

    HANDLE event;
    unsigned int k = 0;

    *event_name = HeapAlloc( GetProcessHeap(), 0, EVENT_NAME_LEN );
    if (!*event_name) return NULL;
    for (;;)
    {
        snprintfW( *event_name, EVENT_NAME_LEN / sizeof(WCHAR), event_nameW, k++ );
        event = CreateEventW( NULL, TRUE, FALSE, *event_name );
        if (event && GetLastError() != ERROR_ALREADY_EXISTS)
            return event;
        CloseHandle( event );
    }
}

static void WINAPI ServiceMain( DWORD argc, LPWSTR *argv )
{
    SERVICE_STATUS status;
    WCHAR *event_name;

    WINE_TRACE( "starting service %s\n", wine_dbgstr_w(driver_name) );

    stop_event = create_named_event( &event_name );
    if (!stop_event)
        return;
    service_handle = RegisterServiceCtrlHandlerExW( driver_name, service_handler, NULL );
    if (!service_handle)
    {
        HeapFree( GetProcessHeap(), 0, event_name );
        return;
    }

    status.dwServiceType             = SERVICE_WIN32;
    status.dwCurrentState            = SERVICE_START_PENDING;
    status.dwControlsAccepted        = 0;
    status.dwWin32ExitCode           = 0;
    status.dwServiceSpecificExitCode = 0;
    status.dwCheckPoint              = 0;
    status.dwWaitHint                = 10000;
    SetServiceStatus( service_handle, &status );

    if (!loading_request( event_name ))
    {
        status.dwCurrentState     = SERVICE_RUNNING;
        status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
        SetServiceStatus( service_handle, &status );

        WaitForSingleObject( stop_event, INFINITE );
    }
    else WINE_ERR( "driver %s failed to load\n", wine_dbgstr_w(driver_name) );

    HeapFree( GetProcessHeap(), 0, event_name );
    status.dwCurrentState     = SERVICE_STOPPED;
    status.dwControlsAccepted = 0;
    SetServiceStatus( service_handle, &status );
    WINE_TRACE( "service %s stopped\n", wine_dbgstr_w(driver_name) );
}

static DWORD CALLBACK driver_thread( HANDLE pipe )
{
    DRIVER_OBJECT driver_obj;
    DRIVER_EXTENSION driver_extension;
    WCHAR *drv_name, *event_name;
    HMODULE module;

    RtlZeroMemory( &driver_obj, sizeof(driver_obj) );
    RtlZeroMemory( &driver_extension, sizeof(driver_extension) );
    module = handle_loading_request( pipe, &driver_obj, &driver_extension,
            &drv_name, &event_name );
    if (module)
    {
        HANDLE loop_event;

        loop_event = CreateEventW( NULL, TRUE, FALSE, event_name );
        if (__wine_add_driver_object( &driver_obj, drv_name ))
        {
            wine_ntoskrnl_main_loop( loop_event );
            __wine_del_driver_object( &driver_obj );
        }
        /* stop service if wine_ntoskrnl_main_loop exits */
        SetEvent( loop_event );
        CloseHandle( loop_event );
        unload_driver( module, &driver_obj );
        HeapFree( GetProcessHeap(), 0, drv_name );
        HeapFree( GetProcessHeap(), 0, event_name );
    }
    return 0;
}

static int driver_process(void)
{
    HANDLE pipe, winedevice_mutex, thread;

    __wine_make_process_system();
    winedevice_mutex = CreateMutexW( NULL, TRUE, winedevice_mutexW );
    if (GetLastError() == ERROR_ALREADY_EXISTS)
    {
        CloseHandle( winedevice_mutex );
        return 1;
    }
    for (;;)
    {
        pipe = CreateNamedPipeW( pipe_nameW, PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES,
                256, 256, 10000, NULL );
        if (pipe == INVALID_HANDLE_VALUE)
        {
            WINE_ERR( "failed to create pipe\n" );
            continue;
        }
        if (!ConnectNamedPipe( pipe, NULL ) &&
            GetLastError() != ERROR_PIPE_CONNECTED)
        {
            CloseHandle( pipe );
            continue;
        }

        thread = CreateThread( NULL, 0, driver_thread, pipe, 0, NULL );
        if (!thread)
        {
            WINE_ERR( "failed to create thread\n" );
            DisconnectNamedPipe( pipe );
            CloseHandle( pipe );
            continue;
        }
        CloseHandle( thread );
    }
}

int wmain( int argc, WCHAR *argv[] )
{
    SERVICE_TABLE_ENTRYW service_table[2];

    if (!argv[1]) return driver_process();
    driver_name = argv[1];

    service_table[0].lpServiceName = argv[1];
    service_table[0].lpServiceProc = ServiceMain;
    service_table[1].lpServiceName = NULL;
    service_table[1].lpServiceProc = NULL;

    StartServiceCtrlDispatcherW( service_table );
    return 0;
}
