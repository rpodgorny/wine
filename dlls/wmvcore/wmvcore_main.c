/*
 * Copyright 2012 Austin English
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

#include <stdarg.h>

#define COBJMACROS

#include "windef.h"
#include "winbase.h"
#include "initguid.h"
#include "wmsdkidl.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(wmvcore);

static inline void *heap_alloc(size_t len)
{
    return HeapAlloc(GetProcessHeap(), 0, len);
}

static inline BOOL heap_free(void *mem)
{
    return HeapFree(GetProcessHeap(), 0, mem);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    TRACE("(0x%p, %d, %p)\n", hinstDLL, fdwReason, lpvReserved);

    switch (fdwReason)
    {
        case DLL_WINE_PREATTACH:
            return FALSE;    /* prefer native version */
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            break;
    }

    return TRUE;
}

HRESULT WINAPI DllRegisterServer(void)
{
    FIXME("(): stub\n");

    return S_OK;
}

HRESULT WINAPI WMCreateEditor(IWMMetadataEditor **editor)
{
    FIXME("(%p): stub\n", editor);

    *editor = NULL;

    return E_NOTIMPL;
}

HRESULT WINAPI WMCreateReader(IUnknown *reserved, DWORD rights, IWMReader **reader)
{
    FIXME("(%p, %x, %p): stub\n", reserved, rights, reader);

    *reader = NULL;

    return E_NOTIMPL;
}

HRESULT WINAPI WMCreateSyncReader(IUnknown *pcert, DWORD rights, IWMSyncReader **syncreader)
{
    FIXME("(%p, %x, %p): stub\n", pcert, rights, syncreader);

    *syncreader = NULL;

    return E_NOTIMPL;
}

typedef struct {
    IWMProfileManager IWMProfileManager_iface;
    LONG ref;
} WMProfileManager;

static inline WMProfileManager *impl_from_IWMProfileManager(IWMProfileManager *iface)
{
    return CONTAINING_RECORD(iface, WMProfileManager, IWMProfileManager_iface);
}

static HRESULT WINAPI WMProfileManager_QueryInterface(IWMProfileManager *iface, REFIID riid, void **ppv)
{
    WMProfileManager *This = impl_from_IWMProfileManager(iface);

    if(IsEqualGUID(&IID_IUnknown, riid)) {
        TRACE("(%p)->(IID_IUnknown %p)\n", This, ppv);
        *ppv = &This->IWMProfileManager_iface;
    }else if(IsEqualGUID(&IID_IWMProfileManager, riid)) {
        TRACE("(%p)->(IID_IWMProfileManager %p)\n", This, ppv);
        *ppv = &This->IWMProfileManager_iface;
    }else {
        *ppv = NULL;
        return E_NOINTERFACE;
    }

    IUnknown_AddRef((IUnknown*)*ppv);
    return S_OK;
}

static ULONG WINAPI WMProfileManager_AddRef(IWMProfileManager *iface)
{
    WMProfileManager *This = impl_from_IWMProfileManager(iface);
    LONG ref = InterlockedIncrement(&This->ref);

    TRACE("(%p) ref=%d\n", This, ref);

    return ref;
}

static ULONG WINAPI WMProfileManager_Release(IWMProfileManager *iface)
{
    WMProfileManager *This = impl_from_IWMProfileManager(iface);
    LONG ref = InterlockedDecrement(&This->ref);

    TRACE("(%p) ref=%d\n", This, ref);

    if(!ref)
        heap_free(This);

    return ref;
}

static HRESULT WINAPI WMProfileManager_CreateEmptyProfile(IWMProfileManager *iface, WMT_VERSION version, IWMProfile **ret)
{
    WMProfileManager *This = impl_from_IWMProfileManager(iface);
    FIXME("(%p)->(%x %p)\n", This, version, ret);
    return E_NOTIMPL;
}

static HRESULT WINAPI WMProfileManager_LoadProfileByID(IWMProfileManager *iface, REFGUID guid, IWMProfile **ret)
{
    WMProfileManager *This = impl_from_IWMProfileManager(iface);
    FIXME("(%p)->(%s %p)\n", This, debugstr_guid(guid), ret);
    return E_NOTIMPL;
}

static HRESULT WINAPI WMProfileManager_LoadProfileByData(IWMProfileManager *iface, const WCHAR *profile, IWMProfile **ret)
{
    WMProfileManager *This = impl_from_IWMProfileManager(iface);
    FIXME("(%p)->(%s %p)\n", This, debugstr_w(profile), ret);
    return E_NOTIMPL;
}

static HRESULT WINAPI WMProfileManager_SaveProfile(IWMProfileManager *iface, IWMProfile *profile, WCHAR *profile_str, DWORD *len)
{
    WMProfileManager *This = impl_from_IWMProfileManager(iface);
    FIXME("(%p)->(%p %p %p)\n", This, profile, profile_str, len);
    return E_NOTIMPL;
}

static HRESULT WINAPI WMProfileManager_GetSystemProfileCount(IWMProfileManager *iface, DWORD *ret)
{
    WMProfileManager *This = impl_from_IWMProfileManager(iface);
    FIXME("(%p)->(%p)\n", This, ret);
    return E_NOTIMPL;
}

static HRESULT WINAPI WMProfileManager_LoadSystemProfile(IWMProfileManager *iface, DWORD index, IWMProfile **ret)
{
    WMProfileManager *This = impl_from_IWMProfileManager(iface);
    FIXME("(%p)->(%d %p)\n", This, index, ret);
    return E_NOTIMPL;
}

static const IWMProfileManagerVtbl WMProfileManagerVtbl = {
    WMProfileManager_QueryInterface,
    WMProfileManager_AddRef,
    WMProfileManager_Release,
    WMProfileManager_CreateEmptyProfile,
    WMProfileManager_LoadProfileByID,
    WMProfileManager_LoadProfileByData,
    WMProfileManager_SaveProfile,
    WMProfileManager_GetSystemProfileCount,
    WMProfileManager_LoadSystemProfile
};

HRESULT WINAPI WMCreateProfileManager(IWMProfileManager **ret)
{
    WMProfileManager *profile_mgr;

    TRACE("(%p)\n", ret);

    profile_mgr = heap_alloc(sizeof(*profile_mgr));
    if(!profile_mgr)
        return E_OUTOFMEMORY;

    profile_mgr->IWMProfileManager_iface.lpVtbl = &WMProfileManagerVtbl;
    profile_mgr->ref = 1;

    *ret = &profile_mgr->IWMProfileManager_iface;
    return S_OK;
}
