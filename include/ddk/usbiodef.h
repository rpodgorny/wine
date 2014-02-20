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

#ifndef __DDK_USBIODEF_H__
#define __DDK_USBIODEF_H__

#define USB_SUBMIT_URB 0

#define USB_GET_NODE_INFORMATION               258
#define USB_GET_NODE_CONNECTION_INFORMATION    259
#define USB_GET_NODE_CONNECTION_DRIVERKEY_NAME 264

#define HCD_GET_ROOT_HUB_NAME    258

DEFINE_GUID( GUID_DEVINTERFACE_USB_HUB,
  0xF18A0E88, 0xC30C, 0x11D0, 0x88, 0x15, 0x00, 0xA0, 0xC9, 0x06, 0xBE, 0xD8 );

#define FILE_DEVICE_USB FILE_DEVICE_UNKNOWN

#endif /* __DDK_USBIODEF_H__ */
