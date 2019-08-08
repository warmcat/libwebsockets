/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2018 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 *
 *  This is included from core/private.h if LWS_ROLE_DBUS
 */

#include <dbus/dbus.h>

extern struct lws_role_ops role_ops_dbus;

#define lwsi_role_dbus(wsi) (wsi->role_ops == &role_ops_dbus)

struct lws_role_dbus_timer {
	struct lws_dll2 timer_list;
	void *data;
	time_t fire;
};

struct lws_pt_role_dbus {
	struct lws_dll2_owner timer_list_owner;
};

struct _lws_dbus_mode_related {
	DBusConnection *conn;
};
