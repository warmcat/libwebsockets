/*
 * Example ESP32 app code using Libwebsockets
 *
 * Copyright (C) 2017 Andy Green <andy@warmcat.com>
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
 * This is intended to be mounted somewhere in your ESP32 user app... if the
 * client touched the mount, the plugin hangs up and reboots into the
 * factory mode one second later.
 *
 * The factory mode will reassociate with the same IP with the same MAC
 * shortly afterwards and be accessible by the same IP / mDNS name.
 */
#include <string.h>
#include <esp_partition.h>
#include <esp_ota_ops.h>
#include <nvs.h>

static int
callback_esplws_rtf(struct lws *wsi, enum lws_callback_reasons reason,
		    void *user, void *in, size_t len)
{
	switch (reason) {

	case LWS_CALLBACK_HTTP:
		
		lws_esp32_restart_guided(LWS_MAGIC_REBOOT_TYPE_REQ_FACTORY);
		return 1;

	default:
		break;
	}

	return 0;
}

#define LWS_PLUGIN_PROTOCOL_ESPLWS_RTF \
	{ \
		"esplws-rtf", \
		callback_esplws_rtf, \
		0, \
		10, 0, NULL, 0 \
	}

