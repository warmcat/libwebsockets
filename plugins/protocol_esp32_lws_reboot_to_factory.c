 /*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2019 Andy Green <andy@warmcat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
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

