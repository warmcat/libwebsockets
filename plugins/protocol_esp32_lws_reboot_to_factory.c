/*
 * Example ESP32 app code using Libwebsockets
 *
 * Copyright (C) 2017 Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The person who associated a work with this deed has dedicated
 * the work to the public domain by waiving all of his or her rights
 * to the work worldwide under copyright law, including all related
 * and neighboring rights, to the extent allowed by law. You can copy,
 * modify, distribute and perform the work, even for commercial purposes,
 * all without asking permission.
 *
 * The test apps are intended to be adapted for use in your code, which
 * may be proprietary.	So unlike the library itself, they are licensed
 * Public Domain.
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

