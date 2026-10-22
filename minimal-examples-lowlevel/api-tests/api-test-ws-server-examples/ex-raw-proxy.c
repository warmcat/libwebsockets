/*
 * lws-api-test-ws-server-examples
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The example protocols all call their callback callback_minimal(), and
 * several have the same protocol name, so each is built in its own unit.
 */

#include <libwebsockets.h>
#include "examples.h"

#define LWS_PLUGIN_STATIC
#include "../../ws-server/minimal-ws-raw-proxy/protocol_lws_ws_raw_proxy.c"

const struct lws_protocols wse_protocols_raw_proxy[] = {
	{ "http", lws_callback_http_dummy, 0, 0, 0, NULL, 0 },
	LWS_PLUGIN_PROTOCOL_WS_RAW_PROXY,
	LWS_PROTOCOL_LIST_TERM
};

/* the example connects to 127.0.0.1:1234: we tell it where our backend is */
void
wse_raw_proxy_backend(const char *address, int port)
{
	proxy_backend.address = address;
	proxy_backend.port = port;
}
