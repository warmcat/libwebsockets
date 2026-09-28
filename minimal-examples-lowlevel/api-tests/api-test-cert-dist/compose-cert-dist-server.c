/*
 * lws-api-test-cert-dist
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The cert-dist server plugin, composed into us.  It is in a translation unit
 * of its own because the two plugins' statics share names; main.c reaches its
 * export through the pointer below.
 */

#define LWS_PLUGIN_STATIC
#include "protocol_lws_cert_dist_server/protocol_lws_cert_dist_server.c"

extern const lws_plugin_protocol_t * const composed_cds;
const lws_plugin_protocol_t * const composed_cds = &lws_cert_dist_server;
