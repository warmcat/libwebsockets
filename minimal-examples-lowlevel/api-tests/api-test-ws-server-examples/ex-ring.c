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
#include "../../ws-server/minimal-ws-server-ring/protocol_lws_minimal.c"

const struct lws_protocols wse_protocol_ring =
					LWS_PLUGIN_PROTOCOL_MINIMAL;

/* the largest message the example passes on */
const size_t wse_max_message_ring = MINIMAL_MAX_MESSAGE;
