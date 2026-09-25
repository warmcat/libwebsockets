/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
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
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * lws-sansio.h: the protocol half of lws, as an application sees it.  The
 * callbacks a protocol makes into the application, the write flags, the
 * http, ws, h2, h3 and mqtt vocabulary.  Nothing in here names a socket, an
 * fd, a poll flag, a tls library object, an event loop handle or a platform
 * device: this is what a port of the protocols carries, and what an
 * embedder of the sansIO half alone sees.  See READMEs/README.sans-io-split.md.
 *
 * Needs lws-core.h first.  IO's objects appear here only through pointers.
 */

struct lws;
struct lws_context;
struct lws_vhost;
struct lws_http_mount;
struct lws_protocol_vhost_options;
struct lws_context_creation_info;

#include <libwebsockets/lws-callbacks.h>

#if defined(LWS_WITH_NETWORK)
#include <libwebsockets/lws-ws-close.h>
#include <libwebsockets/lws-ws-state.h>
#include <libwebsockets/lws-ws-ext.h>
#endif

#include <libwebsockets/lws-protocols-plugins.h>

#if defined(LWS_WITH_NETWORK)
#if defined(LWS_ROLE_MQTT)
#include <libwebsockets/lws-mqtt.h>
#endif
#include <libwebsockets/lws-http.h>
#if defined(LWS_ROLE_H3)
#include <libwebsockets/lws-qpack.h>
#include <libwebsockets/lws-webtransport.h>
#endif
#include <libwebsockets/lws-spa.h>
#include <libwebsockets/lws-write.h>
#include <libwebsockets/lws-writeable.h>
#endif
#if defined(LWS_WITH_TLS)
#include <libwebsockets/lws-quic.h>
#endif
