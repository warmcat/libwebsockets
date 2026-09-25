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
 * lws-core.h: the substrate both halves of lws stand on.  Data structures,
 * logging, time as data, parsers, decoders, utilities.  Nothing in here
 * names a socket, an fd, a poll flag, a tls library object, an event loop
 * handle or a platform device.  See READMEs/README.sans-io-split.md.
 *
 * Included by libwebsockets.h after its platform preamble, first of the
 * three tiers.
 */

struct lws;
struct lws_context;
struct lws_vhost;
struct lws_context_creation_info;

#include <libwebsockets/lws-dll2.h>
#include <libwebsockets/lws-map.h>

#include <libwebsockets/lws-fault-injection.h>
#include <libwebsockets/lws-backtrace.h>
#include <libwebsockets/lws-timeout-timer.h>
#include <libwebsockets/lws-cache-ttl.h>
#if defined(LWS_WITH_SYS_SMD)
#include <libwebsockets/lws-smd.h>
#endif
#include <libwebsockets/lws-state.h>
#include <libwebsockets/lws-retry.h>
#include <libwebsockets/lws-adapt.h>
#if defined(LWS_WITH_NETWORK)
#include <libwebsockets/lws-metrics.h>
#endif

#include <libwebsockets/lws-purify.h>
#include <libwebsockets/lws-misc.h>
#include <libwebsockets/lws-dsh.h>
#include <libwebsockets/lws-ring.h>
#if defined(LWS_WITH_MNEMONIC)
#include <libwebsockets/lws-mnemonic.h>
#endif
#include <libwebsockets/lws-sha1-base64.h>
#if defined(LWS_WITH_FILE_OPS)
#include <libwebsockets/lws-vfs.h>
#endif

#include <libwebsockets/lws-lejp.h>
#include <libwebsockets/lws-lecp.h>
#include <libwebsockets/lws-struct.h>
#include <libwebsockets/lws-threadpool.h>
#include <libwebsockets/lws-tokenize.h>
#include <libwebsockets/lws-lwsac.h>
#include <libwebsockets/lws-fts.h>
#include <libwebsockets/lws-diskcache.h>
#include <libwebsockets/lws-settings.h>

#include <libwebsockets/lws-upng.h>
#include <libwebsockets/lws-jpeg.h>
#include <libwebsockets/lws-svg.h>
#include <libwebsockets/lws-gif.h>
#if defined(LWS_WITH_HL)
#include <libwebsockets/lws-hl.h>
#endif
#if defined(LWS_WITH_MD)
#include <libwebsockets/lws-md.h>
#endif
#include <libwebsockets/qrcodegen.h>
