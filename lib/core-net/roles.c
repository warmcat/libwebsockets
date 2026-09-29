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
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * roles.c: the registry of the protocol roles the build has, sansIO's,
 * found by name and asked in turn (an alpn, a client's bind).  Neither
 * half's (see READMEs/README.sans-io-split.md): sansIO dispatches through
 * it, and IO too, which adds its own transport adapter roles
 * (lib/io/roles.c).
 */

#include "private-lib-core.h"

const struct lws_role_ops * const available_roles[] = {
#if defined(LWS_ROLE_H2)
	&role_ops_h2,
#endif
#if defined(LWS_ROLE_QUIC)
	&role_ops_quic,
#endif
#if defined(LWS_ROLE_H3)
	&role_ops_h3,
#endif
#if defined(LWS_ROLE_WT)
	&role_ops_wt,
#endif
#if defined(LWS_ROLE_H1)
	&role_ops_h1,
#endif
#if defined(LWS_ROLE_WS)
	&role_ops_ws,
#endif
#if defined(LWS_ROLE_RAW_PROXY)
	&role_ops_raw_proxy,
#endif
#if defined(LWS_ROLE_MQTT) && defined(LWS_WITH_CLIENT)
	&role_ops_mqtt,
#endif
	NULL
};

const struct lws_role_ops *
lws_role_by_name(const char *name)
{
	LWS_FOR_EVERY_AVAILABLE_ROLE_START(ar)
		if (!strcmp(ar->name, name))
			return ar;
	LWS_FOR_EVERY_AVAILABLE_ROLE_END;

	if (!strcmp(name, role_ops_raw_skt.name))
		return &role_ops_raw_skt;

	return NULL;
}
