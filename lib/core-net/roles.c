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
 * roles.c: the role registry: every role the build has, sansIO's and the
 * transport adapters IO wears the role interface for, found by name, and
 * offered a socket or file being adopted in turn.  Neither half's (see
 * READMEs/README.sans-io-split.md): both halves dispatch through it.
 */

#include "private-lib-core.h"

const struct lws_role_ops *available_roles[] = {
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
#if defined(LWS_ROLE_DBUS)
	&role_ops_dbus,
#endif
#if defined(LWS_ROLE_RAW_PROXY)
	&role_ops_raw_proxy,
#endif
#if defined(LWS_ROLE_MQTT) && defined(LWS_WITH_CLIENT)
	&role_ops_mqtt,
#endif
#if defined(LWS_WITH_NETLINK)
	&role_ops_netlink,
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

#if defined(LWS_ROLE_RAW_FILE)
	if (!strcmp(name, role_ops_raw_file.name))
		return &role_ops_raw_file;
#endif

	return NULL;
}

int
lws_role_call_adoption_bind(struct lws *wsi, int type, const char *prot)
{
	int n;

	/*
	 * if the vhost is told to bind accepted sockets to a given role,
	 * then look it up by name and try to bind to the specific role.
	 */
	if (lws_check_opt(wsi->a.vhost->options,
			  LWS_SERVER_OPTION_ADOPT_APPLY_LISTEN_ACCEPT_CONFIG) &&
	    wsi->a.vhost->listen_accept_role) {
		const struct lws_role_ops *role =
			lws_role_by_name(wsi->a.vhost->listen_accept_role);

		if (!prot)
			prot = wsi->a.vhost->listen_accept_protocol;

		if (!role)
			lwsl_wsi_err(wsi, "can't find role '%s'",
					  wsi->a.vhost->listen_accept_role);

		if (!strcmp(wsi->a.vhost->listen_accept_role, "raw-proxy"))
			type |= LWS_ADOPT_FLAG_RAW_PROXY;

		if (role && lws_rops_fidx(role, LWS_ROPS_adoption_bind)) {
			n = (lws_rops_func_fidx(role, LWS_ROPS_adoption_bind)).
						adoption_bind(wsi, type, prot);
			if (n < 0)
				return -1;
			if (n) /* did the bind */
				return 0;
		}

		if (type & _LWS_ADOPT_FINISH) {
			lwsl_wsi_debug(wsi, "leaving bound to role %s",
					    wsi->role_ops->name);
			return 0;
		}

		lwsl_wsi_warn(wsi, "adoption bind to role '%s', "
			  "protocol '%s', type 0x%x, failed",
			  wsi->a.vhost->listen_accept_role, prot, type);
	}

	/*
	 * Otherwise ask each of the roles in order of preference if they
	 * want to bind to this accepted socket
	 */

	LWS_FOR_EVERY_AVAILABLE_ROLE_START(ar)
		if (lws_rops_fidx(ar, LWS_ROPS_adoption_bind) &&
		    (lws_rops_func_fidx(ar, LWS_ROPS_adoption_bind)).
					    adoption_bind(wsi, type, prot))
			return 0;
	LWS_FOR_EVERY_AVAILABLE_ROLE_END;

	/* fall back to raw socket role if, eg, h1 not configured */

	if (lws_rops_fidx(&role_ops_raw_skt, LWS_ROPS_adoption_bind) &&
	    (lws_rops_func_fidx(&role_ops_raw_skt, LWS_ROPS_adoption_bind)).
				    adoption_bind(wsi, type, prot))
		return 0;

#if defined(LWS_ROLE_RAW_FILE)

	lwsl_wsi_info(wsi, "falling back to raw file role bind");

	/* fall back to raw file role if, eg, h1 not configured */

	if (lws_rops_fidx(&role_ops_raw_file, LWS_ROPS_adoption_bind) &&
	    (lws_rops_func_fidx(&role_ops_raw_file, LWS_ROPS_adoption_bind)).
				    adoption_bind(wsi, type, prot))
		return 0;
#endif

	return 1;
}
