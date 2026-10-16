/*
 * libwebsockets - protocol - dht_dnssec_monitor
 *
 * Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
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
 * Who may ask the root process for what
 *
 * Every IPC request to the root process carries a JWT signed with the secret
 * it shares with the unprivileged process.  Several parts of that process
 * sign with it, and its "sub" says which: the proxy, for what it forwards
 * from a browser, the ACME client and the whois lookups.
 *
 * A browser can have the proxy forward any request at all, so the requests
 * that only the ACME client or the whois lookups have any business making
 * are refused from anyone else.  Otherwise a browser could, eg, overwrite a
 * domain's TLS key and cert or the ACME account key, or fetch the account
 * key.  The proxy never hands a browser a JWT, and they last a minute or
 * two, so a browser can't pass itself off as the others.
 */

#if !defined(LWS_PLUGIN_STATIC)
#define LWS_DLL
#define LWS_INTERNAL
#include <libwebsockets.h>
#endif

#include <string.h>

#include "private.h"

static const struct {
	const char	*req;
	const char	*sub;	/* the only requester it is taken from */
} mon_ipc_only[] = {
	{ "save_auth_key",		MON_IPC_SUB_ACME },
	{ "get_auth_key",		MON_IPC_SUB_ACME },
	{ "save_cert",			MON_IPC_SUB_ACME },
	{ "save_key",			MON_IPC_SUB_ACME },
	{ "save_dns_challenge",		MON_IPC_SUB_ACME },
	{ "cleanup_dns_challenge",	MON_IPC_SUB_ACME },
	{ "trigger_resign",		MON_IPC_SUB_ACME },
	{ "update_whois",		MON_IPC_SUB_WHOIS },
};

mon_ipc_auth_t
monitor_ipc_authorize(struct lws_context *cx, struct lws_jwk *auth_jwk,
		      const char *jwt, const char *req)
{
	char out[2048], temp[2048], sub[32];
	size_t out_len = sizeof(out), n;
	unsigned long exp_time;

	if (auth_jwk->kty != LWS_GENCRYPTO_KTY_OCT) {
		lwsl_notice("%s: IPC secret not bootstrapped\n", __func__);
		return MON_IPC_AUTH_FAILED;
	}

	if (!jwt || !jwt[0]) {
		lwsl_notice("%s: %s: no JWT\n", __func__, req);
		return MON_IPC_AUTH_FAILED;
	}

	if (lws_jwt_signed_validate(cx, auth_jwk, "HS256", jwt, strlen(jwt),
				    temp, sizeof(temp), out, &out_len)) {
		lwsl_notice("%s: %s: bad JWT\n", __func__, req);
		return MON_IPC_AUTH_FAILED;
	}

	/* we require the subject, so we know who it is */
	if (lws_jwt_token_sanity(out, out_len, "acme-ipc", "dnssec-monitor",
				 NULL, sub, sizeof(sub), &exp_time)) {
		lwsl_notice("%s: %s: unacceptable JWT claims\n", __func__, req);
		return MON_IPC_AUTH_FAILED;
	}

	for (n = 0; n < LWS_ARRAY_SIZE(mon_ipc_only); n++)
		if (!strcmp(req, mon_ipc_only[n].req) &&
		    strcmp(sub, mon_ipc_only[n].sub)) {
			lwsl_notice("%s: refusing %s from %s\n", __func__, req,
				    sub);
			return MON_IPC_AUTH_NOT_PERMITTED;
		}

	return MON_IPC_AUTH_OK;
}
