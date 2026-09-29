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
 * UI requests answered by the proxy itself
 *
 * Almost everything the browser asks is forwarded to the root monitor
 * process.  "Force cert reissue" is for the ACME client though, which runs
 * in this unprivileged lwsws process alongside the proxy, not in the root
 * process: the proxy asks it directly over SMD class LWSSMDCL_CERTS and
 * answers the browser itself.
 */

#if !defined(LWS_PLUGIN_STATIC)
#define LWS_DLL
#define LWS_INTERNAL
#include <libwebsockets.h>
#endif

#include <string.h>

#include "private.h"

static const char * const ui_local_paths[] = {
	"req",
	"domain",
};

struct ui_local_req {
	char req[32];
	char domain[128];
};

static signed char
ui_local_req_cb(struct lejp_ctx *ctx, char reason)
{
	struct ui_local_req *r = (struct ui_local_req *)ctx->user;

	if (reason != LEJPCB_VAL_STR_END || !ctx->path_match)
		return 0;

	switch (ctx->path_match - 1) {
	case 0:
		lws_strncpy(r->req, ctx->buf, sizeof(r->req));
		if (strcmp(r->req, "force_cert_reissue"))
			return -1; /* not ours, stop looking */
		break;
	case 1:
		lws_strncpy(r->domain, ctx->buf, sizeof(r->domain));
		break;
	}

	return 0;
}

int
monitor_ui_local_req(struct lws_context *cx, const void *in, size_t len,
		     char *reply, size_t reply_len)
{
	struct ui_local_req r;
	struct lejp_ctx ctx;
	const char *err = NULL;
	int n;

	memset(&r, 0, sizeof(r));
	lejp_construct(&ctx, ui_local_req_cb, &r, ui_local_paths,
		       LWS_ARRAY_SIZE(ui_local_paths));
	n = lejp_parse(&ctx, (const uint8_t *)in, (int)len);
	lejp_destruct(&ctx);

	if (strcmp(r.req, "force_cert_reissue"))
		return -1;

	if (reply_len < 2)
		/* no room to answer, so don't act on it either */
		return 0;

	if (n < 0)
		err = "Malformed request";
	else if (!r.domain[0] || r.domain[0] == '.')
		err = "Missing domain";
	else
		/* a DNS name: then it can go in the SMD JSON and the reply */
		for (n = 0; r.domain[n] && !err; n++)
			if (!((r.domain[n] >= 'a' && r.domain[n] <= 'z') ||
			      (r.domain[n] >= 'A' && r.domain[n] <= 'Z') ||
			      (r.domain[n] >= '0' && r.domain[n] <= '9') ||
			      r.domain[n] == '.' || r.domain[n] == '-'))
				err = "Invalid domain";

	/*
	 * Say it only if the whole answer fits: we must not ask for a reissue
	 * the browser never hears about
	 */
	if (!err)
		n = lws_snprintf(reply, reply_len, "{\"req\":\"force_cert_reissue\","
				 "\"status\":\"ok\",\"domain\":\"%s\"}\n",
				 r.domain);
	else
		n = lws_snprintf(reply, reply_len, "{\"req\":\"force_cert_reissue\","
				 "\"status\":\"error\",\"msg\":\"%s\"}\n", err);
	if ((size_t)n >= reply_len - 1)
		return 0;

	if (err)
		return n;

	/*
	 * Nothing tells us if an ACME client is listening: with none, the
	 * message just goes nowhere
	 */
	if (lws_smd_msg_printf(cx, LWSSMDCL_CERTS, "{\"acme\":\"force-reissue\","
			       "\"domain\":\"%s\"}", r.domain)) {
		n = lws_snprintf(reply, reply_len, "{\"req\":\"force_cert_reissue\","
				 "\"status\":\"error\",\"msg\":\"Unable to "
				 "reach the ACME client\"}\n");
		if ((size_t)n >= reply_len - 1)
			return 0;

		return n;
	}

	lwsl_notice("%s: forced cert reissue requested for %s\n", __func__,
		    r.domain);

	return n;
}
