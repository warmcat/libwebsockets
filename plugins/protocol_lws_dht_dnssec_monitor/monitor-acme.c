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
 * answers the browser itself that it was asked.  The ACME client says what
 * came of it later, on the same SMD class, and the proxy passes that on to
 * the browsers too.
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
	"fqdn",
};

struct ui_local_req {
	char req[32];
	char domain[128];
	char fqdn[128];
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
	case 2:
		lws_strncpy(r->fqdn, ctx->buf, sizeof(r->fqdn));
		break;
	}

	return 0;
}

/*
 * A DNS name, then it can go in the SMD JSON and the reply as it is.  The
 * ACME client's cert names may also be wildcards, or carry '_'
 */

static int
ui_valid_name(const char *p, int cert_name)
{
	if (!*p || *p == '.')
		return 0;

	for (; *p; p++)
		if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
		      (*p >= '0' && *p <= '9') || *p == '.' || *p == '-' ||
		      (cert_name && (*p == '_' || *p == '*'))))
			return 0;

	return 1;
}

int
monitor_ui_local_req(struct lws_context *cx, const void *in, size_t len,
		     char *reply, size_t reply_len)
{
	struct ui_local_req r;
	struct lejp_ctx ctx;
	const char *err = NULL;
	size_t dl, fl;
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

	dl = strlen(r.domain);
	fl = strlen(r.fqdn);

	if (n < 0)
		err = "Malformed request";
	else if (!r.domain[0] || r.domain[0] == '.')
		err = "Missing domain";
	else if (!r.fqdn[0])
		err = "Missing fqdn";
	else if (!ui_valid_name(r.domain, 0))
		err = "Invalid domain";
	else if (!ui_valid_name(r.fqdn, 1))
		err = "Invalid fqdn";
	else if (fl < dl || strcmp(r.fqdn + fl - dl, r.domain) ||
		 (fl > dl && r.fqdn[fl - dl - 1] != '.'))
		/* the cert must be one of the domain's own */
		err = "fqdn not in domain";

	/*
	 * Say it only if the whole answer fits: we must not ask for a reissue
	 * the browser never hears about
	 */
	if (!err)
		n = lws_snprintf(reply, reply_len, "{\"req\":\"force_cert_reissue\","
				 "\"status\":\"ok\",\"domain\":\"%s\","
				 "\"fqdn\":\"%s\"}\n", r.domain, r.fqdn);
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
			       "\"domain\":\"%s\",\"common-name\":\"%s\"}",
			       r.domain, r.fqdn)) {
		n = lws_snprintf(reply, reply_len, "{\"req\":\"force_cert_reissue\","
				 "\"status\":\"error\",\"msg\":\"Unable to "
				 "reach the ACME client\"}\n");
		if ((size_t)n >= reply_len - 1)
			return 0;

		return n;
	}

	lwsl_notice("%s: forced cert reissue requested for %s (%s)\n",
		    __func__, r.fqdn, r.domain);

	return n;
}

static const char * const acme_result_paths[] = {
	"acme",
	"domain",
	"common-name",
	"status",
	"msg",
};

struct acme_result {
	char acme[32];
	char domain[128];
	char cn[128];
	char status[8];
	char msg[128];
};

static signed char
acme_result_cb(struct lejp_ctx *ctx, char reason)
{
	struct acme_result *r = (struct acme_result *)ctx->user;

	if (reason != LEJPCB_VAL_STR_END || !ctx->path_match)
		return 0;

	switch (ctx->path_match - 1) {
	case 0:
		lws_strncpy(r->acme, ctx->buf, sizeof(r->acme));
		break;
	case 1:
		lws_strncpy(r->domain, ctx->buf, sizeof(r->domain));
		break;
	case 2:
		lws_strncpy(r->cn, ctx->buf, sizeof(r->cn));
		break;
	case 3:
		lws_strncpy(r->status, ctx->buf, sizeof(r->status));
		break;
	case 4:
		lws_strncpy(r->msg, ctx->buf, sizeof(r->msg));
		break;
	}

	return 0;
}

int
monitor_acme_result_ui_line(const void *in, size_t len, char *line,
			    size_t line_len)
{
	char esc[256] = "";
	struct acme_result r;
	struct lejp_ctx ctx;
	int n, ok;

	if (line_len < 2)
		return -1;

	memset(&r, 0, sizeof(r));
	lejp_construct(&ctx, acme_result_cb, &r, acme_result_paths,
		       LWS_ARRAY_SIZE(acme_result_paths));
	n = lejp_parse(&ctx, (const uint8_t *)in, (int)len);
	lejp_destruct(&ctx);

	if (n < 0 || strcmp(r.acme, "force-reissue-result"))
		return -1;

	/* it's only sent by another plugin, but it goes on to the browser */
	ok = !strcmp(r.status, "ok");
	if ((!ok && strcmp(r.status, "error")) || !ui_valid_name(r.domain, 0) ||
	    !ui_valid_name(r.cn, 1))
		return -1;

	if (!ok)
		lws_json_purify(esc, r.msg[0] ? r.msg : "unknown",
				(int)sizeof(esc), NULL);

	n = lws_snprintf(line, line_len, "{\"req\":\"force_cert_reissue_result\","
			 "\"status\":\"%s\",\"domain\":\"%s\",\"fqdn\":\"%s\""
			 "%s%s%s}\n", r.status, r.domain, r.cn,
			 ok ? "" : ",\"msg\":\"", esc, ok ? "" : "\"");

	return (size_t)n >= line_len - 1 ? -1 : n;
}
