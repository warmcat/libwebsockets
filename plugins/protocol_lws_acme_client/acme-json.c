/*
 * libwebsockets ACME client protocol plugin
 *
 * Copyright (C) 2010 - 2022 Andy Green <andy@warmcat.com>
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
 *  This implementation follows draft 7 of the IETF standard, and falls back
 *  to whatever differences exist for Boulder's tls-sni-01 challenge.
 *  tls-sni-02 is also supported.
 */

/*
 * Parsers for the JSON the ACME server answers with, for the root daemon's
 * answer lines on the IPC stream, and the collector for the issued cert's
 * PEM body.  They live apart from the rest of the plugin so
 * api-test-acme-json can run them on canned responses.
 */

#if !defined(LWS_PLUGIN_STATIC)
#if !defined(LWS_DLL)
#define LWS_DLL
#endif
#if !defined(LWS_INTERNAL)
#define LWS_INTERNAL
#endif
#include <libwebsockets.h>
#endif

#include <string.h>
#include <stdlib.h>

#include "private-acme-client.h"

/* directory JSON parsing */

const char * const acme_jdir_tok[6] = {
	"keyChange",
	"meta.termsOfService",
	"newAccount",
	"newNonce",
	"newOrder",
	"revokeCert",
};

signed char
acme_cb_dir(struct lejp_ctx *ctx, char reason)
{
	struct per_vhost_data__lws_acme_client *s =
		(struct per_vhost_data__lws_acme_client *)ctx->user;

	/*
	 * The accumulator state lives in the vhd, but s->dest points into the
	 * per-acquisition ac, which is freed at the end of each attempt.  Make
	 * sure no pointer from a previous parse survives into this one
	 */
	if (reason == LEJPCB_CONSTRUCTED) {
		s->dest = NULL;
		s->pos = 0;
		s->len = 0;

		return 0;
	}

	if (reason == LEJPCB_VAL_STR_START && ctx->path_match) {
		s->pos = 0;
		s->len = sizeof(s->ac->urls[0]) - 1;
		s->dest = s->ac->urls[ctx->path_match - 1];
		return 0;
	}

	/*
	 * LEJP_FLAG_CB_IS_VALUE is also set for true / false / null and for
	 * numbers, none of which passed through LEJPCB_VAL_STR_START above.
	 * Only accumulate string pieces, and only into a dest we actually set:
	 * otherwise a directory like { "newNonce": null } writes through a NULL
	 * or stale dest
	 */
	if ((reason != LEJPCB_VAL_STR_CHUNK && reason != LEJPCB_VAL_STR_END) ||
	    !ctx->path_match || !s->dest)
		return 0;

	if (s->pos + ctx->npos > s->len) {
		lwsl_notice("url too long\n");
		return -1;
	}

	memcpy(s->dest + s->pos, ctx->buf, ctx->npos);
	s->pos += ctx->npos;
	s->dest[s->pos] = '\0';

	return 0;
}


/*
 * lejp delivers a string value longer than LEJP_STRING_CHUNK as a series of
 * LEJPCB_VAL_STR_CHUNK callbacks with only that piece in ctx->buf, ending with
 * LEJPCB_VAL_STR_END.  The callbacks below each copy ctx->buf straight into a
 * fixed field, so without this an over-long value would silently leave the
 * *tail* of the value there (eg, a URL with no scheme or host).  None of the
 * fields we care about can legitimately be this long, so fail the parse rather
 * than act on a fragment
 */
static signed char
acme_reject_long_value(struct lejp_ctx *ctx)
{
	lwsl_notice("%s: over-long JSON value for %s\n", __func__, ctx->path);

	return -1;
}

/* order JSON parsing */

const char * const acme_jorder_tok[7] = {
	"status",
	"expires",
	"identifiers[].type",
	"identifiers[].value",
	"authorizations",
	"finalize",
	"certificate"
};

enum enum_jorder_tok {
	JAO_STATUS,
	JAO_EXPIRES,
	JAO_IDENTIFIERS_TYPE,
	JAO_IDENTIFIERS_VALUE,
	JAO_AUTHORIZATIONS,
	JAO_FINALIZE,
	JAO_CERT
};

signed char
acme_cb_order(struct lejp_ctx *ctx, char reason)
{
	struct acme_connection *s = (struct acme_connection *)ctx->user;

	if (reason == LEJPCB_CONSTRUCTED)
		s->authz_url[0] = '\0';

	if (!(reason & LEJP_FLAG_CB_IS_VALUE) || !ctx->path_match)
		return 0;

	if (reason == LEJPCB_VAL_STR_CHUNK)
		return acme_reject_long_value(ctx);

	switch (ctx->path_match - 1) {
	case JAO_STATUS:
		lws_strncpy(s->status, ctx->buf, sizeof(s->status));
		break;
	case JAO_EXPIRES:
		break;
	case JAO_IDENTIFIERS_TYPE:
		break;
	case JAO_IDENTIFIERS_VALUE:
		break;
	case JAO_AUTHORIZATIONS:
		lws_snprintf(s->authz_url, sizeof(s->authz_url), "%s",
			     ctx->buf);
		break;
	case JAO_FINALIZE:
		lws_snprintf(s->finalize_url, sizeof(s->finalize_url), "%s",
				ctx->buf);
		break;
	case JAO_CERT:
		lws_snprintf(s->cert_url, sizeof(s->cert_url), "%s", ctx->buf);
		break;
	}

	return 0;
}

/*
 * RFC 8555 8.1: a challenge token is base64url, no padding.  It goes into the
 * http-01 mountpoint and the key authorization we serve or publish, so take
 * nothing else, and nothing we would have to truncate
 */

static int
acme_token_valid(const char *t, size_t room)
{
	size_t n;

	for (n = 0; t[n]; n++)
		if (n == room - 1 ||
		    !((t[n] >= 'A' && t[n] <= 'Z') ||
		      (t[n] >= 'a' && t[n] <= 'z') ||
		      (t[n] >= '0' && t[n] <= '9') ||
		      t[n] == '-' || t[n] == '_'))
			return 0;

	return n > 0;
}

/* authz JSON parsing */

const char * const acme_jauthz_tok[9] = {
	"identifier.type",
	"identifier.value",
	"status",
	"expires",
	"challenges[].type",
	"challenges[].status",
	"challenges[].url",
	"challenges[].token",
	"detail"
};

enum enum_jauthz_tok {
	JAAZ_ID_TYPE,
	JAAZ_ID_VALUE,
	JAAZ_STATUS,
	JAAZ_EXPIRES,
	JAAZ_CHALLENGES_TYPE,
	JAAZ_CHALLENGES_STATUS,
	JAAZ_CHALLENGES_URL,
	JAAZ_CHALLENGES_TOKEN,
	JAAZ_DETAIL,
};

signed char
acme_cb_authz(struct lejp_ctx *ctx, char reason)
{
	struct per_vhost_data__lws_acme_client *vhd = (struct per_vhost_data__lws_acme_client *)ctx->user;
	struct acme_connection *s = vhd->ac;

	if (reason == LEJPCB_CONSTRUCTED) {
		s->yes = 0;
		s->use = 0;
		s->chall_token[0] = '\0';
		s->chall_type[0] = '\0';
	}

	if (!(reason & LEJP_FLAG_CB_IS_VALUE) || !ctx->path_match)
		return 0;

	if (reason == LEJPCB_VAL_STR_CHUNK)
		return acme_reject_long_value(ctx);

	switch (ctx->path_match - 1) {
	case JAAZ_ID_TYPE:
		break;
	case JAAZ_ID_VALUE:
		break;
	case JAAZ_STATUS:
		break;
	case JAAZ_EXPIRES:
		break;
	case JAAZ_DETAIL:
		lws_snprintf(s->detail, sizeof(s->detail), "%s", ctx->buf);
		break;
	case JAAZ_CHALLENGES_TYPE:
		lwsl_notice("JAAZ_CHALLENGES_TYPE: %s\n", ctx->buf);
		lws_acme_challenge_type expected_challenge = vhd->active_cert ? vhd->active_cert->challenge_type : LWS_ACME_CHALLENGE_TYPE_HTTP_01;
		s->use = !strcmp(ctx->buf, expected_challenge == LWS_ACME_CHALLENGE_TYPE_DNS_01 ? "dns-01" : "http-01");
		if (s->use)
			lws_strncpy(s->chall_type, ctx->buf, sizeof(s->chall_type));
		break;
	case JAAZ_CHALLENGES_STATUS:
		lws_strncpy(s->status, ctx->buf, sizeof(s->status));
		break;
	case JAAZ_CHALLENGES_URL:
		lwsl_notice("JAAZ_CHALLENGES_URL: %s %d\n", ctx->buf, s->use);
		if (s->use) {
			lws_strncpy(s->challenge_uri, ctx->buf,
				    sizeof(s->challenge_uri));
			s->yes = s->yes | 2;
		}
		break;
	case JAAZ_CHALLENGES_TOKEN:
		if (s->use) {
			if (!acme_token_valid(ctx->buf, sizeof(s->chall_token))) {
				lwsl_warn("%s: challenge token is not base64url\n",
					  __func__);
				return -1;
			}
			lwsl_notice("JAAZ_CHALLENGES_TOKEN: %s\n", ctx->buf);
			lws_strncpy(s->chall_token, ctx->buf,
				    sizeof(s->chall_token));
			s->yes = s->yes | 1;
		}
		break;
	}

	return 0;
}

/* challenge accepted JSON parsing */

const char * const acme_jchac_tok[5] = {
	"type",
	"status",
	"url",
	"token",
	"error.detail"
};

enum enum_jchac_tok {
	JCAC_TYPE,
	JCAC_STATUS,
	JCAC_URL,
	JCAC_TOKEN,
	JCAC_DETAIL,
};

signed char
acme_cb_chac(struct lejp_ctx *ctx, char reason)
{
	struct acme_connection *s = (struct acme_connection *)ctx->user;

	if (reason == LEJPCB_CONSTRUCTED) {
		s->yes = 0;
		s->use = 0;
	}

	if (!(reason & LEJP_FLAG_CB_IS_VALUE) || !ctx->path_match)
		return 0;

	if (reason == LEJPCB_VAL_STR_CHUNK)
		return acme_reject_long_value(ctx);

	switch (ctx->path_match - 1) {
	case JCAC_TYPE:
		/*
		 * The answer is about the challenge we took up, whichever type
		 * that was: it used to insist on http-01, which lejp ignored
		 * until it started honouring positive returns at
		 * LEJPCB_VAL_STR_END, and then every dns-01 failed here
		 */
		if (strcmp(ctx->buf, s->chall_type)) {
			lwsl_notice("%s: challenge is %s, we took up %s\n",
				    __func__, ctx->buf, s->chall_type);
			return -1;
		}
		break;
	case JCAC_STATUS:
		lws_strncpy(s->status, ctx->buf, sizeof(s->status));
		break;
	case JCAC_URL:
		s->yes = s->yes | 2;
		break;
	case JCAC_TOKEN:
		if (!acme_token_valid(ctx->buf, sizeof(s->chall_token)))
			return -1;
		lws_strncpy(s->chall_token, ctx->buf, sizeof(s->chall_token));
		s->yes = s->yes | 1;
		break;
	case JCAC_DETAIL:
		lws_snprintf(s->detail, sizeof(s->detail), "%s", ctx->buf);
		break;
	}

	return 0;
}

/*
 * The root daemon's answers on the IPC stream, see private-acme-client.h
 */

int
acme_ipc_rx(struct acme_ipc_rx *rx, const char *in, size_t len,
	    acme_ipc_line_cb_t cb, void *opaque)
{
	size_t n;

	while (len--) {
		char c = *in++;

		if (c != '\n') {
			if (rx->len < sizeof(rx->buf) - 1)
				rx->buf[rx->len] = c;
			/* an overlong line is not an answer of ours, drop it */
			if (rx->len < sizeof(rx->buf))
				rx->len++;
			continue;
		}

		n = rx->len;
		rx->len = 0;
		if (!n || n == sizeof(rx->buf))
			continue;

		rx->buf[n] = '\0';
		if (cb(opaque, rx->buf, n))
			return 1;
	}

	return 0;
}

/* an integer member, eg "days_left":12; 0 if missing or not a number */

static int
acme_ipc_int(const char *line, size_t len, const char *name)
{
	const char *p;
	size_t al, n = 0, d;
	int v = 0, neg = 0;

	p = lws_json_simple_find(line, len, name, &al);
	if (!p)
		return 0;

	if (al && *p == '-') {
		neg = 1;
		n++;
	}

	/* nine digits cannot overflow an int */
	for (d = 0; n < al && d < 9 && p[n] >= '0' && p[n] <= '9'; n++, d++)
		v = (v * 10) + (p[n] - '0');

	return neg ? -v : v;
}

static const char * const acme_ipc_save_reqs[] = {
	"save_cert",			/* the first two store the cert */
	"save_key",
	"save_auth_key",
	"save_dns_challenge",
	"cleanup_dns_challenge",
	"trigger_resign",
};

void
acme_ipc_classify(const char *line, size_t len, struct acme_ipc_reply *r)
{
	const char *req;
	size_t rl, n;

	memset(r, 0, sizeof(*r));

	r->ok = !lws_json_simple_strcmp(line, len, "\"status\":", "ok");

	req = lws_json_simple_find(line, len, "\"req\":", &rl);
	if (!req || (rl == 7 && !strncmp(req, "unknown", 7))) {
		/*
		 * Refused before it knew the request (bad JSON, missing req,
		 * authentication), so it answers one of ours but we can't
		 * say which
		 */
		if (!lws_json_simple_strcmp(line, len, "\"status\":", "error"))
			r->type = ACME_IPC_LINE_REFUSED;

		return;
	}

	if (rl == 17 && !strncmp(req, "get_cert_validity", 17)) {
		r->type = ACME_IPC_LINE_VALIDITY;
		r->days_left = acme_ipc_int(line, len, "\"days_left\":");
		r->total_days = acme_ipc_int(line, len, "\"total_days\":");

		return;
	}

	for (n = 0; n < LWS_ARRAY_SIZE(acme_ipc_save_reqs); n++)
		if (rl == strlen(acme_ipc_save_reqs[n]) &&
		    !strncmp(req, acme_ipc_save_reqs[n], rl)) {
			r->type = ACME_IPC_LINE_SAVE;
			r->stores_cert = n < 2;

			return;
		}

	/* eg, "cert_status" sent to every client: not ours */
}

/* the issued cert's PEM body */

int
acme_cert_rx_append(struct acme_cert_rx *crx, const void *in, size_t len)
{
	size_t need = crx->len + len + 1; /* + NUL */

	if (need > ACME_CERT_CHAIN_MAX + 1)
		return 1;

	if (need > crx->alloc) {
		size_t na = crx->alloc ? crx->alloc : 4096;
		char *np;

		while (na < need)
			na *= 2;
		if (na > ACME_CERT_CHAIN_MAX + 1)
			na = ACME_CERT_CHAIN_MAX + 1;

		np = realloc(crx->pem, na);
		if (!np)
			return 1;

		crx->pem = np;
		crx->alloc = na;
	}

	if (len)
		memcpy(crx->pem + crx->len, in, len);
	crx->len += len;
	crx->pem[crx->len] = '\0';

	return 0;
}

size_t
acme_cert_leaf_len(const struct acme_cert_rx *crx)
{
	static const char end[] = "-----END CERTIFICATE-----";
	const char *p;

	if (!crx->pem)
		return 0;

	/* the body is NUL-terminated, so the needle can only match inside it */
	p = strstr(crx->pem, end);
	if (!p)
		return 0;

	return lws_ptr_diff_size_t(p, crx->pem) + sizeof(end) - 1;
}

void
acme_cert_rx_free(struct acme_cert_rx *crx)
{
	free(crx->pem);
	crx->pem = NULL;
	crx->len = 0;
	crx->alloc = 0;
}
