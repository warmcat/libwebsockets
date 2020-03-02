/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2019 - 2020 Andy Green <andy@warmcat.com>
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
 */

#include <private-lib-core.h>

typedef struct backoffs {
	struct backoffs *next;
	const char *name;
	lws_retry_bo_t r;
} backoff_t;

static const char * const lejp_tokens_policy[] = {
	"release",
	"product",
	"schema-version",
	"via-socks5",
	"retry[].*.backoff",
	"retry[].*.conceal",
	"retry[].*.jitterpc",
	"retry[].*.svalidping",
	"retry[].*.svalidhup",
	"retry[].*",
	"certs[].*",
	"trust_stores[].name",
	"trust_stores[].stack",
	"s[].*.endpoint",
	"s[].*.via-socks5",
	"s[].*.protocol",
	"s[].*.port",
	"s[].*.plugins",
	"s[].*.tls",
	"s[].*.client_cert",
	"s[].*.opportunistic",
	"s[].*.nailed_up",
	"s[].*.urgent_tx",
	"s[].*.urgent_rx",
	"s[].*.long_poll",
	"s[].*.retry",
	"s[].*.tls_trust_store",
	"s[].*.metadata",
	"s[].*.metadata[].*",

	"s[].*.http_auth_header",
	"s[].*.http_dsn_header",
	"s[].*.http_fwv_header",
	"s[].*.http_devtype_header",

	"s[].*.http_auth_preamble",

	"s[].*.http_no_content_length",
	"s[].*.rideshare",	/* streamtype name this rides shotgun with */
	"s[].*.payload_fmt",
	"s[].*.http_method",
	"s[].*.http_url",
	"s[].*.nghttp2_quirk_end_stream",
	"s[].*.h2q_oflow_txcr",
	"s[].*.http_multipart_name",
	"s[].*.http_multipart_filename",
	"s[].*.http_mime_content_type",
	"s[].*.http_www_form_urlencoded",
	"s[].*.ws_subprotocol",
	"s[].*.ws_binary",
	"s[].*.local_sink",
	"s[].*.mqtt_topic",
	"s[].*.mqtt_subscribe",
	"s[].*.mqtt_qos",
	"s[].*.mqtt_keep_alive",
	"s[].*.mqtt_clean_start",
	"s[].*.mqtt_will_topic",
	"s[].*.mqtt_will_message",
	"s[].*.mqtt_will_qos",
	"s[].*.mqtt_will_retain",
	"s[].*",
};

typedef enum {
	LSSPPT_RELEASE,
	LSSPPT_PRODUCT,
	LSSPPT_SCHEMA_VERSION,
	LSSPPT_VIA_SOCKS5,
	LSSPPT_BACKOFF,
	LSSPPT_CONCEAL,
	LSSPPT_JITTERPC,
	LSSPPT_VALIDPING_S,
	LSSPPT_VALIDHUP_S,
	LSSPPT_RETRY,
	LSSPPT_CERTS,
	LSSPPT_TRUST_STORES_NAME,
	LSSPPT_TRUST_STORES_STACK,
	LSSPPT_ENDPOINT,
	LSSPPT_VH_VIA_SOCKS5,
	LSSPPT_PROTOCOL,
	LSSPPT_PORT,
	LSSPPT_PLUGINS,
	LSSPPT_TLS,
	LSSPPT_TLS_CLIENT_CERT,
	LSSPPT_OPPORTUNISTIC,
	LSSPPT_NAILED_UP,
	LSSPPT_URGENT_TX,
	LSSPPT_URGENT_RX,
	LSSPPT_LONG_POLL,
	LSSPPT_RETRYPTR,
	LSSPPT_TRUST,
	LSSPPT_METADATA,
	LSSPPT_METADATA_ITEM,

	LSSPPT_HTTP_AUTH_HEADER,
	LSSPPT_HTTP_DSN_HEADER,
	LSSPPT_HTTP_FWV_HEADER,
	LSSPPT_HTTP_TYPE_HEADER,

	LSSPPT_HTTP_AUTH_PREAMBLE,
	LSSPPT_HTTP_NO_CONTENT_LENGTH,
	LSSPPT_RIDESHARE,
	LSSPPT_PAYLOAD_FORMAT,
	LSSPPT_HTTP_METHOD,
	LSSPPT_HTTP_URL,
	LSSPPT_NGHTTP2_QUIRK_END_STREAM,
	LSSPPT_H2_QUIRK_OVERFLOWS_TXCR,
	LSSPPT_HTTP_MULTIPART_NAME,
	LSSPPT_HTTP_MULTIPART_FILENAME,
	LSSPPT_HTTP_MULTIPART_CONTENT_TYPE,
	LSSPPT_HTTP_WWW_FORM_URLENCODED,
	LSSPPT_WS_SUBPROTOCOL,
	LSSPPT_WS_BINARY,
	LSSPPT_LOCAL_SINK,
	LSSPPT_MQTT_TOPIC,
	LSSPPT_MQTT_SUBSCRIBE,
	LSSPPT_MQTT_QOS,
	LSSPPT_MQTT_KEEPALIVE,
	LSSPPT_MQTT_CLEAN_START,
	LSSPPT_MQTT_WILL_TOPIC,
	LSSPPT_MQTT_WILL_MESSAGE,
	LSSPPT_MQTT_WILL_QOS,
	LSSPPT_MQTT_WILL_RETAIN,
	LSSPPT_STREAMTYPES
} policy_token_t;

union u {
	backoff_t *b;
	lws_ss_x509_t *x;
	lws_ss_trust_store_t *t;
	lws_ss_policy_t *p;
};

enum {
	LTY_BACKOFF,
	LTY_X509,
	LTY_TRUSTSTORE,
	LTY_POLICY,

	_LTY_COUNT /* always last */
};

struct policy_cb_args {
	struct lejp_ctx jctx;
	struct lws_context *context;
	struct lwsac *ac;

	const char *socks5_proxy;

	struct lws_b64state b64;

	union u heads[_LTY_COUNT];
	union u curr[_LTY_COUNT];

	uint8_t *p;

	int count;
};

#define POL_AC_INITIAL	2048
#define POL_AC_GRAIN	800
#define MAX_CERT_TEMP	2048 /* used to discover actual cert size for realloc */

static uint8_t sizes[] = {
	sizeof(backoff_t),
	sizeof(lws_ss_x509_t),
	sizeof(lws_ss_trust_store_t),
	sizeof(lws_ss_policy_t),
};

static const char *protonames[] = {
	"h1",		/* LWSSSP_H1 */
	"h2",		/* LWSSSP_H2 */
	"ws",		/* LWSSSP_WS */
	"mqtt",		/* LWSSSP_MQTT */
};

lws_ss_metadata_t *
lws_ss_policy_metadata(const lws_ss_policy_t *p, const char *name)
{
	lws_ss_metadata_t *pmd = p->metadata;

	while (pmd) {
		if (pmd->name && !strcmp(name, pmd->name))
			return pmd;
		pmd = pmd->next;
	}

	return NULL;
}

lws_ss_metadata_t *
lws_ss_policy_metadata_index(const lws_ss_policy_t *p, size_t index)
{
	lws_ss_metadata_t *pmd = p->metadata;

	while (pmd) {
		if (pmd->length == index)
			return pmd;
		pmd = pmd->next;
	}

	return NULL;
}

int
lws_ss_set_metadata(struct lws_ss_handle *h, const char *name,
		    void *value, size_t len)
{
	lws_ss_metadata_t *omd = lws_ss_policy_metadata(h->policy, name);

	if (!omd) {
		lwsl_err("%s: unknown metadata %s\n", __func__, name);
		return 1;
	}

	h->metadata[omd->length].name = name;
	h->metadata[omd->length].value = value;
	h->metadata[omd->length].length = len;

	return 0;
}

lws_ss_metadata_t *
lws_ss_get_handle_metadata(struct lws_ss_handle *h, const char *name)
{
	lws_ss_metadata_t *omd = lws_ss_policy_metadata(h->policy, name);

	if (!omd)
		return NULL;

	return &h->metadata[omd->length];
}

static signed char
lws_ss_policy_parser_cb(struct lejp_ctx *ctx, char reason)
{
	struct policy_cb_args *a = (struct policy_cb_args *)ctx->user;
	const lws_ss_plugin_t **pin;
	char **pp, dotstar[32], *q;
	lws_ss_trust_store_t *ts;
	lws_ss_metadata_t *pmd;
	lws_retry_bo_t *b;
	size_t inl, outl;
	lws_ss_x509_t *x;
	uint8_t *extant;
	backoff_t *bot;
	int n = -1;

	lwsl_debug("%s: %d %d %s\n", __func__, reason, ctx->path_match - 1,
		   ctx->path);

	switch (ctx->path_match - 1) {
	case LSSPPT_RETRY:
		n = LTY_BACKOFF;
		break;
	case LSSPPT_CERTS:
		n = LTY_X509;
		break;
	case LSSPPT_TRUST_STORES_NAME:
	case LSSPPT_TRUST_STORES_STACK:
		n = LTY_TRUSTSTORE;
		break;
	case LSSPPT_STREAMTYPES:
		n = LTY_POLICY;
		break;
	}

	if (reason == LEJPCB_ARRAY_START &&
	    (ctx->path_match - 1 == LSSPPT_PLUGINS ||
	     ctx->path_match - 1 == LSSPPT_METADATA))
		a->count = 0;

	if (reason == LEJPCB_ARRAY_END &&
	    ctx->path_match - 1 == LSSPPT_TRUST_STORES_STACK && !a->count) {
		lwsl_err("%s: at least one cert required in trust store\n",
				__func__);
		goto oom;
	}

	if (reason == LEJPCB_OBJECT_END && a->p) {
		/*
		 * Allocate a just-the-right-size buf for the cert DER now
		 * we decoded it into the a->p temp buffer and know the exact
		 * size
		 */
		a->curr[LTY_X509].x->ca_der = lws_malloc(a->count, "ssx509");
		if (!a->curr[LTY_X509].x->ca_der)
			goto oom;
		memcpy((uint8_t *)a->curr[LTY_X509].x->ca_der, a->p, a->count);
		a->curr[LTY_X509].x->ca_der_len = a->count;

		/*
		 * ... and then we can free the temp buffer
		 */
		lws_free_set_NULL(a->p);

		return 0;
	}

	if (reason == LEJPCB_PAIR_NAME && n != -1 && n != LTY_TRUSTSTORE) {
		/*
		 * We do the pointers always as .b, all of the participating
		 * structs begin with .next and .name
		 */
		a->curr[n].b = lwsac_use_zero(&a->ac, sizes[n], POL_AC_GRAIN);
		if (!a->curr[n].b)
			goto oom;

		if (n == LTY_X509) {
			a->p = lws_malloc(MAX_CERT_TEMP, "cert temp");
			if (!a->p)
				goto oom;
			memset(&a->b64, 0, sizeof(a->b64));
		}

		a->count = 0;
		a->curr[n].b->next = a->heads[n].b;
		a->heads[n].b = a->curr[n].b;
		pp = (char **)&a->curr[n].b->name;

		goto string1;
	}

	if (!(reason & LEJP_FLAG_CB_IS_VALUE) || !ctx->path_match)
		return 0;

	switch (ctx->path_match - 1) {

	/* strings */

	case LSSPPT_RELEASE:
		break;

	case LSSPPT_PRODUCT:
		break;

	case LSSPPT_SCHEMA_VERSION:
		break;

	case LSSPPT_VIA_SOCKS5:
		/* the global / default proxy */
		pp = (char **)&a->socks5_proxy;
		goto string2;

	case LSSPPT_BACKOFF:
		b = &a->curr[LTY_BACKOFF].b->r;
		if (b->retry_ms_table_count == 8) {
			lwsl_err("%s: > 8 backoff levels\n", __func__);
			return 1;
		}
		if (!b->retry_ms_table_count) {
			b->retry_ms_table = (uint32_t *)lwsac_use_zero(&a->ac,
					   sizeof(uint32_t) * 8, POL_AC_GRAIN);
			if (!b->retry_ms_table)
				goto oom;
		}

		((uint32_t *)b->retry_ms_table)
				[b->retry_ms_table_count++] = atoi(ctx->buf);
		break;

	case LSSPPT_CONCEAL:
		a->curr[LTY_BACKOFF].b->r.conceal_count = atoi(ctx->buf);
		break;

	case LSSPPT_JITTERPC:
		a->curr[LTY_BACKOFF].b->r.jitter_percent = atoi(ctx->buf);
		break;

	case LSSPPT_VALIDPING_S:
		a->curr[LTY_BACKOFF].b->r.secs_since_valid_ping = atoi(ctx->buf);
		break;

	case LSSPPT_VALIDHUP_S:
		a->curr[LTY_BACKOFF].b->r.secs_since_valid_hangup = atoi(ctx->buf);
		break;

	case LSSPPT_CERTS:
		if (a->count + ctx->npos >= MAX_CERT_TEMP) {
			lwsl_err("%s: cert too big\n", __func__);
			goto oom;
		}
		inl = ctx->npos;
		outl = MAX_CERT_TEMP - a->count;

		lws_b64_decode_stateful(&a->b64, ctx->buf, &inl,
					a->p + a->count, &outl,
					reason == LEJPCB_VAL_STR_END);
		a->count += outl;
		if (inl != ctx->npos) {
			lwsl_err("%s: b64 decode fail\n", __func__);
			goto oom;
		}
		break;

	case LSSPPT_TRUST_STORES_NAME:
		/*
		 * We do the pointers always as .b, all of the participating
		 * structs begin with .next and .name
		 */
		a->curr[LTY_TRUSTSTORE].b = lwsac_use_zero(&a->ac,
					sizes[LTY_TRUSTSTORE], POL_AC_GRAIN);
		if (!a->curr[LTY_TRUSTSTORE].b)
			goto oom;

		a->count = 0;
		a->curr[LTY_TRUSTSTORE].b->next = a->heads[LTY_TRUSTSTORE].b;
		a->heads[LTY_TRUSTSTORE].b = a->curr[LTY_TRUSTSTORE].b;
		pp = (char **)&a->curr[LTY_TRUSTSTORE].b->name;

		goto string2;

	case LSSPPT_TRUST_STORES_STACK:
		if (a->count >= (int)LWS_ARRAY_SIZE(
					a->curr[LTY_TRUSTSTORE].t->ssx509)) {
			lwsl_err("%s: trust store too big\n", __func__);
			goto oom;
		}
		lwsl_debug("%s: trust stores stack %.*s\n", __func__,
			   ctx->npos, ctx->buf);
		x = a->heads[LTY_X509].x;
		while (x) {
			if (!strncmp(x->vhost_name, ctx->buf, ctx->npos)) {
				a->curr[LTY_TRUSTSTORE].t->ssx509[a->count++] = x;
				a->curr[LTY_TRUSTSTORE].t->count++;

				return 0;
			}
			x = x->next;
		}
		lws_strnncpy(dotstar, ctx->buf, ctx->npos, sizeof(dotstar));
		lwsl_err("%s: unknown trust store entry %s\n", __func__,
			 dotstar);
		goto oom;

	case LSSPPT_ENDPOINT:
		pp = (char **)&a->curr[LTY_POLICY].p->endpoint;
		goto string2;

	case LSSPPT_VH_VIA_SOCKS5:
		pp = (char **)&a->curr[LTY_POLICY].p->socks5_proxy;
		goto string2;

	case LSSPPT_PORT:
		a->curr[LTY_POLICY].p->port = atoi(ctx->buf);
		break;

	case LSSPPT_HTTP_METHOD:
		pp = (char **)&a->curr[LTY_POLICY].p->u.http.method;
		goto string2;

	case LSSPPT_HTTP_URL:
		pp = (char **)&a->curr[LTY_POLICY].p->u.http.url;
		goto string2;

	case LSSPPT_RIDESHARE:
		pp = (char **)&a->curr[LTY_POLICY].p->rideshare_streamtype;
		goto string2;

	case LSSPPT_PAYLOAD_FORMAT:
		pp = (char **)&a->curr[LTY_POLICY].p->payload_fmt;
		goto string2;

	case LSSPPT_PLUGINS:
		pin = a->context->pss_plugins;
		if (a->count ==
			  (int)LWS_ARRAY_SIZE(a->curr[LTY_POLICY].p->plugins)) {
			lwsl_err("%s: too many plugins\n", __func__);

			goto oom;
		}
		if (!pin)
			break;
		while (*pin) {
			if (!strncmp((*pin)->name, ctx->buf, ctx->npos)) {
				a->curr[LTY_POLICY].p->plugins[a->count++] = *pin;
				return 0;
			}
			pin++;
		}
		lwsl_err("%s: unknown plugin\n", __func__);
		goto oom;

	case LSSPPT_TLS:
		if (reason == LEJPCB_VAL_TRUE)
			a->curr[LTY_POLICY].p->flags |= LWSSSPOLF_TLS;
		break;

	case LSSPPT_TLS_CLIENT_CERT:
		a->curr[LTY_POLICY].p->client_cert = atoi(ctx->buf) + 1;
		break;

	case LSSPPT_OPPORTUNISTIC:
		if (reason == LEJPCB_VAL_TRUE)
			a->curr[LTY_POLICY].p->flags |= LWSSSPOLF_OPPORTUNISTIC;
		break;
	case LSSPPT_NAILED_UP:
		if (reason == LEJPCB_VAL_TRUE)
			a->curr[LTY_POLICY].p->flags |= LWSSSPOLF_NAILED_UP;
		break;
	case LSSPPT_URGENT_TX:
		if (reason == LEJPCB_VAL_TRUE)
			a->curr[LTY_POLICY].p->flags |= LWSSSPOLF_URGENT_TX;
		break;
	case LSSPPT_URGENT_RX:
		if (reason == LEJPCB_VAL_TRUE)
			a->curr[LTY_POLICY].p->flags |= LWSSSPOLF_URGENT_RX;
		break;
	case LSSPPT_LONG_POLL:
		if (reason == LEJPCB_VAL_TRUE)
			a->curr[LTY_POLICY].p->flags |= LWSSSPOLF_LONG_POLL;
		break;
	case LSSPPT_HTTP_WWW_FORM_URLENCODED:
		if (reason == LEJPCB_VAL_TRUE)
			a->curr[LTY_POLICY].p->flags |=
					LWSSSPOLF_HTTP_X_WWW_FORM_URLENCODED;
		break;

	case LSSPPT_RETRYPTR:
		bot = a->heads[LTY_BACKOFF].b;
		while (bot) {
			if (!strncmp(ctx->buf, bot->name, ctx->npos)) {
				a->curr[LTY_POLICY].p->retry_bo = &bot->r;

				return 0;
			}
			bot = bot->next;
		}
		lwsl_err("%s: unknown backoff scheme\n", __func__);

		return -1;

	case LSSPPT_TRUST:
		ts = a->heads[LTY_TRUSTSTORE].t;
		while (ts) {
			if (!strncmp(ctx->buf, ts->name, ctx->npos)) {
				a->curr[LTY_POLICY].p->trust_store = ts;
				return 0;
			}
			ts = ts->next;
		}
		lws_strnncpy(dotstar, ctx->buf, ctx->npos, sizeof(dotstar));
		lwsl_err("%s: unknown trust store name %s\n", __func__,
			 dotstar);

		return -1;

	case LSSPPT_METADATA:
		break;

	case LSSPPT_METADATA_ITEM:
		pmd = a->curr[LTY_POLICY].p->metadata;
		a->curr[LTY_POLICY].p->metadata = lwsac_use_zero(&a->ac,
			sizeof(lws_ss_metadata_t) + ctx->npos +
			(ctx->path_match_len - ctx->st[ctx->sp - 2].p + 1) + 2,
			POL_AC_GRAIN);
		a->curr[LTY_POLICY].p->metadata->next = pmd;

		q = (char *)a->curr[LTY_POLICY].p->metadata +
				sizeof(lws_ss_metadata_t);
		a->curr[LTY_POLICY].p->metadata->name = q;
		memcpy(q, ctx->path + ctx->st[ctx->sp - 2].p + 1,
		       ctx->path_match_len - ctx->st[ctx->sp - 2].p);

		q += ctx->path_match_len - ctx->st[ctx->sp - 2].p;
		a->curr[LTY_POLICY].p->metadata->value = q;
		memcpy(q, ctx->buf, ctx->npos);

		a->curr[LTY_POLICY].p->metadata->length = /* the index in handle->metadata */
				a->curr[LTY_POLICY].p->metadata_count++;
		break;

	case LSSPPT_HTTP_AUTH_HEADER:
	case LSSPPT_HTTP_DSN_HEADER:
	case LSSPPT_HTTP_FWV_HEADER:
	case LSSPPT_HTTP_TYPE_HEADER:
		pp = (char **)&a->curr[LTY_POLICY].p->u.http.blob_header[
		               (ctx->path_match - 1) - LSSPPT_HTTP_AUTH_HEADER];
		goto string2;

	case LSSPPT_HTTP_AUTH_PREAMBLE:
		pp = (char **)&a->curr[LTY_POLICY].p->u.http.auth_preamble;
		goto string2;

	case LSSPPT_HTTP_NO_CONTENT_LENGTH:
		if (reason == LEJPCB_VAL_TRUE)
			a->curr[LTY_POLICY].p->flags |=
					LWSSSPOLF_HTTP_NO_CONTENT_LENGTH;
		break;

	case LSSPPT_NGHTTP2_QUIRK_END_STREAM:
		if (reason == LEJPCB_VAL_TRUE)
			a->curr[LTY_POLICY].p->flags |=
					LWSSSPOLF_QUIRK_NGHTTP2_END_STREAM;
		break;
	case LSSPPT_H2_QUIRK_OVERFLOWS_TXCR:
		if (reason == LEJPCB_VAL_TRUE)
			a->curr[LTY_POLICY].p->flags |=
					LWSSSPOLF_H2_QUIRK_OVERFLOWS_TXCR;
		break;
	case LSSPPT_HTTP_MULTIPART_NAME:
		a->curr[LTY_POLICY].p->flags |= LWSSSPOLF_HTTP_MULTIPART;
		pp = (char **)&a->curr[LTY_POLICY].p->u.http.multipart_name;
		goto string2;
	case LSSPPT_HTTP_MULTIPART_FILENAME:
		a->curr[LTY_POLICY].p->flags |= LWSSSPOLF_HTTP_MULTIPART;
		pp = (char **)&a->curr[LTY_POLICY].p->u.http.multipart_filename;
		goto string2;
	case LSSPPT_HTTP_MULTIPART_CONTENT_TYPE:
		a->curr[LTY_POLICY].p->flags |= LWSSSPOLF_HTTP_MULTIPART;
		pp = (char **)&a->curr[LTY_POLICY].p->u.http.multipart_content_type;
		goto string2;
	case LSSPPT_WS_SUBPROTOCOL:
		pp = (char **)&a->curr[LTY_POLICY].p->u.http.u.ws.subprotocol;
		goto string2;

	case LSSPPT_WS_BINARY:
		a->curr[LTY_POLICY].p->u.http.u.ws.binary =
						reason == LEJPCB_VAL_TRUE;
		break;
	case LSSPPT_LOCAL_SINK:
		if (reason == LEJPCB_VAL_TRUE)
			a->curr[LTY_POLICY].p->flags |= LWSSSPOLF_LOCAL_SINK;
		break;

	case LSSPPT_MQTT_TOPIC:
		pp = (char **)&a->curr[LTY_POLICY].p->u.mqtt.topic;
		goto string2;

	case LSSPPT_MQTT_SUBSCRIBE:
		pp = (char **)&a->curr[LTY_POLICY].p->u.mqtt.subscribe;
		goto string2;

	case LSSPPT_MQTT_QOS:
		a->curr[LTY_POLICY].p->u.mqtt.qos = atoi(ctx->buf);
		break;

	case LSSPPT_MQTT_KEEPALIVE:
		a->curr[LTY_POLICY].p->u.mqtt.keep_alive = atoi(ctx->buf);
		break;

	case LSSPPT_MQTT_CLEAN_START:
		a->curr[LTY_POLICY].p->u.mqtt.clean_start =
						reason == LEJPCB_VAL_TRUE;
		break;
	case LSSPPT_MQTT_WILL_TOPIC:
		pp = (char **)&a->curr[LTY_POLICY].p->u.mqtt.will_topic;
		goto string2;

	case LSSPPT_MQTT_WILL_MESSAGE:
		pp = (char **)&a->curr[LTY_POLICY].p->u.mqtt.will_message;
		goto string2;

	case LSSPPT_MQTT_WILL_QOS:
		a->curr[LTY_POLICY].p->u.mqtt.will_qos = atoi(ctx->buf);
		break;
	case LSSPPT_MQTT_WILL_RETAIN:
		a->curr[LTY_POLICY].p->u.mqtt.will_retain =
						reason == LEJPCB_VAL_TRUE;
		break;

	case LSSPPT_PROTOCOL:
		a->curr[LTY_POLICY].p->protocol = 0xff;
		for (n = 0; n < (int)LWS_ARRAY_SIZE(protonames); n++)
			if (strlen(protonames[n]) == ctx->npos &&
			    !strncmp(ctx->buf, protonames[n], ctx->npos))
				a->curr[LTY_POLICY].p->protocol = (uint8_t)n;

		if (a->curr[LTY_POLICY].p->protocol != 0xff)
			break;
		lws_strnncpy(dotstar, ctx->buf, ctx->npos, sizeof(dotstar));
		lwsl_err("%s: unknown protocol name %s\n", __func__, dotstar);
		return -1;
	}

	return 0;

string2:
	/*
	 * If we can do const string folding, reuse the existing string rather
	 * than make a new entry
	 */
	extant = lwsac_scan_extant(a->ac, (uint8_t *)ctx->buf, ctx->npos, 1);
	if (extant) {
		*pp = (char *)extant;

		return 0;
	}
	*pp = lwsac_use_backfill(&a->ac, ctx->npos + 1, POL_AC_GRAIN);
	if (!*pp)
		goto oom;
	memcpy(*pp, ctx->buf, ctx->npos);
	(*pp)[ctx->npos] = '\0';

	return 0;

string1:
	n = ctx->st[ctx->sp].p;
	*pp = lwsac_use_backfill(&a->ac, ctx->path_match_len + 1 - n,
				 POL_AC_GRAIN);
	if (!*pp)
		goto oom;
	memcpy(*pp, ctx->path + n, ctx->path_match_len - n);
	(*pp)[ctx->path_match_len - n] = '\0';

	return 0;

oom:
	lwsl_err("%s: OOM\n", __func__);
	lws_free_set_NULL(a->p);
	lwsac_free(&a->ac);

	return -1;
}

int
lws_ss_policy_parse_begin(struct lws_context *context)
{
	struct policy_cb_args *args;
	char *p;

	args = lws_zalloc(sizeof(struct policy_cb_args), __func__);
	if (!args) {
		lwsl_err("%s: OOM\n", __func__);

		return 1;
	}

	context->pol_args = args;
	args->context = context;
	p = lwsac_use(&args->ac, 1, POL_AC_INITIAL);
	if (!p) {
		lwsl_err("%s: OOM\n", __func__);
		lws_free_set_NULL(context->pol_args);

		return -1;
	}
	*p = 0;
	lejp_construct(&args->jctx, lws_ss_policy_parser_cb, args,
		       lejp_tokens_policy, LWS_ARRAY_SIZE(lejp_tokens_policy));

	return 0;
}

int
lws_ss_policy_parse_abandon(struct lws_context *context)
{
	struct policy_cb_args *args = (struct policy_cb_args *)context->pol_args;

	lejp_destruct(&args->jctx);
	lws_free_set_NULL(context->pol_args);

	return 0;
}

int
lws_ss_policy_parse(struct lws_context *context, const uint8_t *buf, size_t len)
{
	struct policy_cb_args *args = (struct policy_cb_args *)context->pol_args;
	int m;

	m = (int)(signed char)lejp_parse(&args->jctx, buf, len);
	if (m == LEJP_CONTINUE || m >= 0)
		return m;

	lwsl_err("%s: parse failed: %d: %s\n", __func__, m,
		 lejp_error_to_string(m));
	lws_ss_policy_parse_abandon(context);

	return m;
}

int
lws_ss_policy_set(struct lws_context *context, const char *name)
{
	struct policy_cb_args *args = (struct policy_cb_args *)context->pol_args;
	lws_ss_trust_store_t *ts;
	struct lws_vhost *v;
	lws_ss_x509_t *x;
	char buf[16];
	int m, ret = 0;

	/*
	 * Parsing seems to have succeeded, and we're going to use the new
	 * policy that's laid out in args->ac
	 */

	lejp_destruct(&args->jctx);

	if (context->ac_policy) {

		/*
		 * So this is a bit fun-filled, we already had a policy in
		 * force, perhaps it was the default policy that's just good for
		 * fetching the real policy, and we're doing that now.
		 *
		 * We can destroy all the policy-related direct allocations
		 * easily because they're cleanly in a single lwsac...
		 */
		lwsac_free(&context->ac_policy);

		/*
		 * ...but when we did the trust stores, we created vhosts for
		 * each.  We need to destroy those now too, and recreate new
		 * ones from the new policy, perhaps with different X.509s.
		 */

		v = context->vhost_list;
		while (v) {
			if (v->from_ss_policy) {
				struct lws_vhost *vh = v->vhost_next;
				lwsl_debug("%s: destroying vh %p\n", __func__, v);
				lws_vhost_destroy(v);
				v = vh;
				continue;
			}
			v = v->vhost_next;
		}

		lws_check_deferred_free(context, 0, 1);
	}

	context->pss_policies = args->heads[LTY_POLICY].p;
	context->ac_policy = args->ac;

	lws_humanize(buf, sizeof(buf), lwsac_total_alloc(args->ac),
			humanize_schema_si_bytes);
	if (lwsac_total_alloc(args->ac))
		m = (int)((lwsac_total_overhead(args->ac) * 100) /
				lwsac_total_alloc(args->ac));
	else
		m = 0;

	lwsl_notice("%s: %s, pad %d%c: %s\n", __func__, buf, m, '%', name);

	/* Create vhosts for each type of trust store */

	ts = args->heads[LTY_TRUSTSTORE].t;
	while (ts) {
		struct lws_context_creation_info i;

		memset(&i, 0, sizeof(i));

		/*
		 * We get called from context creation... instantiates
		 * vhosts with client tls contexts set up for each unique CA.
		 *
		 * Create the vhost with the first (mandatory) entry in the
		 * trust store...
		 */

		v = lws_get_vhost_by_name(context, ts->name);
		if (!v) {
			int n;

			i.options = context->options;
			i.vhost_name = ts->name;
			lwsl_debug("%s: %s\n", __func__, i.vhost_name);
			i.client_ssl_ca_mem = ts->ssx509[0]->ca_der;
			i.client_ssl_ca_mem_len = ts->ssx509[0]->ca_der_len;
			i.port = CONTEXT_PORT_NO_LISTEN;
			lwsl_info("%s: %s trust store initial '%s'\n", __func__,
				  ts->name, ts->ssx509[0]->vhost_name);

			v = lws_create_vhost(context, &i);
			if (!v) {
				lwsl_err("%s: failed to create vhost %s\n",
					 __func__, ts->name);
				ret = 1;
			} else
				v->from_ss_policy = 1;

			for (n = 1; v && n < ts->count; n++) {
				lwsl_info("%s: add '%s' to trust store\n",
					  __func__, ts->ssx509[n]->vhost_name);
				if (lws_tls_client_vhost_extra_cert_mem(v,
						ts->ssx509[n]->ca_der,
						ts->ssx509[n]->ca_der_len)) {
					lwsl_err("%s: add extra cert failed\n",
							__func__);
					ret = 1;
				}
			}
		}

		ts = ts->next;
	}

#if defined(LWS_WITH_SOCKS5)

	/*
	 * ... we need to go through every vhost updating its understanding of
	 * which socks5 proxy to use...
	 */

	v = context->vhost_list;
	while (v) {
		lws_set_socks(v, args->socks5_proxy);
		v = v->vhost_next;
	}
	if (context->vhost_system)
		lws_set_socks(context->vhost_system, args->socks5_proxy);

	if (args->socks5_proxy)
		lwsl_notice("%s: global socks5 proxy: %s\n", __func__,
			    args->socks5_proxy);
#endif

	/* now we processed the x.509 CAs, we can free all of our originals */

	x = args->heads[LTY_X509].x;
	while (x) {
		/*
		 * Free all the DER buffers now they have been parsed into
		 * tls library X.509 objects
		 */
		lws_free((void *)x->ca_der);
		x->ca_der = NULL;
		x = x->next;
	}

	/* and we can discard the parsing args object now, invalidating args */

	lws_free_set_NULL(context->pol_args);

	return ret;
}

const lws_ss_policy_t *
lws_ss_policy_lookup(const struct lws_context *context, const char *streamtype)
{
	const lws_ss_policy_t *p = context->pss_policies;

	if (!streamtype)
		return NULL;

	while (p) {
		if (!strcmp(p->streamtype, streamtype))
			return p;
		p = p->next;
	}

	return NULL;
}
