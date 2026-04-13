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
 */

#include "private-lib-core.h"

#define LWS_WHS_DOMAIN_MAX 256

struct lws_whois {
	struct lws_dll2		        list;
	struct lws_whois_args	        args;
	struct lws		        *wsi;

	char			        domain[LWS_WHS_DOMAIN_MAX];
	char			        server[LWS_WHS_DOMAIN_MAX];

	struct lws_tokenize	        ts;
	struct lws_whois_results        res;

	char			        vk[128];
	char			        vv[LWS_WHS_DOMAIN_MAX + 1];
	size_t			        vk_len;
	size_t			        vv_len;

	int			        state; /* 0 = IANA / initial, 1 = authoritative, 2 = error */
	int			        last_effline;
	uint8_t			        is_value;
};

static void
lws_whois_destroy(struct lws_whois *w)
{
	if (!w)
		return;

	lws_dll2_remove(&w->list);
	lws_free(w);
}

static int
lws_whois_trigger(struct lws_whois *w, const char *server)
{
	struct lws_client_connect_info i;
	struct lws *wsi = NULL;

	memset(&i, 0, sizeof(i));
	i.context               = w->args.context;
	i.vhost                 = w->args.context->vhost_system;
	i.address               = server;
	i.port                  = 43;
	i.path                  = "";
	i.host                  = i.address;
	i.origin                = i.address;
	i.ssl_connection        = 0;
	i.method                = "RAW";
	i.protocol              = "lws-whois";
	i.opaque_user_data      = w;
	i.pwsi                  = &wsi;
	i.fi_wsi_name           = "whois";

	lwsl_cx_notice(w->args.context, "whois connecting to %s for domain: %s (state %d)", server, w->args.domain, w->state);

	/* Initialize tokenizer for this connection */
	memset(&w->ts, 0, sizeof(w->ts));
	w->ts.flags             = LWS_TOKENIZE_F_EXPECT_MORE |
				  LWS_TOKENIZE_F_MINUS_NONTERM |
				  LWS_TOKENIZE_F_DOT_NONTERM |
				  LWS_TOKENIZE_F_SLASH_NONTERM |
				  LWS_TOKENIZE_F_COLON_NONTERM |
				  LWS_TOKENIZE_F_NO_FLOATS |
				  LWS_TOKENIZE_F_NO_INTEGERS;
	w->vk_len               = 0;
	w->vv_len               = 0;
	w->is_value             = 0;
	w->last_effline         = 0;

	w->wsi = lws_client_connect_via_info(&i);
	if (!w->wsi) {
		lwsl_cx_err(w->args.context, "Failed to connect to WHOIS %s", server);
		if (!wsi)
			return 1;
		return 0;
	}

	return 0;
}

enum whois_match {
	WHS_M_REFER,
	WHS_M_WHOIS,
	WHS_M_CREATION_DATE,
	WHS_M_CREATED_ON,
	WHS_M_REGISTRY_EXPIRY,
	WHS_M_EXPIRY_DATE,
	WHS_M_EXPIRATION_DATE,
	WHS_M_UPDATED_DATE,
	WHS_M_LAST_UPDATED,
	WHS_M_NAME_SERVER,
	WHS_M_NSERVER,
	WHS_M_DNSSEC,
	WHS_M_DNSSEC_DS_DATA,
};

static const char * const whois_key_strings[] = {
	/* WHS_M_REFER */		"refer:",
	/* WHS_M_WHOIS */		"whois:",
	/* WHS_M_CREATION_DATE */	"Creation Date:",
	/* WHS_M_CREATED_ON */		"Created On:",
	/* WHS_M_REGISTRY_EXPIRY */	"Registry Expiry Date:",
	/* WHS_M_EXPIRY_DATE */		"Expiry Date:",
	/* WHS_M_EXPIRATION_DATE */	"Expiration Date:",
	/* WHS_M_UPDATED_DATE */	"Updated Date:",
	/* WHS_M_LAST_UPDATED */	"Last Updated:",
	/* WHS_M_NAME_SERVER */		"Name Server:",
	/* WHS_M_NSERVER */		"nserver:",
	/* WHS_M_DNSSEC */		"DNSSEC:",
	/* WHS_M_DNSSEC_DS_DATA */	"DNSSEC DS Data:",
};

static void
lws_whois_eval_line(struct lws_whois *w)
{
	unsigned int n;

	if (!w->vk_len)
		return;

	for (n = 0; n < LWS_ARRAY_SIZE(whois_key_strings); n++)
		if (!strcmp(w->vk, whois_key_strings[n]))
			break;

	if (n == LWS_ARRAY_SIZE(whois_key_strings))
		return;

	if (w->state == 0) {
		if ((n == WHS_M_REFER || n == WHS_M_WHOIS) && w->vv_len) {
			lws_strncpy(w->server, w->vv, sizeof(w->server));
	        	w->args.server = w->server;
			lwsl_info("%s: IANA referral to %s\n", __func__, w->server);
		}
		return;
	}

	switch (n) {
	case WHS_M_CREATION_DATE:
	case WHS_M_CREATED_ON:
		w->res.creation_date = lws_parse_iso8601(w->vv);
		break;
	case WHS_M_REGISTRY_EXPIRY:
	case WHS_M_EXPIRY_DATE:
	case WHS_M_EXPIRATION_DATE:
		w->res.expiry_date = lws_parse_iso8601(w->vv);
		break;
	case WHS_M_UPDATED_DATE:
	case WHS_M_LAST_UPDATED:
		w->res.updated_date = lws_parse_iso8601(w->vv);
		break;
	case WHS_M_NAME_SERVER:
	case WHS_M_NSERVER:
	{
		size_t max_len, cur_len;

		if (w->res.nameservers[0])
			strncat(w->res.nameservers, ", ",
				sizeof(w->res.nameservers) - strlen(w->res.nameservers) - 1);
		max_len = sizeof(w->res.nameservers) - strlen(w->res.nameservers) - 1;
		cur_len = w->vv_len;
		strncat(w->res.nameservers, w->vv, cur_len < max_len ? cur_len : max_len);
		break;
	}
	case WHS_M_DNSSEC:
		lws_strncpy(w->res.dnssec, w->vv, sizeof(w->res.dnssec));
		break;
	case WHS_M_DNSSEC_DS_DATA:
		lws_strncpy(w->res.ds_data, w->vv, sizeof(w->res.ds_data));
		break;
	}
}

static int
callback_whois(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	      void *in, size_t len)
{
	struct lws_whois *w = (struct lws_whois *)lws_get_opaque_user_data(wsi);

	switch (reason) {

	case LWS_CALLBACK_RAW_ADOPT:
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		w->state = 2;
		break;

	case LWS_CALLBACK_RAW_CLOSE:
		if (!w)
			break;
		w->wsi = NULL;

		if (w->state == 2) {
			if (w->args.cb)
				w->args.cb(w->args.opaque, NULL);
			lws_set_opaque_user_data(wsi, NULL);
			lws_whois_destroy(w);
			break;
		}

		/* finish loose ends tokenizing */
		w->ts.flags &= (uint16_t)~LWS_TOKENIZE_F_EXPECT_MORE;
		w->ts.start = NULL;
		w->ts.len = 0;
		do {
			w->ts.e = (int8_t)lws_tokenize(&w->ts);
		} while (w->ts.e > 0);

		if (w->vk_len || w->vv_len)
			lws_whois_eval_line(w);

		if (w->state == 0) {
			if (w->server[0]) {
				w->state = 1;
				if (lws_whois_trigger(w, w->server)) {
					lwsl_notice("%s: Failed triggering referral\n", __func__);
					if (w->args.cb)
						w->args.cb(w->args.opaque, NULL);
					lws_whois_destroy(w);
				}
			} else {
				lwsl_wsi_notice(wsi, "No referral found for %s", w->args.domain);
				if (w->args.cb)
					w->args.cb(w->args.opaque, NULL);
				lws_whois_destroy(w);
			}
		} else {
			if (w->args.cb)
				w->args.cb(w->args.opaque, &w->res);
			lws_whois_destroy(w);
		}
		break;

	case LWS_CALLBACK_RAW_RX:
		if (!w)
			break;

		w->ts.start = (const char *)in;
		w->ts.len = len;

		do {
			w->ts.e = (int8_t)lws_tokenize(&w->ts);
			if (w->ts.e == LWS_TOKZE_WANT_READ)
				break;

			if (w->ts.effline != w->last_effline) {
				lws_whois_eval_line(w);
				w->vk_len = 0;
				w->vv_len = 0;
				w->vk[0] = '\0';
				w->vv[0] = '\0';
				w->is_value = 0;
				w->last_effline = w->ts.effline;
			}

			if (w->ts.e == LWS_TOKZE_TOKEN) {
				if (!w->is_value) {
					if (w->vk_len + w->ts.token_len + 2 < sizeof(w->vk)) {
						if (w->vk_len)
							w->vk[w->vk_len++] = ' ';
						memcpy(&w->vk[w->vk_len], w->ts.token, w->ts.token_len);
						w->vk_len += w->ts.token_len;
						w->vk[w->vk_len] = '\0';

						if (w->vk[w->vk_len - 1] == ':')
							w->is_value = 1;
					}
				} else {
					if (w->vv_len + w->ts.token_len + 2 < sizeof(w->vv)) {
						if (w->vv_len)
							w->vv[w->vv_len++] = ' ';
						memcpy(&w->vv[w->vv_len], w->ts.token, w->ts.token_len);
						w->vv_len += w->ts.token_len;
						w->vv[w->vv_len] = '\0';
					}
				}
			}
		} while (w->ts.e > 0);
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		{
			char d[LWS_WHS_DOMAIN_MAX + 3];
			int n = lws_snprintf(d, sizeof(d), "%s\r\n", w->domain);
			if (lws_write(wsi, (uint8_t *)d, (size_t)n, LWS_WRITE_RAW) != n)
				return -1;
		}
		break;

	default:
		break;
	}

	return 0;
}

LWS_VISIBLE int
lws_whois_query(const struct lws_whois_args *args)
{
	struct lws_whois *w;

	if (!args || !args->context || !args->domain)
		return 1;

	w = lws_zalloc(sizeof(*w), "whois_query");
	if (!w)
		return 1;

	w->args = *args;
	lws_strncpy(w->domain, args->domain, sizeof(w->domain));
	w->args.domain = w->domain;

	if (args->server) {
		lws_strncpy(w->server, args->server, sizeof(w->server));
		w->args.server = w->server;
		w->state = 1; /* Skip IANA if server provided */
		if (lws_whois_trigger(w, w->server)) {
			lws_free(w);
			return 1;
		}
	} else
		if (lws_whois_trigger(w, "whois.iana.org")) {
			lws_free(w);
			return 1;
		}

	return 0;
}

const struct lws_protocols lws_system_protocol_whois =
	{ "lws-whois", callback_whois, 0, 0, 0, NULL, 0 };
