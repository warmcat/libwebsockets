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

struct lws_whois {
	struct lws_dll2		list;
	struct lws_whois_args	args;
	struct lws		*wsi;

	char			domain[128];
	char			server[128];

	char			*buf;
	size_t			buf_len;
	size_t			buf_alloc;

	int			state; /* 0 = IANA / initial, 1 = authoritative */
};

static void
lws_whois_destroy(struct lws_whois *w)
{
	if (!w)
		return;

	lws_dll2_remove(&w->list);
	if (w->buf)
		lws_free(w->buf);
	lws_free(w);
}

static int
lws_whois_trigger(struct lws_whois *w, const char *server)
{
	struct lws_client_connect_info i;
	struct lws *wsi = NULL;

	memset(&i, 0, sizeof(i));
	i.context = w->args.context;
	i.vhost = w->args.context->vhost_system;
	i.address = server;
	i.port = 43;
	i.path = "";
	i.host = i.address;
	i.origin = i.address;
	i.ssl_connection = 0;
	i.method = "RAW";
	i.protocol = "lws-whois";
	i.opaque_user_data = w;
	i.pwsi = &wsi;
	i.fi_wsi_name = "whois";

	lwsl_cx_notice(w->args.context, "whois connecting to %s for domain: %s (state %d)", server, w->args.domain, w->state);

	w->wsi = lws_client_connect_via_info(&i);
	if (!w->wsi) {
		lwsl_cx_err(w->args.context, "Failed to connect to WHOIS %s", server);
		if (!wsi)
			return 1;
		return 0;
	}

	return 0;
}

static void
lws_whois_parse_final(struct lws_whois *w)
{
	struct lws_whois_results res;
	char *p, *end;

	memset(&res, 0, sizeof(res));

	p = w->buf;
	while (p && *p) {
		end = strchr(p, '\n');
		if (end) {
			*end = '\0';
			if (end > p && *(end - 1) == '\r')
				*(end - 1) = '\0';
		}

		if (strstr(p, "Creation Date:") || strstr(p, "Created On:")) {
			char *v = strchr(p, ':') + 1;
			while (*v == ' ' || *v == '\t') v++;
			res.creation_date = lws_parse_iso8601(v);
			lwsl_notice("%s: parsed creation date\n", __func__);
		} else if (strstr(p, "Registry Expiry Date:") ||
			   strstr(p, "Expiry Date:") ||
			   strstr(p, "Expiration Date:")) {
			char *v = strchr(p, ':') + 1;
			while (*v == ' ' || *v == '\t') v++;
			res.expiry_date = lws_parse_iso8601(v);
			lwsl_notice("%s: parsed expiry date\n", __func__);
		} else if (strstr(p, "Updated Date:") || strstr(p, "Last Updated:")) {
			char *v = strchr(p, ':') + 1;
			while (*v == ' ' || *v == '\t') v++;
			res.updated_date = lws_parse_iso8601(v);
			lwsl_notice("%s: parsed updated date\n", __func__);
		} else if (strstr(p, "Name Server:") || strstr(p, "nserver:")) {
			char *v = strchr(p, ':') + 1;
			while (*v == ' ' || *v == '\t') v++;
			char *item_end = v;
			while (*item_end && *item_end != ' ' && *item_end != '\t' &&
			       *item_end != '\r' && *item_end != '\n')
				item_end++;
			
			if (res.nameservers[0])
				strncat(res.nameservers, ", ",
					sizeof(res.nameservers) - strlen(res.nameservers) - 1);
			size_t max_len = sizeof(res.nameservers) - strlen(res.nameservers) - 1;
			size_t cur_len = lws_ptr_diff_size_t(item_end, v);
			strncat(res.nameservers, v, cur_len < max_len ? cur_len : max_len);
		} else if (strstr(p, "DNSSEC:")) {
			char *v = strchr(p, ':') + 1;
			while (*v == ' ' || *v == '\t') v++;
			char *te = v + strlen(v) - 1;
			while (te > v && (*te == ' ' || *te == '\t' || *te == '\r' || *te == '\n'))
				*te-- = '\0';
			lws_strncpy(res.dnssec, v, sizeof(res.dnssec));
			lwsl_notice("%s: Parsed DNSSEC: '%s'\n", __func__, res.dnssec);
		} else if (strstr(p, "DNSSEC DS Data:")) {
			char *v = strchr(p, ':') + 1;
			while (*v == ' ' || *v == '\t') v++;
			char *te = v + strlen(v) - 1;
			while (te > v && (*te == ' ' || *te == '\t' || *te == '\r' || *te == '\n'))
				*te-- = '\0';
			lws_strncpy(res.ds_data, v, sizeof(res.ds_data));
			lwsl_notice("%s: parsed DS data\n", __func__);
		}

		if (end) {
			*end = '\n';
			p = end + 1;
		} else {
			p = NULL;
		}
	}

	lwsl_notice("[INSTRUMENT] %s: Parsed final for %s (len: %lu, dnssec: '%s', res.expiry: %llu)\n", __func__, w->args.domain, (unsigned long)w->buf_len, res.dnssec, (unsigned long long)res.expiry_date);

	if (w->args.cb)
		w->args.cb(w->args.opaque, &res);
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
		lwsl_wsi_notice(wsi, "whois connection error for %s on %s", w->args.domain, w->server[0] ? w->server : "iana");
		w->state = 2;
		break;

	case LWS_CALLBACK_RAW_CLOSE:
		if (!w)
			break;
		w->wsi = NULL;
		
		if (w->state == 2) {
			lwsl_notice("[INSTRUMENT] %s: RAW_CLOSE in state 2, calling callback with NULL for %s\n", __func__, w->args.domain);
			if (w->args.cb)
				w->args.cb(w->args.opaque, NULL);
			lws_set_opaque_user_data(wsi, NULL);
			lws_whois_destroy(w);
			break;
		}

		if (w->state == 0) {
			/* IANA step done, look for referral */
			char *p = strstr(w->buf, "refer:");
			if (!p) p = strstr(w->buf, "whois:");
			if (p) {
				p = strchr(p, ':') + 1;
				while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
				char s[128];
				char *end = p;
				while (*end && *end != '\r' && *end != '\n') end++;
				size_t cur_len = lws_ptr_diff_size_t(end, p);
				if (cur_len >= sizeof(s)) cur_len = sizeof(s) - 1;
				lws_strncpy(s, p, cur_len + 1);
				
				w->state = 1;
				lwsl_notice("%s: IANA referred %s to %s\n", __func__, w->args.domain, s);
				lws_free(w->buf);
				w->buf = NULL;
				w->buf_len = 0;
				w->buf_alloc = 0;
				if (lws_whois_trigger(w, s)) {
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
			/* Final result */
			lws_whois_parse_final(w);
			lws_whois_destroy(w);
		}
		break;

	case LWS_CALLBACK_RAW_RX:
		if (!w)
			break;
		if (w->buf_len + len + 1 > w->buf_alloc) {
			char *nb;
			w->buf_alloc += len + 2048;
			nb = lws_realloc(w->buf, w->buf_alloc, "whois_rx");
			if (!nb)
				return -1;
			w->buf = nb;
		}
		memcpy(w->buf + w->buf_len, in, len);
		w->buf_len += len;
		w->buf[w->buf_len] = '\0';
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		{
			char d[256];
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
	} else {
		if (lws_whois_trigger(w, "whois.iana.org")) {
			lws_free(w);
			return 1;
		}
	}

	return 0;
}

const struct lws_protocols lws_system_protocol_whois =
	{ "lws-whois", callback_whois, 0, 0, 0, NULL, 0 };
