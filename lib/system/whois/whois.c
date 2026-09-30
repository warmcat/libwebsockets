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
	struct lws_dll2		        list; /* on cx->whois_owner */
	lws_sorted_usec_list_t	        sul_deadline; /* the whole query */
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
	size_t			        vv_first_len; /* first value token */
	size_t			        rx_total; /* this server's answer so far */

	int			        state; /* 0 = IANA / initial, 1 = authoritative, 2 = error */
	int			        last_effline;
	int			        bad_line; /* 1 + tokenizer line with bad content, or 0 */
	uint8_t			        is_value;
	uint8_t			        in_trigger; /* inside the connect call */
};

static void
lws_whois_destroy(struct lws_whois *w)
{
	if (!w)
		return;

	lws_sul_cancel(&w->sul_deadline);
	lws_dll2_remove(&w->list);
	lws_free(w);
}

/*
 * The one way a query that was started ends: the caller hears about it
 * exactly once, and w is gone afterwards.  w must already be detached from
 * any wsi, so nothing can find it again.
 */

static void
lws_whois_complete(struct lws_whois *w, const struct lws_whois_results *res)
{
	if (w->args.cb)
		w->args.cb(w->args.opaque, res);

	lws_whois_destroy(w);
}

/*
 * Give up on the query while its connection is still up: once detached,
 * whatever the connection does before it's gone can't reach w.  The caller
 * sees the connection closed.
 */

static void
lws_whois_fail(struct lws_whois *w)
{
	if (w->wsi) {
		lws_set_opaque_user_data(w->wsi, NULL);
		w->wsi = NULL;
	}

	lws_whois_complete(w, NULL);
}

/*
 * Whois servers answer once and close, and after sending the query we have
 * nothing more to send, so nothing else notices one that accepts the
 * connection and then says nothing (or trickles bytes), nor a flow that was
 * silently dropped on the way... lws's own connect timeout stops applying
 * as soon as the TCP connection is up.
 */

static void
lws_whois_deadline_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_whois *w = lws_container_of(sul, struct lws_whois,
					       sul_deadline);
	struct lws *wsi = w->wsi;

	lwsl_cx_notice(w->args.context, "whois for %s timed out", w->domain);

	lws_whois_fail(w);
	if (wsi)
		lws_wsi_close(wsi, LWS_TO_KILL_ASYNC);
}

/*
 * The context is going away: every wsi is already closed.  Queries still
 * in flight can only fail, but their callers must still hear it.  A
 * connection that was still being set up is dropped without a callback to
 * us, so w->wsi may be stale here and must not be touched.
 */

void
lws_whois_destroy_all(struct lws_context *cx)
{
	struct lws_whois *w;

	while (lws_dll2_get_head(&cx->whois_owner)) {
		w = lws_container_of(lws_dll2_get_head(&cx->whois_owner),
				     struct lws_whois, list);
		w->wsi = NULL;
		lws_whois_complete(w, NULL);
	}
}

static int
lws_whois_trigger(struct lws_whois *w, const char *server)
{
	struct lws_client_connect_info i;

	memset(&i, 0, sizeof(i));
	i.context               = w->args.context;
	i.vhost                 = w->args.context->vhost_system;
	i.address               = server;
	i.port                  = w->args.port ? w->args.port : 43;
	i.path                  = "";
	i.host                  = i.address;
	i.origin                = i.address;
	i.ssl_connection        = 0;
	i.method                = "RAW";
	i.protocol              = "lws-whois";
	i.opaque_user_data      = w;
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
	w->vv_first_len         = 0;
	w->is_value             = 0;
	w->last_effline         = 0;
	w->bad_line             = 0;
	w->rx_total             = 0;

	/*
	 * The connect can fail synchronously in here, and if it does, it can
	 * already have issued CLIENT_CONNECTION_ERROR on us before it returns.
	 * Flag that, so the callback leaves ownership of w with us instead of
	 * completing and destroying it under our feet.
	 */
	w->in_trigger = 1;
	w->wsi = lws_client_connect_via_info(&i);
	w->in_trigger = 0;
	if (!w->wsi) {
		/*
		 * A NULL return always means the wsi is gone... there is no
		 * live wsi left to report the failure later, so it's ours.
		 */
		lwsl_cx_err(w->args.context, "Failed to connect to WHOIS %s", server);
		return 1;
	}

	return 0;
}

enum whois_match {
	WHS_M_REFER,
	WHS_M_WHOIS,
	WHS_M_CREATION_DATE,
	WHS_M_CREATED_ON,
	WHS_M_REGISTRATION_DATE,
	WHS_M_REGISTRY_EXPIRY,
	WHS_M_EXPIRY_DATE,
	WHS_M_EXPIRATION_DATE,
	WHS_M_UPDATED_DATE,
	WHS_M_LAST_UPDATED,
	WHS_M_MODIFICATION_DATE,
	WHS_M_NAME_SERVER,
	WHS_M_NSERVER,
	WHS_M_DNS,
	WHS_M_DNSSEC,
	WHS_M_DNSSEC_SIGNED,
	WHS_M_DNSSEC_DS_DATA,
};

/*
 * Registries don't agree on the capitalization of these, so they are
 * matched case-insensitively.  The RNIDS (.rs) forms are
 * "Registration date:", "Modification date:", "DNS:" and "DNSSEC signed:".
 */

static const char * const whois_key_strings[] = {
	/* WHS_M_REFER */		"refer:",
	/* WHS_M_WHOIS */		"whois:",
	/* WHS_M_CREATION_DATE */	"Creation Date:",
	/* WHS_M_CREATED_ON */		"Created On:",
	/* WHS_M_REGISTRATION_DATE */	"Registration Date:",
	/* WHS_M_REGISTRY_EXPIRY */	"Registry Expiry Date:",
	/* WHS_M_EXPIRY_DATE */		"Expiry Date:",
	/* WHS_M_EXPIRATION_DATE */	"Expiration Date:",
	/* WHS_M_UPDATED_DATE */	"Updated Date:",
	/* WHS_M_LAST_UPDATED */	"Last Updated:",
	/* WHS_M_MODIFICATION_DATE */	"Modification Date:",
	/* WHS_M_NAME_SERVER */		"Name Server:",
	/* WHS_M_NSERVER */		"nserver:",
	/* WHS_M_DNS */			"DNS:",
	/* WHS_M_DNSSEC */		"DNSSEC:",
	/* WHS_M_DNSSEC_SIGNED */	"DNSSEC signed:",
	/* WHS_M_DNSSEC_DS_DATA */	"DNSSEC DS Data:",
};

/*
 * Most registries give ISO 8601 dates, but some (eg, RNIDS for .rs) give
 * "DD.MM.YYYY HH:MM:SS".  That form is reordered into ISO 8601 so it gets
 * the same strict validation.  The registry's timezone is only stated in
 * free text, if at all, so like ISO 8601 without a zone it is taken as UTC.
 *
 * Returns the unixtime, or 0 if the date is not in a form we understand.
 */

static lws_usec_t
lws_whois_parse_date(const char *s)
{
	char iso[32];
	size_t n, len;

	if (!s)
		return 0;

	len = strlen(s);
	if (len >= 10 && s[4] == '-')
		return lws_parse_iso8601(s);

	/* "DD.MM.YYYY" and an optional time part */

	if (len < 10 || len - 10 >= sizeof(iso) - 10 ||
	    s[2] != '.' || s[5] != '.')
		return 0;

	for (n = 0; n < 10; n++)
		if (n != 2 && n != 5 && (s[n] < '0' || s[n] > '9'))
			return 0;

	memcpy(iso, s + 6, 4);
	iso[4] = '-';
	memcpy(iso + 5, s + 3, 2);
	iso[7] = '-';
	memcpy(iso + 8, s, 2);
	/* the time part, if any, is validated by lws_parse_iso8601() */
	memcpy(iso + 10, s + 10, len - 10);
	iso[len] = '\0';

	return lws_parse_iso8601(iso);
}

static void
lws_whois_eval_line(struct lws_whois *w)
{
	unsigned int n;

	if (!w->vk_len)
		return;

	for (n = 0; n < LWS_ARRAY_SIZE(whois_key_strings); n++)
		if (!strcasecmp(w->vk, whois_key_strings[n]))
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
	case WHS_M_REGISTRATION_DATE:
		w->res.creation_date = lws_whois_parse_date(w->vv);
		break;
	case WHS_M_REGISTRY_EXPIRY:
	case WHS_M_EXPIRY_DATE:
	case WHS_M_EXPIRATION_DATE:
		w->res.expiry_date = lws_whois_parse_date(w->vv);
		break;
	case WHS_M_UPDATED_DATE:
	case WHS_M_LAST_UPDATED:
	case WHS_M_MODIFICATION_DATE:
		w->res.updated_date = lws_whois_parse_date(w->vv);
		break;
	case WHS_M_NAME_SERVER:
	case WHS_M_NSERVER:
	case WHS_M_DNS:
	{
		/*
		 * Append with explicit bounds rather than strncat(): gcc 14
		 * cannot prove strncat's source and destination do not
		 * overlap inside the same containing object, and this keeps
		 * the whole append behind a single bounds computation
		 */

		size_t ol = strlen(w->res.nameservers);
		size_t room = sizeof(w->res.nameservers) - 1 - ol;

		/*
		 * Only the name is wanted: some registries follow it on the
		 * same line with glue addresses, or with a "-" placeholder
		 * where there are none (RNIDS)
		 */
		if (!w->vv_first_len)
			break;

		/* room for the ", " plus at least one nameserver character */
		if (ol && room > 2) {
			w->res.nameservers[ol++] = ',';
			w->res.nameservers[ol++] = ' ';
			room -= 2;
		}

		if (w->vv_first_len < room)
			room = w->vv_first_len;

		memcpy(w->res.nameservers + ol, w->vv, room);
		w->res.nameservers[ol + room] = '\0';
		break;
	}
	case WHS_M_DNSSEC:
	case WHS_M_DNSSEC_SIGNED:
		lws_strncpy(w->res.dnssec, w->vv, sizeof(w->res.dnssec));
		break;
	case WHS_M_DNSSEC_DS_DATA:
		lws_strncpy(w->res.ds_data, w->vv, sizeof(w->res.ds_data));
		break;
	}
}

/*
 * Assemble "key: value" lines from whatever is in w->ts, evaluating each
 * completed line.  The server's text is untrusted and not necessarily even
 * UTF-8: a line with content the tokenizer rejects is dropped, but the
 * lines around it are still used.
 */

static void
lws_whois_tokenize(struct lws_whois *w)
{
	size_t left;

	do {
		left = w->ts.len;
		w->ts.e = (int8_t)lws_tokenize(&w->ts);
		if (w->ts.e == LWS_TOKZE_WANT_READ)
			break;

		if (w->ts.effline != w->last_effline) {
			if (w->bad_line != w->last_effline + 1)
				lws_whois_eval_line(w);
			w->vk_len = 0;
			w->vv_len = 0;
			w->vv_first_len = 0;
			w->vk[0] = '\0';
			w->vv[0] = '\0';
			w->is_value = 0;
			w->last_effline = w->ts.effline;
		}

		if (w->ts.e < 0) {
			/*
			 * The tokenizer has consumed the bad content, we can
			 * carry on after it.  The token it was in may have
			 * begun on an earlier line, but the bad byte is on
			 * the current one
			 */
			w->bad_line = w->ts.line + 1;
			if (w->ts.len == left)
				/*
				 * ...unless it consumed nothing, eg, an
				 * unterminated quote at the end
				 */
				break;
			continue;
		}

		if (w->ts.e != LWS_TOKZE_TOKEN)
			continue;

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
			continue;
		}

		if (w->vv_len + w->ts.token_len + 2 < sizeof(w->vv)) {
			if (w->vv_len)
				w->vv[w->vv_len++] = ' ';
			memcpy(&w->vv[w->vv_len], w->ts.token, w->ts.token_len);
			w->vv_len += w->ts.token_len;
			w->vv[w->vv_len] = '\0';
			if (!w->vv_first_len)
				w->vv_first_len = w->vv_len;
		}
	} while (w->ts.e != LWS_TOKZE_ENDED);
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
		if (!w)
			break;

		/*
		 * lws makes CLIENT_CONNECTION_ERROR mutually exclusive with the
		 * role close callback (see __lws_close_free_wsi()), so no
		 * RAW_CLOSE is coming for a connection that failed to
		 * establish... we have to complete and destroy w here, or the
		 * caller waits forever for a callback and w is leaked.
		 */

		w->state = 2;
		w->wsi = NULL;
		lws_set_opaque_user_data(wsi, NULL);

		if (w->in_trigger)
			/*
			 * We're being called from inside the connect itself,
			 * which is going to return failure to whoever called
			 * lws_whois_trigger()... he owns completing and
			 * destroying w then, we must not do it twice.
			 */
			break;

		lws_whois_complete(w, NULL);
		break;

	case LWS_CALLBACK_RAW_CLOSE:
		if (!w)
			break;
		w->wsi = NULL;
		/*
		 * This is the last callback for this wsi, and below we may
		 * destroy w, or hand it on to a referral connection
		 */
		lws_set_opaque_user_data(wsi, NULL);

		if (lws_context_is_being_destroyed(w->args.context)) {
			/*
			 * Our close, not the server's: the answer may be cut
			 * off, and a referral can't be followed any more
			 */
			lws_whois_complete(w, NULL);
			break;
		}

		/* finish loose ends tokenizing */
		w->ts.flags &= (uint16_t)~LWS_TOKENIZE_F_EXPECT_MORE;
		w->ts.start = NULL;
		w->ts.len = 0;
		lws_whois_tokenize(w);

		/* the last line, which had no following line to flush it */
		if ((w->vk_len || w->vv_len) &&
		    w->bad_line != w->last_effline + 1)
			lws_whois_eval_line(w);

		if (w->state == 0) {
			if (w->server[0]) {
				w->state = 1;
				if (lws_whois_trigger(w, w->server)) {
					lwsl_notice("%s: Failed triggering referral\n", __func__);
					lws_whois_complete(w, NULL);
				}
			} else {
				lwsl_wsi_notice(wsi, "No referral found for %s", w->args.domain);
				lws_whois_complete(w, NULL);
			}
		} else
			lws_whois_complete(w, &w->res);
		break;

	case LWS_CALLBACK_RAW_RX:
		if (!w)
			break;

		/*
		 * Real answers are a few KB... one that goes on and on, even
		 * one line at a time, isn't one
		 */
		w->rx_total += len;
		if (w->rx_total > LWS_WHOIS_ANSWER_MAX) {
			lwsl_wsi_notice(wsi, "whois answer for %s too large",
					w->domain);
			lws_whois_fail(w);
			return -1;
		}

		w->ts.start = (const char *)in;
		w->ts.len = len;
		lws_whois_tokenize(w);
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		{
			char d[LWS_WHS_DOMAIN_MAX + 3];
			int n;

			if (!w)
				break;

			n = lws_snprintf(d, sizeof(d), "%s\r\n", w->domain);
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

	if (!args || !args->context || !args->domain ||
	    lws_context_is_being_destroyed(args->context))
		return 1;

	w = lws_zalloc(sizeof(*w), "whois_query");
	if (!w)
		return 1;

	w->args = *args;
	lws_strncpy(w->domain, args->domain, sizeof(w->domain));
	w->args.domain = w->domain;

	/* so it can't outlive the context */
	lws_dll2_add_tail(&w->list, &args->context->whois_owner);

	/* one deadline for the whole query, including any referral */
	lws_sul_schedule(args->context, 0, &w->sul_deadline,
			 lws_whois_deadline_cb, (lws_usec_t)(args->timeout_ms ?
				args->timeout_ms : LWS_WHOIS_TIMEOUT_DEFAULT_MS) *
				LWS_US_PER_MS);

	if (args->server) {
		lws_strncpy(w->server, args->server, sizeof(w->server));
		w->args.server = w->server;
		w->state = 1; /* Skip IANA if server provided */
	}

	if (lws_whois_trigger(w, args->server ? w->server : "whois.iana.org")) {
		/* no callback when we return failure */
		lws_whois_destroy(w);
		return 1;
	}

	return 0;
}

const struct lws_protocols lws_system_protocol_whois =
	{ "lws-whois", callback_whois, 0, 0, 0, NULL, 0 };
