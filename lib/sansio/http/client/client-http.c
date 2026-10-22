/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2025 Andy Green <andy@warmcat.com>
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

void
lws_client_http_body_pending(struct lws *wsi, int something_left_to_send)
{
	wsi->client_http_body_pending = !!something_left_to_send;

#if defined(LWS_ROLE_H1)
	/*
	 * An h1 client reads nothing while it sends its body (its rx policy),
	 * so the end of the body, which only a service pass acts on, cannot
	 * wait for the response to arrive to be noticed: a pass comes now
	 */
	if (!something_left_to_send && !wsi->mux_substream &&
	    lwsi_role_client(wsi) && lwsi_role_h1(wsi) &&
	    lwsi_state(wsi) == LRS_ISSUE_HTTP_BODY)
		lws_callback_on_writable(wsi);
#endif
}

#if defined(LWS_WITH_HTTP_PROXY)
/*
 * The onward leg of an http proxy has request body it can send now: some of
 * the parent's body is stashed for it, or the parent's body is complete and
 * the chunked onward body still owes its last-chunk
 */
static int
lws_http_proxy_onward_body_ready(struct lws *wsi)
{
	return wsi->http.proxy_clientside && wsi->parent &&
	       (wsi->parent->http.buflist_post_body ||
		(wsi->parent->http.proxy_body_chunked &&
		 wsi->parent->http.proxy_body_complete &&
		 !wsi->parent->http.proxy_body_ended));
}
#endif

/*
 * A "+path" address is a unix socket, and only the app may choose one.  A
 * connection retargeted by what a server said (a redirect, a digest auth
 * retry) must never move into the unix socket namespace, out of it, or to
 * another socket in it: an http origin could otherwise send our request,
 * method, body and all, to any local socket we can reach, eg, a container
 * runtime's api, or any linux abstract socket.
 *
 * The leading '+' is what the connect path acts on, so that is what is
 * judged here, rather than how the Location happened to be spelled.
 */
static int
lws_client_retarget_allowed(struct lws *wsi, const char *address)
{
	const char *cur = lws_wsi_client_stash_item(wsi, CIS_ADDRESS,
					_WSI_TOKEN_CLIENT_PEER_ADDRESS);
	int cur_uds = cur && cur[0] == '+';

	if (address[0] != '+')
		return !cur_uds;

	return cur_uds && !strcmp(cur, address);
}

#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2) || defined(LWS_ROLE_H3)
/*
 * RFC 3986 2: what a URI reference may be made of.  Anything else in a
 * Location (a space, a control, a quote, a non-ascii byte, a '%' that does
 * not start an escape) means it is not a URI, and we would only be guessing
 * at what the server meant by it.
 */
static int
lws_uri_ref_valid(const char *p)
{
	for (; *p; p++) {
		unsigned char c = (unsigned char)*p;

		if (c == '%') {
			if (!isxdigit((int)(unsigned char)p[1]) ||
			    !isxdigit((int)(unsigned char)p[2]))
				return 0;
			p += 2;
			continue;
		}

		/* not isalnum() alone: a locale may say yes to non-ascii */
		if (c >= 0x80 || (!isalnum((int)c) &&
				  !strchr("-._~:/?#[]@!$&'()*+,;=", (int)c)))
			return 0;
	}

	return 1;
}

/*
 * RFC 3986 5.2.4: path [p, end), which starts with '/', goes to o without its
 * "." and ".." segments.  o may be p: the output never overtakes the input.
 */
static char *
lws_uri_remove_dot_segments(char *o, const char *p, const char *end)
{
	char *start = o;

	while (p < end) {
		const char *s = p + 1, *e = s;
		size_t l;

		while (e < end && *e != '/')
			e++;
		l = lws_ptr_diff_size_t(e, s);

		if (l == 1 && s[0] == '.') {
			if (e == end)
				*o++ = '/';
		} else if (l == 2 && s[0] == '.' && s[1] == '.') {
			/* back to the '/' that began the last segment out */
			while (o > start && *--o != '/')
				;
			if (e == end)
				*o++ = '/';
		} else {
			*o++ = '/';
			memmove(o, s, l);
			o += l;
		}
		p = e;
	}

	if (o == start)
		*o++ = '/';
	*o = '\0';

	return o;
}

/*
 * The host of a Host: header value or an address: an IPv6 literal without its
 * brackets, no port, and no trailing dot, which names the same host
 */
static void
lws_client_hostname(const char *h, const char **s, size_t *len)
{
	const char *e;

	if (*h == '[') {
		h++;
		e = strchr(h, ']');
	} else {
		e = strchr(h, ':');
		/* more than one ':' is a bare IPv6 literal, with no port */
		if (e && strchr(e + 1, ':'))
			e = NULL;
	}
	if (!e)
		e = h + strlen(h);
	if (e > h && e[-1] == '.')
		e--;

	*s = h;
	*len = lws_ptr_diff_size_t(e, h);
}

#if defined(LWS_WITH_TLS)
static int
lws_client_host_is_address(const char *h, size_t len)
{
	size_t n;

	if (memchr(h, ':', len) || memchr(h, '%', len))
		return 1; /* IPv6, or a zone */

	for (n = 0; n < len; n++)
		if (!isdigit((int)(unsigned char)h[n]) && h[n] != '.')
			return 0;

	return 1;
}

/*
 * Go net/http's rule for the hosts a redirected request may take the
 * initial request's credentials to: the same host, or a subdomain of it.
 * An address has no subdomains, and is nobody's subdomain.
 */
static int
lws_client_host_domain_match(const char *sub, size_t sl, const char *parent,
			     size_t pl)
{
	if (!sl || !pl)
		return 0;

	if (sl == pl && !strncasecmp(sub, parent, sl))
		return 1;

	if (lws_client_host_is_address(sub, sl) ||
	    lws_client_host_is_address(parent, pl))
		return 0;

	return sl > pl + 1 && sub[sl - pl - 1] == '.' &&
	       !strncasecmp(sub + sl - pl, parent, pl);
}
#endif

/*
 * The host the request had before its first redirect: credentials set for the
 * request are set for it, wherever the redirects then take the request
 */
static int
lws_client_redir_origin_capture(struct lws *wsi)
{
	const char *h, *s;
	size_t len;

	if (wsi->cli_redir_origin)
		return 0;

	h = lws_wsi_client_stash_item(wsi, CIS_HOST, _WSI_TOKEN_CLIENT_HOST);
	if (!h)
		h = lws_wsi_client_stash_item(wsi, CIS_ADDRESS,
					      _WSI_TOKEN_CLIENT_PEER_ADDRESS);
	if (!h)
		return 1;

	lws_client_hostname(h, &s, &len);
	wsi->cli_redir_origin = lws_malloc(len + 1, __func__);
	if (!wsi->cli_redir_origin)
		return 1;
	memcpy(wsi->cli_redir_origin, s, len);
	wsi->cli_redir_origin[len] = '\0';

	return 0;
}

/*
 * May what the request carries as credentials go where redirect r takes it?
 * Only over https with strict verification, and only to the host the request
 * started with or a subdomain of it, or to a host in, or a subdomain of a
 * host in, also: a comma-separated list of hosts, or NULL.
 */
int
lws_client_redirect_creds_ok(struct lws *wsi, const lws_client_redir_t *r,
			     const char *also)
{
#if defined(LWS_WITH_TLS)
	const char *th, *oh, *a;
	size_t tl, ol;

	if (!r->ssl || (wsi->flags & (LCCSCF_ALLOW_SELFSIGNED |
				      LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK |
				      LCCSCF_ALLOW_EXPIRED |
				      LCCSCF_ALLOW_INSECURE)))
		return 0;

	lws_client_hostname(r->host, &th, &tl);

	oh = wsi->cli_redir_origin;
	if (!oh)
		oh = lws_wsi_client_stash_item(wsi, CIS_HOST,
					       _WSI_TOKEN_CLIENT_HOST);
	if (oh) {
		lws_client_hostname(oh, &oh, &ol);
		if (lws_client_host_domain_match(th, tl, oh, ol))
			return 1;
	}

	while (also && *also) {
		a = strchr(also, ',');
		if (!a)
			a = also + strlen(also);
		if (lws_client_host_domain_match(th, tl, also,
						 lws_ptr_diff_size_t(a, also)))
			return 1;
		also = *a ? a + 1 : a;
	}
#endif

	return 0;
}

int
lws_client_redirect_info(struct lws *wsi, lws_client_redirect_info_t *info)
{
	const lws_client_redir_t *r;
	lws_client_redir_t cur;

	if (!wsi || !info)
		return 1;

	r = wsi->cli_redir_pending;
	if (!r) {
		/* not being redirected now: was this request redirected? */
		if (!wsi->cli_redir_origin)
			return 1;

		cur.address = lws_wsi_client_stash_item(wsi, CIS_ADDRESS,
					_WSI_TOKEN_CLIENT_PEER_ADDRESS);
		cur.host = lws_wsi_client_stash_item(wsi, CIS_HOST,
					_WSI_TOKEN_CLIENT_HOST);
		cur.path = lws_wsi_client_stash_item(wsi, CIS_PATH,
					_WSI_TOKEN_CLIENT_URI);
		if (!cur.address)
			return 1;
		if (!cur.host)
			cur.host = cur.address;
		if (!cur.path)
			cur.path = "/";
		cur.port = lws_get_network_wsi(wsi)->c_port;
		cur.ssl = !!(wsi->flags & LCCSCF_USE_SSL);
		r = &cur;
	}

	info->address		= r->address;
	info->host		= r->host;
	info->path		= r->path;
	info->port		= r->port;
	info->tls		= (uint8_t)!!r->ssl;
	info->credentials_ok	= (uint8_t)!!lws_client_redirect_creds_ok(wsi,
								r, NULL);

	return 0;
}

/*
 * Where a redirect's Location takes the request it answers, resolved against
 * that request as RFC 3986 5.2 says.  A reference with a scheme, or starting
 * "//", names a new authority.  Otherwise it keeps ours, the Host: header
 * included, and its path is taken as it is if absolute, or merged with ours
 * if relative ("foo" from "/a/b" is "/a/foo"); an empty one keeps our path
 * and changes the query.  Dot segments are removed, and any fragment is
 * dropped, since neither belongs in a request target.
 *
 * Stricter than a browser: a Location that is not a valid URI reference, has
 * a scheme other than http(s) or ws(s), carries userinfo, or names a port
 * outside 1 - 65535 is refused, rather than guessed at.
 *
 * Returns the result in one allocation, freed with lws_free(), or NULL if the
 * Location is refused or on OOM.
 */
lws_client_redir_t *
lws_client_redirect_resolve(struct lws *wsi, const char *loc)
{
	const char *cur_ads, *cur_host, *base, *be, *e, *rp, *pe, *q,
		   *hs = NULL, *he = NULL, *auth_end;
	struct lws *nwsi = lws_get_network_wsi(wsi);
	lws_client_redir_t *r;
	int ssl, port, n, v6 = 0;
	size_t len;
	char *o;

	cur_ads = lws_wsi_client_stash_item(wsi, CIS_ADDRESS,
					    _WSI_TOKEN_CLIENT_PEER_ADDRESS);
	cur_host = lws_wsi_client_stash_item(wsi, CIS_HOST,
					     _WSI_TOKEN_CLIENT_HOST);
	base = lws_wsi_client_stash_item(wsi, CIS_PATH, _WSI_TOKEN_CLIENT_URI);

	if (!cur_ads || !loc[0] || !lws_uri_ref_valid(loc))
		return NULL;
	if (!cur_host)
		cur_host = cur_ads;
	if (!base || base[0] != '/')
		base = "/";
	be = strchr(base, '?');
	if (!be)
		be = base + strlen(base);

#if defined(LWS_WITH_TLS)
	ssl = !!(nwsi->use_ssl & LCCSCF_USE_SSL);
#else
	ssl = 0;
#endif
	port = nwsi->c_port;

	/* the fragment is the client's alone */
	e = strchr(loc, '#');
	if (!e)
		e = loc + strlen(loc);

	/* a scheme is ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ) ":" */

	rp = loc;
	if (isalpha((int)(unsigned char)*loc)) {
		q = loc + 1;
		while (q < e && (isalnum((int)(unsigned char)*q) ||
				 *q == '+' || *q == '-' || *q == '.'))
			q++;

		if (q < e && *q == ':') {
			n = lws_ptr_diff(q, loc);

			if ((n == 4 && !strncasecmp(loc, "http", 4)) ||
			    (n == 2 && !strncasecmp(loc, "ws", 2)))
				ssl = 0;
			else if ((n == 5 && !strncasecmp(loc, "https", 5)) ||
				 (n == 3 && !strncasecmp(loc, "wss", 3)))
				ssl = 1;
			else
				return NULL;

			rp = q + 1;
			/* and these schemes always have an authority */
			if (rp[0] != '/' || rp[1] != '/')
				return NULL;
		}
	}

	if (rp[0] == '/' && rp[1] == '/') {
		/* a new authority: host and port, never userinfo */
		hs = rp + 2;
		auth_end = hs;
		while (auth_end < e && *auth_end != '/' && *auth_end != '?')
			auth_end++;
		if (memchr(hs, '@', lws_ptr_diff_size_t(auth_end, hs)))
			return NULL;

		if (*hs == '[') {
			/* an IPv6 literal, connected to without its brackets */
			hs++;
			for (he = hs; he < auth_end && *he != ']'; he++)
				if (!isxdigit((int)(unsigned char)*he) &&
				    *he != ':' && *he != '.')
					return NULL;
			if (he == auth_end)
				return NULL;
			q = he + 1;
			v6 = 1;
		} else {
			for (he = hs; he < auth_end && *he != ':'; he++)
				if (*he == '[' || *he == ']')
					return NULL;
			q = he;
		}
		if (he == hs)
			return NULL;

		port = ssl ? 443 : 80;
		if (q < auth_end) {
			if (*q++ != ':')
				return NULL;
			/* an empty port is the scheme's default */
			if (q < auth_end) {
				if (auth_end - q > 5)
					return NULL;
				n = 0;
				while (q < auth_end) {
					if (!isdigit((int)(unsigned char)*q))
						return NULL;
					n = (n * 10) + (*q++ - '0');
				}
				if (n < 1 || n > 65535)
					return NULL;
				port = n;
			}
		}
		rp = auth_end;
	}

	pe = rp;
	while (pe < e && *pe != '?')
		pe++;

	/*
	 * Each of the three strings is shorter than these sources together: a
	 * merged path is at most our path and the reference's, and a Host:
	 * made from the authority adds at most "[]:65535"
	 */
	len = strlen(cur_ads) + strlen(cur_host) + strlen(base) +
	      lws_ptr_diff_size_t(e, loc) + 16;
	r = lws_malloc(sizeof(*r) + (3 * len), __func__);
	if (!r)
		return NULL;

	o = (char *)&r[1];
	r->ssl = (char)ssl;
	r->port = port;

	r->address = o;
	if (hs) {
		memcpy(o, hs, lws_ptr_diff_size_t(he, hs));
		o += lws_ptr_diff_size_t(he, hs);
		*o++ = '\0';

		r->host = o;
		o += lws_snprintf(o, len, "%s%.*s%s", v6 ? "[" : "",
				  lws_ptr_diff(he, hs), hs, v6 ? "]" : "");
		if (port != (ssl ? 443 : 80))
			o += lws_snprintf(o, len, ":%d", port);
		o++;
	} else {
		o += lws_snprintf(o, len, "%s", cur_ads) + 1;
		r->host = o;
		o += lws_snprintf(o, len, "%s", cur_host) + 1;
	}

	r->path = o;
	if (rp == pe) {
		/* no path: an authority's root, or our own path */
		if (hs) {
			*o++ = '/';
			*o = '\0';
		} else {
			memcpy(o, base, lws_ptr_diff_size_t(be, base));
			o += lws_ptr_diff_size_t(be, base);
			*o = '\0';
			/* no query either: we keep ours */
			if (pe == e) {
				lws_strncpy(o, be, len);
				o += strlen(o);
			}
		}
	} else if (*rp == '/')
		o = lws_uri_remove_dot_segments(o, rp, pe);
	else {
		/* merged: our path up to its last '/', then the reference's */
		q = be;
		while (q > base && q[-1] != '/')
			q--;
		memcpy(o, base, lws_ptr_diff_size_t(q, base));
		memcpy(o + (q - base), rp, lws_ptr_diff_size_t(pe, rp));
		o = lws_uri_remove_dot_segments(o, o, o + (q - base) +
							(pe - rp));
	}

	/* the reference's query, if it has one, is taken as it is */
	memcpy(o, pe, lws_ptr_diff_size_t(e, pe));
	o[e - pe] = '\0';

	return r;
}

/*
 * RFC 9110 15.4: the method a redirect is followed with, or NULL if the
 * request's own is kept.  A 303 is followed with a GET, unless it was a HEAD;
 * a 301 or 302 turns only a POST into a GET, as every browser does; 307 and
 * 308 keep the method, and so the body.
 */
static const char *
lws_client_redirect_method(int status, const char *meth)
{
	if (status == 303 && strcmp(meth, "HEAD"))
		return "GET";

	if ((status == 301 || status == 302) && !strcmp(meth, "POST"))
		return "GET";

	return NULL;
}

/*
 * RFC 9112 9.6: a response whose Connection header has the "close" option
 * is the last on its connection
 */
static int
lws_client_response_says_close(struct lws *wsi)
{
	const char *conn = lws_hdr_simple_ptr(wsi, WSI_TOKEN_CONNECTION);
	struct lws_tokenize ts;

	if (!conn)
		return 0;

	lws_tokenize_init(&ts, conn, LWS_TOKENIZE_F_COMMA_SEP_LIST |
				     LWS_TOKENIZE_F_MINUS_NONTERM);
	do {
		ts.e = (int8_t)lws_tokenize(&ts);
		if (ts.e == LWS_TOKZE_TOKEN && ts.token_len == 5 &&
		    !strncasecmp(ts.token, "close", 5))
			return 1;
	} while (ts.e > 0);

	return 0;
}
#endif

/*
 * Returns 0 for wsi survived OK, or LWS_HPI_RET_WSI_ALREADY_DIED
 * meaning the wsi was destroyed by us before return.
 */
	
#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2) || defined(LWS_ROLE_H3)
/*
 * sansIO rx for an h1 client until it is established: the socks and http
 * CONNECT legs of its transport, the wait for its response headers, and the
 * idle wait between transactions of a connection kept warm.
 *
 * While it waits for its response headers it is the header parser's.  The
 * parser takes bytes one at a time and stops at the end of the block, so
 * whatever the peer coalesced after it (a browser's first ws frames, say)
 * is left for the next phase, which interprets the completed block once
 * the remainder has been parked.  A parse failure, or the peer closing
 * before responding, is a connection failure for the user.
 */
lws_handling_result_t
lws_h1_client_rx(struct lws *wsi, const uint8_t *buf, size_t len,
		 int from_transport, size_t *used)
{
	struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];
	const char *cce;
	int n, m;

	(void)from_transport;
	*used = 0;
	(void)pt;

	/* the proxy's replies, CONNECT or socks, are the shared tunnel rx's */
	if (lwsi_in_tunnel_leg(wsi))
		return lws_client_tunnel_rx(wsi, buf, len, used);

	if (lwsi_state(wsi) == LRS_IDLING) {
		/*
		 * Kept warm between transactions: the peer has nothing to
		 * say to us.  It closing, or sending anyway, ends the
		 * connection; the 1-byte probe read this replaces silently
		 * ate whatever arrived.
		 */
		lwsl_wsi_info(wsi, "peer %s while idle",
			      len ? "sent" : "closed");

		return LWS_HPI_RET_PLEASE_CLOSE_ME;
	}

	if (lwsi_state(wsi) != LRS_WAITING_SERVER_REPLY || !wsi->stream.ah) {
		lwsl_wsi_err(wsi, "%s: rx in state 0x%x", __func__,
			     lwsi_state(wsi));

		return LWS_HPI_RET_PLEASE_CLOSE_ME;
	}

	if (!len) {
		cce = "server closed before responding";
		goto fail;
	}

	n = (int)len;
	m = lws_parse(wsi, (unsigned char *)buf, &n);
	if (m) {
		lwsl_wsi_warn(wsi, "problems parsing header");
		if (m == LPR_FAIL || m == LPR_TOO_LARGE)
			lws_parse_fail_diag(wsi, buf, (int)len - n, (int)len);
		cce = "problems parsing header";
		goto fail;
	}
	m = (int)len - n;
	/* the block is ours, what follows it in the read is not */
	lws_servbuf_trim(pt, buf + m);

#if defined(LWS_WITH_SECURE_STREAMS_BUFFER_DUMP)
	do {
		lws_ss_handle_t *h;

		/* the opaque user data is only an ss handle on
		 * a wsi that belongs to a secure stream */
		if (!wsi->for_ss)
			break;

		h = (lws_ss_handle_t *)lws_get_opaque_user_data(wsi);
		if (!h)
			break;

		if (h->info.dump)
			h->info.dump(ss_to_userobj(h), buf, (size_t)m,
				     (wsi->stream.ah->parser_state ==
					WSI_PARSING_COMPLETE) ? 1 : 0);
	} while (0);
#endif

	*used = (size_t)m;

	return LWS_HPI_RET_HANDLED;

fail:
	lwsl_info("%s: failing conn at LWS_CONNMODE...SERVER_REPLY, %s, state 0x%x\n",
		  __func__, lws_wsi_tag(wsi), lwsi_state(wsi));
	lwsl_info("reason: %s\n", cce);
	lws_inform_client_conn_fail(wsi, (void *)cce, strlen(cce));

	return LWS_HPI_RET_PLEASE_CLOSE_ME;
}
#endif

/*
 * Our request headers went out (or the body that followed them): the
 * response is awaited, and read, which the rx policy held off until now
 * (unless the app holds rx off itself).  Returns nonzero if the wsi must be
 * closed.
 */
int
lws_h1_client_request_sent(struct lws *wsi)
{
#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2) || defined(LWS_ROLE_H3)
	/* prepare ourselves to do the parsing */
	wsi->stream.ah->parser_state = WSI_TOKEN_NAME_PART;
	wsi->stream.ah->lextable_pos = 0;
	wsi->stream.ah->unk_pos = 0;
	lws_header_table_rx_snapshot(wsi);
#endif
	if (lwsi_state(wsi) == LRS_ISSUE_HTTP_BODY)
		lws_wsi_event(wsi, LWS_WSIEV_REQ_BODY_SENT);
	lws_set_timeout(wsi, PENDING_TIMEOUT_AWAITING_SERVER_RESPONSE,
			(int)wsi->a.context->timeout_secs);

	return lws_io_read_after_drain(wsi);
}

/*
 * The transport is up and it is our turn on it: compose and send the
 * request (or ws upgrade) headers.  Returns 0, or -1 when that failed and
 * the caller should close the wsi.
 */
int
lws_h1_client_issue_handshake(struct lws *wsi)
{
	struct lws_context *context = wsi->a.context;
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	char *p = (char *)pt->compose_buf, *end = p + context->pt_serv_buf_size;
	char *sb = p;
	int n, sbc;

	sbc = lws_servbuf_claim(pt, sb, context->pt_serv_buf_size,
				"h1 client handshake");
	p = lws_generate_client_handshake(wsi, p, lws_ptr_diff_size_t(end, p));
	if (p == NULL) {
		lws_servbuf_release(pt, sbc);
		lwsl_err("Failed to generate handshake for client\n");

		return -1;
	}

	/* send our request to the server */

	lwsl_wsi_info(wsi, "HANDSHAKE2: sending headers (wsistate 0x%lx)",
		      (unsigned long)wsi->wsistate);

	/* IO keeps what a short write leaves, and sends it first */
	n = lws_io_tx_push(wsi, (unsigned char *)sb,
			   lws_ptr_diff_size_t(p, sb));
	lws_servbuf_release(pt, sbc);
	if (n < 0) {
		lwsl_debug("ERROR writing to client socket\n");

		return -1;
	}

	if (wsi->client_http_body_pending || lws_has_buffered_out(wsi)) {
		lwsl_debug("body pending\n");
		lws_wsi_event(wsi, LWS_WSIEV_REQ_HDRS_SENT_BODY);
		lws_set_timeout(wsi, PENDING_TIMEOUT_CLIENT_ISSUE_PAYLOAD,
				(int)context->timeout_secs);

		if (wsi->flags & LCCSCF_HTTP_X_WWW_FORM_URLENCODED)
			lws_callback_on_writable(wsi);
#if defined(LWS_WITH_HTTP_PROXY)
		if (lws_http_proxy_onward_body_ready(wsi))
			lws_callback_on_writable(wsi);
#endif
		/* user code must ask for writable callback */
		return 0;
	}

	lws_wsi_event(wsi, LWS_WSIEV_REQ_HDRS_SENT);

	lws_set_timeout(wsi, PENDING_TIMEOUT_AWAITING_SERVER_RESPONSE,
			(int)wsi->a.context->timeout_secs);

	lws_callback_on_writable(wsi);

	return lws_h1_client_request_sent(wsi) ? -1 : 0;
}

/*
 * The client's transport is up (IO's connect and tls are done): an h2
 * connection, by alpn or prior knowledge, sends its preface; an h1 one its
 * request.  The client_transport_up op.
 */
lws_handling_result_t
lws_h1_client_transport_up(struct lws *wsi, const lws_sockaddr46 *peer)
{
#if defined(LWS_ROLE_H2)
	if (wsi->flags & LCCSCF_H2_PRIOR_KNOWLEDGE) {
		lwsl_info("h2 prior knowledge\n");
		lws_role_call_alpn_negotiated(wsi, "h2");
	}

	if (lwsi_role_h2(wsi))
		return lws_h2_client_transport_up(wsi, peer);
#endif

	return lws_h1_client_issue_handshake(wsi) ? LWS_HPI_RET_PLEASE_CLOSE_ME :
						    LWS_HPI_RET_HANDLED;
}

/*
 * The body the app was writing after our request headers has all gone
 * (nothing pending, nothing buffered): the response is awaited.  Checked on
 * the writeable and after the pass's reading, since the app clears the
 * pending flag from either.
 */
int
lws_h1_client_body_done_check(struct lws *wsi)
{
	if (lwsi_state(wsi) != LRS_ISSUE_HTTP_BODY)
		return 0;

#if defined(LWS_WITH_HTTP_PROXY)
	if (lws_http_proxy_onward_body_ready(wsi))
		lws_callback_on_writable(wsi);
#endif
	if (wsi->client_http_body_pending || lws_has_buffered_out(wsi))
		/* user code must ask for writable callback */
		return 0;

	return lws_h1_client_request_sent(wsi);
}

/*
 * The pass's reading for an h1 client is done.  While the response headers
 * are awaited, the block that just completed is interpreted here rather
 * than from rx: interpreting may close or restart the wsi, which must not
 * happen under the pump that fed it.  Once established, the app pulls the
 * body at its own pace (lws_http_client_read()): reading stops and the app
 * hears there is something to pull.
 */
lws_handling_result_t
lws_h1_client_rx_done(struct lws *wsi)
{
	if (lws_is_flowcontrolled(wsi))
		return LWS_HPI_RET_HANDLED;

	if (lws_h1_client_body_done_check(wsi))
		return LWS_HPI_RET_PLEASE_CLOSE_ME;

	if (lwsi_state(wsi) == LRS_WAITING_SERVER_REPLY) {
		if (!wsi->stream.ah ||
		    wsi->stream.ah->parser_state != WSI_PARSING_COMPLETE)
			/* the block is not complete yet; the timeout guards */
			return LWS_HPI_RET_HANDLED;

		/*
		 * The peer may coalesce what follows the block: the parser
		 * stopped at its end and the pump parked the rest for the
		 * next phase.  Interpret the handshake: it may close the wsi,
		 * or restart it, and says which
		 */
		return lws_client_interpret_server_handshake(wsi);
	}

	if (!lwsi_hdrs_pending(wsi) && lwsi_close(wsi) != LCS_USER_TOLD) {
		/*
		 * In SSL mode we get POLLIN notification about encrypted
		 * data in, not necessarily decrypted data out becoming
		 * available.  Either way, turn off our POLLIN and let the
		 * app know: it usually asks for writeable and drains /
		 * re-enables from there
		 */
		if (lws_io_want_read(wsi, 0))
			return LWS_HPI_RET_PLEASE_CLOSE_ME;

		if (user_callback_handle_rxflow(wsi->a.protocol->callback, wsi,
					       LWS_CALLBACK_RECEIVE_CLIENT_HTTP,
						wsi->user_space, NULL, 0)) {
			lwsl_info("RECEIVE_CLIENT_HTTP closed it\n");
			return LWS_HPI_RET_PLEASE_CLOSE_ME;
		}
	}

	return LWS_HPI_RET_HANDLED;
}

#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2) || defined(LWS_ROLE_H3)

int LWS_WARN_UNUSED_RESULT
lws_http_transaction_completed_client(struct lws *wsi)
{
	struct lws_context *cx = wsi->a.context;
	struct lws_context_per_thread *pt = &cx->pt[(int)wsi->tsi];
	int n;

	lwsl_info("%s: %s (%s)\n", __func__, lws_wsi_tag(wsi),
			wsi->a.protocol->name);

	// if (wsi->stream.ah && wsi->stream.ah->http_response)
	/* we're only judging if any (200, or 500 etc) http txn completed */
	lws_metrics_caliper_report(wsi->cal_conn, METRES_GO);

#if defined(LWS_WITH_HTTP_PROXY)
	/*
	 * A proxy's onward leg ends its parent's transaction with this
	 * completion, once.  The close hooks only report a completion for a
	 * leg that never got one, eg, a response ended by the hangup: if they
	 * reported it again when this connection goes, it could land after
	 * the parent took up its next pipelined request, and end that one
	 * before its response was relayed
	 */
	wsi->http.proxy_clientside = 0;
#endif

	if (user_callback_handle_rxflow(wsi->a.protocol->callback, wsi,
					LWS_CALLBACK_COMPLETED_CLIENT_HTTP,
					wsi->user_space, NULL, 0)) {
		lwsl_debug("%s: Completed call returned nonzero (role 0x%lx)\n",
			   __func__, (unsigned long)lwsi_role(wsi));
		return -1;
	}

	wsi->http.rx_content_length = 0;

	/*
	 * For h1, wsi may pass some assets on to a queued child and be
	 * destroyed during this.  It sets timeouts, which take the context
	 * lock: that must come before the pt lock, as for a close.
	 */
	lws_context_lock(cx, __func__); /* ------------------------ cx { */
	lws_pt_lock(pt, __func__); /* ---------------------------- pt { */
	n = _lws_generic_transaction_completed_active_conn(&wsi, 1);
	lws_pt_unlock(pt); /* } pt */
	lws_context_unlock(cx); /* } cx */

	if (n < 0) {
		/*
		 * We could not hand our connection to the queued transaction:
		 * the queue is intact and closes with us, each told its
		 * connection failed.  We have no socket to set up again on.
		 */
		lwsl_wsi_info(wsi, "pipeline hand-off failed, closing");

		return -1;
	}

	if (wsi->stream.ah) {
		if (wsi->client_mux_substream)
			/*
			 * As an h2 client, once we did our transaction, that is
			 * it for us.  Further transactions will happen as new
			 * SIDs on the connection.
			 */
			__lws_header_table_detach(wsi, 0);
		else
			if (!n)
				_lws_header_table_reset(wsi->stream.ah);
	}

	if (!n || !wsi->stream.ah)
		return 0;

	/*
	 * H1: we can serialize the queued guys into the same ah
	 * H2: everybody needs their own ah until their own STREAM_END
	 */

	/* otherwise set ourselves up ready to go again */

	wsi->stream.ah->parser_state = WSI_TOKEN_NAME_PART;
	wsi->stream.ah->lextable_pos = 0;
	wsi->stream.ah->unk_pos = 0;
	lws_header_table_rx_snapshot(wsi);

	lws_set_timeout(wsi, PENDING_TIMEOUT_AWAITING_SERVER_RESPONSE,
			(int)wsi->a.context->timeout_secs);

	/* If we're (re)starting on headers, need other implied init */
	wsi->stream.ah->ues = URIES_IDLE;
	lws_wsi_event(wsi, LWS_WSIEV_REQ_ISSUE);

	lwsl_info("%s: %s: new queued transaction\n", __func__, lws_wsi_tag(wsi));
	lws_callback_on_writable(wsi);

	return 0;
}

unsigned int
lws_http_client_http_response(struct lws *wsi)
{
	if (wsi->stream.ah && wsi->stream.ah->http_response)
		return wsi->stream.ah->http_response;

	return 0;
}
#endif


#if defined(LWS_WITH_HTTP_DIGEST_AUTH) && defined(LWS_WITH_TLS)

static const char *digest_toks[] = {
	"Digest",	// 1 <<  0
	"username",	// 1 <<  1
	"realm",	// 1 <<  2
	"nonce",	// 1 <<  3
	"uri",		// 1 <<  4 optional
	"response",	// 1 <<  5
	"opaque",	// 1 <<  6
	"qop",		// 1 <<  7
	"algorithm",	// 1 <<  8
	"nc",		// 1 <<  9
	"cnonce",	// 1 << 10
	"domain",	// 1 << 11
};

#define PEND_NAME_EQ -1
#define PEND_DELIM -2

/*
 * Is the server's challenge one we can answer with digest auth?  Only if it
 * leads with the Digest scheme, which is also all lws_http_digest_auth()
 * takes.  Any other one, like Basic, is the user code's to see as the 401
 * it is.
 */
static int
lws_http_challenge_is_digest(struct lws *wsi)
{
	const char *wa = lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP_WWW_AUTHENTICATE);

	return wa && !strncasecmp(wa, "Digest", 6) &&
	       (!wa[6] || wa[6] == ' ' || wa[6] == '\t');
}

enum lws_check_basic_auth_results
lws_http_digest_auth(struct lws* wsi)
{
	uint8_t nonce[256], response[LWS_GENHASH_LARGEST * 2 + 1], qop[32];
	int seen = 0, have = 0, n, pend = -1;
	char *tmp_digest = NULL;
	size_t l = 0;
	struct lws_tokenize ts;
	char resp_username[32];
	lws_tokenize_elem e;
	char realm[64];
	char b64[512];
	int m, ml, fi;
	char algo[16];
	enum lws_genhash_types hash_type = LWS_GENHASH_TYPE_MD5;

	qop[0] = '\0';
	lws_strncpy(algo, "MD5", sizeof(algo));

	/* Did he send auth? */
	ml = lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_WWW_AUTHENTICATE);
	if (!ml)
		return LCBA_FAILED_AUTH;

	/* Disallow fragmentation monkey business */

	fi = wsi->stream.ah->frag_index[WSI_TOKEN_HTTP_WWW_AUTHENTICATE];
	if (wsi->stream.ah->frags[fi].nfrag) {
		lwsl_wsi_err(wsi, "fragmented http auth header not allowed\n");
		return LCBA_FAILED_AUTH;
	}

	m = lws_hdr_copy(wsi, b64, sizeof(b64), WSI_TOKEN_HTTP_WWW_AUTHENTICATE);
	if (m < 7) {
		lwsl_wsi_err(wsi, "HTTP auth length bad\n");
		return LCBA_END_TRANSACTION;
	}

	/*
	 * We are expecting AUTHORIZATION to have something like this
	 *
	 * Authorization: Digest
	 *   username="Mufasa",
	 *   realm="testrealm@host.com",
	 *   nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
	 *   uri="/dir/index.html",
	 *   response="e966c932a9242554e42c8ee200cec7f6",
	 *   opaque="5ccc069c403ebaf9f0171e9517f40e41"
	 *
	 * but the order, whitespace etc is quite open.  uri is optional
	 */
	lws_tokenize_init(&ts,b64, LWS_TOKENIZE_F_MINUS_NONTERM |
				   LWS_TOKENIZE_F_NO_INTEGERS |
				   LWS_TOKENIZE_F_RFC7230_DELIMS);

	do {
		e = lws_tokenize(&ts);
		switch (e) {
		case LWS_TOKZE_TOKEN:
			if (pend >= 0)
				goto str_val;

			if (ts.token_len == 6 &&
			    !strncasecmp(ts.token, "Digest", 6)) {
				seen |= 1 << 0;
				break;
			}
			if (seen) /* we must be first and one time */
				return LCBA_END_TRANSACTION;

			seen |= 1 << 15;
			pend = PEND_NAME_EQ;
			break;

		case LWS_TOKZE_TOKEN_NAME_EQUALS:
			if ((seen & (1 << 15)) == (1 << 15) || pend != -1)
				/* no auth type token or disordered */
				return LCBA_END_TRANSACTION;

			/* the whole name, not just a prefix of one */
			for (n = 0; n < (int)LWS_ARRAY_SIZE(digest_toks); n++)
				if (strlen(digest_toks[n]) == ts.token_len &&
				    !strncmp(ts.token, digest_toks[n], ts.token_len))
					break;

			if (n == LWS_ARRAY_SIZE(digest_toks)) {
				lwsl_wsi_notice(wsi, "c: '%.*s'\n",
						(int)ts.token_len,
						ts.token);

				return LCBA_END_TRANSACTION;
			}

			if (seen & (1 << n) || (seen & (1 << 15)) == (1 << 15))
				/* dup or no auth type token */
				return LCBA_END_TRANSACTION;

			seen |= 1 << n;
			pend = n;
			break;

		case LWS_TOKZE_QUOTED_STRING:
str_val:
			if (pend < 0)
				return LCBA_END_TRANSACTION;

			switch (pend) {
			case 1: /* username */
				if (ts.token_len >= (int)sizeof(resp_username))
					return LCBA_END_TRANSACTION;

				strncpy(resp_username, ts.token, ts.token_len);
				break;
			case 2: /* realm */
				if (ts.token_len >= (int)sizeof(realm))
					return LCBA_END_TRANSACTION;

				strncpy(realm, ts.token, ts.token_len);
				realm[ts.token_len] = 0;
				break;
			case 3: /* nonce */
				if (ts.token_len >= (int)sizeof(nonce))
					return LCBA_END_TRANSACTION;

				strncpy((char *)nonce, ts.token, ts.token_len);
				nonce[ts.token_len] = 0;
				break;
			case 4: /* uri */
				break;
			case 5: /* response */
				if (ts.token_len !=
					lws_genhash_size(hash_type) * 2)
					return LCBA_END_TRANSACTION;

				if (lws_hex_len_to_byte_array(ts.token, ts.token_len,
							  response,
							  sizeof(response)) < 0)
					return LCBA_END_TRANSACTION;
				break;
			case 6: /* opaque */
				break;
			case 7: /* qop */
				if (ts.token_len >= (int)sizeof(qop))
					return LCBA_END_TRANSACTION;

				strncpy((char *)qop, ts.token, ts.token_len);
				qop[ts.token_len] = '\0';
				{
					char *p = (char *)qop;
					while (p) {
						if (!strncmp(p, "auth", 4) && (p[4] == '\0' || p[4] == ',' || p[4] == ' ')) {
							strcpy((char *)qop, "auth");
							break;
						}
						p = (char *)strchr(p, ',');
						if (p) {
							p++;
							while (*p == ' ') p++;
						}
					}
					if (!p)
						return LCBA_END_TRANSACTION;
				}
				break;
			case 8: /* algorithm */
				if (ts.token_len == 3 && !strncasecmp(ts.token, "MD5", 3)) {
					hash_type = LWS_GENHASH_TYPE_MD5;
					lws_strncpy(algo, "MD5", sizeof(algo));
				} else if (ts.token_len == 7 && !strncasecmp(ts.token, "SHA-256", 7)) {
					hash_type = LWS_GENHASH_TYPE_SHA256;
					lws_strncpy(algo, "SHA-256", sizeof(algo));
				} else if (ts.token_len == 7 && !strncasecmp(ts.token, "SHA-384", 7)) {
					hash_type = LWS_GENHASH_TYPE_SHA384;
					lws_strncpy(algo, "SHA-384", sizeof(algo));
				} else if (ts.token_len == 7 && !strncasecmp(ts.token, "SHA-512", 7)) {
					hash_type = LWS_GENHASH_TYPE_SHA512;
					lws_strncpy(algo, "SHA-512", sizeof(algo));
				} else {
					lwsl_wsi_err(wsi, "wrong alg %.*s\n", (int)ts.token_len, ts.token);
					return LCBA_END_TRANSACTION;
				}
				break;
			}
			/* only now has the parameter got a value */
			have |= 1 << pend;
			pend = PEND_DELIM;
			break;

			case LWS_TOKZE_DELIMITER:
				if (*ts.token == ',') {
					if (pend != PEND_DELIM)
						return LCBA_END_TRANSACTION;

					pend = PEND_NAME_EQ;
					break;
				}
				if (*ts.token == ';') {
					/* it's the end */
					e = LWS_TOKZE_ENDED;
					break;
				}
				break;

			case LWS_TOKZE_ENDED:
				break;

			default:
				lwsl_wsi_notice(wsi, "unexpected token %d\n", e);
				return LCBA_END_TRANSACTION;
		}

	} while (e > 0);

	/*
	 * we got all the parts we care about? Realm + Nonce... with their
	 * values: "realm=" at the end, or before a ';', is only the name, and
	 * the realm / nonce buffers were never written
	 */

	if (!(seen & 1) || pend >= 0 || (have & 0xc) != 0xc) {
		lwsl_wsi_err(wsi,
				"%s: Not all digest auth tokens found! "
				"m: 0x%x\nServer sent: %s",
				__func__, seen & 0x81ef, b64);

		return LCBA_END_TRANSACTION;
	}

	lwsl_wsi_info(wsi, "HTTP digest auth realm %s nonce %s\n", realm, nonce);

	if (wsi->stash &&
	    wsi->stash->cis[CIS_PATH]) {
		char *username =  wsi->stash->cis[CIS_USERNAME];
		char *password = wsi->stash->cis[CIS_PASSWORD];
		uint8_t digest[LWS_GENHASH_LARGEST * 2 + 1];
		char *uri = wsi->stash->cis[CIS_PATH];
		char a1[LWS_GENHASH_LARGEST * 2 + 1];
		char a2[LWS_GENHASH_LARGEST * 2 + 1];
		char nc[sizeof(int) * 2 + 1];
		struct lws_genhash_ctx hc;
		int ncount = 1, ssl;
		const char *a, *p, *h;
		struct lws *nwsi;
		char cnonce[256];
		l = sizeof(a1) + sizeof(a2) + sizeof(nonce) +
			(sizeof(ncount) *2) + sizeof(response) +
			sizeof(cnonce) + sizeof(qop) + strlen(uri) +
			strlen(username) + strlen(password) +
			strlen(realm) + 111;

		tmp_digest = lws_malloc(l, __func__);
		if (!tmp_digest)
			return LCBA_FAILED_AUTH;

		n = lws_snprintf(tmp_digest, l, "%s:%s:%s",
				 username, realm, password);

		if (lws_genhash_init(&hc, hash_type) ||
				lws_genhash_update(&hc,
						   tmp_digest,
							(size_t)n) ||
				lws_genhash_destroy(&hc, digest)) {
			lws_genhash_destroy(&hc, NULL);

			goto bail;
		}

		lws_hex_from_byte_array(digest,
					lws_genhash_size(hash_type),
					a1, sizeof(a1));

		/*
		 * In case of Websocket upgrade, method is NULL
		 * we assume it is a GET
		*/

		n = lws_snprintf(tmp_digest, l, "%s:%s",
				   wsi->stash->cis[CIS_METHOD] ?
				   wsi->stash->cis[CIS_METHOD] : "GET", uri);

		if (lws_genhash_init(&hc, hash_type) ||
				     lws_genhash_update(&hc,
						    tmp_digest,
						    (size_t)n) ||
				     lws_genhash_destroy(&hc, digest)) {
			lws_genhash_destroy(&hc, NULL);
			lwsl_err("%s: hash failed\n", __func__);

			goto bail;
		}
		lws_hex_from_byte_array(digest,
					lws_genhash_size(hash_type),
					a2, sizeof(a2));
#if (_LWS_ENABLED_LOGS & LLL_DEBUG)
		{
			char lp[128];

			lwsl_debug("A2: %s:%s = %s\n",
				   wsi->stash->cis[CIS_METHOD],
				   lws_http_log_path(lp, sizeof(lp), uri), a2);
		}
#endif

		if (lws_hex_random(lws_get_context(wsi), cnonce, sizeof(cnonce)))
			goto bail;
		lws_hex_from_byte_array((const uint8_t *)&ncount,
					sizeof(ncount), nc, sizeof(nc));

		if (qop[0])
			n = lws_snprintf(tmp_digest, l, "%s:%s:%08x:%s:%s:%s", a1,
					nonce, ncount, cnonce, qop, a2);
		else
			n = lws_snprintf(tmp_digest, l, "%s:%s:%s", a1,
					nonce, a2);


		if (lws_genhash_init(&hc, hash_type) ||
				lws_genhash_update(&hc, tmp_digest, (size_t)n) ||
				lws_genhash_destroy(&hc, digest)) {
			lws_genhash_destroy(&hc, NULL);
			lwsl_wsi_err(wsi, "hash failed\n");

			goto bail;
		}
		lws_hex_from_byte_array(digest,
					lws_genhash_size(hash_type),
					(char *)response,
					lws_genhash_size(hash_type) * 2 + 1);

		if (qop[0]) {
			n = lws_snprintf(tmp_digest, l,
					 "Digest username=\"%s\", realm=\"%s\", "
					 "nonce=\"%s\", uri=\"%s\", qop=%s, nc=%08x, "
					 "cnonce=\"%s\", response=\"%s\", "
					 "algorithm=\"%s\"",
					 username, realm, nonce, uri, qop, ncount,
					 cnonce, response, algo);
		} else {
			n = lws_snprintf(tmp_digest, l,
					 "Digest username=\"%s\", realm=\"%s\", "
					 "nonce=\"%s\", uri=\"%s\", "
					 "response=\"%s\", "
					 "algorithm=\"%s\"",
					 username, realm, nonce, uri,
					 response, algo);
		}
		/*
		 * The buffer outlives us as the header to send; nothing of
		 * username:realm:password or HA1 from before may linger past
		 * the header's NUL
		 */
		if (n >= 0 && (size_t)n + 1 < l)
			lws_explicit_bzero(tmp_digest + n + 1, l - (size_t)n - 1);

		if (lws_hdr_simple_create(wsi, WSI_TOKEN_HTTP_AUTHORIZATION,
								tmp_digest)) {
			lwsl_wsi_err(wsi, "Failed to add Digest auth header");
			goto bail;
		}

		nwsi = lws_get_network_wsi(wsi);
		ssl = nwsi->use_ssl & LCCSCF_USE_SSL;

		a = wsi->stash->cis[CIS_ADDRESS];
		p = &wsi->stash->cis[CIS_PATH][1];
		/* the retry is to the same authority: the user's Host: stays */
		h = wsi->stash->cis[CIS_HOST] ? wsi->stash->cis[CIS_HOST] : a;

		wsi->client_pipeline = 0;

		/*
		 * If the server kept the TCP/TLS connection alive on the 401
		 * and sent an explicitly empty body, reuse the existing
		 * session instead of tearing down and recreating it.
		 * Fall back to the close/reconnect path if any doubt exists.
		 */
		{
			int keep_alive = !lws_client_response_says_close(wsi),
			    empty_body;
			uint64_t cl401;
			char cl[32];

			/*
			 * The body is known to be empty only with no
			 * Transfer-Encoding, and one Content-Length of 0
			 */
			empty_body = !lws_hdr_total_length(wsi,
					WSI_TOKEN_HTTP_TRANSFER_ENCODING) &&
				lws_hdr_copy_fragment(wsi, cl, sizeof(cl) - 1,
					WSI_TOKEN_HTTP_CONTENT_LENGTH, 1) == -1 &&
				lws_hdr_copy(wsi, cl, sizeof(cl) - 1,
					WSI_TOKEN_HTTP_CONTENT_LENGTH) > 0 &&
				!lws_http_parse_content_length(cl, &cl401) &&
				!cl401;

			/*
			 * Only an h1 connection carries the retry itself: an
			 * h2 / h3 stream's conn_type says KEEP_ALIVE too, but
			 * the stream was ended by the 401 and can't take
			 * another request.  They restart the way a redirect
			 * does, below.
			 */
			if (!wsi->client_mux_substream &&
			    wsi->http.conn_type == HTTP_CONNECTION_KEEP_ALIVE &&
			    keep_alive && empty_body) {
				/*
				 * Bounded as the reconnecting retry below is
				 * by lws_client_reset(): a server answering
				 * every attempt with another 401 must not
				 * keep us going round forever
				 */
				if (wsi->redirects == 4) {
					lwsl_wsi_err(wsi, "too many auth retries");
					goto bail;
				}
				wsi->redirects++;
				wsi->http.digest_auth_hdr = tmp_digest;
				return LCBA_AUTH_RETRY_KEEPALIVE;
			}
		}

		/*
		 * This prevents connection pipelining when two
		 * HTTP connection use the same tcp socket.
		 */
		wsi->keepalive_rejected = 1;

		if (!lws_client_reset(&wsi, ssl, a, wsi->c_port, p, h, NULL,
				      1)) {
			lwsl_wsi_err(wsi, "Failed to reset WSI for Digest auth");

			goto bail;
		}

		/*
		 * Keep track of digest auth to send it at next attempt, lws_client_reset will free it
		*/

		wsi->http.digest_auth_hdr = tmp_digest;
	} else {
		/*
		 * We have no stashed path to compute the digest response
		 * against (the client connect info left .path NULL)...
		 *
		 * We must not return LCBA_CONTINUE here: the caller takes that
		 * to mean we went through lws_client_reset(), ie, that the wsi
		 * is in LTS_RESTARTING and so survives the
		 * lws_close_free_wsi() it does next.  Without the reset the
		 * wsi is really freed there and touching it afterwards is a
		 * use-after-free.
		 */

		lwsl_wsi_err(wsi, "digest auth: no path stashed");

		return LCBA_FAILED_AUTH;
	}

	/*
	 * We only get here having successfully done lws_client_reset(), so
	 * the wsi is in LTS_RESTARTING and the caller's close leaves it
	 * extant for the retry
	 */

	return LCBA_CONTINUE;

bail:
	if (tmp_digest) {
		lws_explicit_bzero(tmp_digest, l);
		lws_free(tmp_digest);
	}

	return LCBA_FAILED_AUTH;
}
#endif

#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2) || defined(LWS_ROLE_H3)

int
lws_http_is_redirected_to_get(struct lws *wsi)
{
	return wsi->redirected_to_get;
}

/*
 * Is the response head in the ah a 1xx interim (not 101 Switching Protocols,
 * which is the final response to an Upgrade)?  Only h1 has them: an h2 / h3
 * stream gets :status in its own HEADERS.
 */
static int
lws_http_client_response_is_interim(struct lws *wsi)
{
	const char *st;
	int n;

	if (wsi->client_mux_substream)
		return 0;

	st = lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP);
	if (!st)
		return 0;

	n = atoi(st);

	return n >= 100 && n < 200 && n != 101;
}

/*
 * Returns LWS_HPI_RET_HANDLED, or when the response ended the wsi's part in
 * this pass, what the close of it said: LWS_HPI_RET_WSI_ALREADY_DIED, it was
 * freed, or LWS_HPI_RET_CLOSING, it lives on, in its close or restarted to
 * follow a redirect or answer a digest auth challenge
 */
lws_handling_result_t
lws_client_interpret_server_handshake(struct lws *wsi)
{
	lws_handling_result_t hr;
	int n, rej;
	int close_reason = LWS_CLOSE_STATUS_PROTOCOL_ERR;
	const char *meth, *cce = NULL;
	struct allocated_headers *ah, *ah1;
	char *p = NULL, *simp, c1;
	int bodyless;
#if defined(LWS_ROLE_WT)
	char wt_cce[40];
#endif
	lws_client_redir_t *redir = NULL;

	// lws_free_set_NULL(wsi->stash);

#if defined(LWS_WITH_CONMON)
	wsi->conmon.ciu_txn_resp = (lws_conmon_interval_us_t)
					(lws_wsi_now(wsi) - wsi->conmon_datum);
#endif
	// lws_free_set_NULL(wsi->stash);

	ah = wsi->stream.ah;
	if (!wsi->do_ws) {
		/* we are being an http client...
		 */

		/*
		 * Learn any h3 alternative the server advertises on this
		 * authenticated response, so later connections to this origin
		 * can race QUIC to the right endpoint... but not from a 1xx
		 * interim, which is swallowed further down and would otherwise
		 * buy the server a cache write per interim
		 */

		if (!lws_http_client_response_is_interim(wsi))
			lws_client_alt_svc_learn(wsi);

#if defined(LWS_ROLE_WT)
		if (wsi->a.protocol && !strcmp(wsi->a.protocol->name, "webtransport")) {
			const char *st = lws_hdr_simple_ptr(wsi,
						WSI_TOKEN_HTTP_COLON_STATUS);

			/*
			 * The server may refuse the WebTransport CONNECT, eg,
			 * 403 from LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION.
			 * Anything other than 2xx means there is no session:
			 * fail the client connection rather than entering the
			 * wt role and waiting for a FIN.
			 */
			n = st ? atoi(st) : 0;
			if (n < 200 || n > 299) {
				if (ah)
					ah->http_response = (unsigned int)n;
				lws_snprintf(wt_cce, sizeof(wt_cce),
					     "HS: WT CONNECT refused %d", n);
				lwsl_wsi_notice(wsi, "%s", wt_cce);
				cce = wt_cce;
				goto bail3_l;
			}

			lwsl_debug("%s: %s: transitioning to WebTransport client\n",
				   __func__, lws_wsi_tag(wsi));
			lws_wsi_event(wsi, LWS_WSIEV_WT_SESSION);
			wsi->wt.is_session = 1;
		} else
#endif
		{
			/* the response headers are in: h1, or a mux stream */
			lws_wsi_event(wsi, LWS_WSIEV_RESP_HDRS);
		}

		wsi->stream.ah = ah;
		ah->http_response = 0;
	}

#if defined(LWS_WITH_CACHE_NSCOOKIEJAR) && defined(LWS_WITH_CLIENT)

	if ((wsi->flags & LCCSCF_CACHE_COOKIES) &&
	    !lws_http_client_response_is_interim(wsi) &&
	    lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_SET_COOKIE))
		lws_parse_set_cookie(wsi);

#endif
	/*
	 * well, what the server sent looked reasonable for syntax.
	 * Now let's confirm it sent all the necessary headers
	 *
	 * http (non-ws) client will expect something like this
	 *
	 * HTTP/1.0.200
	 * server:.libwebsockets
	 * content-type:.text/html
	 * content-length:.17703
	 * set-cookie:.test=LWS_1456736240_336776_COOKIE;Max-Age=360000
	 */

	wsi->http.conn_type = HTTP_CONNECTION_KEEP_ALIVE;
	if (!wsi->client_mux_substream) {
		p = lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP);
		/*
		if (wsi->do_ws && !p) {
			lwsl_info("no URI\n");
			cce = "HS: URI missing";
			goto bail3_l;
		}
		*/
		if (!p) {
			p = lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP1_0);
			wsi->http.conn_type = HTTP_CONNECTION_CLOSE;
		}
		if (!p) {
			cce = "HS: URI missing";
			lwsl_info("no URI\n");
			goto bail3_l;
		}
		/*
		 * RFC 9112 9.6: the server will close after this response, so
		 * nothing queued on the connection can follow it there, and
		 * nothing new may join it
		 */
		if (lws_client_response_says_close(wsi))
			wsi->http.conn_type = HTTP_CONNECTION_CLOSE;
#if defined(LWS_ROLE_H2)
	} else {
		p = lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP_COLON_STATUS);
		if (!p) {
			cce = "HS: :status missing";
			lwsl_info("no status\n");
			goto bail3_l;
		}
#endif
	}
#if !defined(LWS_ROLE_H2)
	if (!p) {
		cce = "HS: :status missing";
		lwsl_info("no status\n");
		goto bail3_l;
	}
#endif
	n = atoi(p);

#if defined(LWS_WITH_HTTP_DIGEST_AUTH) && defined(LWS_WITH_TLS)
	if (n == 401 && lws_http_challenge_is_digest(wsi)) {
		if (!(wsi->stash && wsi->stash->cis[CIS_USERNAME] &&
                		    wsi->stash->cis[CIS_PASSWORD])) {
			/*
			 * Our contract with our caller is 0, or
			 * LWS_HPI_RET_WSI_ALREADY_DIED meaning we closed the
			 * wsi ourselves... an LCBA_xxx result here would be
			 * taken as "already died" while leaving the wsi alive
			 * and still in the fds table
			 */

			cce = "HS: digest auth wanted but no credentials";
			lwsl_wsi_err(wsi, "%s", cce);

			goto bail3_l;
		}

		enum lws_check_basic_auth_results auth_res = lws_http_digest_auth(wsi);

		if (auth_res == LCBA_AUTH_RETRY_KEEPALIVE) {
			/*
			 * Server kept the TCP/TLS connection alive:
			 * reuse it for the authenticated retry without
			 * any close/reconnect.  Reset the AH parser and
			 * re-populate client request headers from stash,
			 * then schedule a new HTTP handshake send.
			 */
			static const uint8_t hnames_cis[] = {
				_WSI_TOKEN_CLIENT_PEER_ADDRESS,
				_WSI_TOKEN_CLIENT_URI,
				_WSI_TOKEN_CLIENT_HOST,
				_WSI_TOKEN_CLIENT_ORIGIN,
				_WSI_TOKEN_CLIENT_SENT_PROTOCOLS,
				_WSI_TOKEN_CLIENT_METHOD,
				_WSI_TOKEN_CLIENT_IFACE,
				_WSI_TOKEN_CLIENT_ALPN
			};
			int m;

			lwsl_wsi_info(wsi, "digest auth: reusing TCP/TLS connection\n");

			/*
			 * The 401 was a transaction's answer: it is over, and
			 * the retry's head binds the caliper afresh
			 */
			lws_metrics_caliper_report(wsi->cal_conn, METRES_GO);

			_lws_header_table_reset(wsi->stream.ah);

			if (wsi->stash)
				for (m = 0; m < (int)LWS_ARRAY_SIZE(hnames_cis); m++)
					if (hnames_cis[m] &&
					    wsi->stash->cis[m] &&
					    lws_hdr_simple_create(wsi, hnames_cis[m], wsi->stash->cis[m]))
						goto bail3_l;

			wsi->stream.ah->ues = URIES_IDLE;
			lws_wsi_event(wsi, LWS_WSIEV_REQ_ISSUE);
			lws_callback_on_writable(wsi);
			return LWS_HPI_RET_HANDLED;
		}

		if (auth_res)
			goto bail3_l;

		/*
		 * The close either restarts this wsi, keeping its opaque
		 * (close.c leaves the ss binding alone for a restart), or
		 * fails and frees it: nothing may be written to it after
		 */
		return _lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS,
					   "digest_auth_step2");
	}

    ah = wsi->stream.ah;
#endif
	if (ah)
		ah->http_response = (unsigned int)n;

	if (n >= 100 && n < 200 && n != 101 && !wsi->client_mux_substream) {
		/*
		 * A 1xx interim response (100 Continue, 103 Early Hints...).
		 * RFC 9110 15.2: a client MUST be able to parse one or more of
		 * these before the final response, whether or not it asked for
		 * one with Expect.  101 Switching Protocols is not one of them:
		 * it is the final response to our Upgrade (ws, h2c), handled
		 * below.  An interim carries nothing for the user: rewind the
		 * header table to where the response section began, so our own
		 * request tokens survive, and go back to waiting for the real
		 * one.  It is the server talking to us, so the connection
		 * validity and the response timeout start again from here.
		 *
		 * But not for ever: each interim re-arms the response timeout,
		 * so a server sending one every few seconds would hold this
		 * wsi, its fd and its ah indefinitely for a few bytes each.
		 */
		if (!ah || ++ah->rx_interims > LWS_HTTP_INTERIM_RESPONSE_LIMIT) {
			cce = "HS: too many interim responses";
			goto bail3_l;
		}

		lwsl_wsi_info(wsi, "%d interim response, awaiting the final one",
			      n);
		lws_header_table_rx_rewind(wsi);
		/*
		 * back to waiting: from ESTABLISHED, where the response
		 * headers took us above, or for a ws client, which takes only
		 * the 101's, still waiting
		 */
		lws_wsi_event(wsi, LWS_WSIEV_RESP_INTERIM);
		lws_validity_confirmed(wsi);
		lws_set_timeout(wsi, PENDING_TIMEOUT_AWAITING_SERVER_RESPONSE,
				(int)wsi->a.context->timeout_secs);

		return LWS_HPI_RET_HANDLED;
	}

	if (!wsi->client_no_follow_redirect &&
#if defined(LWS_WITH_HTTP_PROXY)
	    !wsi->http.proxy_clientside &&
#endif
	    (n == 301 || n == 302 || n == 303 || n == 307 || n == 308)) {
		p = lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP_LOCATION);
		if (!p) {
			cce = "HS: Redirect code but no Location";
			goto bail3_l;
		}

		/* RFC 9110 10.2.2: with two, we can't know which was meant */
		if (lws_hdr_copy_fragment(wsi, &c1, 1,
					  WSI_TOKEN_HTTP_LOCATION, 1) != -1) {
			cce = "HS: Redirect with more than one Location";
			goto bail3_l;
		}

#if defined(LWS_WITH_CONMON)
		if (wsi->conmon.pcol == LWSCONMON_PCOL_NONE) {
			wsi->conmon.pcol = LWSCONMON_PCOL_HTTP;
			wsi->conmon.protocol_specific.http.response = n;
		}

#if defined(LWS_WITH_SECURE_STREAMS)
		if (wsi->for_ss
#if defined(LWS_WITH_SECURE_STREAMS_PROXY_API)
		    && !wsi->client_bound_sspc
#endif
		   ) {
	
			lws_ss_handle_t *h = (lws_ss_handle_t *)lws_get_opaque_user_data(wsi);

			if (h)
				lws_conmon_ss_json(h);
		}
#endif
#endif

		/*
		 * Where it would take us, which the user code may ask about
		 * (lws_client_redirect_info()), to judge whether what it sends
		 * as credentials may go there, the way we judge what we send
		 * on its behalf below
		 */

		redir = lws_client_redirect_resolve(wsi, p);
		if (lws_client_redir_origin_capture(wsi)) {
			cce = "HS: OOM";
			goto bail3_l;
		}

		/* let's let the user code know, if he cares */

		wsi->cli_redir_pending = redir;
		rej = wsi->a.protocol->callback(wsi,
					LWS_CALLBACK_CLIENT_HTTP_REDIRECT,
					wsi->user_space, p, (unsigned int)n);
		wsi->cli_redir_pending = NULL;
		if (rej) {
			cce = "HS: user code rejected redirect";
			goto bail3_l;
		}

		if (!redir) {
			cce = "HS: Redirect Location refused";
			goto bail3_l;
		}

		/*
		 * The cookies from our jar, and the digest auth credentials,
		 * are what we would send for the user code: the same rule
		 * goes for them.  A secure stream's policy decided for its
		 * stream in its redirect callback.
		 */
		if (
#if defined(LWS_WITH_SECURE_STREAMS)
		    !wsi->for_ss &&
#endif
		    ((wsi->flags & LCCSCF_CACHE_COOKIES) ||
		     (wsi->stash && wsi->stash->cis[CIS_USERNAME])) &&
		    !lws_client_redirect_creds_ok(wsi, redir, NULL)) {
			cce = "HS: Redirect would take credentials elsewhere";
			goto bail3_l;
		}

#if defined(LWS_WITH_TLS)
		if ((wsi->use_ssl & LCCSCF_USE_SSL) && !redir->ssl &&
		     !(wsi->flags & LCCSCF_ACCEPT_TLS_DOWNGRADE_REDIRECTS)) {
			cce = "HS: Redirect attempted SSL downgrade";
			goto bail3_l;
		}
#endif

		if (!lws_client_retarget_allowed(wsi, redir->address)) {
			cce = "HS: Redirect to or from a unix socket refused";
			goto bail3_l;
		}

		meth = lws_wsi_client_stash_item(wsi, CIS_METHOD,
						 _WSI_TOKEN_CLIENT_METHOD);

		if (!lws_client_reset(&wsi, redir->ssl, redir->address,
				      redir->port, redir->path, redir->host,
				      lws_client_redirect_method(n,
						meth ? meth : "GET"), 1)) {
			lwsl_err("Redirect failed\n");
			cce = "HS: Redirect failed";
			goto bail3_l;
		}

		/*
		 * We are redirecting, let's close in order to extricate
		 * ourselves from the current wsi usage, eg, h2 mux cleanly.
		 *
		 * We will notice LTS_RESTARTING and switch to redirect
		 * flow late in the close action.
		 */

		/* restarts the wsi, or fails and frees it: no write after */
		hr = _lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS, "redir");

		lws_free(redir);

		return hr;
	}

	/* if h1 KA is allowed, enable the queued pipeline guys */

	if (lwsi_role_h1(wsi)) {
		/* ie, coming to this for the first time */
		if (wsi->http.conn_type != HTTP_CONNECTION_KEEP_ALIVE) {
			/*
			 * The role the restarted guys go back to... this has
			 * to be computed outside the event macro's argument
			 * list, MSVC rejects #if inside one (C5101)
			 */
			const struct lws_role_ops *rops =
#if defined(LWS_ROLE_H1)
						   &role_ops_h1;
#elif defined(LWS_ROLE_H2)
						   &role_ops_h2;
#elif defined(LWS_ROLE_H3)
						   &role_ops_h3;
#else
						   NULL;
#endif

			/*
			 * Ugh... now the main http connection has seen
			 * both sides, we learn the server doesn't
			 * support keepalive.
			 *
			 * That means any guys queued on us are going
			 * to have to be restarted from connect2 with
			 * their own connections.
			 */

			/*
			 * stick around telling any new guys they can't
			 * pipeline to this server
			 */
			wsi->keepalive_rejected = 1;

			lws_vhost_lock(wsi->a.vhost);
			lws_start_foreach_dll_safe(struct lws_dll2 *,
						   d, d1,
			  lws_dll2_get_head(&wsi->dll2_cli_txn_queue_owner)) {
				struct lws *ww = lws_container_of(d,
					struct lws,
					dll2_cli_txn_queue);

				/* remove him from our queue */
				lws_dll2_remove(&ww->dll2_cli_txn_queue);
				/* give up on pipelining */
				ww->client_pipeline = 0;

				/* go back to "trying to connect" state */
				lws_wsi_event_role(ww, LWS_WSIEV_RESTART, rops);
				ww->user_space = NULL;
			} lws_end_foreach_dll_safe(d, d1);
			lws_vhost_unlock(wsi->a.vhost);
		}
	}

#ifdef LWS_WITH_HTTP_PROXY
	wsi->http.perform_rewrite = 0;
	if (lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE)) {
		if (!strncmp(lws_hdr_simple_ptr(wsi,
					WSI_TOKEN_HTTP_CONTENT_TYPE),
					"text/html", 9))
			wsi->http.perform_rewrite = 0;
	}
#endif

	/*
	 * RFC 9112 6.3: the response to a HEAD, and any 204 or 304, has no
	 * body, whatever its Content-Length or Transfer-Encoding say: they
	 * describe what the representation would have had.  Framed by them,
	 * the response was taken to have a body, and the client waited for
	 * bytes that never come
	 */
	simp = lws_hdr_simple_ptr(wsi, _WSI_TOKEN_CLIENT_METHOD);
	bodyless = lws_http_client_http_response(wsi) == 204 ||
		   lws_http_client_http_response(wsi) == 304 ||
		   (simp && !strcmp(simp, "HEAD"));

	/* he may choose to send us stuff in chunked transfer-coding */
	wsi->http.rx_chunked = 0;
	wsi->http.chunk_remaining = 0; /* ie, next thing is chunk size */
	wsi->http.chunk_skip = 0;
	if (!bodyless &&
	    lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_TRANSFER_ENCODING)) {
		/*
		 * All of it, not just its first header: "chunked" followed by
		 * a second Transfer-Encoding header is a list of codings, and
		 * we do not know where a body framed by it ends
		 */
		if (!lws_http_te_is_chunked(wsi)) {
			lwsl_wsi_err(wsi, "unsupported TE");
			cce = "HS: unsupported TE";
			goto bail2;
		}
		wsi->http.rx_chunked = 1;
		/* first thing is hex, after payload there is crlf */
		wsi->http.chunk_parser = ELCP_HEX;
	}

	wsi->http.content_length_given = 0;
	if (bodyless) {
		/* nothing to frame, and nothing that ends at the close */
		wsi->http.rx_content_length = 0;
		wsi->http.rx_content_remain = 0;
	} else if (wsi->http.rx_chunked &&
	    lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_CONTENT_LENGTH)) {
		/*
		 * RFC 9112 6.3: with both, Transfer-Encoding overrides
		 * Content-Length.  Taking the Content-Length as well left
		 * rx_content_remain clamping every body slice, and chunked
		 * delivery never decrements it, so a "Content-Length: 1"
		 * made us deliver (and a proxy forward) the body a byte at
		 * a time.
		 */
		lwsl_wsi_notice(wsi, "ignoring Content-Length with chunked");
		wsi->http.rx_content_length = 0;
		wsi->http.rx_content_remain = 0;
	} else if (lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_CONTENT_LENGTH)) {
		char cl[32];
		uint64_t cl_val;

		/*
		 * As a server takes a request's: one Content-Length, that is
		 * only digits.  atoll() took "12abc" as 12, a second header
		 * went unseen, and past LLONG_MAX it gave whatever it gave
		 */
		if (lws_hdr_copy_fragment(wsi, cl, sizeof(cl) - 1,
					  WSI_TOKEN_HTTP_CONTENT_LENGTH, 1) != -1 ||
		    lws_hdr_copy(wsi, cl, sizeof(cl) - 1,
				 WSI_TOKEN_HTTP_CONTENT_LENGTH) <= 0 ||
		    lws_http_parse_content_length(cl, &cl_val)) {
			lwsl_wsi_err(wsi, "bad Content-Length");
			cce = "HS: bad Content-Length";
			goto bail2;
		}
		wsi->http.rx_content_length = (lws_filepos_t)cl_val;
		lwsl_info("%s: incoming content length %llu\n",
			    __func__, (unsigned long long)
				    wsi->http.rx_content_length);
		wsi->http.rx_content_remain =
				wsi->http.rx_content_length;
		wsi->http.content_length_given = 1;
	} else { /* can't do 1.1 without a content length or chunked */
		if (!wsi->http.rx_chunked)
			wsi->http.conn_type = HTTP_CONNECTION_CLOSE;
		lwsl_debug("%s: no content length\n", __func__);
	}

	if (wsi->do_ws) {
		/*
		 * Give one last opportunity to ws protocols to inspect server reply
		 * before the ws upgrade code discard it. ie: download reply body in case
		 * of any other response code than 101.
		 */
		if (wsi->a.protocol->callback(wsi,
					  LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP,
					  wsi->user_space, NULL, 0)) {

			cce = "HS: disallowed by client filter";
			goto bail2;
		}
	} else {
		/* allocate the per-connection user memory (if any) */
		if (lws_ensure_user_space(wsi)) {
			lwsl_err("Problem allocating wsi user mem\n");
			cce = "HS: OOM";
			goto bail2;
		}


		/*
		 * we seem to be good to go, give client last chance to check
		 * headers and OK it
		 */
		ah1 = wsi->stream.ah;
		wsi->stream.ah = ah;
		if (wsi->a.protocol->callback(wsi,
				LWS_CALLBACK_CLIENT_FILTER_PRE_ESTABLISH,
					    wsi->user_space, NULL, 0)) {
			wsi->stream.ah = ah1;
			cce = "HS: disallowed by client filter";
			goto bail2;
		}

		/* clear his proxy connection timeout */
		lws_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);

		wsi->rxflow_change_to = LWS_RXFLOW_ALLOW;

		/* call him back to inform him he is up */
		if (wsi->a.protocol->callback(wsi,
					    LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP,
					    wsi->user_space, NULL, 0)) {
			wsi->stream.ah = ah1;
			cce = "HS: disallowed at ESTABLISHED";
			goto bail3_l;
		}

		wsi->stream.ah = ah1;

		lwsl_info("%s: %s: client conn up\n", __func__, lws_wsi_tag(wsi));

		/*
		 * Did we get a response from the server with an explicit
		 * content-length of zero?  If so, and it's not H2 which will
		 * notice it via END_STREAM, this transaction is already
		 * completed at the end of the header processing...
		 * Likewise one that has no body at all: the answer to a HEAD,
		 * a 204 or a 304.
		 *
		 * A chunked response's Content-Length was ignored above, and
		 * rx_content_length zeroed with it: that is not a length of
		 * zero, the body is still to come and ends at its last-chunk.
		 * Completing it here handed a kept-alive connection to the
		 * next queued request with the body still on it, to be read
		 * as that request's response (C-701)
		 */
		if (!wsi->mux_substream &&
		    !wsi->client_mux_substream &&
		    (bodyless ||
		     (lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_CONTENT_LENGTH) &&
		      !wsi->http.rx_chunked && !wsi->http.rx_content_length))) {
			if (!lws_http_transaction_completed_client(wsi))
				return LWS_HPI_RET_HANDLED;

			/*
			 * The user callback asked us to close from
			 * LWS_CALLBACK_COMPLETED_CLIENT_HTTP... nothing did the
			 * close for us, so we do it here
			 */

			return _lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS,
					   "client txn completed close");
		}

		/*
		 * We can also get a case where it's http/1 and there's no
		 * content-length at all, so anything that comes is the body
		 * until it hangs up on us.  With that situation, hanging up
		 * on us past this point should generate a valid
		 * LWS_CALLBACK_COMPLETED_CLIENT_HTTP.
		 *
		 * In that situation, he can't pipeline because in h1 there's
		 * no post-header in-band way to signal the end of the
		 * transaction except hangup.
		 *
		 * lws_http_transaction_completed_client() is the right guy to
		 * issue it when we see the peer has hung up on us.
		 */

		return LWS_HPI_RET_HANDLED;
	}

#if defined(LWS_ROLE_WS)
	switch (lws_client_ws_upgrade(wsi, &cce)) {
	case 2:
		goto bail2;
	case 3:
		goto bail3_l;
	}

	return LWS_HPI_RET_HANDLED;
#endif

bail3_l:
	close_reason = LWS_CLOSE_STATUS_NOSTATUS;

bail2:
	if (wsi->a.protocol) {
		n = 0;
		if (cce)
			n = (int)strlen(cce);

		lws_inform_client_conn_fail(wsi, (void *)cce, (unsigned int)n);
	}

	lwsl_info("closing connection (prot %s) "
		  "due to bail2 connection error: %s\n", wsi->a.protocol ?
				  wsi->a.protocol->name : "unknown", cce);

	/* closing will free up his parsing allocations */
	hr = _lws_close_free_wsi(wsi, (enum lws_close_status)close_reason,
				 "c hs interp");

	lws_free(redir);

	return hr;
}
#endif

/*
 * set the boundary string and the content-type for client multipart mime
 *
 * \p end is one past the last byte we may write at \p p
 */

uint8_t *
lws_http_multipart_headers(struct lws *wsi, uint8_t *p, uint8_t *end)
{
	/*
	 * 9 random bytes are 12 base64 characters with no padding, which
	 * with the terminating NUL fit the 16 the boundary has room for
	 */
	char buf[9], arg[48];
	int n;

	if (lws_get_random(wsi->a.context, (uint8_t *)buf, sizeof(buf)) !=
			sizeof(buf))
		return NULL;

	if (lws_b64_encode_string(buf, sizeof(buf),
				  wsi->http.multipart_boundary,
				  sizeof(wsi->http.multipart_boundary)) < 0)
		return NULL;

	n = lws_snprintf(arg, sizeof(arg), "multipart/form-data; boundary=\"%s\"",
			 wsi->http.multipart_boundary);

	if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE,
					 (uint8_t *)arg, n, &p, end))
		return NULL;

	wsi->http.multipart = 1;
	lws_client_http_body_pending(wsi, 1);

	return p;
}

/*
 * A part's name and filename go in quoted-strings in its Content-Disposition
 * (RFC 7578 4.2).  Rather than escape or percent-encode characters that would
 * end the quoted-string, escape inside it or end the header line, which
 * servers decode differently, we refuse them.
 */

static int
lws_http_mp_quotable(const char *s)
{
	for (; *s; s++)
		if (*s == '"' || *s == '\\' || (unsigned char)*s < 0x20 ||
		    *s == 0x7f)
			return 0;

	return 1;
}

/* a part's Content-Type value can't have control chars that end the line */

static int
lws_http_mp_hdr_value_ok(const char *s)
{
	for (; *s; s++)
		if (((unsigned char)*s < 0x20 && *s != '\t') || *s == 0x7f)
			return 0;

	return 1;
}

int
lws_client_http_multipart(struct lws *wsi, const char *name,
			  const char *filename, const char *content_type,
			  char **p, char *end)
{
	/*
	 * Client conn must have been created with LCCSCF_HTTP_MULTIPART_MIME
	 * flag to use this api
	 */
	assert(wsi->http.multipart);

	if ((name && !lws_http_mp_quotable(name)) ||
	    (filename && !lws_http_mp_quotable(filename)) ||
	    (content_type && !lws_http_mp_hdr_value_ok(content_type))) {
		lwsl_wsi_warn(wsi, "unusable part name, filename or type");

		return 1;
	}

	if (!name) {
		*p += lws_snprintf((char *)(*p), lws_ptr_diff_size_t(end, *p),
					"\xd\xa--%s--\xd\xa",
					wsi->http.multipart_boundary);

		return *p == end;
	}

	if (wsi->client_subsequent_mime_part)
		*p += lws_snprintf((char *)(*p), lws_ptr_diff_size_t(end, *p), "\xd\xa");
	wsi->client_subsequent_mime_part = 1;

	*p += lws_snprintf((char *)(*p), lws_ptr_diff_size_t(end, *p), "--%s\xd\xa"
				    "Content-Disposition: form-data; "
				      "name=\"%s\"",
				      wsi->http.multipart_boundary, name);
	if (filename)
		*p += lws_snprintf((char *)(*p), lws_ptr_diff_size_t(end, *p),
				   "; filename=\"%s\"", filename);

	if (content_type)
		*p += lws_snprintf((char *)(*p), lws_ptr_diff_size_t(end, *p), "\xd\xa"
				"Content-Type: %s", content_type);

	*p += lws_snprintf((char *)(*p), lws_ptr_diff_size_t(end, *p), "\xd\xa\xd\xa");

	return *p == end;
}

/*
 * replacement multipart state machine
 *
 * We want it to emit this kind of thing:
 *
 * POST /builds?project=warmcat%2Flibwebsockets HTTP/1.1
 * Host: 127.0.0.1
 * User-Agent: lws
 * Accept: * / *
 * Content-Length: 698
 * Content-Type: multipart/form-data; boundary=------------------------dbe229171d826cc3
 *
 * --------------------------dbe229171d826cc3
 * Content-Disposition: form-data; name="file"; filename="xxx.bin"
 * Content-Type: application/octet-stream
 *
 * #!/bin/bash -x
 * xxx
 * exit $?
 *
 * --------------------------dbe229171d826cc3
 * Content-Disposition: form-data; name="version"
 *
 * f2dcc4ea
 * --------------------------dbe229171d826cc3
 * Content-Disposition: form-data; name="description"
 * 
 * lws qa
 * --------------------------dbe229171d826cc3
 * Content-Disposition: form-data; name="token"
 *
 * mytoken
 * --------------------------dbe229171d826cc3
 * Content-Disposition: form-data; name="email"
 *
 * my@email.com
 * --------------------------dbe229171d826cc3--
 *
 */

typedef enum {
	LWS_POST_STATE__NEXT,	/* get the next form element */
	LWS_POST_STATE__STAGE,	/* send what's in stage[] */
	LWS_POST_STATE__FILE,	/* send the open file's contents */
	LWS_POST_STATE__DONE,	/* the closing delimiter has gone */
} post_state;

/*
 * The longest form element, "name=value" or "name=@path", is two less than
 * this: an element the cb filled the whole buffer with may have been
 * truncated, so it's refused.
 */
#define LWS_HTTP_MP_FT_LEN 4096

typedef struct lws_http_mp_sm {
	struct lws_context	*cx;
	lws_http_mp_sm_cb_t	cb;
	char			boundary[24 + 16 + 1];
	char			ft[LWS_HTTP_MP_FT_LEN];
	/*
	 * Everything a form element puts in the body apart from a file's
	 * contents: its delimiter and part headers, and for a field, the
	 * value and its CRLF.  Or the closing delimiter.  Room for the
	 * longest element and the fixed text around it.
	 */
	char			stage[LWS_HTTP_MP_FT_LEN + 256];
	size_t			stage_len;
	size_t			stage_pos;
	uint64_t		cl;	/* the Content-Length we declared */
	uint64_t		sent;	/* body bytes given out so far */
	int			fd;	/* -1 unless sending a file */
	lws_filepos_t		pos;
	lws_filepos_t		total;
	const char		*a; /* last hit */
	post_state		ps;
	post_state		ps_after_stage;
} lws_http_mp_sm_t;

/*
 * Get the next form element from the app's cb into phms->ft, and compose
 * everything it puts in the body, apart from a file's contents, into
 * phms->stage.  When there are no more elements, stage gets the closing
 * delimiter.
 *
 * Both lws_http_mp_sm_init(), adding up the Content-Length, and
 * lws_http_mp_sm_fill(), generating the body, get their bytes from here,
 * from the same buffers, so what is declared and what is sent can't
 * disagree about anything the app's cb gave.
 *
 * Returns -1 if the element can't be sent, 1 if there are no more elements,
 * else 0.  For a file element, *path is set to the file whose contents
 * and a CRLF follow stage, else it is NULL.
 */

static int
lws_http_mp_sm_element(struct lws_http_mp_sm *phms, const char **path)
{
	char *eq;
	int n;

	*path = NULL;

	n = phms->cb(phms->cx, phms->ft, sizeof(phms->ft), &phms->a);
	if (n < 0)
		return -1;

	phms->stage_pos = 0;

	if (n) { /* no more form elements */
		phms->stage_len = (size_t)lws_snprintf(phms->stage,
					sizeof(phms->stage), "--%s--\x0d\x0a",
					phms->boundary);

		return 1;
	}

	/* the cb is the app's code, it may not have terminated it */
	phms->ft[sizeof(phms->ft) - 1] = '\0';
	if (strlen(phms->ft) >= sizeof(phms->ft) - 1) {
		/* it may have been truncated to fit, we can't tell */
		lwsl_warn("%s: form element too long\n", __func__);

		return -1;
	}

	eq = strchr(phms->ft, '=');
	if (!eq) {
		lwsl_warn("%s: form element without '='\n", __func__);

		return -1;
	}
	*eq++ = '\0'; /* ft is the name, eq the value */

	if (!lws_http_mp_quotable(phms->ft)) {
		lwsl_warn("%s: unusable form element name\n", __func__);

		return -1;
	}

	if (*eq == '@') { /* form file contents */
		const char *fn = eq + 1, *q;

		*path = eq + 1;

		/*
		 * The server gets only the file's own name, not where it
		 * is on our side
		 */
		for (q = fn; *q; q++)
			if (*q == '/'
#if defined(WIN32)
			    || *q == '\\' || *q == ':'
#endif
			)
				fn = q + 1;

		if (!*fn || !lws_http_mp_quotable(fn)) {
			lwsl_warn("%s: unusable form file name\n", __func__);

			return -1;
		}

		n = lws_snprintf(phms->stage, sizeof(phms->stage),
				 "--%s\x0d\x0a"
				 "Content-Disposition: form-data; name=\"%s\"; "
							"filename=\"%s\"\x0d\x0a"
				 "Content-Type: application/octet-stream"
							"\x0d\x0a\x0d\x0a",
				 phms->boundary, phms->ft, fn);
	} else
		n = lws_snprintf(phms->stage, sizeof(phms->stage),
				 "--%s\x0d\x0a"
				 "Content-Disposition: form-data; name=\"%s\""
							"\x0d\x0a\x0d\x0a"
				 "%s\x0d\x0a",
				 phms->boundary, phms->ft, eq);

	/* lws_snprintf() says the whole size if it had to truncate */
	if ((size_t)n >= sizeof(phms->stage)) {
		lwsl_warn("%s: form element too long\n", __func__);

		return -1;
	}
	phms->stage_len = (size_t)n;

	return 0;
}

struct lws_http_mp_sm *
lws_http_mp_sm_init(struct lws *wsi, lws_http_mp_sm_cb_t cb, uint8_t **p, uint8_t *end)
{
	struct lws_http_mp_sm *phms;
	char cla[128];
	const char *path;
	struct stat s;
	int n;

	phms = lws_zalloc(sizeof(*phms), __func__);
	if (!phms)
		return NULL;
	phms->cb = cb;
	phms->cx = lws_get_context(wsi);
	phms->fd = -1;

	for (n = 0; n < 24; n++)
		phms->boundary[n] = '-';
	/* 16 hex chars and the NUL */
	if (lws_hex_random(phms->cx, phms->boundary + 24,
			   sizeof(phms->boundary) - 24))
		goto bail;

	n = lws_snprintf(cla, sizeof(cla), "multipart/form-data; boundary=%s", phms->boundary);
	if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE,
		     (const uint8_t *)cla, n, p, end)) {
		lwsl_warn("%s: failed to set content_type\n", __func__);
		goto bail;
	}

	/*
	 * We have to now add together the length of everything we will put in
	 * the body, in order to know the content-length now at header-time.
	 *
	 * That includes the multipart boundaries, headers, and CRLF delimiters.
	 */

	do {
		n = lws_http_mp_sm_element(phms, &path);
		if (n < 0)
			goto bail;

		phms->cl += phms->stage_len;
		if (n)
			break;

		if (path) {
			if (stat(path, &s) || s.st_size < 0) {
				lwsl_warn("%s: failed to stat %s\n", __func__,
					  path);
				goto bail;
			}

			phms->cl += (uint64_t)s.st_size + 2 /* ending CRLF */;
		}
	} while (1);

	if (lws_add_http_header_content_length(wsi, phms->cl, p, end))
		goto bail;

	/* lws_http_mp_sm_fill() starts the form again from the beginning */

	phms->a		= NULL;
	phms->ps	= LWS_POST_STATE__NEXT;

	return phms;

bail:
	lws_free(phms);

	return NULL;
}

void
lws_http_mp_sm_destroy(struct lws_http_mp_sm **pphms)
{
	if (*pphms) {
		/* abandoned while sending a file */
		if ((*pphms)->fd != -1)
			close((*pphms)->fd);
		lws_free(*pphms);
		*pphms = NULL;
	}
}

/*
 * Everything that goes in the body is counted here before it's given out:
 * whatever happened since the Content-Length was computed, we never send
 * more than it said, so the end of the body is where the peer expects it.
 */

static int
lws_http_mp_sm_budget(struct lws_http_mp_sm *phms, uint64_t len)
{
	if (len > phms->cl - phms->sent) {
		lwsl_warn("%s: form changed since it was sized, it no longer "
			  "fits the Content-Length\n", __func__);

		return 1;
	}

	return 0;
}

int
lws_http_mp_sm_fill(struct lws_http_mp_sm *phms, uint8_t **p, uint8_t *end)
{
	const char *path;
	struct stat s;
	size_t chunk;
	ssize_t r;
	int n;

	assert(phms);

	while (phms->ps != LWS_POST_STATE__DONE && *p < end) {

		switch (phms->ps) {
		case LWS_POST_STATE__NEXT:
			n = lws_http_mp_sm_element(phms, &path);
			if (n < 0)
				goto fail;

			if (n && phms->sent + phms->stage_len != phms->cl) {
				/* eg, a file got shorter since it was sized */
				lwsl_warn("%s: form changed since it was "
					  "sized\n", __func__);
				goto fail;
			}

			phms->ps = LWS_POST_STATE__STAGE;
			phms->ps_after_stage = n ? LWS_POST_STATE__DONE :
						   LWS_POST_STATE__NEXT;
			if (!path)
				break;

			phms->fd = lws_open(path, LWS_O_RDONLY);
			if (phms->fd == -1) {
				lwsl_warn("%s: unable to open '%s'\n",
					  __func__, path);
				goto fail;
			}
			if (fstat(phms->fd, &s) || s.st_size < 0) {
				lwsl_warn("%s: failed to stat %s\n", __func__,
					  path);
				goto fail;
			}
			phms->pos = 0;
			phms->total = (lws_filepos_t)s.st_size;
			phms->ps_after_stage = LWS_POST_STATE__FILE;
			break;

		case LWS_POST_STATE__STAGE:
			chunk = phms->stage_len - phms->stage_pos;
			if (chunk > lws_ptr_diff_size_t(end, *p))
				chunk = lws_ptr_diff_size_t(end, *p);
			if (lws_http_mp_sm_budget(phms, chunk))
				goto fail;

			memcpy(*p, phms->stage + phms->stage_pos, chunk);
			*p += chunk;
			phms->sent += chunk;
			phms->stage_pos += chunk;

			if (phms->stage_pos == phms->stage_len)
				phms->ps = phms->ps_after_stage;
			break;

		case LWS_POST_STATE__FILE:
			if (phms->pos == phms->total) {
				close(phms->fd);
				phms->fd = -1;
				/* the CRLF ending the file's part */
				phms->stage[0] = '\x0d';
				phms->stage[1] = '\x0a';
				phms->stage_len = 2;
				phms->stage_pos = 0;
				phms->ps = LWS_POST_STATE__STAGE;
				phms->ps_after_stage = LWS_POST_STATE__NEXT;
				break;
			}

			/*
			 * Never read past the size we sized it at, even if the
			 * file grew since
			 */
			chunk = lws_ptr_diff_size_t(end, *p);
			if (chunk > phms->total - phms->pos)
				chunk = (size_t)(phms->total - phms->pos);
			if (lws_http_mp_sm_budget(phms, chunk))
				goto fail;

			r = read(phms->fd, *p, LWS_POSIX_LENGTH_CAST(chunk));
			if (r <= 0) {
				/*
				 * A file that ends early, eg, truncated since
				 * we sized it, can't make up the length we
				 * declared
				 */
				lwsl_warn("%s: %s\n", __func__, r ?
						"unable to read" :
						"file ended early");
				goto fail;
			}

			*p += r;
			phms->sent += (uint64_t)r;
			phms->pos += (uint64_t)r;
			break;

		case LWS_POST_STATE__DONE:
			break;
		}
	}

	return phms->ps != LWS_POST_STATE__DONE; /* 1 = more to do */

fail:
	if (phms->fd != -1) {
		close(phms->fd);
		phms->fd = -1;
	}

	return -1;
}


/*
 * Does the request head composed so far, from head to end, frame a body:
 * does it have a Content-Length or a Transfer-Encoding?  The app writes
 * these as header lines (lws_add_http_header_by_token(), or by hand), in
 * whatever case, so each line's start is compared case-insensitively.
 */
static int
lws_h1_client_head_frames_body(const char *head, const char *end)
{
	static const char * const names[] = { "content-length:",
					      "transfer-encoding:" };
	const char *p = head;

	while (p < end) {
		size_t n;

		for (n = 0; n < LWS_ARRAY_SIZE(names); n++) {
			size_t l = strlen(names[n]);

			if ((size_t)(end - p) > l &&
			    !strncasecmp(p, names[n], l))
				return 1;
		}
		/* to the start of the next line */
		while (p < end && *p != '\n')
			p++;
		if (p < end)
			p++;
	}

	return 0;
}

char *
lws_generate_client_handshake(struct lws *wsi, char *pkt, size_t pkt_len)
{
	const char *meth, *pp = lws_hdr_simple_ptr(wsi,
				_WSI_TOKEN_CLIENT_SENT_PROTOCOLS), *path;
	char *p = pkt, *p1, *end = p + pkt_len;

	meth = lws_hdr_simple_ptr(wsi, _WSI_TOKEN_CLIENT_METHOD);
	if (!meth) {
		meth = "GET";
#if defined(LWS_ROLE_WS)
		wsi->do_ws = wsi->ws ? 1 : 0;
#else
		wsi->do_ws = 0;
#endif
	} else {
		wsi->do_ws = 0;
	}

	if (!strcmp(meth, "RAW")) {
		lws_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);
		lwsl_notice("client transition to raw\n");

		if (pp) {
			const struct lws_protocols *pr;

			pr = lws_vhost_name_to_protocol(wsi->a.vhost, pp);

			if (!pr) {
				lwsl_err("protocol %s not enabled on vhost\n",
					 pp);
				return NULL;
			}

			lws_bind_protocol(wsi, pr, __func__);
		}

		if ((wsi->a.protocol->callback)(wsi, LWS_CALLBACK_RAW_ADOPT,
					      wsi->user_space, NULL, 0))
			return NULL;

		lws_wsi_event(wsi, LWS_WSIEV_RAW_UPGRADED);
		lws_header_table_detach(wsi, 1);

		return NULL;
	}

	/*
	 * 04 example client handshake
	 *
	 * GET /chat HTTP/1.1
	 * Host: server.example.com
	 * Upgrade: websocket
	 * Connection: Upgrade
	 * Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
	 * Sec-WebSocket-Origin: http://example.com
	 * Sec-WebSocket-Protocol: chat, superchat
	 * Sec-WebSocket-Version: 4
	 */

	path = lws_hdr_simple_ptr(wsi, _WSI_TOKEN_CLIENT_URI);
	if (!path) {
		if (wsi->stash && wsi->stash->cis[CIS_PATH] &&
			wsi->stash->cis[CIS_PATH][0])
			path = wsi->stash->cis[CIS_PATH];
		else
			path = "/";
	}

	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
			  "%s %s HTTP/1.1\x0d\x0a", meth, path);

	if (!(wsi->flags & LCCSCF_HTTP_NO_CACHE_CONTROL))
		p += lws_snprintf(p,  lws_ptr_diff_size_t(end, p),
				  "Pragma: no-cache\x0d\x0a"
				  "Cache-Control: no-cache\x0d\x0a");

	const char *host = lws_wsi_client_stash_item(wsi, CIS_HOST, _WSI_TOKEN_CLIENT_HOST);
	if (host) {
		char v6[64];

		p += lws_snprintf(p,  lws_ptr_diff_size_t(end, p),
				  "Host: %s\x0d\x0a",
				  lws_http_client_authority(host, v6,
							    sizeof(v6)));
	}

	const char *origin = lws_wsi_client_stash_item(wsi, CIS_ORIGIN, _WSI_TOKEN_CLIENT_ORIGIN);
	if (origin) {
		char v6[64];

		if (lws_check_opt(wsi->a.context->options,
				  LWS_SERVER_OPTION_JUST_USE_RAW_ORIGIN))
			p += lws_snprintf(p,  lws_ptr_diff_size_t(end, p),
					  "Origin: %s\x0d\x0a", origin);
		else
			/* the origin's host is an authority, like Host's */
			p += lws_snprintf(p,  lws_ptr_diff_size_t(end, p),
					  "Origin: %s://%s\x0d\x0a",
					  wsi->flags & LCCSCF_USE_SSL ?
							 "https" : "http",
					  lws_http_client_authority(origin, v6,
								    sizeof(v6)));
	}

	if (wsi->flags & LCCSCF_HTTP_MULTIPART_MIME) {
		p1 = (char *)lws_http_multipart_headers(wsi, (uint8_t *)p,
							(uint8_t *)end);
		if (!p1)
			return NULL;
		p = p1;
	}

	/*
	 * A proxied onward leg used to copy Content-Length, Authorization and
	 * Content-Type from the parent's ah here, and splice the parent's
	 * extra onward headers in verbatim.  Both now happen in the proxy's
	 * LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER handler, from the
	 * snapshot lws_http_proxy_start() took while the ah was attached, so
	 * the composer has no dependency on the parent's ah (C-460), and the
	 * same replay serves an h2 onward leg, which never saw them before.
	 */

#if defined(LWS_WITH_HTTP_DIGEST_AUTH)
    if (wsi->http.digest_auth_hdr) {
        p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
			  "Authorization: %s\x0d\x0a",
                          wsi->http.digest_auth_hdr);
        lws_free(wsi->http.digest_auth_hdr);
        wsi->http.digest_auth_hdr = NULL;
    }
#endif

#if defined(LWS_ROLE_WS)
	if (wsi->do_ws) {
		const char *conn1 = "";
	//	if (!wsi->client_pipeline)
	//		conn1 = "close, ";
		p = lws_generate_client_ws_handshake(wsi, p, conn1,
						     lws_ptr_diff_size_t(end, p));
                if (!p)
                    return NULL;
	} else
#endif
	{
		if (!wsi->client_pipeline)
			p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
					  "connection: close\x0d\x0a");
	}

	/* give userland a chance to append, eg, cookies */

#if defined(LWS_WITH_CACHE_NSCOOKIEJAR) && defined(LWS_WITH_CLIENT)
	if ((wsi->flags & LCCSCF_CACHE_COOKIES) &&
	    lws_cookie_send_cookies(wsi, &p, end)) {
		/* better no request than one carrying scratch as cookies */
		lwsl_wsi_err(wsi, "cookie jar attach failed");

		return NULL;
	}
#endif

	/*
	 * lws_snprintf() returns size on truncation, so if any emit above did
	 * not fit, p is sitting exactly on end and everything after it was
	 * silently dropped.  We must not go on to tell the user callback how
	 * much room is left by subtracting from that, since the result
	 * underflows to ~4GB and any bound the callback derives from it is
	 * then meaningless.  A truncated request head is not something we can
	 * send anyway, so fail the connection.
	 */

	if (lws_ptr_diff(end, p) <= 12) {
		lwsl_wsi_err(wsi, "request head too long for pt compose_buf");

		return NULL;
	}

	if (wsi->a.protocol->callback(wsi,
			LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER,
			wsi->user_space, &p,
			lws_ptr_diff_size_t(end, p) - 12))
		return NULL;

	if (wsi->flags & LCCSCF_HTTP_X_WWW_FORM_URLENCODED) {
		p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "Content-Type: application/x-www-form-urlencoded\x0d\x0a");
		p += lws_snprintf(p,  lws_ptr_diff_size_t(end, p), "Content-Length: %lu\x0d\x0a", wsi->http.writeable_len);
		lws_client_http_body_pending(wsi, 1);
	}

	/*
	 * A body is to follow the head (lws_client_http_body_pending()), and
	 * the head says nothing of how it is framed: neither a Content-Length
	 * nor a Transfer-Encoding came from the app.  No server can know
	 * where such a body ends: RFC 9112 6.3 has a request with neither
	 * header carry no body at all, and what follows its head taken as
	 * the next request.  So it goes chunked: lws_write() frames each
	 * piece as a chunk, and the final piece is followed by the
	 * last-chunk (rops_write_role_protocol_h1()).  An app that knows its
	 * body's length adds the Content-Length itself and is left alone.
	 */
	wsi->http.client_body_chunked = 0;
	if (wsi->client_http_body_pending &&
	    !lws_h1_client_head_frames_body(pkt, p) && p < end) {
		lwsl_wsi_notice(wsi, "body with no Content-Length: sending it "
				     "chunked");
		p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
				  "Transfer-Encoding: chunked\x0d\x0a");
		wsi->http.client_body_chunked = 1;
	}

	p += lws_snprintf(p,  lws_ptr_diff_size_t(end, p), "\x0d\x0a");

	/*
	 * Same again for anything the user callback and the tail emitted...
	 * if p ended up on end, the head is truncated (it may not even have
	 * its terminating CRLF) and must not be sent
	 */

	if (p >= end) {
		lwsl_wsi_err(wsi, "request head truncated");

		return NULL;
	}

	if (wsi->client_http_body_pending || lws_has_buffered_out(wsi))
		lws_callback_on_writable(wsi);

	lws_metrics_caliper_bind(wsi->cal_conn, wsi->a.context->mt_http_txn);
#if defined(LWS_WITH_CONMON)
	wsi->conmon_datum = lws_wsi_now(wsi);
#endif

	// puts(pkt);

	return p;
}

#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2) || defined(LWS_ROLE_H3)
#if defined(LWS_WITH_HTTP_BASIC_AUTH)

int
lws_http_basic_auth_gen2(const char *user, const void *pw, size_t pwd_len,
			 char *buf, size_t len)
{
	size_t n = strlen(user), m = pwd_len;
	char b[128];

	if (len < 6 + ((4 * (n + m + 1)) / 3) + 1)
		return 1;

	memcpy(buf, "Basic ", 6);

	n = (unsigned int)lws_snprintf(b, sizeof(b), "%s:", user);
	if ((n + pwd_len) >= sizeof(b) - 2)
		return 2;

	memcpy(&b[n], pw, pwd_len);
	n += pwd_len;

	lws_b64_encode_string(b, (int)n, buf + 6, (int)len - 6);
	buf[len - 1] = '\0';

	return 0;
}

int lws_http_basic_auth_gen(const char *user, const char *pw, char *buf, size_t len)
{
	return lws_http_basic_auth_gen2(user, pw, strlen(pw), buf, len);
}

#endif

/*
 * sansIO body rx for an http client: the bytes the app pulled with
 * lws_http_client_read(), or none when the transport ended.  Strips any
 * chunked framing, delivers the payload to the app in
 * LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ (a callback per chunk block), keeps
 * the content accounting and completes the transaction when the body is
 * done.  Returns the bytes taken, or -1: the caller closes the wsi.
 */
int
lws_h1_client_body_rx(struct lws *wsi, uint8_t *buf, size_t len)
{
	unsigned char *p = buf;
	int rem = (int)len, consumed = 0, n;

	if (!len) {
		if (!lwsi_hdrs_pending(wsi) &&
		    !wsi->http.content_length_given && !wsi->http.rx_chunked) {
			/*
			 * We had the headers from this stream, but as there
			 * was no content-length: we had to wait until the
			 * stream ended to inform the user code the transaction
			 * has completed to the best of our knowledge
			 */
			lwsl_wsi_info(wsi, "body ended with the stream");
			if (lws_http_transaction_completed_client(wsi))
				/* closing anyway, the api has warn_unused_result */
				return -1;
		}

		return -1;
	}

	/*
	 * server may insist on transfer-encoding: chunked,
	 * so http client must deal with it
	 */
spin_chunks:
	if (wsi->http.rx_chunked) {
		unsigned char *b = p;
		size_t l = (size_t)rem;

		/* consume any chunk framing before the next payload bytes */

		n = lws_http_dechunk_framing(wsi, &b, &l);
		consumed += rem - (int)l;
		p = b;
		rem = (int)l;

		if (n < 0)
			return -1;

		if (n > 0)
			/* that was the terminating chunk */
			goto completed;

		if (!rem)
			/* need more to get to the next payload bytes */
			return consumed;
	}

	if (wsi->http.rx_content_remain &&
	    wsi->http.rx_content_remain < (unsigned int)rem)
		n = (int)wsi->http.rx_content_remain;
	else
		n = rem;

	if (wsi->http.rx_chunked && wsi->http.chunk_remaining &&
	    wsi->http.chunk_remaining < n)
		n = wsi->http.chunk_remaining;

#if defined(LWS_WITH_HTTP_PROXY) && defined(LWS_WITH_HUBBUB)
	/* hubbub */
	if (wsi->http.perform_rewrite)
		lws_rewrite_parse(wsi->http.rw, p, n);
	else
#endif
	{
		if (
#if defined(LWS_WITH_HTTP_PROXY)
		    !wsi->protocol_bind_balance ==
		    !!wsi->http.proxy_clientside
#else
		    !!wsi->protocol_bind_balance
#endif
		  ) {
			if (user_callback_handle_rxflow(wsi->a.protocol->callback,
					wsi, LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ,
					wsi->user_space, p, (unsigned int)n)) {
				lwsl_wsi_info(wsi, "RECEIVE_CLIENT_HTTP_READ refused");

				return -1;
			}
		} else
			lwsl_wsi_notice(wsi, "swallowed read (%d)", n);
	}

	p += n;
	rem -= n;
	if (wsi->http.rx_chunked && wsi->http.chunk_remaining)
		wsi->http.chunk_remaining -= n;

	consumed += n;

	if (wsi->http.rx_chunked && !wsi->http.chunk_remaining)
		wsi->http.chunk_parser = ELCP_POST_CR;

	if (wsi->http.rx_chunked && rem)
		goto spin_chunks;

	if (wsi->http.rx_chunked)
		return consumed;

	/* if we know the content length, decrement the content remaining */
	if (wsi->http.rx_content_length > 0)
		wsi->http.rx_content_remain -= (unsigned int)n;

	if (wsi->http.rx_content_remain || !wsi->http.content_length_given)
		return consumed;

completed:
	if (lws_http_transaction_completed_client(wsi)) {
		lwsl_wsi_info(wsi, "transaction completed says -1");

		return -1;
	}

	return consumed;
}

#endif

static uint8_t hnames2[] = {
	_WSI_TOKEN_CLIENT_ORIGIN,
	_WSI_TOKEN_CLIENT_SENT_PROTOCOLS,
	_WSI_TOKEN_CLIENT_METHOD,
	_WSI_TOKEN_CLIENT_IFACE
};

/**
 * lws_client_reset() - retarget a connected wsi to start over with a new
 * 			connection (ie, redirect)
 *			this only works if still in HTTP, ie, not upgraded yet
 * wsi:		connection to reset
 * address:	network address of the new server
 * port:	port to connect to
 * path:	uri path to connect to on the new server
 * host:	host header to send to the new server
 * method:	method to use instead of the request's (a redirect that says
 *		to follow it with a GET), or NULL to keep the request's
 */
struct lws *
lws_client_reset(struct lws **pwsi, int ssl, const char *address, int port,
		const char *path, const char *host, const char *method,
		char weak)
{
#if defined(LWS_ROLE_WS)
	struct _lws_websocket_related *ws;
#endif
	const char *cisin[CIS_COUNT];
	unsigned int keepalive_rejected;
	struct lws *wsi;
	size_t o;
	int n;

	if (!pwsi)
		return NULL;

	wsi = *pwsi;

	if (!address)
		return NULL;

	if (!lws_client_retarget_allowed(wsi, address)) {
		lwsl_wsi_err(wsi, "refusing retarget to or from a unix socket");
		return NULL;
	}

	/*
	 * A server that refused keep-alive is still refusing it if we are
	 * going back to it (a digest auth retry, or a redirect to itself):
	 * the retargeted request must not try to share a connection with it
	 */
	keepalive_rejected = wsi->keepalive_rejected && wsi->stash &&
			     wsi->c_port == port &&
			     wsi->stash->cis[CIS_ADDRESS] &&
			     !strcmp(wsi->stash->cis[CIS_ADDRESS], address);

	lwsl_debug("%s: %s: redir %d: %s\n", __func__, lws_wsi_tag(wsi),
			wsi->redirects, address);

	if (wsi->redirects == 4) {
		lwsl_err("%s: Too many redirects\n", __func__);
		return NULL;
	}
	wsi->redirects++;

	/*
	 * goal is to close our role part, close the sockfd, detach the ah
	 * but leave our wsi extant and still bound to whatever vhost it was
	 */

	o = path[0] == '/' && path[1] == '/';

	memset((char *)cisin, 0, sizeof(cisin));

	cisin[CIS_ADDRESS]	= address;
	cisin[CIS_PATH]		= path + o;
	cisin[CIS_HOST]		= host;

	/*
	 * The request's own items, from the stash when there is one (a QUIC
	 * attempt keeps its request there, and so must a fallback to tcp
	 * still asking for its ws protocol), else from the _WSI_TOKEN_CLIENT_*
	 * tokens in the ah.  Never from anything the response put in the ah:
	 * a server's ":method" in its response is not the method to follow
	 * its redirect with.
	 */
	for (n = 0; n < (int)LWS_ARRAY_SIZE(hnames2); n++)
		cisin[n + 3] = lws_wsi_client_stash_item(wsi, n + 3,
							 hnames2[n]);

	if (method)
		cisin[CIS_METHOD] = method;

#if defined(LWS_WITH_TLS)
	cisin[CIS_ALPN]		= wsi->alpn;
#endif

	if (!port) {
		lwsl_info("%s: forcing port 443\n", __func__);

		port = 443;
		ssl = 1;
	}

	wsi->c_port = (uint16_t)port;

	wsi->flags = (wsi->flags & (~LCCSCF_USE_SSL)) |
		(ssl ? LCCSCF_USE_SSL : 0);

	if (!cisin[CIS_ALPN] || !cisin[CIS_ALPN][0])
#if defined(LWS_ROLE_H2)
		cisin[CIS_ALPN] = "h2,http/1.1";
#else
	cisin[CIS_ALPN] = "http/1.1";
#endif

#if (_LWS_ENABLED_LOGS & LLL_NOTICE)
	{
		char lp[128];

		/* F-016: a followed redirect's query may carry a token */
		lwsl_notice("%s: REDIRECT %d: %s %s:%d, path='%s', ssl = %d, "
			    "alpn='%s'\n", __func__, wsi->stream.ah ?
				(int)wsi->stream.ah->http_response : 0,
			    cisin[CIS_METHOD] ? cisin[CIS_METHOD] : "(null)",
			    address, port, lws_http_log_path(lp, sizeof(lp),
							     path),
			    ssl, cisin[CIS_ALPN]);
	}
#endif

	{
		/*
		 * The wsi's own binding is the live one: a stash that
		 * survived the first connect may carry none (the redirect
		 * case: it was what the post-close restore in the redirect
		 * path used to put back), and when we are reset from inside
		 * the close flow (the h3 grace timer, a failed QUIC attempt
		 * falling back to tcp) the stash is already gone.  Fall back
		 * to the stash only if the wsi has no binding.
		 */
		void *opaque = wsi->a.opaque_user_data;

		if (!opaque && wsi->stash)
			opaque = wsi->stash->opaque_user_data;

		if (lws_client_stash_create(wsi, cisin))
			return NULL;

		wsi->stash->opaque_user_data = opaque;
	}

	/* the old transport is no longer watched; the close releases it */
	__lws_io_close_transport(wsi, LWS_IOCLOSE_UNWATCH);

#if defined(LWS_ROLE_WS)
	if (weak) {
		ws = wsi->ws;
		wsi->ws = NULL;
	}
#endif

	/*
	 * After this point we can't trust the incoming strings like address,
	 * path any more, since they may have been pointing into the old ah.
	 *
	 * We must use the copies in the wsi->stash instead if we want them.
	 */

	__lws_reset_wsi(wsi); /* detaches ah here */
#if defined(LWS_ROLE_WS)
	if (weak)
		wsi->ws = ws;
#endif
	/* the retargeted request pipelines only if the user said it may */
	wsi->keepalive_rejected = !!keepalive_rejected;
	wsi->client_pipeline = !!(wsi->flags & LCCSCF_PIPELINE) &&
			       !keepalive_rejected;

	/*
	 * A redirect that changed the method to GET also drops the body: the
	 * app learns not to send it again from lws_http_is_redirected_to_get().
	 * One that kept the method (any 307 / 308, a 301 / 302 to a PUT) has
	 * the app send the body again.
	 */
	wsi->redirected_to_get = method && !strcmp(method, "GET");

	/*
	 * Will complete at close flow: the close sees the restarting phase and
	 * hands the wsi back to the connect path instead of freeing it
	 */

	lws_wsi_event(wsi, LWS_WSIEV_RETARGET);

	return *pwsi;
}
