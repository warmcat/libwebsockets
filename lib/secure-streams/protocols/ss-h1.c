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
 *
 * This is the glue that wires up h1 to Secure Streams.
 */

#include <private-lib-core.h>

#if !defined(LWS_PLAT_FREERTOS) || defined(LWS_ROLE_H2)
#define LWS_WITH_SS_RIDESHARE
#endif

#if defined(LWS_WITH_SS_RIDESHARE)

/*
 * Issue q[from] up to q[to] of the current part to the app, adding SOM if it
 * is the first piece of the part.  Nothing is issued for an empty range
 * unless it carries the EOM.
 *
 * If it doesn't return LWSSSSRET_OK, h may have been destroyed.
 */

static lws_ss_state_return_t
ss_http_multipart_issue(lws_ss_handle_t *h, const uint8_t *q, size_t from,
			size_t to, int flags)
{
	size_t len = to > from ? to - from : 0;

	if (!len && !(flags & LWSSS_FLAG_EOM))
		return LWSSSSRET_OK;

	if (!h->u.http.som) {
		flags |= LWSSS_FLAG_SOM;
		h->u.http.som = 1;
	}
	if (flags & LWSSS_FLAG_EOM)
		h->u.http.som = 0; /* the next part gets a SOM */

	return h->info.rx(ss_to_userobj(h), len ? q + from : NULL, len, flags);
}

/*
 * Deframe an incoming multipart body (RFC 2046 5.1.1) into one SOM .. EOM
 * message per part, the part's own headers included.  The group of parts is
 * bracketed by zero-length RELATED_START and RELATED_END messages.  The
 * preamble before the first delimiter and the epilogue after the close
 * delimiter are discarded.
 *
 * The body comes to us in pieces split wherever the peer likes, eg, at each
 * chunk of an h1 chunked body or each h2 / h3 DATA frame, so a delimiter may
 * straddle any number of calls.  We never keep pointers into an earlier
 * call's buffer: the bytes we are holding back because they may be the start
 * of a delimiter are by definition the first boundary_seq bytes of
 * u.http.boundary, so if the match fails, they can be issued from there.
 *
 * "held" is how many of the matched bytes came from earlier calls.  Once a
 * match fails, held is zero and any matched bytes are all in q[] after s.
 */

static int
ss_http_multipart_parser(lws_ss_handle_t *h, struct lws *wsi, void *in,
			 size_t len)
{
	const uint8_t *q = (const uint8_t *)in;
	uint8_t held = h->u.http.boundary_seq;
	lws_ss_state_return_t r;
	size_t n, s = 0; /* q[s] is the first part byte not yet issued */

	for (n = 0; n < len; n++) {

		switch (h->u.http.mp_state) {
		case LWSSS_MP_PREAMBLE:
		case LWSSS_MP_PART:
			if (q[n] != (uint8_t)
				   h->u.http.boundary[h->u.http.boundary_seq]) {
				if (!h->u.http.boundary_seq)
					break;

				/*
				 * It wasn't a delimiter after all, so what we
				 * held back from earlier calls is part content
				 */
				if (held && h->u.http.mp_state == LWSSS_MP_PART) {
					r = ss_http_multipart_issue(h,
						(const uint8_t *)h->u.http.boundary,
						0, held, 0);
					if (r != LWSSSSRET_OK)
						return _lws_ss_handle_state_ret_CAN_DESTROY_HANDLE(
								r, wsi, &h);
				}
				held = 0;

				/*
				 * The CR the delimiter starts with appears
				 * nowhere else in it (lws_tokenize never gives
				 * us a boundary token containing whitespace),
				 * so this byte is the only place a new match
				 * can start
				 */
				h->u.http.boundary_seq =
					q[n] == (uint8_t)h->u.http.boundary[0];
				break;
			}

			if (++h->u.http.boundary_seq != h->u.http.boundary_len)
				break;

			/*
			 * A complete CRLF--boundary.  Any part we were in
			 * ended where it started: that's in q[] unless it
			 * started in an earlier call, when this call has none
			 * of the part and it is complete with what we already
			 * issued.
			 */
			if (h->u.http.mp_state == LWSSS_MP_PART) {
				r = ss_http_multipart_issue(h, q, s, held ? s :
					n + 1 - h->u.http.boundary_len,
					LWSSS_FLAG_EOM);
				if (r != LWSSSSRET_OK)
					return _lws_ss_handle_state_ret_CAN_DESTROY_HANDLE(
								r, wsi, &h);
			}
			held = 0;
			h->u.http.boundary_seq = 0;
			h->u.http.mp_state = LWSSS_MP_TAIL;
			break;

		case LWSSS_MP_TAIL:
		case LWSSS_MP_TAIL_LWSP:
			/*
			 * After the boundary, either "--" for the close
			 * delimiter, or optional linear whitespace and CRLF
			 */
			if (q[n] == '-' && h->u.http.mp_state == LWSSS_MP_TAIL)
				h->u.http.mp_state = LWSSS_MP_TAIL_DASH;
			else if (q[n] == ' ' || q[n] == '\t')
				h->u.http.mp_state = LWSSS_MP_TAIL_LWSP;
			else if (q[n] == '\r')
				h->u.http.mp_state = LWSSS_MP_TAIL_CR;
			else
				goto malformed;
			break;

		case LWSSS_MP_TAIL_CR:
			if (q[n] != '\n')
				goto malformed;

			/* the next part starts with the next byte */
			h->u.http.mp_state = LWSSS_MP_PART;
			s = n + 1;
			break;

		case LWSSS_MP_TAIL_DASH:
			if (q[n] != '-')
				goto malformed;

			/* the close delimiter: the group is complete */
			h->u.http.mp_state = LWSSS_MP_EPILOGUE;
			r = h->info.rx(ss_to_userobj(h), NULL, 0,
				       LWSSS_FLAG_RELATED_END);
			if (r != LWSSSSRET_OK)
				return _lws_ss_handle_state_ret_CAN_DESTROY_HANDLE(
								r, wsi, &h);

			/*
			 * Peer may not END_STREAM us
			 */
			return 0;

		default: /* LWSSS_MP_EPILOGUE */
			return 0;
		}
	}

	if (h->u.http.mp_state != LWSSS_MP_PART)
		return 0;

	/*
	 * Issue what we have of the part, less the end of q[] we are holding
	 * back because it may be the start of a delimiter
	 */

	r = ss_http_multipart_issue(h, q, s,
				    len - (size_t)(h->u.http.boundary_seq - held),
				    0);
	if (r != LWSSSSRET_OK)
		return _lws_ss_handle_state_ret_CAN_DESTROY_HANDLE(r, wsi, &h);

	return 0;

malformed:
	lwsl_ss_notice(h, "malformed multipart delimiter");

	return -1;
}
#endif

/*
 * Returns 0, or the ss state resp maps on to
 */

static int
lws_ss_http_resp_to_state(lws_ss_handle_t *h, int resp)
{
	const lws_ss_http_respmap_t *r = h->policy->u.http.respmap;
	int n = h->policy->u.http.count_respmap;

	while (n--)
		if (resp == r->resp)
			return r->state;
		else
			r++;

	return 0; /* no hit */
}

/*
 * Metadata values are length-delimited blobs, they are NOT necessarily NUL-
 * terminated (eg, _lws_ss_alloc_set_metadata() allocates exactly the length it
 * was given, and the value may have come from a peer's header).  So we can't
 * hand one to atoi().  We only need to know if it's a nonzero decimal number.
 */

static int
ss_md_nonzero_num(const void *value, size_t len)
{
	const uint8_t *p = (const uint8_t *)value;
	size_t n;

	for (n = 0; n < len; n++) {
		if (p[n] < '0' || p[n] > '9')
			return 0; /* not (or no longer) a decimal number */
		if (p[n] != '0')
			return 1;
	}

	return 0;
}

/*
 * This converts any set metadata items into outgoing http headers
 */

static int
lws_apply_metadata(lws_ss_handle_t *h, struct lws *wsi, uint8_t *buf,
		   uint8_t **pp, uint8_t *end)
{
	lws_ss_metadata_t *polmd = h->policy->metadata;
	int m = 0;

	while (polmd) {

		/* has to have a non-empty header string */

		if (polmd->value__may_own_heap &&
		    ((uint8_t *)polmd->value__may_own_heap)[0] &&
		    h->metadata[m].value__may_own_heap) {
			if (lws_add_http_header_by_name(wsi,
					polmd->value__may_own_heap,
					h->metadata[m].value__may_own_heap,
					(int)h->metadata[m].length, pp, end))
			        return -1;

			/*
			 * Check for the case he's setting a non-zero
			 * content-length "via the backdoor" metadata-
			 * driven headers, and set the body_pending()
			 * state if so...
			 */

			if (!strncmp(polmd->value__may_own_heap, "content-length", 14) &&
			    ss_md_nonzero_num(h->metadata[m].value__may_own_heap,
					      h->metadata[m].length))
				lws_client_http_body_pending(wsi, 1);
		}

		m++;
		polmd = polmd->next;
	}

	/*
	 * POST / PUT / PATCH carry the body the stream's tx gives, up to its
	 * EOM.  Content-length if we have the length information... otherwise
	 * the h1 request composer sends the body chunked, since a request
	 * with neither header has no body (RFC 9112 6.3)
	 */

	if (h->policy->u.http.method && (
#if defined(LWS_WITH_HTTP_UNCOMMON_HEADERS) || defined(LWS_HTTP_HEADERS_ALL)
		 !strcmp(h->policy->u.http.method, "PATCH") ||
		 !strcmp(h->policy->u.http.method, "PUT") ||
#endif
		(!strcmp(h->policy->u.http.method, "POST")))) {
		if (wsi->http.writeable_len) {
			if (!(h->policy->flags &
				LWSSSPOLF_HTTP_NO_CONTENT_LENGTH)) {
				int n = lws_snprintf((char *)buf, 20, "%u",
					(unsigned int)wsi->http.writeable_len);
				if (lws_add_http_header_by_token(wsi,
						WSI_TOKEN_HTTP_CONTENT_LENGTH,
						buf, n, pp, end))
					return -1;
			}
			lws_client_http_body_pending(wsi, 1);
		} else if (h->info.tx
#if defined(LWS_WITH_SERVER)
			   && !(h->info.flags & LWSSSINFLAGS_ACCEPTED)
#endif
			  )
			lws_client_http_body_pending(wsi, 1);
	}

	return 0;
}


#if defined(LWS_WITH_SS_DIRECT_PROTOCOL_STR)
static int
lws_apply_instant_metadata(lws_ss_handle_t *h, struct lws *wsi, uint8_t *buf,
		   uint8_t **pp, uint8_t *end)
{
	lws_ss_metadata_t *imd = h->instant_metadata;

	while (imd) {
		if (imd->name && imd->value__may_own_heap) {
			lwsl_debug("%s add header %s %s %d\n", __func__,
					           imd->name,
			                           (char *)imd->value__may_own_heap,
						   (int)imd->length);
			if (lws_add_http_header_by_name(wsi,
					(const unsigned char *)imd->name,
					(const unsigned char *)imd->value__may_own_heap,
					(int)imd->length, pp, end))
				return -1;

			/* it's possible user set content-length directly */
			if (!strncmp(imd->name,
				     "content-length", 14) &&
			    ss_md_nonzero_num(imd->value__may_own_heap,
					      imd->length))
				lws_client_http_body_pending(wsi, 1);

		}

		imd = imd->next;
	}

	return 0;
}
#endif
/*
 * Check if any metadata headers present in the server headers, and record
 * them into the associated metadata item if so.
 */

static int
lws_extract_metadata(lws_ss_handle_t *h, struct lws *wsi)
{
	lws_ss_metadata_t *polmd = h->policy->metadata, *omd;
	int n;

	while (polmd) {

		if (polmd->value_is_http_token != LWS_HTTP_NO_KNOWN_HEADER) {

			/* it's a well-known header token */

			n = lws_hdr_total_length(wsi, polmd->value_is_http_token);
			if (n) {
				const char *cp = lws_hdr_simple_ptr(wsi,
						polmd->value_is_http_token);
				omd = lws_ss_get_handle_metadata(h, polmd->name);
				if (!omd || !cp)
					return 1;

				assert(!strcmp(omd->name, polmd->name));

				/*
				 * it's present on the wsi, we want to
				 * set the related metadata name to it then
				 */

				_lws_ss_alloc_set_metadata(omd, polmd->name, cp,
							   (unsigned int)n);

#if defined(LWS_WITH_SECURE_STREAMS_PROXY_API)
				/*
				 * ...and because we are doing it from parsing
				 * onward rx, we want to mark the metadata as
				 * needing passing to the client
				 */
				omd->pending_onward = 1;
#endif
			}
		}

#if defined(LWS_WITH_CUSTOM_HEADERS)
		else

			/* has to have a non-empty header string */

			if (polmd->value__may_own_heap &&
			    ((uint8_t *)polmd->value__may_own_heap)[0]) {
				char *p;

				/*
				 * Can it be a custom header?
				 */

				n = lws_hdr_custom_length(wsi, (const char *)
						    polmd->value__may_own_heap,
						    polmd->value_length);
				if (n > 0) {
					int r;

					p = lws_malloc((unsigned int)n + 1, __func__);
					if (!p)
						return 1;

					/*
					 * copy the named custom header value
					 * into the malloc'd buffer
					 */

					r = lws_hdr_custom_copy(wsi, p, n + 1,
						     (const char *)
						     polmd->value__may_own_heap,
						     polmd->value_length);

					/* if needed, free any previous value */

					if (polmd->value_on_lws_heap) {
						lws_free(
						    polmd->value__may_own_heap);
						polmd->value_on_lws_heap = 0;
					}

					if (r < 0) {
						lws_free(p);

						return 1;
					}

					omd = lws_ss_get_handle_metadata(h,
								   polmd->name);
					if (omd) {

						_lws_ss_set_metadata(omd,
							polmd->name, p, (size_t)n);
						omd->value_on_lws_heap = 1;

#if defined(LWS_WITH_SECURE_STREAMS_PROXY_API)
						omd->pending_onward = 1;
#endif
					}
				}
			}
#endif

		polmd = polmd->next;
	}

	return 0;
}

static const uint8_t blob_idx[] = {
	LWS_SYSBLOB_TYPE_AUTH,
	LWS_SYSBLOB_TYPE_DEVICE_SERIAL,
	LWS_SYSBLOB_TYPE_DEVICE_FW_VERSION,
	LWS_SYSBLOB_TYPE_DEVICE_TYPE,
};

/*
 * The peer picks the Location: we would be redirected to, but the handshake we
 * would send there re-emits the blob headers below (the system auth token, and
 * the device serial / fw version / device type) and any cached cookies.  Those
 * belong to the authority the policy named... following a redirect to a
 * different authority, or one that drops us out of tls, would hand them to a
 * host of the peer's choosing, in the clear in the tls-downgrade case.
 *
 * Returns nonzero if the redirect must be refused.
 */

static int
ss_h1_redirect_leaks_identity(lws_ss_handle_t *h, struct lws *wsi,
			      const char *loc)
{
	const char *cur;
	lws_parse_uri_t *puri;
	int m, bad = 0;

	if (!loc)
		return 1;

	/* does this stream carry anything of ours worth protecting? */

	for (m = 0; m < _LWSSS_HBI_COUNT; m++)
		if (h->policy->u.http.blob_header[m])
			break;

	if (m == _LWSSS_HBI_COUNT &&
	    !(h->policy->flags & LWSSSPOLF_HTTP_CACHE_COOKIES))
		return 0;

	/* relative references stay on the authority we're already talking to */

	if (loc[0] == '/' || !strchr(loc, ':'))
		return 0;

	puri = lws_parse_uri_create(loc);
	if (!puri)
		return 1;

	cur = lws_hdr_simple_ptr(wsi, _WSI_TOKEN_CLIENT_PEER_ADDRESS);

	if (!cur || strcasecmp(puri->host, cur) || puri->port != wsi->c_port)
		bad = 1;

#if defined(LWS_WITH_TLS)
	if (!bad && (wsi->use_ssl & LCCSCF_USE_SSL) &&
	    strcmp(puri->scheme, "https") && strcmp(puri->scheme, "wss"))
		bad = 1; /* tls downgrade */
#endif

	lws_parse_uri_destroy(&puri);

	if (bad)
		lwsl_ss_warn(h, "refusing redirect to different authority");

	return bad;
}

#if defined(LWS_WITH_SERVER)

/*
 * On a server stream, these metadata names are set by lws from the request
 * itself (the request line or :method / :path, and the Authorization header)
 */

static const char * const ss_srv_req_md[] = { "path", "method", "auth" };

static int
ss_srv_md_is_request_derived(const char *name)
{
	size_t n;

	for (n = 0; n < LWS_ARRAY_SIZE(ss_srv_req_md); n++)
		if (!strcmp(name, ss_srv_req_md[n]))
			return 1;

	return 0;
}

/*
 * Metadata the policy associates with an http header is what the server
 * emits as that response header (see lws_apply_metadata())
 */

static int
ss_srv_md_is_header(const lws_ss_metadata_t *polmd)
{
	return polmd->value__may_own_heap &&
	       ((const uint8_t *)polmd->value__may_own_heap)[0];
}

/*
 * Every server request starts with what lws fills from the request unset,
 * so nothing an earlier request on the same connection provided, eg, its
 * Authorization, can be mistaken for part of this one.  That's path, method,
 * auth, and the metadata without a header association, which the request's
 * URL arguments fill.
 */

static void
ss_srv_request_metadata_reset(lws_ss_handle_t *h)
{
	lws_ss_metadata_t *polmd = h->policy->metadata;
	int m = 0;

	while (polmd && m < h->policy->metadata_count) {
		if (ss_srv_md_is_request_derived(polmd->name) ||
		    !ss_srv_md_is_header(polmd))
			_lws_ss_set_metadata(&h->metadata[m],
					     h->metadata[m].name, NULL, 0);
		polmd = polmd->next;
		m++;
	}
}

/*
 * A URL argument may only fill metadata without a header association, and
 * never what lws set from the request itself.  Otherwise ?path=/admin or
 * ?auth=... would replace what the request really said before the user code
 * sees it, and ?mime=... would choose our response header's value.
 */

static int
ss_srv_request_urlargs_to_metadata(lws_ss_handle_t *h, struct lws *wsi)
{
	lws_ss_metadata_t *polmd = h->policy->metadata;
	char buf[1024];
	int n;

	while (polmd) {
		if (!ss_srv_md_is_request_derived(polmd->name) &&
		    !ss_srv_md_is_header(polmd)) {
			n = lws_get_urlarg_by_name_safe(wsi, polmd->name, buf,
							sizeof(buf));
			if (n >= 0 && lws_ss_alloc_set_metadata(h, polmd->name,
							buf, (unsigned int)n))
				return -1;
		}

		polmd = polmd->next;
	}

	return 0;
}

#endif

int
secstream_h1(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
#if defined(LWS_WITH_SERVER)
	struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];
#endif
	lws_ss_handle_t *h = (lws_ss_handle_t *)lws_get_opaque_user_data(wsi);
	uint8_t buf[LWS_PRE + 1520], *p = &buf[LWS_PRE],
#if defined(LWS_WITH_SERVER)
			*start = p,
#endif
		*end = &buf[sizeof(buf) - 1];
	lws_ss_state_return_t r;
	int f = 0, m, status;
	char conceal_eom = 0;
	lws_usec_t inter;
	size_t buflen;

	switch (reason) {

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		if (!h) {
			lwsl_notice("%s: CCE with no ss handle %s\n", __func__, lws_wsi_tag(wsi));
			break;
		}

		lws_ss_assert_extant(wsi->a.context, wsi->tsi, h);

		assert(h->policy);

#if defined(LWS_WITH_CONMON)
		lws_conmon_ss_json(h);
#endif

		lws_metrics_caliper_report_hist(h->cal_txn, wsi);
		lwsl_info("%s: %s CLIENT_CONNECTION_ERROR: %s\n", __func__,
			  h->lc.gutag, in ? (const char *)in : "none");
		if (h->ss_dangling_connected) {
			/* already disconnected, no action for DISCONNECT_ME */
			r = lws_ss_event_helper(h, LWSSSCS_DISCONNECTED);
			if (r != LWSSSSRET_OK)
				return _lws_ss_handle_state_ret_CAN_DESTROY_HANDLE(r, wsi, &h);
		} else {
			/* already disconnected, no action for DISCONNECT_ME */
			r = lws_ss_event_helper(h, LWSSSCS_UNREACHABLE);
			if (r) {
				if (h->inside_connect) {
					h->pending_ret = r;
					break;
				}

				return _lws_ss_handle_state_ret_CAN_DESTROY_HANDLE(r, wsi, &h);
			}
		}

		if (h->wsi == wsi) /* not a newer wsi the app just started */
			h->wsi = NULL;
		if (h->wsi)
			/*
			 * The app started a new connection from inside the
			 * state callback above; it owns the handle now, we
			 * must not schedule a competing retry on top of it
			 */
			break;
		r = lws_ss_backoff(h);
		if (r != LWSSSSRET_OK) {
			if (h->inside_connect) {
				h->pending_ret = r;
				break;
			}
			return _lws_ss_handle_state_ret_CAN_DESTROY_HANDLE(r, wsi, &h);
		}
		break;

	case LWS_CALLBACK_CLIENT_HTTP_REDIRECT:

		if (!h)
			return -1;

		if (h->policy->u.http.fail_redirect)
			lws_system_cpd_set(lws_get_context(wsi),
					   LWS_CPD_CAPTIVE_PORTAL);
		/* unless it's explicitly allowed, reject to follow it */
		if (!(h->policy->flags & LWSSSPOLF_ALLOW_REDIRECTS))
			return 1;

		/* ... and even then, not off to another authority */
		return ss_h1_redirect_leaks_identity(h, wsi, (const char *)in);

	case LWS_CALLBACK_CLOSED_HTTP: /* server */
	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		if (!h)
			break;

		/*
		 * Only the wsi the handle believes represents him may report
		 * closure up: this is the guard ss-h2 / ss-h3 already apply
		 * before delegating here.  A stale wsi closing later must not
		 * be allowed to reset the handle state, clear h->wsi or start
		 * a retry on behalf of a different, live connection.
		 */

		if (h->wsi && h->wsi != wsi)
			break;

		h->txn_n_acked = 0;
		// lws_sul_cancel(&h->sul_timeout);

		lws_ss_assert_extant(wsi->a.context, wsi->tsi, h);

#if defined(LWS_WITH_CONMON)
		if (wsi->conmon.pcol == LWSCONMON_PCOL_NONE) {
			wsi->conmon.pcol = LWSCONMON_PCOL_HTTP;
			wsi->conmon.protocol_specific.http.response =
					(int)lws_http_client_http_response(wsi);
		}

		lws_conmon_ss_json(h);
#endif

		lws_metrics_caliper_report_hist(h->cal_txn, wsi);
		//lwsl_notice("%s: %s LWS_CALLBACK_CLOSED_CLIENT_HTTP\n",
		//		__func__, wsi->lc.gutag);

		h->wsi = NULL; /* guarded above to be NULL or wsi already */
		h->hanging_som = 0;
		h->subseq = 0;

#if defined(LWS_WITH_SERVER)
		lws_pt_lock(pt, __func__);
		lws_dll2_remove(&h->cli_list);
		lws_pt_unlock(pt);
#endif

		if (h->policy && !(h->policy->flags & LWSSSPOLF_OPPORTUNISTIC) &&
#if defined(LWS_WITH_SERVER)
		    !(h->info.flags & LWSSSINFLAGS_ACCEPTED) && /* not server */
#endif
		    !h->txn_ok && !wsi->a.context->being_destroyed) {
			r = lws_ss_backoff(h);
			if (r != LWSSSSRET_OK)
				return _lws_ss_handle_state_ret_CAN_DESTROY_HANDLE(r, wsi, &h);
			if (h->seqstate == SSSEQ_IDLE)
				lws_sul_cancel(&h->sul_timeout);

			break;
		} else {
			h->seqstate = SSSEQ_IDLE;
			lws_sul_cancel(&h->sul_timeout);
		}

		if (h->ss_dangling_connected) {
			/* already disconnected, no action for DISCONNECT_ME */
			r = lws_ss_event_helper(h, LWSSSCS_DISCONNECTED);
			if (r == LWSSSSRET_DESTROY_ME)
				return _lws_ss_handle_state_ret_CAN_DESTROY_HANDLE(r, wsi, &h);
		} else if (h->policy && !h->txn_ok &&
#if defined(LWS_WITH_SERVER)
			   !(h->info.flags & LWSSSINFLAGS_ACCEPTED) && /* not server */
#endif
			   !wsi->a.context->being_destroyed) {
			/*
			 * The connection died mid-transaction, before any
			 * response headers arrived... because it never got as
			 * far as CONNECTED, ss_dangling_connected is clear, and
			 * without this, nobody would ever be told anything
			 * leaving the app's stream silently stuck in
			 * LWSSSCS_CONNECTING forever.
			 *
			 * Treat it identically to the connection attempt itself
			 * failing in the CLIENT_CONNECTION_ERROR path: report
			 * UNREACHABLE, and follow the policy retry / backoff.
			 */
			r = lws_ss_event_helper(h, LWSSSCS_UNREACHABLE);
			if (r != LWSSSSRET_OK)
				return _lws_ss_handle_state_ret_CAN_DESTROY_HANDLE(r, wsi, &h);

			r = lws_ss_backoff(h);
			if (r != LWSSSSRET_OK)
				return _lws_ss_handle_state_ret_CAN_DESTROY_HANDLE(r, wsi, &h);
		}
		break;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:

		if (!h)
			return -1;

		lws_ss_assert_extant(wsi->a.context, wsi->tsi, h);
		h->wsi = wsi; /* since we accept the wsi is bound to the SS,
			       * ensure the SS feels the same way about the wsi */

#if defined(LWS_WITH_CONMON)
		if (wsi->conmon.pcol == LWSCONMON_PCOL_NONE) {
			wsi->conmon.pcol = LWSCONMON_PCOL_HTTP;
			wsi->conmon.protocol_specific.http.response =
					(int)lws_http_client_http_response(wsi);
		}

		lws_conmon_ss_json(h);
#endif

		status = (int)lws_http_client_http_response(wsi);
		lwsl_info("%s: LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP: %d\n", __func__, status);
	//	if (!status)
			/* it's just telling use we connected / joined the nwsi */
	//		break;

#if defined(LWS_WITH_SYS_METRICS)
		if (status) {
			lws_snprintf((char *)buf, 10, "%d", status);
			lws_metrics_tag_ss_add(h, "http_resp", (char *)buf);
		}
#endif

		if (status == HTTP_STATUS_SERVICE_UNAVAILABLE /* 503 */ ||
		    status == 429 /* Too many requests */) {
			/*
			 * We understand this attempt failed, and that we should
			 * conceal this attempt.  If there's a specified
			 * retry-after, we should use that if larger than our
			 * computed backoff
			 */

			inter = 0;
			lws_http_check_retry_after(wsi, &inter);

			r = _lws_ss_backoff(h, inter);
			if (r != LWSSSSRET_OK)
				return _lws_ss_handle_state_ret_CAN_DESTROY_HANDLE(r, wsi, &h);

			return -1; /* end this stream */
		}

		if (h->policy->u.http.resp_expect)
			h->u.http.good_respcode =
					status == h->policy->u.http.resp_expect;
		else
			h->u.http.good_respcode = (status >= 200 && status < 300);
		// lwsl_err("%s: good resp %d %d\n", __func__, status, h->u.http.good_respcode);

		if (lws_extract_metadata(h, wsi)) {
			lwsl_info("%s: rx metadata extract failed\n", __func__);

			return -1;
		}

		if (status) {
			/*
			 * Check and see if it's something from the response
			 * map, if so, generate the requested status.  If we're
			 * the proxy onward connection, metadata has priority
			 * over state updates on the serialization, so the
			 * state callback will see the right metadata.
			 */
			int n = lws_ss_http_resp_to_state(h, status);
			if (n) {
				r = lws_ss_event_helper(h, (lws_ss_constate_t)n);
				if (r != LWSSSSRET_OK)
					return _lws_ss_handle_state_ret_CAN_DESTROY_HANDLE(r, wsi,
									&h);
			}
		}

		if (h->u.http.good_respcode)
			lwsl_info("%s: Connected streamtype %s, %d\n", __func__,
				h->policy->streamtype, status);
		else
			lwsl_info("%s: Connected streamtype %s, BAD %d\n",
				__func__, h->policy->streamtype, status);

		h->hanging_som = 0;

		h->retry = 0;
		h->seqstate = SSSEQ_CONNECTED;
		lws_sul_cancel(&h->sul);

		if (h->prev_ss_state != LWSSSCS_CONNECTED) {
			wsi->client_suppress_CONNECTION_ERROR = 1;
			/*
			 * back-to-back http transactions otherwise go
			 * DISCONNECTED -> CONNECTED, we should insert
			 * CONNECTING inbetween
			 */
			if (h->prev_ss_state == LWSSSCS_DISCONNECTED) {
				r = lws_ss_event_helper(h, LWSSSCS_CONNECTING);
				if (r != LWSSSSRET_OK)
					return _lws_ss_handle_state_ret_CAN_DESTROY_HANDLE(r, wsi, &h);
			}
                       if (h->prev_ss_state != LWSSSCS_CONNECTED &&
                           h->prev_ss_state != LWSSSCS_QOS_ACK_REMOTE &&
                           h->prev_ss_state != LWSSSCS_QOS_NACK_REMOTE) {
                               // lwsl_ss_notice(h, "HTTP_ESTABLISHED");
				r = lws_ss_event_helper(h, LWSSSCS_CONNECTED);
				if (r != LWSSSSRET_OK)
					return _lws_ss_handle_state_ret_CAN_DESTROY_HANDLE(r, wsi, &h);
			}
		}

		/*
		 * Since it's an http transaction we initiated... this is
		 * proof of connection validity
		 */
		lws_validity_confirmed(wsi);

#if defined(LWS_WITH_SS_RIDESHARE)

		/*
		 * There are two ways we might want to deal with multipart,
		 * one is pass it through raw (although the user code needs
		 * a helping hand for learning the boundary), and the other
		 * is to deframe it and provide basically submessages in the
		 * different parts.
		 *
		 * Either way, nothing about the last response's multipart
		 * framing, if any, applies to this one.
		 */

		h->u.http.boundary[0] = '\0';
		h->u.http.boundary_len = 0;
		h->u.http.boundary_seq = 0;
		h->u.http.mp_state = LWSSS_MP_PREAMBLE;
		h->u.http.som = 0;

		if (lws_hdr_copy(wsi, (char *)buf, sizeof(buf),
				 WSI_TOKEN_HTTP_CONTENT_TYPE) > 0 &&
		/* multipart/form-data;
		 * boundary=----WebKitFormBoundarycc7YgAPEIHvgE9Bf */

		    (!strncmp((char *)buf, "multipart/form-data", 19) ||
		     !strncmp((char *)buf, "multipart/related", 17))) {
			struct lws_tokenize ts;
			lws_tokenize_elem e;

			// puts((const char *)buf);

			memset(&ts, 0, sizeof(ts));
			ts.start = (char *)buf;
			ts.len = strlen(ts.start);
			ts.flags = LWS_TOKENIZE_F_RFC7230_DELIMS |
					LWS_TOKENIZE_F_SLASH_NONTERM |
					LWS_TOKENIZE_F_MINUS_NONTERM;

			do {
				e = lws_tokenize(&ts);
				if (e == LWS_TOKZE_TOKEN_NAME_EQUALS &&
				    !strncmp(ts.token, "boundary", 8) &&
				    ts.token_len == 8) {
					e = lws_tokenize(&ts);
					if (e != LWS_TOKZE_TOKEN)
						goto malformed_l;
					h->u.http.boundary[0] = '\x0d';
					h->u.http.boundary[1] = '\x0a';
					h->u.http.boundary[2] = '-';
					h->u.http.boundary[3] = '-';
					lws_strnncpy(h->u.http.boundary + 4,
						     ts.token, ts.token_len,
						     sizeof(h->u.http.boundary) - 4);
					/*
					 * The copy above is clamped to the
					 * boundary buffer, so the recorded
					 * length must come from what actually
					 * landed there and not from the peer's
					 * token length... otherwise the
					 * matcher below indexes boundary[]
					 * out of bounds (and boundary_len,
					 * being uint8_t, can even wrap)
					 */
					h->u.http.boundary_len = (uint8_t)
						strlen(h->u.http.boundary);
					/*
					 * The first delimiter may start the
					 * body without the CRLF
					 */
					h->u.http.boundary_seq = 2;
				}
			} while (e > 0);
			lwsl_info("%s: multipart boundary '%s' len %d\n", __func__,
					h->u.http.boundary, h->u.http.boundary_len);

			/* inform the ss that a related message group begins */

			if ((h->policy->flags & LWSSSPOLF_HTTP_MULTIPART_IN) &&
			    h->u.http.boundary[0] && h->info.rx) {
				r = h->info.rx(ss_to_userobj(h), NULL, 0,
					       LWSSS_FLAG_RELATED_START);
				if (r != LWSSSSRET_OK)
					return _lws_ss_handle_state_ret_CAN_DESTROY_HANDLE(
								r, wsi, &h);
			}

			// lws_header_table_detach(wsi, 0);
		}
		break;
malformed_l:
		lwsl_notice("%s: malformed multipart header\n", __func__);
		return -1;
#else
		break;
#endif

	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
		if (!h)
			return -1;
		if (h->writeable_len)
			wsi->http.writeable_len = h->writeable_len;

		{
			uint8_t **p = (uint8_t **)in, *end, *oin;

		/*
		 * We are about to write policy- and metadata-driven headers in
		 * here, so do not take the composer's word for how much room
		 * there is
		 */

		if (lws_client_hdr_append_room_bad(wsi, (unsigned char **)p,
						   len)) {
			lwsl_wsi_err(wsi, "bad append-header room");

			return -1;
		}

		oin = *p;
		end = (*p) + len;

		/*
		 * blob-based headers
		 */

		for (m = 0; m < _LWSSS_HBI_COUNT; m++) {
			lws_system_blob_t *ab;
			int o = 0, n;

			if (!h->policy->u.http.blob_header[m])
				continue;

			/*
			 * To be backward compatible, default is system-wide LWA auth,
			 * and "http_auth_header" is for default LWA auth, current users do not
			 * need any change in their policy.
			 * If user wants different auth/token, need to specify the "use_auth"
			 * and will be handled after metadata headers are applied.
			 */

			if (m == LWSSS_HBI_AUTH &&
			    h->policy->u.http.auth_preamble)
				o = lws_snprintf((char *)buf, sizeof(buf), "%s",
					h->policy->u.http.auth_preamble);

			if (o > (int)sizeof(buf) - 2)
				return -1;

			ab = lws_system_get_blob(wsi->a.context, blob_idx[m], 0);
			if (!ab)
				return -1;

			buflen = sizeof(buf) - (unsigned int)o - 2u;
			n = lws_system_blob_get(ab, buf + o, &buflen, 0);
			if (n < 0)
				return -1;

			buf[(unsigned int)o + buflen] = '\0';
			lwsl_debug("%s: adding blob %d: %s\n", __func__, m, buf);

			if (lws_add_http_header_by_name(wsi,
				 (uint8_t *)h->policy->u.http.blob_header[m],
				 buf, (int)((int)buflen + o), p, end))
				return -1;
		}

		/*
		 * metadata-based headers
		 */

		if (lws_apply_metadata(h, wsi, buf, p, end))
			return -1;

#if defined(LWS_WITH_SS_DIRECT_PROTOCOL_STR)
		if (h->policy->flags & LWSSSPOLF_DIRECT_PROTO_STR) {
			if (lws_apply_instant_metadata(h, wsi, buf, p, end))
				return -1;
		}
#endif

#if defined(LWS_WITH_SECURE_STREAMS_AUTH_SIGV4)
		if (h->policy->auth && h->policy->auth->type &&
				!strcmp(h->policy->auth->type, "sigv4")) {

			if (lws_ss_apply_sigv4(wsi, h, p, end))
				return -1;
		}
#endif


		(void)oin;
		//if (*p != oin)
		//	lwsl_hexdump_notice(oin, lws_ptr_diff_size_t(*p, oin));

		}

		/*
		 * So when proxied, for POST we have to synthesize a CONNECTED
		 * state, so it can request a writeable and deliver the POST
		 * body
		 */
		if ((h->policy->protocol == LWSSSP_H1 ||
		     h->policy->protocol == LWSSSP_H2 ||
		     h->policy->protocol == LWSSSP_H3) &&
		     h->being_serialized && (
#if defined(LWS_WITH_HTTP_UNCOMMON_HEADERS) || defined(LWS_HTTP_HEADERS_ALL)
				!strcmp(h->policy->u.http.method, "PUT") ||
				!strcmp(h->policy->u.http.method, "PATCH") ||
#endif
				!strcmp(h->policy->u.http.method, "POST"))) {

			wsi->client_suppress_CONNECTION_ERROR = 1;
			if (h->prev_ss_state != LWSSSCS_CONNECTED) {
				r = lws_ss_event_helper(h, LWSSSCS_CONNECTED);
				if (r)
					return _lws_ss_handle_state_ret_CAN_DESTROY_HANDLE(r, wsi, &h);
			}
		}

		break;

	/* chunks of chunked content, with header removed */
	case LWS_CALLBACK_HTTP_BODY:
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		lwsl_debug("%s: RECEIVE_CLIENT_HTTP_READ: read %d\n",
				__func__, (int)len);
		if (!h || !h->info.rx)
			return 0;

#if defined(LWS_WITH_SS_RIDESHARE)
		if ((h->policy->flags & LWSSSPOLF_HTTP_MULTIPART_IN) &&
		    h->u.http.boundary[0])
			return ss_http_multipart_parser(h, wsi, in, len);
#endif

		if (!h->subseq) {
			f |= LWSSS_FLAG_SOM;
			h->hanging_som = 1;
			h->subseq = 1;
		}

	//	lwsl_notice("%s: HTTP_READ: client side sent len %d fl 0x%x\n",
	//		    __func__, (int)len, (int)f);

		h->wsi = wsi; /* since we accept the wsi is bound to the SS,
			       * ensure the SS feels the same way about the wsi */
		r = h->info.rx(ss_to_userobj(h), (const uint8_t *)in, len, f);
		if (r != LWSSSSRET_OK)
			return _lws_ss_handle_state_ret_CAN_DESTROY_HANDLE(r, wsi, &h);

		return 0; /* don't passthru */

	/* uninterpreted http content */
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		{
			char *px = (char *)buf + LWS_PRE; /* guarantees LWS_PRE */
			int lenx = sizeof(buf) - LWS_PRE;

			if (lws_http_client_read(wsi, &px, &lenx) < 0)
				return -1;
		}

		if (!h->txn_ok)
			lws_set_timeout(wsi, PENDING_TIMEOUT_HTTP_CONTENT, 30);

		return 0; /* don't passthru */

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		// lwsl_debug("%s: LWS_CALLBACK_COMPLETED_CLIENT_HTTP\n", __func__);

		if (!h)
			return -1;

		if (h->hanging_som) {
			r = LWSSSSRET_OK;
			if (h->info.rx)
				r = h->info.rx(ss_to_userobj(h), NULL, 0,
					       LWSSS_FLAG_EOM);
			h->hanging_som = 0;
			h->subseq = 0;
			/* the app may have answered DESTROY_ME / DISCONNECT_ME */
			if (r != LWSSSSRET_OK)
				return _lws_ss_handle_state_ret_CAN_DESTROY_HANDLE(
								r, wsi, &h);
		}

		wsi->http.writeable_len = h->writeable_len = 0;
		lws_sul_cancel(&h->sul_timeout);

		h->txn_ok = 1;

#if defined(LWS_WITH_SYS_METRICS)
		lws_metrics_tag_ss_add(h, "result",
				       h->u.http.good_respcode ?
				       "SS_ACK_REMOTE" : "SS_NACK_REMOTE");
#endif

		if (!h->ss_dangling_connected) {
			r = lws_ss_event_helper(h, LWSSSCS_CONNECTED);
			if (r != LWSSSSRET_OK)
				return _lws_ss_handle_state_ret_CAN_DESTROY_HANDLE(r, wsi, &h);
		}

		if (!h->txn_n_acked) {
			h->txn_n_acked = 1;
			r = lws_ss_event_helper(h, h->u.http.good_respcode ?
						LWSSSCS_QOS_ACK_REMOTE :
						LWSSSCS_QOS_NACK_REMOTE);
			if (r != LWSSSSRET_OK)
				return _lws_ss_handle_state_ret_CAN_DESTROY_HANDLE(r, wsi, &h);
		}
		lws_cancel_service(lws_get_context(wsi)); /* abort poll wait */
		break;

	case LWS_CALLBACK_HTTP_WRITEABLE:
	case LWS_CALLBACK_CLIENT_HTTP_WRITEABLE:

		if (!h || !h->info.tx) {
			lwsl_debug("%s: no handle / tx\n", __func__);
			return 0;
		}

#if defined(LWS_WITH_SERVER)
		if (h->txn_resp_pending) {
			/*
			 * If we're going to start sending something, we need to
			 * to take care of the http response header for it first
			 */
			h->txn_resp_pending = 0;

			if (lws_add_http_common_headers(wsi,
					(unsigned int)(h->txn_resp_set ?
						(h->txn_resp ? h->txn_resp : 200) :
						HTTP_STATUS_NOT_FOUND),
					NULL,
					h->policy->flags & LWSSSPOLF_HTTP_NO_CONTENT_LENGTH ?
						LWS_ILLEGAL_HTTP_CONTENT_LEN :
						h->wsi->http.writeable_len,
					&p, end))
				return 1;

			/*
			 * metadata-based headers
			 */

			if (lws_apply_metadata(h, wsi, buf, &p, end))
				return -1;

			if (lws_finalize_write_http_header(wsi, start, &p, end))
				return 1;

			/* write the body separately */
			lws_callback_on_writable(wsi);

			return 0;
		}
#endif

		if (
#if defined(LWS_WITH_SERVER)
		    !(h->info.flags & LWSSSINFLAGS_ACCEPTED) && /* not accepted */
#endif
		    !h->rideshare)

			h->rideshare = h->policy;

#if defined(LWS_WITH_SS_RIDESHARE)
		if (
#if defined(LWS_WITH_SERVER)
		    !(h->info.flags & LWSSSINFLAGS_ACCEPTED) && /* not accepted */
#endif
		    !h->inside_msg && h->rideshare->u.http.multipart_name)
			lws_client_http_multipart(wsi,
				h->rideshare->u.http.multipart_name,
				h->rideshare->u.http.multipart_filename,
				h->rideshare->u.http.multipart_content_type,
				(char **)&p, (char *)end);

		buflen = lws_ptr_diff_size_t(end, p);
		if (h->rideshare && h->rideshare->u.http.multipart_name) {
			/*
			 * We must keep room for the closing "\r\n--" +
			 * boundary + "--\r\n" that gets written after whatever
			 * the user tx gives us.  The part preamble above can
			 * legally have consumed almost all of buf, so check
			 * rather than let the size_t subtraction underflow and
			 * offer the user tx a ~2^64 byte "buffer".  Retrying
			 * can't help (we'd compose the same preamble again),
			 * so it's fatal for the connection.
			 *
			 * It's h->rideshare, not h->policy, that decides if the
			 * closing boundary gets written below.
			 */
			if (buflen < 24) {
				lwsl_err("%s: multipart preamble too big\n",
					 __func__);
				return -1;
			}
			buflen -= 24; /* allow space for end of multipart */
		}
#else
		buflen = lws_ptr_diff_size_t(end, p);
#endif
		r = h->info.tx(ss_to_userobj(h), h->txord++, p, &buflen, &f);
		if (r == LWSSSSRET_TX_DONT_SEND)
			return 0;
		if (r < 0)
			return _lws_ss_handle_state_ret_CAN_DESTROY_HANDLE(r, wsi, &h);

		// lwsl_notice("%s: WRITEABLE: user tx says len %d fl 0x%x\n",
		//	    __func__, (int)buflen, (int)f);

		p += buflen;

		if (f & LWSSS_FLAG_EOM) {
#if defined(LWS_WITH_SERVER)
		    if (!(h->info.flags & LWSSSINFLAGS_ACCEPTED)) {
#endif
			conceal_eom = 1;
			/* end of rideshares */
			if (!h->rideshare || !h->rideshare->rideshare_streamtype) {
				lws_client_http_body_pending(wsi, 0);
#if defined(LWS_WITH_SS_RIDESHARE)
				if (h->rideshare &&
				    h->rideshare->u.http.multipart_name)
					lws_client_http_multipart(wsi, NULL, NULL, NULL,
						(char **)&p, (char *)end);
				conceal_eom = 0;
#endif
			} else {
				const char *rs = h->rideshare->rideshare_streamtype;

				h->rideshare = lws_ss_policy_lookup(wsi->a.context,
								    rs);
				if (!h->rideshare) {
					/*
					 * The policy names a rideshare
					 * streamtype that does not exist...
					 * nothing validates that at policy
					 * parse time, and the next WRITEABLE
					 * would dereference it.  Fatal for the
					 * connection.
					 */
					lwsl_ss_err(h, "unknown rideshare "
						       "streamtype '%s'", rs);
					return -1;
				}
				lws_callback_on_writable(wsi);
			}
#if defined(LWS_WITH_SERVER)
		    }
#endif

			h->inside_msg = 0;
		} else {
			/* otherwise we can spin with zero length writes */
			if (!f && !lws_ptr_diff(p, buf + LWS_PRE))
				break;
			h->inside_msg = 1;
			lws_callback_on_writable(wsi);
		}

		lwsl_info("%s: lws_write %d %d\n", __func__,
			  lws_ptr_diff(p, buf + LWS_PRE), f);

		if (lws_write(wsi, buf + LWS_PRE, lws_ptr_diff_size_t(p, buf + LWS_PRE),
			 (!conceal_eom && (f & LWSSS_FLAG_EOM)) ?
				    LWS_WRITE_HTTP_FINAL : LWS_WRITE_HTTP) !=
				(int)lws_ptr_diff(p, buf + LWS_PRE)) {
			lwsl_err("%s: write failed\n", __func__);
			return -1;
		}

#if defined(LWS_WITH_SERVER)
		if ((h->info.flags & LWSSSINFLAGS_ACCEPTED) /* server */ &&
		    (f & LWSSS_FLAG_EOM) &&
		     lws_http_transaction_completed(wsi))
			return -1;
#else
		lws_set_timeout(wsi, 0, 0);
#endif
		break;

#if defined(LWS_WITH_SERVER)
	case LWS_CALLBACK_HTTP:

		if (!h)
			return -1;

		if (h->wsi && h->wsi->mount_hit)
			break;

		lwsl_info("%s: LWS_CALLBACK_HTTP\n", __func__);
		{
			ss_srv_request_metadata_reset(h);

			h->txn_resp_set = 0;
			h->txn_resp_pending = 1;
			h->writeable_len = 0;

#if defined(LWS_ROLE_H2)
			m = lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_COLON_METHOD);
			if (m) {
				if (lws_ss_alloc_set_metadata(h, "method",
						    lws_hdr_simple_ptr(wsi,
						     WSI_TOKEN_HTTP_COLON_METHOD), (unsigned int)m))
					return -1;
				m = lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_COLON_PATH);
				if (m && lws_ss_alloc_set_metadata(h, "path",
						    lws_hdr_simple_ptr(wsi,
						     WSI_TOKEN_HTTP_COLON_PATH), (unsigned int)m))
					return -1;
			} else
#endif
			{
				m = lws_hdr_total_length(wsi, WSI_TOKEN_GET_URI);
				if (m) {
					if (lws_ss_alloc_set_metadata(h, "path",
							lws_hdr_simple_ptr(wsi,
								WSI_TOKEN_GET_URI), (unsigned int)m))
						return -1;
					if (lws_ss_alloc_set_metadata(h, "method", "GET", 3))
						return -1;
					m = lws_hdr_fragment_length(wsi, WSI_TOKEN_HTTP_AUTHORIZATION, 0);
					if (m && lws_ss_alloc_set_metadata(h, "auth",
							lws_hdr_simple_ptr(wsi,
								WSI_TOKEN_HTTP_AUTHORIZATION), (unsigned int)m))
						return -1;
				} else {
					m = lws_hdr_total_length(wsi, WSI_TOKEN_POST_URI);
					if (m) {
						if (lws_ss_alloc_set_metadata(h, "path",
								lws_hdr_simple_ptr(wsi,
									WSI_TOKEN_POST_URI), (unsigned int)m))
							return -1;
						if (lws_ss_alloc_set_metadata(h, "method", "POST", 4))
							return -1;
						m = lws_hdr_fragment_length(wsi, WSI_TOKEN_HTTP_AUTHORIZATION, 0);
						if (m && lws_ss_alloc_set_metadata(h, "auth",
							lws_hdr_simple_ptr(wsi,
								WSI_TOKEN_HTTP_AUTHORIZATION), (unsigned int)m))
							return -1;
					} else {
#if defined(LWS_WITH_HTTP_UNCOMMON_HEADERS) || defined(LWS_HTTP_HEADERS_ALL)
						m = lws_hdr_total_length(wsi, WSI_TOKEN_PATCH_URI);
						if (m) {
							if (lws_ss_alloc_set_metadata(h, "path",
									lws_hdr_simple_ptr(wsi,
										WSI_TOKEN_PATCH_URI), (unsigned int)m))
								return -1;
							if (lws_ss_alloc_set_metadata(h, "method", "PATCH", 5))
								return -1;
							m = lws_hdr_fragment_length(wsi, WSI_TOKEN_HTTP_AUTHORIZATION, 0);
							if (m && lws_ss_alloc_set_metadata(h, "auth",
								lws_hdr_simple_ptr(wsi,
									WSI_TOKEN_HTTP_AUTHORIZATION), (unsigned int)m))
								return -1;
						}
#endif
					}
				}
			}
		}

		if (!h->ss_dangling_connected) {
#if defined(LWS_WITH_SYS_METRICS)
			/*
			 * If any hanging caliper measurement, dump it, and free any tags
			 */
			lws_metrics_caliper_report_hist(h->cal_txn, (struct lws *)NULL);
#endif
			wsi->client_suppress_CONNECTION_ERROR = 1;
			if (h->prev_ss_state != LWSSSCS_CONNECTED) {
				r = lws_ss_event_helper(h, LWSSSCS_CONNECTED);
				if (r)
					return _lws_ss_handle_state_ret_CAN_DESTROY_HANDLE(r, wsi, &h);
			}
		}

		/*
		 * Adopt urlargs named like metadata defined in the policy as
		 * the metadata values, where that's allowed
		 */
		if (ss_srv_request_urlargs_to_metadata(h, wsi))
			return -1;

		r = lws_ss_event_helper(h, LWSSSCS_SERVER_TXN);
		if (r)
			return _lws_ss_handle_state_ret_CAN_DESTROY_HANDLE(r,
								wsi, &h);

		return 0;
#endif

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

const struct lws_protocols protocol_secstream_h1 = {
	"lws-secstream-h1",
	secstream_h1,
	0, 0, 0, NULL, 0
};

/*
 * Munge connect info according to protocol-specific considerations... this
 * usually means interpreting aux in a protocol-specific way and using the
 * pieces at connection setup time, eg, http url pieces.
 *
 * len bytes of buf can be used for things with scope until after the actual
 * connect.
 */

static int
secstream_connect_munge_h1(lws_ss_handle_t *h, char *buf, size_t len,
			   struct lws_client_connect_info *i,
			   union lws_ss_contemp *ct)
{
	const char *pbasis = h->policy->u.http.url;
	size_t used_in, used_out;
	lws_strexp_t exp;

	/* i.path on entry is used to override the policy urlpath if not "" */

	if (i->path[0])
		pbasis = i->path;

	if (!pbasis)
		return 0;

	/* uncomment to force h1 */
	// i->alpn = "http/1.1";

#if defined(LWS_WITH_SS_RIDESHARE)
	if (h->policy->flags & LWSSSPOLF_HTTP_MULTIPART)
		i->ssl_connection |= LCCSCF_HTTP_MULTIPART_MIME;

	if (h->policy->flags & LWSSSPOLF_HTTP_X_WWW_FORM_URLENCODED)
		i->ssl_connection |= LCCSCF_HTTP_X_WWW_FORM_URLENCODED;
#endif

	if (h->policy->flags & LWSSSPOLF_HTTP_CACHE_COOKIES)
		i->ssl_connection |= LCCSCF_CACHE_COOKIES;

	/* protocol aux is the path part */

	i->path = buf;

	/* skip the unnessary '/' */
	if (*pbasis == '/')
		pbasis = pbasis + 1;

	buf[0] = '/';

	lws_strexp_init(&exp, (void *)h, lws_ss_exp_cb_metadata, buf + 1, len - 1);

	if (lws_strexp_expand(&exp, pbasis, strlen(pbasis),
			      &used_in, &used_out) != LSTRX_DONE)
		return 1;

	if (used_out + 1 < len - 1)
		buf[used_out + 1] = '\0';

	__lws_lc_tag_append(&h->lc, buf);

	return 0;
}


const struct ss_pcols ss_pcol_h1 = {
	"h1",
	"http/1.1",
	&protocol_secstream_h1,
	secstream_connect_munge_h1,
	NULL, NULL, NULL
};
