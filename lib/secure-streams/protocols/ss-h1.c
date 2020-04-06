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
static int
ss_http_multipart_parser(lws_ss_handle_t *h, void *in, size_t len)
{
	uint8_t *q = (uint8_t *)in;
	int pending_issue = 0, n = 0;

	/* let's stick it in the boundary state machine first */
	while (n < (int)len) {
		if (h->u.http.boundary_seq != h->u.http.boundary_len) {
			if (q[n] == h->u.http.boundary[h->u.http.boundary_seq])
				h->u.http.boundary_seq++;
			else {
				h->u.http.boundary_seq = 0;
				h->u.http.boundary_dashes = 0;
				h->u.http.boundary_post = 0;
			}
			goto around;
		}

		/*
		 * We already matched the boundary string, now we're
		 * looking if there's a -- afterwards
		 */
		if (h->u.http.boundary_dashes < 2) {
			if (q[n] == '-') {
				h->u.http.boundary_dashes++;
				goto around;
			}
			/* there was no final -- ... */
		}

		if (h->u.http.boundary_dashes == 2) {
			/*
			 * It's an EOM boundary: issue pending + multipart EOP
			 */
			lwsl_debug("%s: seen EOP, n %d pi %d\n",
				    __func__, n, pending_issue);
			/*
			 * It's possible we already started the decode before
			 * the end of the last packet.  Then there is no
			 * remainder to send.
			 */
			if (n >= pending_issue + h->u.http.boundary_len +
			    (h->u.http.any ? 2 : 0) + 1)
				h->info.rx(ss_to_userobj(h),
					   &q[pending_issue],
					   n - pending_issue -
					   h->u.http.boundary_len - 1 -
					   (h->u.http.any ? 2 : 0) /* crlf */,
				   (!h->u.http.som ? LWSSS_FLAG_SOM : 0) |
				   LWSSS_FLAG_EOM | LWSSS_FLAG_RELATED_END);

			/*
			 * Peer may not END_STREAM us
			 */
			return 0;
			//return -1;
		}

		/* how about --boundaryCRLF */

		if (h->u.http.boundary_post < 2) {
			if ((!h->u.http.boundary_post && q[n] == '\x0d') ||
			    (h->u.http.boundary_post && q[n] == '\x0a')) {
				h->u.http.boundary_post++;
				goto around;
			}
			/* there was no final CRLF ... it's wrong */

			return -1;
		}
		if (h->u.http.boundary_post != 2)
			goto around;

		/*
		 * We have a starting "--boundaryCRLF" or intermediate
		 * "CRLF--boundaryCRLF" boundary
		 */
		lwsl_debug("%s: b_post = 2 (pi %d)\n", __func__, pending_issue);
		h->u.http.boundary_seq = 0;
		h->u.http.boundary_post = 0;

		if (n >= pending_issue && (h->u.http.any || !h->u.http.som)) {
			/* Intermediate... do the EOM */
			lwsl_debug("%s: seen interm EOP n %d pi %d\n", __func__,
				   n, pending_issue);
			/*
			 * It's possible we already started the decode before
			 * the end of the last packet.  Then there is no
			 * remainder to send.
			 */
			if (n >= pending_issue + h->u.http.boundary_len +
			    (h->u.http.any ? 2 : 0))
				h->info.rx(ss_to_userobj(h), &q[pending_issue],
					   n - pending_issue -
					       h->u.http.boundary_len -
					       (h->u.http.any ? 2 /* crlf */ : 0),
					   (!h->u.http.som ? LWSSS_FLAG_SOM : 0) |
					   LWSSS_FLAG_EOM);
		}

		/* Next message starts after this boundary */

		pending_issue = n;
		h->u.http.som = 0;

around:
		n++;
	}

	if (pending_issue != n) {
		h->info.rx(ss_to_userobj(h), &q[pending_issue], n - pending_issue,
			   (!h->u.http.som ? LWSSS_FLAG_SOM : 0));
		h->u.http.any = 1;
		h->u.http.som = 1;
	}

	return 0;
}
#endif

static const uint8_t blob_idx[] = {
	LWS_SYSBLOB_TYPE_AUTH,
	LWS_SYSBLOB_TYPE_DEVICE_SERIAL,
	LWS_SYSBLOB_TYPE_DEVICE_FW_VERSION,
	LWS_SYSBLOB_TYPE_DEVICE_TYPE,
};

int
secstream_h1(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	lws_ss_handle_t *h = (lws_ss_handle_t *)lws_get_opaque_user_data(wsi);
	uint8_t buf[LWS_PRE + 1520], *p = &buf[LWS_PRE],
		*end = &buf[sizeof(buf) - 1];
	int f = 0, m, status;
	size_t buflen;

	switch (reason) {

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		assert(h);
		assert(h->policy);
		lwsl_info("%s: h: %p, %s CLIENT_CONNECTION_ERROR: %s\n", __func__,
			  h, h->policy->streamtype, in ? (char *)in : "(null)");
		lws_ss_event_helper(h, LWSSSCS_UNREACHABLE);
		h->wsi = NULL;
		lws_ss_backoff(h);
		break;

	case LWS_CALLBACK_CLIENT_HTTP_REDIRECT:
		if (h->policy->u.http.fail_redirect)
			lws_system_cpd_set(lws_get_context(wsi),
					   LWS_CPD_CAPTIVE_PORTAL);
		/* don't follow it */
		return 1;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		if (!h)
			break;
		lwsl_info("%s: h: %p, %s LWS_CALLBACK_CLOSED_CLIENT_HTTP\n",
			  __func__, h,
			  h->policy ? h->policy->streamtype : "no policy");
		h->wsi = NULL;
		//bad = status != 200;
		//lws_cancel_service(lws_get_context(wsi)); /* abort poll wait */
		if (h->policy && !(h->policy->flags & LWSSSPOLF_OPPORTUNISTIC) &&
		    !h->txn_ok && !wsi->context->being_destroyed)
			lws_ss_backoff(h);
		if (lws_ss_event_helper(h, LWSSSCS_DISCONNECTED))
			lws_ss_destroy(&h);
		break;


	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		status = lws_http_client_http_response(wsi);
		lwsl_info("%s: LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP: %d\n", __func__, status);
	//	if (!status)
			/* it's just telling use we connected / joined the nwsi */
	//		break;

		if (h->policy->u.http.resp_expect)
			h->u.http.good_respcode =
					status == h->policy->u.http.resp_expect;
		else
			h->u.http.good_respcode = (status >= 200 && status < 300);
		// lwsl_err("%s: good resp %d %d\n", __func__, status, h->u.http.good_respcode);

		if (h->u.http.good_respcode)
			lwsl_info("%s: Connected streamtype %s, %d\n", __func__,
				  h->policy->streamtype, status);
		else
			lwsl_warn("%s: Connected streamtype %s, BAD %d\n", __func__,
				  h->policy->streamtype, status);

		h->hanging_som = 0;

		h->retry = 0;
		h->seqstate = SSSEQ_CONNECTED;
		lws_ss_set_timeout_us(h, LWS_SET_TIMER_USEC_CANCEL);
		lws_ss_event_helper(h, LWSSSCS_CONNECTED);

		/*
		 * Since it's an http transaction we initiated... this is
		 * proof of connection validity
		 */
		lws_validity_confirmed(wsi);

#if !defined(LWS_PLAT_FREERTOS) || defined(LWS_ROLE_H2)

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

			h->u.http.boundary[0] = '\0';
			do {
				e = lws_tokenize(&ts);
				if (e == LWS_TOKZE_TOKEN_NAME_EQUALS &&
				    !strncmp(ts.token, "boundary", 8) &&
				    ts.token_len == 8) {
					e = lws_tokenize(&ts);
					if (e != LWS_TOKZE_TOKEN)
						goto malformed;
					h->u.http.boundary[0] = '\x0d';
					h->u.http.boundary[1] = '\x0a';
					h->u.http.boundary[2] = '-';
					h->u.http.boundary[3] = '-';
					lws_strnncpy(h->u.http.boundary + 4,
						     ts.token, ts.token_len,
						     sizeof(h->u.http.boundary) - 4);
					h->u.http.boundary_len =
						(uint8_t)(ts.token_len + 4);
					h->u.http.boundary_seq = 2;
					h->u.http.boundary_dashes = 0;
				}
			} while (e > 0);
			lwsl_info("%s: multipart boundary '%s' len %d\n", __func__,
					h->u.http.boundary, h->u.http.boundary_len);

			/* inform the ss that a related message group begins */

			if (h->u.http.boundary[0])
				h->info.rx(ss_to_userobj(h), NULL, 0,
					   LWSSS_FLAG_RELATED_START);

			// lws_header_table_detach(wsi, 0);
		}
		break;
malformed:
		lwsl_notice("%s: malformed multipart header\n", __func__);
		return -1;
#else
		break;
#endif

	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
		if (h->writeable_len)
			wsi->http.writeable_len = h->writeable_len;

		{
			uint8_t **p = (uint8_t **)in, *end = (*p) + len,
				*oin = *(uint8_t **)in;

		/*
		 * blob-based headers
		 */

		for (m = 0; m < _LWSSS_HBI_COUNT; m++) {
			int o = 0, n;

			if (!h->policy->u.http.blob_header[m])
				continue;

			if (m == LWSSS_HBI_AUTH &&
			    h->policy->u.http.auth_preamble)
				o = lws_snprintf((char *)buf, sizeof(buf), "%s",
					h->policy->u.http.auth_preamble);

			if (o > (int)sizeof(buf) - 2)
				return -1;

			buflen = sizeof(buf) - o - 2;
			n = lws_system_blob_get(
				lws_system_get_blob(wsi->context, blob_idx[m], 0),
						    buf + o, &buflen, 0);
			if (n < 0)
				return -1;

			buf[o + buflen] = '\0';
			lwsl_debug("%s: adding blob %d: %s\n", __func__, m, buf);

			if (lws_add_http_header_by_name(wsi,
					 (uint8_t *)h->policy->u.http.blob_header[m],
					 buf, (int)(buflen + o), p, end))
				return -1;
		}

		/*
		 * metadata-based headers
		 */

		for (m = 0; m < h->policy->metadata_count; m++) {
			lws_ss_metadata_t *polmd;

			/* has to have a header string listed */
			if (!h->metadata[m].value)
				continue;

			polmd = lws_ss_policy_metadata_index(h->policy, m);

			assert(polmd);
			/* has to have a value */
			if (polmd->value && ((uint8_t *)polmd->value)[0]) {
				if (lws_add_http_header_by_name(wsi,
						polmd->value,
						h->metadata[m].value,
						(int)h->metadata[m].length, p, end))
				return -1;
			}
		}

		/*
		 * Content-length on POST if we have the length information
		 */

		if (!strcmp(h->policy->u.http.method, "POST") &&
		    wsi->http.writeable_len) {
			if (!(h->policy->flags &
				LWSSSPOLF_HTTP_NO_CONTENT_LENGTH)) {
				int n = lws_snprintf((char *)buf, 20, "%u",
					(unsigned int)wsi->http.writeable_len);
				if (lws_add_http_header_by_token(wsi,
						WSI_TOKEN_HTTP_CONTENT_LENGTH,
						buf, n, p, end))
					return -1;
			}
			lws_client_http_body_pending(wsi, 1);
		}

		(void)oin;
		// if (*p != oin)
		//	lwsl_hexdump_notice(oin, lws_ptr_diff(*p, oin));

		}

		break;

	/* chunks of chunked content, with header removed */
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		lwsl_debug("%s: RECEIVE_CLIENT_HTTP_READ: read %d\n",
				__func__, (int)len);
		if (!h)
			return 0;

#if !defined(LWS_PLAT_FREERTOS) || defined(LWS_ROLE_H2)
		if (h->u.http.boundary[0])
			return ss_http_multipart_parser(h, in, len);
#endif

		if (!h->subseq) {
			f |= LWSSS_FLAG_SOM;
			h->hanging_som = 1;
			h->subseq = 1;
		}

	//	lwsl_notice("%s: HTTP_READ: client side sent len %d fl 0x%x\n",
	//		    __func__, (int)len, (int)f);

		h->info.rx(ss_to_userobj(h), (const uint8_t *)in, len, f);

		return 0; /* don't passthru */

	/* uninterpreted http content */
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		{
			char *px = (char *)buf + LWS_PRE; /* guarantees LWS_PRE */
			int lenx = sizeof(buf) - LWS_PRE;

			if (lws_http_client_read(wsi, &px, &lenx) < 0)
				return -1;
		}
		lws_set_timeout(wsi, 99, 30);

		return 0; /* don't passthru */

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		lwsl_debug("%s: LWS_CALLBACK_COMPLETED_CLIENT_HTTP\n", __func__);
		if (h->hanging_som)
			h->info.rx(ss_to_userobj(h), NULL, 0, LWSSS_FLAG_EOM);

		wsi->http.writeable_len = h->writeable_len = 0;

		if (h->u.http.good_respcode)
			lws_ss_event_helper(h, LWSSSCS_QOS_ACK_REMOTE);
		else
			lws_ss_event_helper(h, LWSSSCS_QOS_NACK_REMOTE);

		h->wsi = NULL;
		h->txn_ok = 1;
		//bad = status != 200;
		lws_cancel_service(lws_get_context(wsi)); /* abort poll wait */
		break;

	case LWS_CALLBACK_CLIENT_HTTP_WRITEABLE:
		lwsl_info("%s: LWS_CALLBACK_CLIENT_HTTP_WRITEABLE\n", __func__);
		if (!h)
			return 0;

		if (!h->rideshare)
			h->rideshare = h->policy;

#if !defined(LWS_PLAT_FREERTOS) || defined(LWS_ROLE_H2)
		if (!h->inside_msg && h->rideshare->u.http.multipart_name)
			lws_client_http_multipart(wsi,
				h->rideshare->u.http.multipart_name,
				h->rideshare->u.http.multipart_filename,
				h->rideshare->u.http.multipart_content_type,
				(char **)&p, (char *)end);

		buflen = lws_ptr_diff(end, p);
		if (h->policy->u.http.multipart_name)
			buflen -= 24; /* allow space for end of multipart */

#endif

		if (h->info.tx(ss_to_userobj(h),  h->txord++, p, &buflen, &f)) {
			/* don't want to send anything */
			lwsl_debug("%s: dont want to write\n", __func__);
			return 0;
		}

		lwsl_info("%s: WRITEABLE: user tx says len %d fl 0x%x\n",
			    __func__, (int)buflen, (int)f);

		p += buflen;

		if (f & LWSSS_FLAG_EOM) {
#if !defined(LWS_PLAT_FREERTOS) || defined(LWS_ROLE_H2)
			/* end of rideshares */
			if (!h->rideshare->rideshare_streamtype) {
				lws_client_http_body_pending(wsi, 0);
				if (h->rideshare->u.http.multipart_name)
					lws_client_http_multipart(wsi, NULL, NULL, NULL,
						(char **)&p, (char *)end);
			} else {
#endif
				h->rideshare = lws_ss_policy_lookup(wsi->context,
						h->rideshare->rideshare_streamtype);
				lws_callback_on_writable(wsi);
#if !defined(LWS_PLAT_FREERTOS) || defined(LWS_ROLE_H2)
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

		if (lws_write(wsi, buf + LWS_PRE, lws_ptr_diff(p, buf + LWS_PRE),
			 LWS_WRITE_HTTP) != (int)lws_ptr_diff(p, buf + LWS_PRE)) {
			lwsl_err("%s: write failed\n", __func__);
			return -1;
		}

		lws_set_timeout(wsi, 0, 0);
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

const struct lws_protocols protocol_secstream_h1 = {
	"lws-secstream-h1",
	secstream_h1,
	0,
	0,
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

#if !defined(LWS_PLAT_FREERTOS) || defined(LWS_ROLE_H2)
	if (h->policy->flags & LWSSSPOLF_HTTP_MULTIPART)
		i->ssl_connection |= LCCSCF_HTTP_MULTIPART_MIME;

	if (h->policy->flags & LWSSSPOLF_HTTP_X_WWW_FORM_URLENCODED)
		i->ssl_connection |= LCCSCF_HTTP_X_WWW_FORM_URLENCODED;
#endif

	/* protocol aux is the path part */

	i->path = buf;
	buf[0] = '/';

	lws_strexp_init(&exp, (void *)h, lws_ss_exp_cb_metadata, buf + 1, len - 1);

	if (lws_strexp_expand(&exp, pbasis, strlen(pbasis),
			      &used_in, &used_out) != LSTRX_DONE)
		return 1;

	return 0;
}


const struct ss_pcols ss_pcol_h1 = {
	"h1",
	"http/1.1",
	"lws-secstream-h1",
	secstream_connect_munge_h1,
	NULL
};
