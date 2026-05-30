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
#include "private-lib-roles-h3.h"

struct lws *
lws_get_quic_network_wsi(struct lws *wsi);

static int
rops_write_role_protocol_h3(struct lws *wsi, unsigned char *buf, size_t len,
			    enum lws_write_protocol *wp);

static lws_handling_result_t
rops_handle_POLLIN_h3(struct lws_context_per_thread *pt, struct lws *wsi,
		      struct lws_pollfd *pollfd)
{
	/* h3 is an encapsulation role... it doesn't do POLLIN itself */
	return LWS_HPI_RET_HANDLED;
}

#if defined(LWS_WITH_CLIENT)
static int
lws_h3_client_handshake(struct lws *wsi)
{
	struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];
	uint8_t *buf, *start, *p, *end;
	char *meth = lws_hdr_simple_ptr(wsi, _WSI_TOKEN_CLIENT_METHOD),
	     *uri = lws_hdr_simple_ptr(wsi, _WSI_TOKEN_CLIENT_URI), *simp;
	const char *path = "/";
	int m, n;

	lwsl_wsi_debug(wsi, "%s", __func__);

	p = start = buf = pt->serv_buf + LWS_PRE;
	end = start + (wsi->a.context->pt_serv_buf_size / 2) - LWS_PRE - 1;

	if (wsi->do_ws)
		meth = "CONNECT";
	else if (!meth)
		meth = "GET";

	/* Reserve space for the 2-byte QPACK prefix at the beginning of the header block */
	p += 2;
	wsi->http.h3_prefix_ptr = start;


	if (lws_add_http3_header_by_token(wsi, WSI_TOKEN_HTTP_COLON_METHOD,
				(unsigned char *)meth, (int)strlen(meth), &p, end))
		return -1;

	if (wsi->do_ws) {
		if (lws_add_http3_header_by_token(wsi, WSI_TOKEN_COLON_PROTOCOL,
					(unsigned char *)"websocket", 9, &p, end))
			return -1;
	}

	if (lws_add_http3_header_by_token(wsi, WSI_TOKEN_HTTP_COLON_SCHEME,
				(unsigned char *)"https", 5, &p, end))
		return -1;

	n = lws_hdr_total_length(wsi, _WSI_TOKEN_CLIENT_HOST);
	simp = lws_hdr_simple_ptr(wsi, _WSI_TOKEN_CLIENT_HOST);
	if (!n && wsi->stash && wsi->stash->cis[CIS_ADDRESS]) {
		n = (int)strlen(wsi->stash->cis[CIS_ADDRESS]);
		simp = wsi->stash->cis[CIS_ADDRESS];
	}
	if (n && simp && lws_add_http3_header_by_token(wsi, WSI_TOKEN_HTTP_COLON_AUTHORITY,
			(unsigned char *)simp, n, &p, end))
		return -1;

	n = lws_hdr_total_length(wsi, _WSI_TOKEN_CLIENT_URI);
	if (n)
		path = uri;
	else if (wsi->stash && wsi->stash->cis[CIS_PATH]) {
		path = wsi->stash->cis[CIS_PATH];
		n = (int)strlen(path);
	} else
		n = 1;

	if (n > 1 && path[0] == '/' && path[1] == '/') {
		path++;
		n--;
	}

	if (n && lws_add_http3_header_by_token(wsi, WSI_TOKEN_HTTP_COLON_PATH,
				(unsigned char *)path, n, &p, end))
		return -1;

#if defined(LWS_ROLE_WS)
	if (wsi->do_ws) {
		const char *prot = lws_hdr_simple_ptr(wsi, _WSI_TOKEN_CLIENT_ORIGIN);
		
		if (lws_add_http3_header_by_token(wsi, WSI_TOKEN_VERSION,
					(unsigned char *)"13", 2, &p, end))
			return -1;

		if (!prot && wsi->stash && wsi->stash->cis[CIS_PROTOCOL])
			prot = wsi->stash->cis[CIS_PROTOCOL];

		if (prot) {
			if (lws_add_http3_header_by_token(wsi, WSI_TOKEN_PROTOCOL,
						(unsigned char *)prot, (int)strlen(prot), &p, end))
				return -1;
		}

		wsi->h23_stream_carries_ws = 1;
	}
#endif

	if (wsi->flags & LCCSCF_HTTP_MULTIPART_MIME) {
		uint8_t *p1 = lws_http_multipart_headers(wsi, p);
		if (!p1)
			return -1;
		p = p1;
	}

	/* Let the user append additional headers via callback */
	if (wsi->a.protocol->callback(wsi, LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER,
				wsi->user_space, &p, lws_ptr_diff_size_t(end, p) - 12))
		return -1;

	if (lws_finalize_http_header(wsi, &p, end))
		return -1;
	m = LWS_WRITE_HTTP_HEADERS;
#if defined(LWS_WITH_CLIENT)
	if (!(wsi->client_http_body_pending || lws_has_buffered_out(wsi)))
		m |= LWS_WRITE_H2_STREAM_END;
#endif

	lwsl_notice("%s: calling lws_write with m=0x%x (body_pending=%d, buffered_out=%d)\n", 
		__func__, m, wsi->client_http_body_pending, lws_has_buffered_out(wsi));

	n = lws_write(wsi, start, lws_ptr_diff_size_t(p, start), (enum lws_write_protocol)m);
	if (n != lws_ptr_diff(p, start))
		return -1;

	/* Update WSI state */
	lws_role_transition(wsi, LWSIFR_CLIENT, LRS_ESTABLISHED, &role_ops_h3);

	return 0;
}
#endif


static int
rops_perform_user_POLLOUT_h3(struct lws *wsi)
{
	lwsl_wsi_info(wsi, "rops_perform_user_POLLOUT_h3: entry, state=%d", lwsi_state(wsi));

	if (wsi->http.deferred_transaction_completed) {
		if (!lws_has_buffered_out(wsi)) {
			wsi->http.deferred_transaction_completed = 0;
			if (lws_http_transaction_completed(wsi)) {
				wsi->socket_is_permanently_unusable = 1;
				return -1;
			}
		}
		return 0;
	}

	if (lwsi_state(wsi) == LRS_FLUSHING_BEFORE_CLOSE) {
		if (!lws_has_buffered_out(wsi)) {
			wsi->socket_is_permanently_unusable = 1;
			return -1;
		}
		return 0;
	}

#if defined(LWS_WITH_HTTP_STREAM_COMPRESSION)
	if (wsi->http.comp_ctx.buflist_comp ||
	    wsi->http.comp_ctx.may_have_more) {
		enum lws_write_protocol wp = LWS_WRITE_HTTP;

		lwsl_wsi_info(wsi, "completing comp partial (buflist %p, may %d)",
			   wsi->http.comp_ctx.buflist_comp,
			   wsi->http.comp_ctx.may_have_more);

		if (rops_write_role_protocol_h3(wsi, NULL, 0, &wp) < 0) {
			lwsl_wsi_info(wsi, "signalling to close due to comp write fail");
			return -1;
		}
		lws_callback_on_writable(wsi);
		return 0;
	}
#endif

	if (wsi->h3.h3n && wsi == wsi->h3.h3n->cwsi_qpack_enc) {
		struct lws_qpack_tx_encoder *enc = &wsi->h3.h3n->qpack_tx_encoder;
		uint8_t *p;
		size_t len = (size_t)lws_buflist_next_segment_len(&enc->tx_bl, &p);

		if (len) {
			uint8_t tx_buf[LWS_PRE + 512];
			if (len > 512) len = 512;
			memcpy(tx_buf + LWS_PRE, p, len);

			int n = lws_write(wsi, tx_buf + LWS_PRE, len, LWS_WRITE_BINARY);
			if (n < 0) return -1;
			
			if (n > 0) {
				lws_buflist_use_segment(&enc->tx_bl, (size_t)n);
				if (lws_buflist_next_segment_len(&enc->tx_bl, &p))
					lws_callback_on_writable(wsi);
			}
		}
		return 0;
	}

	if (wsi->h3.h3n && (wsi == wsi->h3.h3n->cwsi_control ||
			    wsi == wsi->h3.h3n->cwsi_qpack_dec))
		return 0;

#if defined(LWS_WITH_FILE_OPS)
	if (lwsi_state(wsi) == LRS_ISSUING_FILE) {
		int n;
		int32_t usable_credit = wsi->txc.tx_cr;
		if (lws_rops_fidx(wsi->role_ops, LWS_ROPS_tx_credit)) {
			usable_credit = lws_rops_func_fidx(wsi->role_ops, LWS_ROPS_tx_credit).
						tx_credit(wsi, LWSTXCR_US_TO_PEER, 0);
		}
		if (lws_wsi_txc_check_skint(&wsi->txc, usable_credit)) {
			return 0;
		}

		((volatile struct lws *)wsi)->leave_pollout_active = 0;

		n = lws_serve_http_file_fragment(wsi);
		lwsl_wsi_info(wsi, "lws_serve_http_file_fragment says %d", n);

		if (n < 0) {
			lwsl_wsi_notice(wsi, "Closing POLLOUT child");
			return -1;
		}
		if (n > 0) {
			if (lws_http_transaction_completed(wsi))
				return -1;
		}
		if (!n) {
			int32_t usable_credit2 = wsi->txc.tx_cr;
			if (lws_rops_fidx(wsi->role_ops, LWS_ROPS_tx_credit)) {
				usable_credit2 = lws_rops_func_fidx(wsi->role_ops, LWS_ROPS_tx_credit).
							tx_credit(wsi, LWSTXCR_US_TO_PEER, 0);
			}
			if (usable_credit2 > 0) {
				lws_callback_on_writable(wsi);
				wsi->mux.requested_POLLOUT = 1;
			}
		}

		return 0;
	}
#endif

	if (lwsi_state(wsi) == LRS_H2_AWAIT_PREFACE) {
		lwsi_set_state(wsi, LRS_H2_WAITING_TO_SEND_HEADERS);
		lwsl_wsi_info(wsi, "rops_perform_user_POLLOUT_h3: advanced to LRS_H2_WAITING_TO_SEND_HEADERS");
		/* fall through to let it send headers now */
	}

	if (lwsi_state(wsi) == LRS_H2_WAITING_TO_SEND_HEADERS) {
#if defined(LWS_WITH_CLIENT)
		struct lws *nwsi = lws_get_quic_network_wsi(wsi);
		if (nwsi && nwsi->h3.h3n && nwsi->h3.h3n->peer_control && !nwsi->h3.h3n->peer_control->h3.seen_settings) {
			/* Wait for peer SETTINGS frame */
			return 0;
		}

		if (wsi->do_ws && nwsi && nwsi->h3.h3n && !nwsi->h3.h3n->peer_supports_ws) {
			if (wsi->cli_hostname_copy && wsi->a.context->alpn_cache && wsi->c_port) {
				char key[256];
				void *p;
				lws_snprintf(key, sizeof(key), "alpn_%s_%u", wsi->cli_hostname_copy, wsi->c_port);
				/* Overwrite h3 entry with h2 */
				lws_cache_write_through(wsi->a.context->alpn_cache, key,
							(const uint8_t *)"h2", 3,
							lws_now_usecs() + (lws_usec_t)(3600ULL * 1000000ULL), &p);
				lwsl_wsi_notice(wsi, "H3 WS not supported by peer, downgrading ALPN cache to h2 for %s", key);
			}
			return -1;
		}
		if (lws_h3_client_handshake(wsi)) {
			lwsl_wsi_err(wsi, "lws_h3_client_handshake failed!");
			return -1;
		}
#endif
		return 0;
	}

#if defined(LWS_WITH_SERVER)
	if (lwsi_state(wsi) == LRS_DEFERRING_ACTION) {
		int n;

		lwsi_set_state(wsi, LRS_ESTABLISHED);

		lwsl_debug("H3_TRACE: wsi %p entering lws_http_action from rops_perform_user_POLLOUT_h3\n", wsi);
		n = lws_http_action(wsi);
		if (n < 0) {
			lwsl_debug("H3_TRACE: wsi %p lws_http_action failed, returning %d\n", wsi, n);
			return -1;
		}
		if (n > 0) {
			lwsl_wsi_notice(wsi, "closing stream after h3 action completed (%d)", n);
			return -1;
		}
		lwsl_debug("H3_TRACE: wsi %p lws_http_action returned 0 (success)\n", wsi);
		return 0;
	}
#endif

	if (lwsi_state(wsi) == LRS_ESTABLISHED) {
		int m = lws_callback_as_writeable(wsi);
		lwsl_wsi_info(wsi, "rops_perform_user_POLLOUT_h3: LRS_ESTABLISHED lws_callback_as_writeable returned %d", m);
		return m;
	}

	lwsl_wsi_info(wsi, "rops_perform_user_POLLOUT_h3: falling through to lws_callback_as_writeable with state=%d", lwsi_state(wsi));
	return lws_callback_as_writeable(wsi);
}

static int
lws_h3_parse_path(struct lws *wsi, const char *value, size_t value_len)
{
	struct allocated_headers *ah = wsi->http.ah;
	struct lws *nwsi = lws_get_quic_network_wsi(wsi);
	size_t i;

	if (!ah)
		return -1;

	/* Start fragment for WSI_TOKEN_HTTP_COLON_PATH */
	ah->nfrag++;
	if (ah->nfrag >= LWS_ARRAY_SIZE(ah->frag_index)) {
		lwsl_wsi_err(wsi, "frag index too big");
		return -1;
	}

	ah->frags[ah->nfrag].offset = ah->pos;
	ah->frags[ah->nfrag].len = 0;
	ah->frags[ah->nfrag].nfrag = 0;
	ah->frags[ah->nfrag].flags = 2; /* we had reason to set it */

	ah->hdr_token_idx = WSI_TOKEN_HTTP_COLON_PATH;
	ah->frag_index[WSI_TOKEN_HTTP_COLON_PATH] = ah->nfrag;

	ah->ues = URIES_IDLE;
	ah->ups = URIPS_IDLE;
	ah->post_literal_equal = 0;

	for (i = 0; i < value_len; i++) {
		uint8_t c = (uint8_t)value[i];

		switch (lws_parse_urldecode(wsi, &c)) {
		case LPUR_CONTINUE:
			break;
		case LPUR_SWALLOW:
			continue;
		case LPUR_EXCESSIVE:
		case LPUR_FORBID:
			lwsl_wsi_notice(wsi, "Evil or excessive URI in H3 path");
			lws_quic_enter_closing_state(nwsi, LWS_H3_MESSAGE_ERROR, 0, 1);
			return -1;
		default:
			return -1;
		}

		/* Append character */
		if ((int)ah->pos >= (int)wsi->a.context->max_http_header_data - 1) {
			lwsl_wsi_err(wsi, "Header data overflow");
			return -1;
		}
		ah->data[ah->pos++] = (char)c;
		ah->frags[ah->nfrag].len++;
	}

	/* Seal fragment */
	if ((int)ah->pos >= (int)wsi->a.context->max_http_header_data - 1) {
		lwsl_wsi_err(wsi, "Header data overflow");
		return -1;
	}
	ah->data[ah->pos++] = '\0';

	return 0;
}

static int
lws_h3_qpack_header_cb(void *user, int name_idx, const char *name, size_t name_len, const char *value, size_t value_len)
{
	struct lws *wsi = (struct lws *)user;
	int tok = name_idx;
	struct lws *nwsi = lws_get_quic_network_wsi(wsi);
	int is_pseudo = 0;

	/* If we haven't attached an ah, do it now */
	if (!wsi->http.ah) {
		if (lws_header_table_attach(wsi, 0)) {
			lwsl_wsi_err(wsi, "Failed to attach ah");
			return -1;
		}
	}

	if (name) {
		lwsl_wsi_debug(wsi, "QPACK decoded header: name=%.*s, value=%.*s", (int)name_len, name, (int)value_len, value);
		/* It's an unknown header, or string-based. We need to match it. */
		tok = lws_http_string_to_known_header(name, name_len);
		if (name_len > 0 && name[0] == ':') is_pseudo = 1;
	} else {
		lwsl_wsi_debug(wsi, "QPACK decoded header: tok=%d (%s), value=%.*s", tok, (const char *)lws_token_to_string((enum lws_token_indexes)tok), (int)value_len, value);
		if (tok == WSI_TOKEN_HTTP_COLON_AUTHORITY ||
		    tok == WSI_TOKEN_HTTP_COLON_METHOD ||
		    tok == WSI_TOKEN_HTTP_COLON_PATH ||
		    tok == WSI_TOKEN_HTTP_COLON_SCHEME ||
		    tok == WSI_TOKEN_HTTP_COLON_STATUS ||
		    tok == WSI_TOKEN_COLON_PROTOCOL) {
			is_pseudo = 1;
		}
	}

	if (is_pseudo) {
		/* HTTP/3 4.1.1: MUST send H3_MESSAGE_ERROR if pseudo-header fields exist after regular fields */
		if (wsi->h3.seen_regular_header) {
			lws_quic_enter_closing_state(nwsi, LWS_H3_MESSAGE_ERROR, 0, 1);
			return -1;
		}

		/* HTTP/3 4.1.1: MUST send H3_MESSAGE_ERROR if a pseudo-header is duplicated */
		if (tok == WSI_TOKEN_HTTP_COLON_METHOD) {
			if (wsi->h3.seen_pseudo_method) goto duplicate;
			wsi->h3.seen_pseudo_method = 1;
		} else if (tok == WSI_TOKEN_HTTP_COLON_SCHEME) {
			if (wsi->h3.seen_pseudo_scheme) goto duplicate;
			wsi->h3.seen_pseudo_scheme = 1;
		} else if (tok == WSI_TOKEN_HTTP_COLON_AUTHORITY) {
			if (wsi->h3.seen_pseudo_authority) goto duplicate;
			wsi->h3.seen_pseudo_authority = 1;
		} else if (tok == WSI_TOKEN_HTTP_COLON_PATH) {
			if (wsi->h3.seen_pseudo_path) goto duplicate;
			wsi->h3.seen_pseudo_path = 1;
		} else if (tok == WSI_TOKEN_HTTP_COLON_STATUS) {
			if (wsi->h3.seen_pseudo_status) goto duplicate;
			wsi->h3.seen_pseudo_status = 1;
		} else if (tok == WSI_TOKEN_COLON_PROTOCOL) {
			if (wsi->h3.seen_pseudo_protocol) goto duplicate;
			wsi->h3.seen_pseudo_protocol = 1;
		} else {
			/* Prohibited pseudo-header */
			lws_quic_enter_closing_state(nwsi, LWS_H3_MESSAGE_ERROR, 0, 1);
			return -1;
		}
	} else {
		wsi->h3.seen_regular_header = 1;
	}

	if (tok >= 0 && tok < WSI_TOKEN_COUNT) {
		/* Known token */
		if (tok == WSI_TOKEN_HTTP_COLON_STATUS) {
			wsi->http.ah->http_response = (uint32_t)atoi(value);
		}
		if (tok == WSI_TOKEN_HTTP_COLON_PATH) {
			if (lws_h3_parse_path(wsi, value, value_len))
				return -1;
		} else {
			if (tok == WSI_TOKEN_HTTP_COLON_AUTHORITY) {
				if (lws_hdr_simple_create(wsi, WSI_TOKEN_HOST, value))
					return -1;
			}
			if (lws_hdr_simple_create(wsi, (enum lws_token_indexes)tok, value))
				return -1;
		}
	} else {
		lwsl_wsi_debug(wsi, "Ignoring unknown header: %s", name ? name : "unknown");
	}

	return 0;

duplicate:
	lws_quic_enter_closing_state(nwsi, LWS_H3_MESSAGE_ERROR, 0, 1);
	return -1;
}

static int
lws_h3_parse_varint_accum(struct lws *wsi, const uint8_t **pbuf, size_t *plen, uint64_t *val)
{
	const uint8_t *buf = *pbuf;
	size_t len = *plen;
	size_t needed = 0;

	if (wsi->h3.rx_varint_len == 0) {
		if (len == 0) return 0;
		uint8_t type = buf[0] >> 6;
		if (type == 0) needed = 1;
		else if (type == 1) needed = 2;
		else if (type == 2) needed = 4;
		else needed = 8;

		if (len >= needed) {
			size_t consumed = lws_quic_parse_varint(buf, len, val);
			*pbuf += consumed;
			*plen -= consumed;
			return 1;
		}
	} else {
		uint8_t type = wsi->h3.rx_varint_buf[0] >> 6;
		if (type == 0) needed = 1;
		else if (type == 1) needed = 2;
		else if (type == 2) needed = 4;
		else needed = 8;
	}

	size_t to_copy = needed - wsi->h3.rx_varint_len;
	if (to_copy > len) to_copy = len;

	memcpy(&wsi->h3.rx_varint_buf[wsi->h3.rx_varint_len], buf, to_copy);
	wsi->h3.rx_varint_len += (uint8_t)to_copy;
	*pbuf += to_copy;
	*plen -= to_copy;

	if (wsi->h3.rx_varint_len == needed) {
		lws_quic_parse_varint(wsi->h3.rx_varint_buf, needed, val);
		wsi->h3.rx_varint_len = 0;
		return 1;
	}

	return 0;
}


#if defined(LWS_WITH_CLIENT)
static int
rops_client_bind_h3(struct lws *wsi, const struct lws_client_connect_info *i)
{
	if (!i)
		return 0;

	/* 
	 * If alpn was specified as h3, we want to start as quic, 
	 * and when ALPN confirms h3, the streams transition to h3.
	 */
	return 0;
}
#endif

static int
rops_adoption_bind_h3(struct lws *wsi, int type, const char *vh_prot_name)
{
	/* 
	 * If we are adopting a QUIC stream that negotiated h3, 
	 * we transition it to h3 role here.
	 */
	return 0;
}

#if defined(LWS_PLAT_FREERTOS)
#define LWS_QPACK_CAP_VARINT 0x50 /* 4096 */
#define LWS_QPACK_CAP_VAL 4096
#else
#define LWS_QPACK_CAP_VARINT 0x60 /* 8192 */
#define LWS_QPACK_CAP_VAL 8192
#endif

static struct lws *
lws_h3_create_unidi_stream(struct lws *nwsi, uint8_t type)
{
	struct lws_quic_netconn *qn = nwsi->quic.qn;
	struct lws *cwsi;

	cwsi = lws_create_new_server_wsi(nwsi->a.vhost, nwsi->tsi, 0, "h3_unidi");
	if (!cwsi)
		return NULL;

	lws_role_transition(cwsi, LWSIFR_CLIENT, LRS_ESTABLISHED, &role_ops_h3);
	cwsi->mux_substream = 1;
#if defined(LWS_WITH_CLIENT)
	cwsi->client_mux_substream = 1;
#endif

	cwsi->quic.qs = lws_zalloc(sizeof(*cwsi->quic.qs), "quic stream");
	if (!cwsi->quic.qs) {
		lws_close_free_wsi(cwsi, LWS_CLOSE_STATUS_NOSTATUS, "oom");
		return NULL;
	}

	if (qn->peer_initial_max_stream_data_uni) {
		cwsi->txc.tx_cr = (int32_t)qn->peer_initial_max_stream_data_uni;
		cwsi->txc.peer_tx_cr_est = (int32_t)qn->peer_initial_max_stream_data_uni;
	} else {
		cwsi->txc.tx_cr = 65535;
		cwsi->txc.peer_tx_cr_est = 65535;
	}
	cwsi->quic.qs->stream_id = qn->next_stream_id_unidi_local;

	/* We're doing client unidi streams */
	lws_wsi_mux_insert(cwsi, nwsi, (unsigned int)qn->next_stream_id_unidi_local);
	qn->next_stream_id_unidi_local += 4;

	cwsi->h3.h3n = nwsi->h3.h3n;

	{
		uint8_t pre[LWS_PRE + 16];
#if (_LWS_ENABLED_LOGS & LLL_NOTICE)
		int n;
#endif
		size_t send_len = 1;
		pre[LWS_PRE] = type;
		if (type == 0x00) {
			/* HTTP/3 Control Stream MUST send a SETTINGS frame (Type 0x04) immediately */

			if (nwsi->a.vhost->h2.set.s[H2SET_ENABLE_CONNECT_PROTOCOL]) {
				pre[LWS_PRE + 1] = 0x04; /* SETTINGS */
				pre[LWS_PRE + 2] = 0x0c; /* Length 12 */
				pre[LWS_PRE + 3] = 0x01; /* SETTINGS_QPACK_MAX_TABLE_CAPACITY */
				pre[LWS_PRE + 4] = LWS_QPACK_CAP_VARINT;
				pre[LWS_PRE + 5] = 0x00;
				pre[LWS_PRE + 6] = 0x08; /* SETTINGS_ENABLE_CONNECT_PROTOCOL */
				pre[LWS_PRE + 7] = 0x01; /* 1 */
				pre[LWS_PRE + 8] = 0x33; /* SETTINGS_H3_DATAGRAM */
				pre[LWS_PRE + 9] = 0x01; /* 1 */
				pre[LWS_PRE + 10] = 0xab; pre[LWS_PRE + 11] = 0x60; pre[LWS_PRE + 12] = 0x37; pre[LWS_PRE + 13] = 0x42; /* SETTINGS_ENABLE_WEBTRANSPORT */
				pre[LWS_PRE + 14] = 0x01; /* 1 */
				send_len = 15;
			} else {
				pre[LWS_PRE + 1] = 0x04; /* SETTINGS */
				pre[LWS_PRE + 2] = 0x03; /* Length 3 */
				pre[LWS_PRE + 3] = 0x01; /* SETTINGS_QPACK_MAX_TABLE_CAPACITY */
				pre[LWS_PRE + 4] = LWS_QPACK_CAP_VARINT;
				pre[LWS_PRE + 5] = 0x00;
				send_len = 6;
			}
			
#if (_LWS_ENABLED_LOGS & LLL_NOTICE)
			n = lws_write(cwsi, &pre[LWS_PRE], send_len, LWS_WRITE_BINARY | LWS_WRITE_NO_FIN);
			lwsl_info("lws_h3_create_unidi_stream: lws_write control ret %d\n", n);
#else
			lws_write(cwsi, &pre[LWS_PRE], send_len, LWS_WRITE_BINARY | LWS_WRITE_NO_FIN);
#endif
		} else {
#if (_LWS_ENABLED_LOGS & LLL_NOTICE)
			n = lws_write(cwsi, &pre[LWS_PRE], 1, LWS_WRITE_BINARY | LWS_WRITE_NO_FIN);
			lwsl_info("lws_h3_create_unidi_stream: lws_write %d ret %d\n", type, n);
#else
			lws_write(cwsi, &pre[LWS_PRE], 1, LWS_WRITE_BINARY | LWS_WRITE_NO_FIN);
#endif
		}
	}

	lws_callback_on_writable(cwsi);

	return cwsi;
}

static size_t
lws_quic_parse_varint_prefix(const uint8_t *buf, size_t len, int prefix_len, uint64_t *val)
{
	if (!len) return 0;
	uint8_t mask = (uint8_t)((1 << prefix_len) - 1);
	uint8_t first = buf[0] & mask;
	if (first < mask) {
		*val = first;
		return 1;
	}
	/* It's mask + a variable length integer... */
	/* We need to parse an integer that is encoded 7 bits per byte until MSB is 0 */
	size_t i = 1;
	uint64_t v = mask;
	int shift = 0;
	while (i < len) {
		uint8_t b = buf[i++];
		v += (uint64_t)(b & 0x7f) << shift;
		if (!(b & 0x80)) {
			*val = v;
			return i;
		}
		shift += 7;
		if (shift >= 64) {
			/* Prevent undefined behavior from shifting >= 64 bits */
			return 0;
		}
	}
	return 0; /* Need more data */
}

int
lws_h3_rx_stream_data(struct lws *wsi, const uint8_t *buf, size_t len)
{
	// lwsl_notice("H3 RX: %d bytes\n", (int)len);
	// lwsl_hexdump_notice(buf, len);

	/* If it's unidirectional and we don't know the type yet */
	if (wsi->quic.qs && wsi->quic.qs->is_unidirectional && !wsi->h3.type_set) {
		uint64_t type;
		size_t consumed = lws_quic_parse_varint(buf, len, &type);
		
		if (!consumed) return 0; /* Need more data */
		
		wsi->h3.stream_type = (uint8_t)type;
		wsi->h3.type_set = 1;
		if (type == 0x02) {
			wsi->h3.qpack_dec_state.state = LQP_DEC_INSTRUCTION;
		}
		buf += consumed;
		len -= consumed;

		lwsl_wsi_info(wsi, "H3 RX: Unidi stream type %llu", (unsigned long long)type);

		/* Link it to peer's control streams if applicable */
		if (wsi->h3.h3n) {
			if (type == 0x00) wsi->h3.h3n->peer_control = wsi;
			else if (type == 0x02) wsi->h3.h3n->peer_qpack_enc = wsi;
			else if (type == 0x03) wsi->h3.h3n->peer_qpack_dec = wsi;
		}
	}

	if (!len)
		return 0;

	while (len > 0) {
		if (wsi->h3.stream_type == 0x00) {
			lwsl_wsi_debug(wsi, "H3 RX: Control Stream data len %d", (int)len);
		} else if (wsi->h3.stream_type == 0x02) {
			struct lws_qpack_context *ctx = wsi->h3.h3n ? &wsi->h3.h3n->qpack_dec_ctx : NULL;
			lwsl_wsi_info(wsi, "LWS_H3_RX_STREAM_DATA: Encoder Stream payload received, len=%d", (int)len);
			
			if (lws_qpack_decode_encoder_stream(&wsi->h3.qpack_dec_state, ctx, buf, len)) {
				struct lws *nwsi = lws_get_quic_network_wsi(wsi);
				lwsl_err("ERROR: QPACK_ENCODER_STREAM_ERROR!!!!\n");
lws_quic_enter_closing_state(nwsi, LWS_QPACK_ENCODER_STREAM_ERROR, 0, 1);
				return 1;
			}
			buf += len; len = 0;
			return 0;
		} else if (wsi->h3.stream_type == 0x03) {
			lwsl_wsi_debug(wsi, "H3 RX: Decoder Stream data len %d", (int)len);
			size_t i = 0;
			while (i < len) {
				uint8_t b = buf[i];
				if ((b & 0x80) == 0x80) { /* Header Acknowledgement */
					uint64_t stream_id;
					size_t consumed = lws_quic_parse_varint_prefix(&buf[i], len - i, 7, &stream_id);
					if (consumed) {
						lwsl_wsi_info(wsi, "QPACK Header Ack stream_id=%llu", (unsigned long long)stream_id);
						i += consumed;
						continue;
					}
					break;
				} else if ((b & 0xc0) == 0x40) { /* Stream Cancellation */
					uint64_t stream_id;
					size_t consumed = lws_quic_parse_varint_prefix(&buf[i], len - i, 6, &stream_id);
					if (consumed) {
						lwsl_wsi_info(wsi, "QPACK Stream Cancel stream_id=%llu", (unsigned long long)stream_id);
						i += consumed;
						continue;
					}
					break;
				} else if ((b & 0xc0) == 0x00) { /* Insert Count Increment */
					uint64_t inc;
					size_t consumed = lws_quic_parse_varint_prefix(&buf[i], len - i, 6, &inc);
					if (consumed) {
						if (inc == 0) {
							struct lws *nwsi = lws_get_quic_network_wsi(wsi);
							lws_quic_enter_closing_state(nwsi, LWS_QPACK_DECODER_STREAM_ERROR, 0, 1);
							return 1;
						}
						if (wsi->h3.h3n)
							wsi->h3.h3n->qpack_tx_encoder.known_received_count += (uint32_t)inc;
						lwsl_wsi_info(wsi, "QPACK Insert Count Increment inc=%llu known=%u", (unsigned long long)inc, (unsigned int)(wsi->h3.h3n ? wsi->h3.h3n->qpack_tx_encoder.known_received_count : 0));
						i += consumed;
						continue;
					}
					break;
				}
				i++;
			}
			buf += len; len = 0;
			return 0;
		}
		if (wsi->h3.rx_frame_state == 0) {
			if (lws_h3_parse_varint_accum(wsi, &buf, &len, &wsi->h3.rx_frame_type)) {
				wsi->h3.rx_frame_state = 1;
			} else break;
		} else if (wsi->h3.rx_frame_state == 1) {
			if (lws_h3_parse_varint_accum(wsi, &buf, &len, &wsi->h3.rx_frame_len)) {
				wsi->h3.rx_frame_state = 2;
				wsi->h3.rx_frame_payload_read = 0;
				lwsl_wsi_info(wsi, "H3 RX: Frame Type %llu, Len %llu on stream type %d (unidi=%d)", 
					(unsigned long long)wsi->h3.rx_frame_type, (unsigned long long)wsi->h3.rx_frame_len,
					wsi->h3.stream_type, wsi->quic.qs ? wsi->quic.qs->is_unidirectional : 0);

				/* Validation: Control Streams */
				if (wsi->quic.qs && wsi->quic.qs->is_unidirectional && wsi->h3.stream_type == 0x00) {
					/* HTTP/3 6.2.1: MUST send H3_MISSING_SETTINGS if the first control frame is not SETTINGS */
					if (!wsi->h3.seen_settings && wsi->h3.rx_frame_type != 0x04) {
						struct lws *nwsi = lws_get_quic_network_wsi(wsi);
						lws_quic_enter_closing_state(nwsi, LWS_H3_MISSING_SETTINGS, 0, 1);
						return 1;
					}
					/* HTTP/3 7.2.1/7.2.2: MUST send H3_FRAME_UNEXPECTED if DATA or HEADERS is received on a control stream */
					if (wsi->h3.rx_frame_type == 0x00 || wsi->h3.rx_frame_type == 0x01) {
						struct lws *nwsi = lws_get_quic_network_wsi(wsi);
						lws_quic_enter_closing_state(nwsi, LWS_H3_FRAME_UNEXPECTED, 0, 1);
						return 1;
					}
					/* HTTP/3 7.2.4: MUST send H3_FRAME_UNEXPECTED if a second SETTINGS frame is received */
					if (wsi->h3.seen_settings && wsi->h3.rx_frame_type == 0x04) {
						struct lws *nwsi = lws_get_quic_network_wsi(wsi);
						lws_quic_enter_closing_state(nwsi, LWS_H3_FRAME_UNEXPECTED, 0, 1);
						return 1;
					}
					if (wsi->h3.rx_frame_type == 0x04) {
						wsi->h3.seen_settings = 1;
					}
				}

				/* Validation: Request Streams */
				if (!wsi->quic.qs || !wsi->quic.qs->is_unidirectional) {
					lwsl_wsi_debug(wsi, "H3 Validation: rx_frame_type=%d, hdr_parsing_completed=%d",
						(int)wsi->h3.rx_frame_type, (int)wsi->hdr_parsing_completed);
					if (wsi->h3.rx_frame_type == 0x00 && !wsi->hdr_parsing_completed) {
						struct lws *nwsi = lws_get_quic_network_wsi(wsi);
						lws_quic_enter_closing_state(nwsi, LWS_H3_FRAME_UNEXPECTED, 0, 1);
						return 1;
					}
					if (wsi->h3.rx_frame_type == 0x03) { /* CANCEL_PUSH */
						struct lws *nwsi = lws_get_quic_network_wsi(wsi);
						lws_quic_enter_closing_state(nwsi, LWS_H3_FRAME_UNEXPECTED, 0, 1);
						return 1;
					}
				}
			} else break;
		} else if (wsi->h3.rx_frame_state == 2) {
			size_t chunk = (size_t)(wsi->h3.rx_frame_len - wsi->h3.rx_frame_payload_read);
			if (chunk > len) chunk = len;

			if (!wsi->quic.qs || !wsi->quic.qs->is_unidirectional) {
				if (wsi->h3.rx_frame_type == 0x01) { /* HEADERS */
					struct lws_qpack_context *ctx = wsi->h3.h3n ? &wsi->h3.h3n->qpack_dec_ctx : NULL;
					if (lws_qpack_decode_header_block(&wsi->h3.qpack_dec_state, ctx, buf, chunk, lws_h3_qpack_header_cb, wsi)) {
						struct lws *nwsi = lws_get_quic_network_wsi(wsi);
						lws_quic_enter_closing_state(nwsi, LWS_QPACK_DECOMPRESSION_FAILED, 0, 1);
						return 1;
					}
				} else if (wsi->h3.rx_frame_type == 0x00) { /* DATA */
					/* Deliver data to application */
#if defined(LWS_WITH_CLIENT)
					int m = 0;
					if (wsi->client_mux_substream) {
						if (!wsi->a.protocol) {
							lwsl_wsi_err(wsi, "doesn't have protocol");
						} else {
							m = user_callback_handle_rxflow(
								wsi->a.protocol->callback,
								wsi,
								LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ,
								wsi->user_space,
								(void *)buf, (unsigned int)chunk);
						}
						if (m) {
							lwsl_wsi_info(wsi, "RECEIVE_CLIENT_HTTP closed it");
							return 1;
						}
						if (wsi->http.rx_content_length > 0)
							wsi->http.rx_content_remain -= chunk;

						if (wsi->http.content_length_given && !wsi->http.rx_content_remain) {
							lwsl_wsi_info(wsi, "H3 client transaction completed via content-length");
							if (lws_http_transaction_completed_client(wsi))
								return 1;
						}
					} else
#endif
					{
						/* Server-side receive */
						int n;
						
						if (lwsi_state(wsi) == LRS_DEFERRING_ACTION) {
							n = lws_buflist_append_segment(&wsi->buflist, buf, chunk);
							if (n < 0)
								return 1;
							lwsl_debug("H3_TRACE: deferred %d bytes in buflist\n", (int)chunk);
						} else {
							wsi->outer_will_close = 1;
							n = lws_read_h1(wsi, (unsigned char *)buf, chunk);
							wsi->outer_will_close = 0;
							
							if (n < 0) {
								lwsl_wsi_info(wsi, "server side read failed");
								return 1;
							}
						}
					}
				}
			} else if (wsi->h3.stream_type == 0x00 && wsi->h3.rx_frame_type == 0x04) {
				/* Parse SETTINGS frame */
				size_t i = 0;
				while (i < chunk) {
					/* Need to parse identifier (varint) and value (varint) */
					/* For now, just check if it's an HTTP/2 setting! (HTTP/3 7.2.4.1) */
					/* Proper parsing requires state, but if we just check bytes: */
					uint64_t id, val;
					const uint8_t *p = buf + i;
					size_t clen = chunk - i;
					size_t consumed = lws_quic_parse_varint(p, clen, &id);
					if (consumed) {
						p += consumed; clen -= consumed; i += consumed;
						consumed = lws_quic_parse_varint(p, clen, &val);
						if (consumed) {
							i += consumed;
							if (id == 0x00 || id == 0x02 || id == 0x03 || id == 0x04 || id == 0x05) {
								/* Prohibited HTTP/2 setting */
								struct lws *nwsi = lws_get_quic_network_wsi(wsi);
								lws_quic_enter_closing_state(nwsi, LWS_H3_SETTINGS_ERROR, 0, 1);
								return 1;
							} else if (id == 0x01) { /* SETTINGS_QPACK_MAX_TABLE_CAPACITY */
								if (wsi->h3.h3n) {
									wsi->h3.h3n->qpack_tx_encoder.virtual_payload_max = (uint32_t)val;
								}
							} else if (id == 0x08) {
								/* SETTINGS_ENABLE_WEB_SOCKETS */
								struct lws *nwsi = lws_get_quic_network_wsi(wsi);
								if (nwsi && nwsi->h3.h3n)
									nwsi->h3.h3n->peer_supports_ws = 1;
							} else if (id == LWS_H3_SETTINGS_H3_DATAGRAM) {
								struct lws *nwsi = lws_get_quic_network_wsi(wsi);
								if (nwsi && nwsi->h3.h3n)
									nwsi->h3.h3n->peer_supports_h3_datagram = 1;
							} else if (id == LWS_H3_SETTINGS_ENABLE_WEBTRANSPORT) {
								struct lws *nwsi = lws_get_quic_network_wsi(wsi);
								if (nwsi && nwsi->h3.h3n)
									nwsi->h3.h3n->peer_supports_webtransport = 1;
							}
						} else {
							i++; /* Malformed but skip to consume */
						}
					} else {
						i++;
					}
				}
			}
			
			wsi->h3.rx_frame_payload_read += chunk;
			buf += chunk;
			len -= chunk;

			/* Replenish flow control window */
			lws_wsi_tx_credit(wsi, LWSTXCR_PEER_TO_US, (int)chunk);

			if (wsi->h3.rx_frame_payload_read == wsi->h3.rx_frame_len) {
				if (wsi->h3.stream_type == 0x00 && wsi->h3.rx_frame_type == 0x04) {
					/* SETTINGS frame fully received, wake up children */
					struct lws *nwsi = lws_get_quic_network_wsi(wsi);
					if (nwsi) {
						struct lws *child = nwsi->mux.child_list;
						while (child) {
							lws_callback_on_writable(child);
							child = child->mux.sibling_list;
						}
					}
				}

				if ((!wsi->quic.qs || !wsi->quic.qs->is_unidirectional) && wsi->h3.rx_frame_type == 0x01) {
					/* HEADERS frame complete, validate and notify application! */
					
					/* HTTP/3 4.1.3: MUST send H3_MESSAGE_ERROR if mandatory pseudo-header fields are absent */
					struct lws *nwsi = lws_get_quic_network_wsi(wsi);
					lwsl_wsi_info(wsi, "H3 HEADERS frame completed. is_server=%d, seen_method=%d, seen_scheme=%d, seen_path=%d", 
						(nwsi && nwsi->quic.qn) ? nwsi->quic.qn->is_server : -1,
						wsi->h3.seen_pseudo_method, wsi->h3.seen_pseudo_scheme, wsi->h3.seen_pseudo_path);
					if (nwsi && nwsi->quic.qn && nwsi->quic.qn->is_server) {
						/* Request headers must have :method, :scheme, :path, and :authority */
						if (!wsi->h3.seen_pseudo_method || !wsi->h3.seen_pseudo_scheme || !wsi->h3.seen_pseudo_path || !wsi->h3.seen_pseudo_authority) {
							lwsl_wsi_notice(wsi, "H3 MESSAGE_ERROR: Missing mandatory pseudo-headers!");
							lws_quic_enter_closing_state(nwsi, LWS_H3_MESSAGE_ERROR, 0, 1);
							return 1;
						}
						/* Prohibited in requests */
						if (wsi->h3.seen_pseudo_status) {
							lws_quic_enter_closing_state(nwsi, LWS_H3_MESSAGE_ERROR, 0, 1);
							return 1;
						}
					}

					/* duplicate :path into the individual method uri header index */
					const char *p = lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP_COLON_METHOD);
#if (_LWS_ENABLED_LOGS & LLL_INFO)
					const char *path_val = lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP_COLON_PATH);
					lwsl_wsi_info(wsi, "Decoded method: %s, Decoded path: %s", p ? p : "NULL", path_val ? path_val : "NULL");
#endif
					
					static const char * const method_names[] = {
						"GET", "POST",
					#if defined(LWS_WITH_HTTP_UNCOMMON_HEADERS)
						"OPTIONS", "PUT", "PATCH", "DELETE",
					#endif
						"CONNECT", "HEAD"
					};
					static const unsigned char method_index[] = {
						WSI_TOKEN_GET_URI,
						WSI_TOKEN_POST_URI,
					#if defined(LWS_WITH_HTTP_UNCOMMON_HEADERS)
						WSI_TOKEN_OPTIONS_URI,
						WSI_TOKEN_PUT_URI,
						WSI_TOKEN_PATCH_URI,
						WSI_TOKEN_DELETE_URI,
					#endif
						WSI_TOKEN_CONNECT,
						WSI_TOKEN_HEAD_URI,
					};
					for (int n = 0; n < (int)LWS_ARRAY_SIZE(method_names); n++) {
						if (p && !strcasecmp(p, method_names[n])) {
							wsi->http.ah->frag_index[method_index[n]] =
								wsi->http.ah->frag_index[WSI_TOKEN_HTTP_COLON_PATH];
							break;
						}
					}
					
					lwsl_debug("H3_TRACE: HEADERS frame complete for wsi %p. :authority len=%d (%s), HOST len=%d (%s), vhost=%s\n",
						wsi,
						lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_COLON_AUTHORITY),
						lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP_COLON_AUTHORITY) ? lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP_COLON_AUTHORITY) : "null",
						lws_hdr_total_length(wsi, WSI_TOKEN_HOST),
						lws_hdr_simple_ptr(wsi, WSI_TOKEN_HOST) ? lws_hdr_simple_ptr(wsi, WSI_TOKEN_HOST) : "null",
						wsi->a.vhost ? wsi->a.vhost->name : "null");

					wsi->hdr_parsing_completed = 1;
					
					/* Extract Content-Length if present */
					if (lws_hdr_extant(wsi, WSI_TOKEN_HTTP_CONTENT_LENGTH)) {
						const char *simp = lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP_CONTENT_LENGTH);
						if (simp) {
							long long cl_val = atoll(simp);
							if (cl_val >= 0) {
								wsi->http.rx_content_length = (unsigned long long)cl_val;
								wsi->http.rx_content_remain = wsi->http.rx_content_length;
								wsi->http.content_length_given = 1;
								if (wsi->http.rx_content_length == 0)
									wsi->http.content_length_explicitly_zero = 1;
							}
						}
					}

#if defined(LWS_WITH_CLIENT)
					if (wsi->client_mux_substream) {
						if (lws_client_interpret_server_handshake(wsi)) {
							lwsl_info("cli int serv hs closed, or redir\n");
							return 1;
						}
					} else
#endif
					{
						lwsl_info("H3_VHOST_SELECT: headers parsed. vhost listen_port: %d, auth len: %d, authority: %s\n",
							wsi->a.vhost->listen_port,
							lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_COLON_AUTHORITY),
							lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP_COLON_AUTHORITY) ? lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP_COLON_AUTHORITY) : "NULL");

						/* select vhost based on authority */
						if (lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_COLON_AUTHORITY)) {
							int port = wsi->a.vhost->listen_port;
							struct lws_vhost *vhost = lws_select_vhost(
								wsi->a.context, port,
								lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP_COLON_AUTHORITY));

							if (!vhost && port != 443) {
								vhost = lws_select_vhost(wsi->a.context, 443,
									lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP_COLON_AUTHORITY));
							}
							if (!vhost) {
								vhost = lws_select_vhost(wsi->a.context, 0,
									lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP_COLON_AUTHORITY));
							}

							lwsl_debug("H3_TRACE: lws_select_vhost returned %p (%s). Original port: %d\n", 
								vhost, vhost ? vhost->name : "none", port);
							if (vhost) {
								lws_vhost_bind_wsi(vhost, wsi);
								lwsl_debug("H3_TRACE: bound wsi %p to vhost %s\n", wsi, vhost->name);
							}
						}

						lwsi_set_state(wsi, LRS_DEFERRING_ACTION);
						lws_callback_on_writable(wsi);
						lwsl_debug("H3_TRACE: wsi %p transitioned to LRS_DEFERRING_ACTION and called callback_on_writable\n", wsi);
					}
				}
				wsi->h3.rx_frame_state = 0; /* Next frame */
			}
		}
	}

	return 0;
}

static int
rops_alpn_negotiated_h3(struct lws *wsi, const char *alpn)
{
	struct lws *nwsi = lws_get_quic_network_wsi(wsi);
	struct lws_h3_netconn *h3n;

	lwsl_wsi_info(wsi, "H3 ALPN Negotiated: %s", alpn);

	if (!nwsi || !nwsi->quic.qn)
		return 1;

	/* Only the first H3 stream (which is the application request) initializes the connection */
	if (!nwsi->h3.h3n) {
		h3n = lws_zalloc(sizeof(*h3n), "h3n");
		if (!h3n)
			return 1;
		nwsi->h3.h3n = h3n;
		h3n->nwsi = nwsi;

		/* Initialize QPACK encoder context */
		h3n->qpack_tx_encoder.entries = h3n->tx_entries;
		h3n->qpack_tx_encoder.num_entries = LWS_ARRAY_SIZE(h3n->tx_entries);
		h3n->qpack_tx_encoder.virtual_payload_max = 4096;
		nwsi->h3.qpack_tx_encoder = &h3n->qpack_tx_encoder;

		h3n->qpack_dec_ctx.dyn_table.virtual_payload_limit = LWS_QPACK_CAP_VAL;

		/* Create the 3 local control streams */
		/* Client unidi start at 2 */
		if (nwsi->quic.qn->next_stream_id_unidi_local == 0)
			nwsi->quic.qn->next_stream_id_unidi_local = lwsi_role_server(nwsi) ? 3 : 2;
			
		h3n->cwsi_control = lws_h3_create_unidi_stream(nwsi, 0x00);
		h3n->cwsi_qpack_enc = lws_h3_create_unidi_stream(nwsi, 0x02);
		h3n->cwsi_qpack_dec = lws_h3_create_unidi_stream(nwsi, 0x03);

		if (!h3n->cwsi_control || !h3n->cwsi_qpack_enc || !h3n->cwsi_qpack_dec)
			return 1;
			
		h3n->qpack_tx_encoder.wsi_qpack_enc = h3n->cwsi_qpack_enc;
	}

	wsi->h3.h3n = nwsi->h3.h3n;
	wsi->h3.qpack_tx_encoder = nwsi->h3.qpack_tx_encoder;

	/* If we are the network wsi, we must notify our children! */
	if (wsi == nwsi) {
		struct lws *child = nwsi->mux.child_list;
		lwsl_wsi_info(wsi, "H3 ALPN Negotiated, child_list=%p", child);
		while (child) {
			lwsl_wsi_info(child, "H3 ALPN child state=%d", lwsi_state(child));
			if (lwsi_state(child) == LRS_UNCONNECTED || lwsi_state(child) == LRS_WAITING_CONNECT) {
				lwsl_wsi_info(child, "H3 ALPN Negotiated, transitioning child");
				lws_role_transition(child, lwsi_role_client(nwsi) ? LWSIFR_CLIENT : LWSIFR_SERVER, LRS_H2_WAITING_TO_SEND_HEADERS, &role_ops_h3);
				child->h3.h3n = nwsi->h3.h3n;
				child->h3.qpack_tx_encoder = nwsi->h3.qpack_tx_encoder;
				lws_callback_on_writable(child);
			}
			child = child->mux.sibling_list;
		}
	}

	return 0;
}

static int
rops_close_kill_connection_h3(struct lws *wsi, enum lws_close_status reason)
{
	if (wsi->mux.parent_wsi)
		lws_wsi_mux_sibling_disconnect(wsi);

	lws_quic_stream_cleanup(wsi);

	return 0;
}

static int
rops_write_role_protocol_h3(struct lws *wsi, unsigned char *buf, size_t len,
			    enum lws_write_protocol *wp)
{
	unsigned char *pre = buf - LWS_PRE;
	int base = (*wp & 0x1f);
	int is_http = base == LWS_WRITE_HTTP || base == LWS_WRITE_HTTP_FINAL;
	int is_headers = base == LWS_WRITE_HTTP_HEADERS;
	size_t olen = len;
	int n;
#if defined(LWS_WITH_HTTP_STREAM_COMPRESSION)
	unsigned char mtubuf[4096 + LWS_PRE];
	int32_t max_out = sizeof(mtubuf) - LWS_PRE;
	
	if (is_http && wsi->http.lcs) {
		struct lws *nwsi = lws_get_quic_network_wsi(wsi);
		int32_t cr = wsi->txc.tx_cr;
		if (nwsi && nwsi->txc.tx_cr < cr)
			cr = nwsi->txc.tx_cr;
		
		/* If there's no tx credit, or it's too small to hold even a tiny frame, return 0 now so 
		 * the application buffers the *uncompressed* data and retries later, instead of
		 * us consuming it and QUIC rejecting it. */
		if (cr <= 16) {
			lwsl_info("%s: delaying compression due to tx_cr %d\n", __func__, cr);
			return 0;
		}
		
		cr -= 16; /* Leave room for H3 DATA frame overhead */
		if (cr > 0 && cr < max_out)
			max_out = cr;
	}
#endif

	if (is_http && wsi->http.tx_content_length) {
		if (wsi->http.tx_content_remain <= len) {
			lwsl_info("%s: selecting final write mode\n", __func__);
			base = LWS_WRITE_HTTP_FINAL;
			*wp = (enum lws_write_protocol)(((unsigned int)*wp & ~0x1fu) | LWS_WRITE_HTTP_FINAL);
		}
	}

	if (base == LWS_WRITE_HTTP_FINAL) {
		*wp = (enum lws_write_protocol)((unsigned int)*wp | LWS_WRITE_H2_STREAM_END);
	}

#if defined(LWS_WITH_HTTP_STREAM_COMPRESSION)
	if (is_http && wsi->http.lcs) {
		unsigned char *out = mtubuf + LWS_PRE;
		size_t o = (size_t)max_out;

		n = lws_http_compression_transform(wsi, buf, len, wp, &out, &o);
		if (n)
			return n;

		buf = out;
		len = o;
		base = (*wp) & 0x1f;

		if (base == LWS_WRITE_HTTP_FINAL) {
			*wp = (enum lws_write_protocol)((unsigned int)*wp | LWS_WRITE_H2_STREAM_END);
		} else {
			*wp = (enum lws_write_protocol)((unsigned int)*wp & ~(unsigned int)LWS_WRITE_H2_STREAM_END);
		}

		if (!len && base != LWS_WRITE_HTTP_FINAL)
			return (int)olen;
	}
#endif

	if (is_http) {
		/* It's HTTP payload, we need to frame it in an H3 DATA frame (type 0x00) */
		/* We assume the caller reserved LWS_PRE bytes before buf. */
		uint8_t len_buf[8];
		int len_bytes = (int)lws_quic_write_varint(len_buf, sizeof(len_buf), len);
		
		pre = buf - len_bytes - 1;
		pre[0] = 0x00; /* DATA frame type */
		memcpy(&pre[1], len_buf, (size_t)len_bytes);

		len += (size_t)(len_bytes + 1);
	} else if (is_headers) {
		/* It's HTTP headers, we need to frame it in an H3 HEADERS frame (type 0x01) */
		/* We assume the caller reserved LWS_PRE bytes before buf. */
		uint8_t len_buf[8];
		int len_bytes = (int)lws_quic_write_varint(len_buf, sizeof(len_buf), len);
		
		pre = buf - len_bytes - 1;
		pre[0] = 0x01; /* HEADERS frame type */
		memcpy(&pre[1], len_buf, (size_t)len_bytes);

		len += (size_t)(len_bytes + 1);
		// lwsl_notice("%s: HTTP/3 HEADERS frame: unframed len=%d, framed len=%d\n", __func__, (int)olen, (int)len);
		// lwsl_hexdump_notice(pre, len);
	}

	{
		struct lws *nwsi = lws_get_quic_network_wsi(wsi);
		if (nwsi && lws_rops_fidx(nwsi->role_ops, LWS_ROPS_write_role_protocol)) {
			n = lws_rops_func_fidx(nwsi->role_ops, LWS_ROPS_write_role_protocol).
					write_role_protocol(wsi, (is_http || is_headers) ? pre : buf, len, wp);
			if (n <= 0)
				return n;

			if (is_http && wsi->http.tx_content_length) {
				wsi->http.tx_content_remain -= olen;
				lwsl_info("%s: %s: tx_content_rem = %llu\n", __func__,
					  lws_wsi_tag(wsi),
					  (unsigned long long)wsi->http.tx_content_remain);
			}

			return (int)olen;
		}
	}

	return -1;
}

static int
rops_callback_on_writable_h3(struct lws *wsi)
{
	struct lws *nwsi = lws_get_quic_network_wsi(wsi);

	if (wsi->mux.requested_POLLOUT) {
		lwsl_debug("already pending writable\n");
	}

	lws_wsi_mux_mark_parents_needing_writeable(wsi);

	if (nwsi && nwsi != wsi)
		return lws_callback_on_writable(nwsi);

	return 0;
}

extern int rops_tx_credit_quic(struct lws *wsi, char peer_to_us, int add);

#if defined(LWS_ROLE_WS) && defined(LWS_WITH_SERVER)
static int
rops_check_upgrades_h3(struct lws *wsi)
{
	const char *p;

	/*
	 * with H3 there's also a way to upgrade a stream to something
	 * else... :method is CONNECT and :protocol says the name of
	 * the new protocol we want to carry.  We have to have sent a
	 * SETTINGS saying that we support it though.
	 */
	p = lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP_COLON_METHOD);
	if (!wsi->a.vhost->h2.set.s[H2SET_ENABLE_CONNECT_PROTOCOL] ||
	    !wsi->mux_substream || !p || strcmp(p, "CONNECT"))
		return LWS_UPG_RET_CONTINUE;

	p = lws_hdr_simple_ptr(wsi, WSI_TOKEN_COLON_PROTOCOL);
	if (!p)
		return LWS_UPG_RET_CONTINUE;

	if (!strcmp(p, "websocket")) {
		lwsl_info("Upgrade h3 to ws\n");
		lws_mux_mark_immortal(wsi);
		wsi->h23_stream_carries_ws = 1;

		lws_metrics_tag_wsi_add(wsi, "upg", "ws_over_h3");

		if (lws_process_ws_upgrade(wsi))
			return LWS_UPG_RET_BAIL;

		lwsl_info("Upgraded h3 to ws OK\n");

		return LWS_UPG_RET_DONE;
	} else if (!strcmp(p, "webtransport")) {
#if defined(LWS_ROLE_WT)
		lwsl_info("Upgrade h3 to wt\n");
		extern const struct lws_role_ops role_ops_wt;
		lws_mux_mark_immortal(wsi);
		lws_metrics_tag_wsi_add(wsi, "upg", "wt_over_h3");

		/* Switch role to WebTransport */
		lws_role_transition(wsi, LWSIFR_SERVER, LRS_ESTABLISHED, &role_ops_wt);

		if (wsi->a.protocol && wsi->a.protocol->callback) {
			if (wsi->a.protocol->callback(wsi, LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED, wsi->user_space, NULL, 0))
				return LWS_UPG_RET_BAIL;
		}

		lwsl_info("Upgraded h3 to wt OK\n");

		return LWS_UPG_RET_DONE;
#else
		return LWS_UPG_RET_CONTINUE;
#endif
	}

	return LWS_UPG_RET_CONTINUE;
}
#endif

static const lws_rops_t rops_table_h3[] = {
	/*  1 */ { .handle_POLLIN	  = rops_handle_POLLIN_h3 },
	/*  2 */ { .perform_user_POLLOUT  = rops_perform_user_POLLOUT_h3 },
	/*  3 */ { .adoption_bind	  = rops_adoption_bind_h3 },
#if defined(LWS_WITH_CLIENT)
	/*  4 */ { .client_bind		  = rops_client_bind_h3 },
#endif
	/*  5 */ { .alpn_negotiated	  = rops_alpn_negotiated_h3 },
	/*  6 */ { .close_kill_connection = rops_close_kill_connection_h3 },
	/*  7 */ { .write_role_protocol	  = rops_write_role_protocol_h3 },
	/*  8 */ { .callback_on_writable  = rops_callback_on_writable_h3 },
	/*  9 */ { .tx_credit		  = rops_tx_credit_quic },
#if defined(LWS_ROLE_WS) && defined(LWS_WITH_SERVER)
	/* 10 */ { .check_upgrades	  = rops_check_upgrades_h3 },
#endif
};

const struct lws_role_ops role_ops_h3 = {
	/* role name */			"h3",
	/* alpn id */			"h3",

	/* rops_table */		rops_table_h3,
	/* rops_idx */			{
#if defined(LWS_ROLE_WS) && defined(LWS_WITH_SERVER)
	  /* LWS_ROPS_check_upgrades */
	  /* LWS_ROPS_pt_init_destroy */		0xA0,
#else
	  /* LWS_ROPS_check_upgrades */
	  /* LWS_ROPS_pt_init_destroy */		0x00,
#endif
	  /* LWS_ROPS_init_vhost */
	  /* LWS_ROPS_destroy_vhost */			0x00,
	  /* LWS_ROPS_service_flag_pending */
	  /* LWS_ROPS_handle_POLLIN */			0x01,
	  /* LWS_ROPS_handle_POLLOUT */
	  /* LWS_ROPS_perform_user_POLLOUT */		0x02,
	  /* LWS_ROPS_callback_on_writable */
	  /* LWS_ROPS_tx_credit */			0x89,
	  /* LWS_ROPS_write_role_protocol */
	  /* LWS_ROPS_encapsulation_parent */		0x70,
	  /* LWS_ROPS_alpn_negotiated */
	  /* LWS_ROPS_close_via_role_protocol */	0x50,
	  /* LWS_ROPS_close_role */
	  /* LWS_ROPS_close_kill_connection */		0x06,
	  /* LWS_ROPS_destroy_role */
	  /* LWS_ROPS_adoption_bind */			0x03,
#if defined(LWS_WITH_CLIENT)
	  /* LWS_ROPS_client_bind */
	  /* LWS_ROPS_issue_keepalive */		0x40,
#else
	  /* LWS_ROPS_client_bind */
	  /* LWS_ROPS_issue_keepalive */		0x00,
#endif
					},

	/* adoption_cb clnt, srv */	{ LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED,
					  LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED },
	/* rx_cb clnt, srv */		{ LWS_CALLBACK_RECEIVE_CLIENT_HTTP,
					  LWS_CALLBACK_HTTP },
	/* writeable cb clnt, srv */	{ LWS_CALLBACK_CLIENT_HTTP_WRITEABLE,
					  LWS_CALLBACK_HTTP_WRITEABLE },
	/* close cb clnt, srv */	{ LWS_CALLBACK_CLOSED_CLIENT_HTTP,
					  LWS_CALLBACK_CLOSED_HTTP },
	/* protocol_bind cb c, srv */	{ LWS_CALLBACK_CLIENT_HTTP_BIND_PROTOCOL,
					  LWS_CALLBACK_HTTP_BIND_PROTOCOL },
	/* protocol_unbind cb c, srv */	{ LWS_CALLBACK_CLIENT_HTTP_DROP_PROTOCOL,
					  LWS_CALLBACK_HTTP_DROP_PROTOCOL },
	/* file_handle */		0,
};

struct lws *
lws_wsi_h3_adopt(struct lws *parent_wsi, struct lws *wsi)
{
	struct lws *nwsi = lws_get_network_wsi(parent_wsi);
	struct lws_quic_netconn *qn = nwsi->quic.qn;
	uint64_t sid;

	if (!qn) {
		lwsl_err("%s: no quic netconn\n", __func__);
		return NULL;
	}

	wsi->seen_nonpseudoheader = 0;
	wsi->hdr_parsing_completed = 0;
#if defined(LWS_WITH_CLIENT)
	wsi->client_mux_substream = 1;
#endif

	wsi->quic.qs = lws_zalloc(sizeof(*wsi->quic.qs), "quic stream");
	if (!wsi->quic.qs)
		return NULL;

	wsi->quic.qs->wsi = wsi;

	/* If next_stream_id_bidi_local is 0, initialize it to 4 because stream 0 is already used */
	if (qn->next_stream_id_bidi_local == 0)
		qn->next_stream_id_bidi_local = 4;

	sid = qn->next_stream_id_bidi_local;
	wsi->quic.qs->stream_id = sid;
	qn->next_stream_id_bidi_local += 4;

	wsi->mux_substream = 1;
#if defined(LWS_WITH_CLIENT)
	wsi->client_h2_alpn = 1;
#endif

	lws_wsi_mux_insert(wsi, nwsi, (unsigned int)sid);

	/* Initialize flow control credits */
	int32_t init_cr = nwsi->txc.manual_initial_tx_credit;
	if (!init_cr) {
		if (qn->peer_initial_max_stream_data_bidi_local)
			init_cr = (int32_t)qn->peer_initial_max_stream_data_bidi_local;
		else
			init_cr = 65535;
	}
	wsi->txc.peer_tx_cr_est = init_cr;
	wsi->txc.tx_cr = init_cr;

	wsi->h3.h3n = nwsi->h3.h3n;

	if (lws_ensure_user_space(wsi)) {
		lws_free_set_NULL(wsi->quic.qs);
		return NULL;
	}

	lws_role_transition(wsi, LWSIFR_CLIENT, LRS_H2_WAITING_TO_SEND_HEADERS,
			    &role_ops_h3);

	lws_callback_on_writable(wsi);

	return wsi;
}

