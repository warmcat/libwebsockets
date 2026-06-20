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

#include "private-lib-core.h"
#include "roles/quic/private-lib-roles-quic.h"

static int quic_secret_cb(struct lws *wsi, enum lws_tls_quic_secret_type type, const uint8_t *secret, size_t secret_len);

static void
lws_quic_pacer_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_quic_netconn *qn = lws_container_of(sul, struct lws_quic_netconn, pacer_sul);
	if (qn && qn->nwsi)
		lws_callback_on_writable(qn->nwsi);
}

static void
lws_quic_pto_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_quic_netconn *qn = lws_container_of(sul, struct lws_quic_netconn, pto_sul);
	if (qn && qn->nwsi) {
		qn->pto_count++;
		if (qn->pto_count >= 8) {
			lwsl_wsi_notice(qn->nwsi, "QUIC connection dead: max PTO count (%d) reached\n", qn->pto_count);
			lws_close_free_wsi(qn->nwsi, LWS_CLOSE_STATUS_NOSTATUS, "quic pto timeout");
			return;
		}

		qn->pto_probe_needed = 1;
#if (_LWS_ENABLED_LOGS & LLL_INFO)
		LWS_RATELIMIT_DEFINE_STATIC(rl);
		lwsl_ratelimit_info(&rl, 1000000, "QUIC PTO Timer Fired! Forcing POLLOUT for retransmission sweep\n");
#endif
		lws_callback_on_writable(qn->nwsi);

		/* Always ensure the timer is running as long as there is data in flight! */
		for (int i = 0; i < LWS_QUIC_LEVEL_COUNT; i++) {
			if (qn->in_flight[i].count) {
				lws_usec_t pto_delay = LWS_QUIC_DEFAULT_PTO_US << qn->pto_count;
				if (pto_delay > 10000000)
					pto_delay = 10000000;
				lws_sul_schedule(qn->nwsi->a.context, 0, &qn->pto_sul, lws_quic_pto_cb, pto_delay);
				break;
			}
		}
	}
}

/* RFC 9000 Section 17.1 */
static uint64_t
lws_quic_decode_packet_number(uint64_t largest_pn, uint64_t truncated_pn, int pn_nbits)
{
	uint64_t expected_pn = largest_pn + 1;
	uint64_t pn_win = 1ULL << pn_nbits;
	uint64_t pn_hwin = pn_win / 2;
	uint64_t pn_mask = pn_win - 1;
	uint64_t candidate_pn = (expected_pn & ~pn_mask) | truncated_pn;

	if (candidate_pn + pn_hwin <= expected_pn && candidate_pn < (1ULL << 62) - pn_win)
		return candidate_pn + pn_win;
	if (candidate_pn > expected_pn + pn_hwin && candidate_pn >= pn_win)
		return candidate_pn - pn_win;

	return candidate_pn;
}

void
lws_quic_handle_ack(struct lws *nwsi, int level, uint64_t acked_pn)
{
	struct lws_quic_netconn *qn = nwsi->quic.qn;
	if (!qn) return;

	/* PMTUD: Check if our active probe was acknowledged */
	if (qn->pmtud_probe_pn != 0 && acked_pn == qn->pmtud_probe_pn) {
		lwsl_wsi_info(nwsi, "QUIC PMTUD: Probe %llu ACKed! MTU upgraded from %d to %d", 
			(unsigned long long)acked_pn, (int)qn->current_mtu, (int)qn->probed_mtu);
		qn->current_mtu = qn->probed_mtu;
		qn->pmtud_probe_pn = 0;
		qn->consecutive_mtu_losses = 0;
		qn->probed_mtu += 100; /* Probe upward in 100-byte increments */
		if (qn->probed_mtu > 1400) /* Cap at typical Ethernet MTU payload limit for this example */
			qn->pmtud_state = 2; /* SEARCH_COMPLETE */
	}

	size_t bytes_acked = 0;
	lws_usec_t rtt = 0;
	lws_usec_t now = lws_now_usecs();

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, qn->in_flight[level].head) {
		struct lws_quic_tx_frame *f = lws_container_of(d, struct lws_quic_tx_frame, list);

		if (f->sent_in_pn == acked_pn) {
			uint64_t sid = f->stream_id;
			bytes_acked += f->wire_len;
			rtt = now > f->sent_time_us ? now - f->sent_time_us : 0;
			/* Packet was received successfully, free the frame! */
			lws_dll2_remove(&f->list);
			lws_free(f);

			struct lws *child = lws_quic_stream_find(nwsi, sid);
			if (child && (lwsi_state(child) == LRS_FLUSHING_BEFORE_CLOSE
#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2) || defined(LWS_ROLE_H3)
			    || child->http.deferred_transaction_completed
#endif
			)) {
				lws_callback_on_writable(child);
			}
		}
	} lws_end_foreach_dll_safe(d, d1);

	if (bytes_acked) {
		qn->pto_count = 0;
		if (qn->cc_ops && qn->cc_ops->on_ack)
			qn->cc_ops->on_ack(nwsi, bytes_acked, rtt);

		/* If we have pending TX and CC might have unblocked, trigger POLLOUT */
		int pending = 0;
		for (int i = 0; i < LWS_QUIC_LEVEL_COUNT; i++) {
			if (qn->pending_tx[i].count) {
				pending = 1;
				break;
			}
		}
		if (pending)
			lws_callback_on_writable(nwsi);
	}

	/* If there are no more in-flight packets across all levels, we can cancel the PTO timer */
	int any_in_flight = 0;
	for (int i = 0; i < LWS_QUIC_LEVEL_COUNT; i++) {
		if (qn->in_flight[i].count) {
			any_in_flight = 1;
			break;
		}
	}
	if (!any_in_flight) {
		lws_sul_cancel(&qn->pto_sul);
	}
}

void
lws_quic_discard_keys(struct lws *nwsi, int level)
{
	struct lws_quic_netconn *qn = nwsi->quic.qn;
	if (!qn) return;

	if (qn->keys[level]) {
		lws_quic_keys_destroy(qn->keys[level]);
		qn->keys[level] = NULL;
	}

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, qn->pending_tx[level].head) {
		struct lws_quic_tx_frame *f = lws_container_of(d, struct lws_quic_tx_frame, list);
		lws_dll2_remove(&f->list);
		lws_free(f);
	} lws_end_foreach_dll_safe(d, d1);

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, qn->in_flight[level].head) {
		struct lws_quic_tx_frame *f = lws_container_of(d, struct lws_quic_tx_frame, list);
		lws_dll2_remove(&f->list);
		lws_free(f);
	} lws_end_foreach_dll_safe(d, d1);

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, qn->rx_crypto_chunks[level].head) {
		struct lws_quic_rx_chunk *c = lws_container_of(d, struct lws_quic_rx_chunk, list);
		lws_dll2_remove(&c->list);
		lws_free(c);
	} lws_end_foreach_dll_safe(d, d1);
}

struct lws *
lws_get_quic_network_wsi(struct lws *wsi)
{
	if (!wsi) return NULL;
	while (wsi) {
		if (wsi->quic.qn)
			return wsi;
		wsi = wsi->mux.parent_wsi;
	}
	return NULL;
}

static lws_handling_result_t
rops_handle_POLLIN_quic(struct lws_context_per_thread *pt, struct lws *wsi,
			struct lws_pollfd *pollfd)
{
	int n;
	uint8_t *p;
	uint8_t scid_len = 0;
	uint8_t dcid_len = 0;
	struct lws_quic_cid dcid, scid;

	if (!(pollfd->revents & LWS_POLLIN))
		goto try_pollout;

	lwsl_wsi_debug(wsi, "QUIC RX: POLLIN fired on socket!");

	lws_sockaddr46 sa46;
	socklen_t slen = sizeof(sa46);

#if defined(WIN32) || defined(_WIN32)
	n = recvfrom(wsi->desc.sockfd, (char *)pt->serv_buf, (int)wsi->a.context->pt_serv_buf_size, 0,
		     sa46_sockaddr(&sa46), &slen);
#else
	n = (int)recvfrom(wsi->desc.sockfd, (void *)pt->serv_buf, wsi->a.context->pt_serv_buf_size, 0,
			  sa46_sockaddr(&sa46), &slen);
#endif

	if (n <= 0) {
		lwsl_wsi_info(wsi, "QUIC RX: recv returned %d (errno %d)", n, errno);
		return LWS_HPI_RET_HANDLED;
	}

#if 0
	{
		char buf_peer[64], buf_recv[64];
#if defined(LWS_WITH_IPV6)
		uint16_t port_recv = sa46.sa4.sin_family == AF_INET ? sa46.sa4.sin_port : sa46.sa6.sin6_port;
		uint16_t port_peer = wsi->sa46_peer.sa4.sin_family == AF_INET ? wsi->sa46_peer.sa4.sin_port : wsi->sa46_peer.sa6.sin6_port;
#else
		uint16_t port_recv = sa46.sa4.sin_port;
		uint16_t port_peer = wsi->sa46_peer.sa4.sin_port;
#endif
		lws_sa46_write_numeric_address(&wsi->sa46_peer, buf_peer, sizeof(buf_peer));
		lws_sa46_write_numeric_address(&sa46, buf_recv, sizeof(buf_recv));
		/* lwsl_notice("QUIC RX: recv %d bytes from %s:%u (wsi peer %s:%u)\n", n,
			    buf_recv, (unsigned int)ntohs(port_recv),
			    buf_peer, (unsigned int)ntohs(port_peer)); */
	}
#endif

	lwsl_wsi_debug(wsi, "QUIC RX: read %d bytes from UDP", n);

	if (n < 2)
		return LWS_HPI_RET_HANDLED;

	p = pt->serv_buf;

	memset(&dcid, 0, sizeof(dcid));
	memset(&scid, 0, sizeof(scid));

	if (p[0] & 0x80) {
		dcid_len = p[5];
		if (dcid_len > LWS_QUIC_MAX_CID_LEN || n < 6 + dcid_len) {
			lwsl_wsi_notice(wsi, "QUIC RX: Invalid DCID length");
			return LWS_HPI_RET_HANDLED;
		}

		dcid.len = dcid_len;
		memcpy(dcid.id, &p[6], dcid_len);

		int scid_pos = 6 + dcid_len;
		if (n < scid_pos + 1) {
			lwsl_wsi_notice(wsi, "QUIC RX: Truncated before SCID");
			return LWS_HPI_RET_HANDLED;
		}

		scid_len = p[scid_pos];
		if (scid_len > LWS_QUIC_MAX_CID_LEN || n < scid_pos + 1 + scid_len) {
			lwsl_wsi_notice(wsi, "QUIC RX: Invalid SCID length");
			return LWS_HPI_RET_HANDLED;
		}

		scid.len = scid_len;
		memcpy(scid.id, &p[scid_pos + 1], scid_len);
	} else {
		dcid_len = 8;
		if (n < 1 + dcid_len) {
			lwsl_wsi_notice(wsi, "QUIC RX: dropping, short header too short");
			return LWS_HPI_RET_HANDLED;
		}

		dcid.len = dcid_len;
		memcpy(dcid.id, &p[1], dcid_len);
	}

	struct lws *nwsi = NULL;
	if (wsi->quic.qn && !wsi->quic.qn->is_server) {
		/* Client connection: the wsi itself is the connection */
		nwsi = wsi;

		/* The client MUST update its remote CID to the server's SCID from the first response */
		if ((p[0] & 0x80) && scid.len) {
			if (nwsi->quic.qn->rem_cid.len != scid.len || memcmp(nwsi->quic.qn->rem_cid.id, scid.id, scid.len)) {
				nwsi->quic.qn->rem_cid = scid;
			}
		}
	} else {
		/* Server listener: search children */
		struct lws *w = wsi->mux.child_list;
		while (w) {
			if (w->quic.qn && w->quic.qn->loc_cid.len == dcid_len &&
			    !memcmp(w->quic.qn->loc_cid.id, dcid.id, dcid_len)) {
				nwsi = w;
				lwsl_debug("QUIC RX: found connection by loc_cid! nwsi=%s\n", lws_wsi_tag(nwsi));
				break;
			}
			/* Also match against the original DCID if the client hasn't switched to our loc_cid yet */
			if (w->quic.qn && w->quic.qn->orig_dcid.len == dcid_len &&
			    !memcmp(w->quic.qn->orig_dcid.id, dcid.id, dcid_len)) {
				nwsi = w;
				lwsl_debug("QUIC RX: found connection by orig_dcid! nwsi=%s\n", lws_wsi_tag(nwsi));
				break;
			}
			w = w->mux.sibling_list;
		}
	}


#if defined(LWS_WITH_SERVER)
	if (!nwsi) {
		if (!(p[0] & 0x80) || ((p[0] & 0x30) >> 4) != 0) {
			lwsl_wsi_notice(wsi, "QUIC RX: Unknown DCID and not Initial, dropping");
			return LWS_HPI_RET_HANDLED;
		}

		uint32_t pkt_version = ((uint32_t)p[1] << 24) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 8) | p[4];

		if (pkt_version != LWS_QUIC_VERSION_1 && pkt_version != LWS_QUIC_VERSION_2) {
			lwsl_wsi_notice(wsi, "QUIC RX: Unsupported version 0x%08X, sending VN packet", pkt_version);
			uint8_t vn[128];
			uint8_t *vp = vn;
			*vp++ = 0x80; /* Long Header */
			*vp++ = 0; *vp++ = 0; *vp++ = 0; *vp++ = 0; /* Version 0 */
			*vp++ = scid.len;
			if (scid.len) { memcpy(vp, scid.id, scid.len); vp += scid.len; }
			*vp++ = dcid.len;
			if (dcid.len) { memcpy(vp, dcid.id, dcid.len); vp += dcid.len; }
			/* Add v1 */
			*vp++ = (uint8_t)(LWS_QUIC_VERSION_1 >> 24); *vp++ = (uint8_t)(LWS_QUIC_VERSION_1 >> 16);
			*vp++ = (uint8_t)(LWS_QUIC_VERSION_1 >> 8); *vp++ = (uint8_t)(LWS_QUIC_VERSION_1);
			/* Add v2 */
			*vp++ = (uint8_t)(LWS_QUIC_VERSION_2 >> 24); *vp++ = (uint8_t)(LWS_QUIC_VERSION_2 >> 16);
			*vp++ = (uint8_t)(LWS_QUIC_VERSION_2 >> 8); *vp++ = (uint8_t)(LWS_QUIC_VERSION_2);

#if defined(WIN32) || defined(_WIN32)
			sendto(wsi->desc.sockfd, (char *)vn, (int)(vp - vn), 0, sa46_sockaddr(&sa46), slen);
#else
			sendto(wsi->desc.sockfd, (void *)vn, (size_t)(vp - vn), 0, sa46_sockaddr(&sa46), slen);
#endif
			return LWS_HPI_RET_HANDLED;
		}

		/* Enforce 1200-byte padding for client-to-server Initial packets (RFC 9000 Section 14.1) */
		if (n < 1200) {
			lwsl_wsi_notice(wsi, "QUIC RX: Dropping under-padded Initial packet (len %d)", n);
			return LWS_HPI_RET_HANDLED;
		}

		/* 1.5 Instantiate new QUIC network connection */
		nwsi = lws_create_new_server_wsi(wsi->a.vhost, wsi->tsi, 0, "quic child");
		if (!nwsi) {
			lwsl_wsi_notice(wsi, "QUIC RX: failed to create server wsi");
			return LWS_HPI_RET_HANDLED;
		}

		lws_role_transition(nwsi, LWSIFR_SERVER, LRS_SSL_INIT, &role_ops_quic);

		nwsi->quic.qn = lws_zalloc(sizeof(*nwsi->quic.qn), "quic_netconn");
		if (!nwsi->quic.qn) {
			lws_close_free_wsi(nwsi, LWS_CLOSE_STATUS_NOSTATUS, "oom");
			return LWS_HPI_RET_HANDLED;
		}

		nwsi->quic.qn->nwsi = nwsi;
		nwsi->quic.qn->is_server = 1;
		nwsi->quic.qn->version = pkt_version;
		nwsi->quic.qn->max_streams_bidi_local = 1024;
		nwsi->quic.qn->max_streams_unidi_local = 1024;

		nwsi->quic.qn->current_mtu = 1280;
		nwsi->quic.qn->probed_mtu = 1380; /* first probe size */
		nwsi->quic.qn->pmtud_state = 1; /* SEARCHING */

		if (nwsi->a.context->quic_cc_ops)
			nwsi->quic.qn->cc_ops = nwsi->a.context->quic_cc_ops;
		else
			nwsi->quic.qn->cc_ops = &lws_cc_ops_newreno;

		if (nwsi->quic.qn->cc_ops->init)
			nwsi->quic.qn->cc_ops->init(nwsi);

		/* Initialize RX Flow Control limits */
		nwsi->quic.qn->rx_max_data = LWS_QUIC_DEFAULT_WINDOW;
		nwsi->quic.qn->rx_window_size = LWS_QUIC_DEFAULT_WINDOW;
		nwsi->quic.qn->last_rx_update_us = lws_now_usecs();
		nwsi->txc.peer_tx_cr_est = LWS_QUIC_DEFAULT_WINDOW; /* How much the peer can write to us */
		/* tx_cr is strictly initialized when we parse the peer's initial_max_data parameter */

#if defined(LWS_WITH_UDP)
		nwsi->udp = lws_malloc(sizeof(*nwsi->udp), "quic udp");
		memset(nwsi->udp, 0, sizeof(*nwsi->udp));
		nwsi->udp->sa46 = sa46; /* Copy peer address */
#endif

#if defined(LWS_WITH_TLS)
		nwsi->tls.use_ssl = (unsigned int)wsi->a.vhost->tls.use_ssl;
		if (wsi->a.vhost->tls.ssl_ctx) {
			if (lws_tls_server_new_nonblocking(nwsi, LWS_SOCK_INVALID)) {
				lwsl_wsi_err(wsi, "QUIC RX: lws_tls_server_new_nonblocking failed");
				lws_close_free_wsi(nwsi, LWS_CLOSE_STATUS_NOSTATUS, "ssl fail");
				return LWS_HPI_RET_HANDLED;
			}
			/* Init the memory BIOs for QUIC crypto */
			extern int lws_tls_quic_init(struct lws *wsi, lws_tls_quic_secret_cb cb);
			if (lws_tls_quic_init(nwsi, quic_secret_cb)) {
				lwsl_wsi_err(wsi, "QUIC RX: lws_tls_quic_init failed");
				lws_close_free_wsi(nwsi, LWS_CLOSE_STATUS_NOSTATUS, "ssl fail");
				return LWS_HPI_RET_HANDLED;
			}
		}
#endif

		/* The client's SCID becomes our Remote CID */
		nwsi->quic.qn->rem_cid = scid;

		/* Save the original DCID to route subsequent Initial packets */
		nwsi->quic.qn->orig_dcid = dcid;

		/* Generate our own 8-byte Local CID */
		nwsi->quic.qn->loc_cid.len = 8;
		lws_get_random(wsi->a.context, nwsi->quic.qn->loc_cid.id, 8);

		{
			uint8_t *tp = nwsi->quic.qn->local_tp_buf;
			uint8_t *tp_end = tp + sizeof(nwsi->quic.qn->local_tp_buf);

#define LWS_QUIC_WRITE_TP_VARINT(_id, _val) \
	do { \
		int _vlen; \
		if (lws_ptr_diff_size_t(tp_end, tp) < 2) goto tp_overflow; \
		*tp++ = (_id); \
		_vlen = (int)lws_quic_write_varint(tp + 1, lws_ptr_diff_size_t(tp_end, tp + 1), (_val)); \
		if (!_vlen) goto tp_overflow; \
		*tp++ = (uint8_t)_vlen; \
		tp += _vlen; \
	} while (0)

#define LWS_QUIC_WRITE_TP_BUF(_id, _buf, _len) \
	do { \
		if (lws_ptr_diff_size_t(tp_end, tp) < (size_t)(2 + (_len))) goto tp_overflow; \
		*tp++ = (_id); \
		*tp++ = (uint8_t)(_len); \
		memcpy(tp, (_buf), (_len)); \
		tp += (_len); \
	} while (0)

			LWS_QUIC_WRITE_TP_VARINT(0x04, LWS_QUIC_DEFAULT_WINDOW);
			LWS_QUIC_WRITE_TP_VARINT(0x05, LWS_QUIC_DEFAULT_WINDOW);
			LWS_QUIC_WRITE_TP_VARINT(0x06, LWS_QUIC_DEFAULT_WINDOW);
			LWS_QUIC_WRITE_TP_VARINT(0x07, LWS_QUIC_DEFAULT_WINDOW);
			LWS_QUIC_WRITE_TP_VARINT(0x08, 1024);
			LWS_QUIC_WRITE_TP_VARINT(0x09, 1024);
			LWS_QUIC_WRITE_TP_VARINT(0x20, 65535);
			LWS_QUIC_WRITE_TP_VARINT(0x01, 30000);

			LWS_QUIC_WRITE_TP_BUF(0x0F, nwsi->quic.qn->loc_cid.id, nwsi->quic.qn->loc_cid.len);
			LWS_QUIC_WRITE_TP_BUF(0x00, nwsi->quic.qn->orig_dcid.id, nwsi->quic.qn->orig_dcid.len);

			lws_tls_quic_set_transport_parameters(nwsi, nwsi->quic.qn->local_tp_buf, (size_t)(tp - nwsi->quic.qn->local_tp_buf));
			
			goto tp_ok;
tp_overflow:
			lwsl_wsi_err(wsi, "QUIC TX: tp buffer overflow");
			lws_close_free_wsi(nwsi, LWS_CLOSE_STATUS_NOSTATUS, "tp overflow");
			return LWS_HPI_RET_HANDLED;
tp_ok:
			;
#undef LWS_QUIC_WRITE_TP_VARINT
#undef LWS_QUIC_WRITE_TP_BUF
		}

		/* Link it to the UDP listening socket */
		lws_mux_mark_immortal(nwsi);
		nwsi->mux_substream = 1;
		nwsi->mux.parent_wsi = wsi;
		nwsi->mux.sibling_list = wsi->mux.child_list;
		wsi->mux.child_list = nwsi;
		wsi->mux.child_count++;

		/* Derive the Initial keys using the client's initial DCID */
		if (lws_quic_derive_initial_keys(nwsi, &dcid)) {
			lwsl_wsi_err(wsi, "QUIC RX: Initial key derivation failed");
			lws_close_free_wsi(nwsi, LWS_CLOSE_STATUS_NOSTATUS, "keys failed");
			return LWS_HPI_RET_HANDLED;
		}

		lwsl_wsi_info(wsi, "QUIC RX: Created new connection! (loc_cid len %d)", nwsi->quic.qn->loc_cid.len);
	}
#else
	if (!nwsi) {
		lwsl_wsi_notice(wsi, "QUIC RX: Unknown DCID and no server support, dropping");
		return LWS_HPI_RET_HANDLED;
	}
#endif

	int pending_migration = 0;
	lws_sockaddr46 migration_sa46;

	if (nwsi && nwsi->udp) {
		int addr_changed = 0;
		if (nwsi->udp->sa46.sa4.sin_family != sa46.sa4.sin_family) {
			addr_changed = 1;
		} else if (sa46.sa4.sin_family == AF_INET) {
			if (nwsi->udp->sa46.sa4.sin_addr.s_addr != sa46.sa4.sin_addr.s_addr ||
			    nwsi->udp->sa46.sa4.sin_port != sa46.sa4.sin_port)
				addr_changed = 1;
		}
#if defined(LWS_WITH_IPV6)
		else if (sa46.sa4.sin_family == AF_INET6) {
			if (memcmp(&nwsi->udp->sa46.sa6.sin6_addr, &sa46.sa6.sin6_addr, sizeof(struct in6_addr)) ||
			    nwsi->udp->sa46.sa6.sin6_port != sa46.sa6.sin6_port)
				addr_changed = 1;
		}
#endif
		if (addr_changed && nwsi->quic.qn) {
			pending_migration = 1;
			migration_sa46 = sa46;
		} else {
			nwsi->udp->sa46 = sa46;
		}
	}

	if (nwsi && nwsi->quic.qn) {
		nwsi->quic.qn->bytes_received += (uint64_t)n;
	}

	while (n > 0) {
		/* If ALPN negotiation migrated the connection in a previous packet, update nwsi */
		if (nwsi && !nwsi->quic.qn) {
			nwsi = lws_get_quic_network_wsi(nwsi);
		}

		if (!nwsi || !nwsi->quic.qn) {
			lwsl_wsi_notice(wsi, "QUIC RX: network connection gone, dropping remaining packets");
			break;
		}

		if (nwsi->quic.qn->is_closing) {
			lwsl_wsi_notice(wsi, "QUIC RX: Connection is closing, dropping remaining packets");
			break;
		}

		/* We have the connection! Grab the appropriate keys based on packet type */
		int level = LWS_QUIC_LEVEL_APP;
		if (p[0] == 0x00) {
			lwsl_wsi_info(wsi, "QUIC RX: Next byte is 0x00, ignoring as padding");
			p++;
			n--;
			continue;
		}

		if (p[0] & 0x80) {
			uint8_t type = (uint8_t)((p[0] & 0x30) >> 4);
			if (type == 0) level = LWS_QUIC_LEVEL_INITIAL;
			else if (type == 2) level = LWS_QUIC_LEVEL_HANDSHAKE;
			else {
				lwsl_wsi_notice(wsi, "QUIC RX: Unsupported long header type %d", type);
				break;
			}
		}

		if (nwsi && nwsi->quic.qn) {
			if (level > nwsi->quic.qn->highest_rx_level)
				nwsi->quic.qn->highest_rx_level = (uint8_t)level;
		}

		/* Enforce 1200-byte padding for subsequent client-to-server Initial packets (RFC 9000 Section 14.1) */
		if (level == LWS_QUIC_LEVEL_INITIAL && nwsi && nwsi->quic.qn && nwsi->quic.qn->is_server && n < 1200) {
			lwsl_wsi_notice(wsi, "QUIC RX: Dropping under-padded Initial packet (len %d)", n);
			break;
		}

		/* 2. Parsing: Safely find the Packet Number offset */
		size_t payload_len_stated;
		size_t pn_offset = lws_quic_get_pn_offset(p, (size_t)n, &payload_len_stated);
		if (!pn_offset) {
			lwsl_wsi_notice(wsi, "QUIC RX: Malformed or truncated packet");
			break;
		}

		size_t packet_size = pn_offset + payload_len_stated;
		if (packet_size > (size_t)n) {
			lwsl_wsi_notice(wsi, "QUIC RX: Packet stated size %zu > remaining UDP %zu", packet_size, (size_t)n);
			break;
		}

		struct lws_quic_keys *k = nwsi->quic.qn->keys[level];

		if (!k || !k->valid) {
			lwsl_wsi_notice(wsi, "QUIC RX: No valid keys for this packet level %d, skipping %zu bytes", level, packet_size);
			p += packet_size;
			n -= (int)packet_size;
			continue;
		}
		
		lwsl_wsi_info(wsi, "QUIC RX: Parsing packet level %d, UDP remaining %d, stated packet_size %zu", level, n, packet_size);

		/* 3. Unmasking: Reveal the true Packet Number */
		int pn_len = lws_quic_unmask_header(k, p, packet_size, pn_offset);
		if (pn_len < 0) {
			lwsl_wsi_notice(wsi, "QUIC RX: Header unmask failed");
			break;
		}

		/* Check reserved bits AFTER unmasking! */
		if (p[0] & 0x80) {
			/* Long header: Bits 0x0c MUST be zero */
			if (p[0] & 0x0c) {
				lwsl_wsi_notice(wsi, "QUIC RX: Reserved bits non-zero in long header");
				if (nwsi && nwsi != wsi) {
					lws_quic_enter_closing_state(nwsi, LWS_QUIC_ERR_PROTOCOL_VIOLATION, 0, 0);
					goto next_packet;
				}
				return LWS_HPI_RET_PLEASE_CLOSE_ME;
			}
		} else {
			/* Short header: Bits 0x18 MUST be zero */
			if (p[0] & 0x18) {
				lwsl_wsi_notice(wsi, "QUIC RX: Reserved bits non-zero in short header");
				if (nwsi && nwsi != wsi) {
					lws_quic_enter_closing_state(nwsi, LWS_QUIC_ERR_PROTOCOL_VIOLATION, 0, 0);
					goto next_packet;
				}
				return LWS_HPI_RET_PLEASE_CLOSE_ME;
			}
		}

		/*
		 * Reconstruct full 62-bit PN.
		 */
		uint64_t truncated_pn = 0;
		for (int i = 0; i < pn_len; i++)
			truncated_pn = (truncated_pn << 8) | p[pn_offset + (size_t)i];

		uint64_t largest_pn = nwsi->quic.qn ? nwsi->quic.qn->highest_rx_pn[level] : 0;
		uint64_t full_pn = lws_quic_decode_packet_number(largest_pn, truncated_pn, pn_len * 8);
		lwsl_wsi_info(wsi, "QUIC RX: Packet level %d, decoded full_pn = %llu", level, (unsigned long long)full_pn);

		struct lws_quic_keys scratch_keys;
		struct lws_quic_keys *decryption_keys = k;
		int is_key_update = 0;

		if (!(p[0] & 0x80)) { /* Short header */
			uint8_t kp = (p[0] & 0x04) >> 2;
			if (nwsi->quic.qn && nwsi->quic.qn->rx_key_phase != kp) {
				/* Provisional key update */
				scratch_keys = *k;
				if (lws_quic_update_keys(&scratch_keys, 1) == 0) {
					decryption_keys = &scratch_keys;
					is_key_update = 1;
					lwsl_wsi_notice(wsi, "QUIC RX: Attempting provisional key update");
				}
			}
		}

		/* 4. Decryption: Authenticate and decrypt the payload in-place! */
		int dec_len = lws_quic_decrypt_payload(decryption_keys, p, packet_size, pn_offset, (uint8_t)pn_len, full_pn);
		if (dec_len < 0) {
			lwsl_wsi_notice(wsi, "QUIC RX: AEAD Decryption failed (bad tag or truncated)");
			break;
		}

		/* Decryption succeeded! Commit key update if pending */
		if (is_key_update) {
			*k = scratch_keys;
			nwsi->quic.qn->rx_key_phase ^= 1;
			nwsi->quic.qn->rx_packets_since_update = 0;
			if (!nwsi->quic.qn->key_update_pending) {
				/* Peer initiated, so we echo by updating TX keys */
				lws_quic_initiate_key_update(nwsi);
			} else {
				/* We initiated, this is the peer echoing back */
				nwsi->quic.qn->key_update_pending = 0;
			}
			lwsl_wsi_notice(wsi, "QUIC RX: Key Update completed successfully");
		}
		
		if (nwsi->quic.qn)
			nwsi->quic.qn->rx_packets_since_update++;

		if (nwsi->quic.qn && level == LWS_QUIC_LEVEL_HANDSHAKE) {
			nwsi->quic.qn->address_validated = 1;
		}

		if (level == LWS_QUIC_LEVEL_HANDSHAKE) {
			lws_quic_discard_keys(nwsi, LWS_QUIC_LEVEL_INITIAL);
		} else if (level == LWS_QUIC_LEVEL_APP) {
			lws_quic_discard_keys(nwsi, LWS_QUIC_LEVEL_INITIAL);
			lws_quic_discard_keys(nwsi, LWS_QUIC_LEVEL_HANDSHAKE);
		}

		lwsl_wsi_info(wsi, "QUIC RX: SUCCESS! Decrypted %d bytes of payload", dec_len);

		/* Check for duplicate/replayed packet numbers (Security Fix) */
		if (nwsi->quic.qn) {
			uint64_t highest = nwsi->quic.qn->highest_rx_pn[level];
			if ((nwsi->quic.qn->rx_pn_bitmask[level] != 0 || highest != 0) && full_pn <= highest) {
				uint64_t diff = highest - full_pn;
				if (diff >= 64 || (nwsi->quic.qn->rx_pn_bitmask[level] & (1ULL << diff))) {
					lwsl_wsi_notice(wsi, "QUIC RX: Dropping duplicated or very old packet %llu", (unsigned long long)full_pn);
					goto next_packet;
				}
				nwsi->quic.qn->rx_pn_bitmask[level] |= (1ULL << diff);
			} else {
				if (nwsi->quic.qn->rx_pn_bitmask[level] != 0 || highest != 0) {
					uint64_t diff = full_pn - highest;
					if (diff >= 64)
						nwsi->quic.qn->rx_pn_bitmask[level] = 0;
					else
						nwsi->quic.qn->rx_pn_bitmask[level] <<= diff;
				}
				nwsi->quic.qn->rx_pn_bitmask[level] |= 1ULL;
				nwsi->quic.qn->highest_rx_pn[level] = full_pn;
			}
			
			/* Connection Migration: Execute pending migration now that the packet is cryptographically verified */
			if (pending_migration) {
				pending_migration = 0;
#if (_LWS_ENABLED_LOGS & LLL_NOTICE)
				char buf_old[64], buf_new[64];
				uint16_t port_old, port_new;

				lws_sa46_write_numeric_address(&nwsi->udp->sa46, buf_old, sizeof(buf_old));
				lws_sa46_write_numeric_address(&migration_sa46, buf_new, sizeof(buf_new));
				
#if defined(LWS_WITH_IPV6)
				port_old = nwsi->udp->sa46.sa4.sin_family == AF_INET ? nwsi->udp->sa46.sa4.sin_port : nwsi->udp->sa46.sa6.sin6_port;
				port_new = migration_sa46.sa4.sin_family == AF_INET ? migration_sa46.sa4.sin_port : migration_sa46.sa6.sin6_port;
#else
				port_old = nwsi->udp->sa46.sa4.sin_port;
				port_new = migration_sa46.sa4.sin_port;
#endif
#endif

				if (nwsi->quic.qn->is_server) {
#if (_LWS_ENABLED_LOGS & LLL_NOTICE)
					lwsl_notice("QUIC Server: Connection Migration verified! Peer address changed from %s:%u to %s:%u\n",
						    buf_old, (unsigned int)ntohs(port_old),
						    buf_new, (unsigned int)ntohs(port_new));
#endif
				} else {
#if (_LWS_ENABLED_LOGS & LLL_NOTICE)
					lwsl_notice("QUIC Client: Server address changed from %s:%u to %s:%u, re-connecting socket\n",
						    buf_old, (unsigned int)ntohs(port_old),
						    buf_new, (unsigned int)ntohs(port_new));
#endif

					/* Re-connect the socket to the new server address */
					if (connect(nwsi->desc.sockfd, sa46_sockaddr(&migration_sa46), sa46_socklen(&migration_sa46)) < 0) {
						lwsl_warn("QUIC: failed to re-connect client socket, errno=%d\n", errno);
					}
				}

				nwsi->udp->sa46 = migration_sa46;

				/* Reset Congestion Control State (RFC 9000 9.3.3) */
				if (nwsi->quic.qn->cc_ops && nwsi->quic.qn->cc_ops->init)
					nwsi->quic.qn->cc_ops->init(nwsi);

				/* Reset RTT estimator */
				nwsi->quic.qn->smoothed_rtt = 0;
				nwsi->quic.qn->rttvar = 0;
				nwsi->quic.qn->latest_rtt = 0;

				/* Reset PMTUD */
				nwsi->quic.qn->current_mtu = 1280;
				nwsi->quic.qn->probed_mtu = 1380;
				nwsi->quic.qn->pmtud_state = 1;

				/* Set path to unvalidated */
				nwsi->quic.qn->address_validated = 0;

				/* Reset Path Bytes for Anti-Amplification tracking */
				nwsi->quic.qn->bytes_received = 0;
				nwsi->quic.qn->bytes_sent = 0;

				/* Initiate Path Validation (Generate PATH_CHALLENGE) */
				struct lws_quic_tx_frame *f_pc = lws_zalloc(sizeof(*f_pc) + 8, "quic path_chall");
				if (f_pc) {
					f_pc->type = LWS_QUIC_FT_PATH_CHALLENGE;
					f_pc->len = 8;
					f_pc->data = (uint8_t *)&f_pc[1];
					lws_get_random(wsi->a.context, f_pc->data, 8);
					memcpy(nwsi->quic.qn->path_challenge, f_pc->data, 8);
					nwsi->quic.qn->path_challenge_pending = 1;

					lws_dll2_add_tail(&f_pc->list, &nwsi->quic.qn->pending_tx[LWS_QUIC_LEVEL_APP]);
					lws_callback_on_writable(nwsi);
				}
			}

			/* 5. Parse the plaintext frames */
			if (dec_len == 0) {
				lwsl_wsi_notice(wsi, "QUIC RX: Packet payload is empty (no frames)");
				if (nwsi && nwsi != wsi) {
					lws_quic_enter_closing_state(nwsi, LWS_QUIC_ERR_PROTOCOL_VIOLATION, 0, 0);
					goto next_packet;
				}
				return LWS_HPI_RET_PLEASE_CLOSE_ME;
			}

			int ack_eliciting = lws_quic_parse_frames(nwsi, level, &p[pn_offset + (size_t)pn_len], (size_t)dec_len);
			
			/* ALPN negotiation might have migrated the network WSI! */
			if (nwsi && !nwsi->quic.qn) {
				nwsi = lws_get_quic_network_wsi(nwsi);
			}

			if (ack_eliciting < 0) {
				lwsl_wsi_notice(wsi, "QUIC RX: Frame parsing aborted");
			if (ack_eliciting == -3) {
				/* Peer closed the connection via CONNECTION_CLOSE. Drop silently without replying. */
				lwsl_wsi_notice(nwsi ? nwsi : wsi, "QUIC RX: Peer closed connection. Dropping silently.");
				if (nwsi && nwsi != wsi) {
					lws_close_free_wsi(nwsi, LWS_CLOSE_STATUS_NORMAL, "quic peer closed");
					goto next_packet;
				}
				return LWS_HPI_RET_PLEASE_CLOSE_ME;
			}
			/* We found an error and queued a CONNECTION_CLOSE frame */
			if (nwsi) {
				lws_quic_enter_closing_state(nwsi, ack_eliciting == -2 ? LWS_QUIC_ERR_PROTOCOL_VIOLATION : LWS_QUIC_ERR_FRAME_ENCODING_ERROR, 0, 0);
				lws_callback_on_writable(nwsi);
			}
			goto next_packet;
			} else if (ack_eliciting > 0) {
				if (nwsi && nwsi->quic.qn) {
					nwsi->quic.qn->needs_ack[level] = 1;
					lws_callback_on_writable(nwsi); /* Ensure POLLOUT fires so we send the ACK! */
				}
			}
		}

next_packet:
		n -= (int)packet_size;
		p += packet_size;
	}

try_pollout:
	if ((pollfd->revents & LWS_POLLOUT) &&
	    lws_handle_POLLOUT_event(wsi, pollfd)) {
		lwsl_debug("POLLOUT event closed it\n");
		return LWS_HPI_RET_PLEASE_CLOSE_ME;
	}

	return LWS_HPI_RET_HANDLED;
}

int
lws_tls_quic_tx_crypto_cb(struct lws *wsi, int level, const uint8_t *buf, size_t len)
{
	struct lws_quic_netconn *qn = wsi->quic.qn;

	if (!qn)
		return -1;

	lwsl_notice("QUIC TLS TX: %s generated %d bytes of crypto data for level %d\n", lws_wsi_tag(wsi), (int)len, level);
	
	struct lws_quic_tx_frame *f;

	/* Allocate frame struct + payload buffer natively */
	f = lws_zalloc(sizeof(*f) + len, "quic tx frame");
	if (!f)
		return -1;

	f->type = LWS_QUIC_FT_CRYPTO;
	f->data = (uint8_t *)&f[1];
	f->len = len;

	/* Copy the TLS library's output into the frame */
	memcpy(f->data, buf, len);

	/*
	 * Set proper offset tracking for CRYPTO streams.
	 */
	f->offset = qn->crypto_tx_offset[level];
	qn->crypto_tx_offset[level] += len;

	/* Add to the pending TX queue for this encryption level! */
	lws_dll2_add_tail(&f->list, &qn->pending_tx[level]);

	/* Wake up the event loop to instantly trigger POLLOUT and send the packet */
	lws_callback_on_writable(wsi);

	return 0;
}

static int
quic_secret_cb(struct lws *wsi, enum lws_tls_quic_secret_type type,
	       const uint8_t *secret, size_t secret_len)
{
	lwsl_info("QUIC TLS: Extracted secret type %d (len %d)\n", type, (int)secret_len);
	if (lws_quic_set_keys(wsi, type, secret, secret_len)) {
		lwsl_wsi_err(wsi, "Failed to set QUIC keys for type %d", type);
		return -1;
	}
	return 0;
}

void
lws_quic_enter_closing_state(struct lws *wsi, uint64_t err_code, uint64_t frame_type, int is_app_error)
{
	struct lws_quic_netconn *qn;
	struct lws *nwsi = lws_get_quic_network_wsi(wsi);
	struct lws_quic_tx_frame *f;
	int level, target_level = LWS_QUIC_LEVEL_INITIAL;

	if (!nwsi || !nwsi->quic.qn) {
		lwsl_notice("lws_quic_enter_closing_state: nwsi %s, qn %p (wsi %s parent %s)\n", 
			lws_wsi_tag(nwsi), nwsi ? nwsi->quic.qn : NULL, lws_wsi_tag(wsi), lws_wsi_tag(wsi ? wsi->mux.parent_wsi : NULL));
		return;
	}

	qn = nwsi->quic.qn;

	if (qn->is_closing) {
		lwsl_notice("lws_quic_enter_closing_state: qn->is_closing is already 1\n");
		return; /* Already closing */
	}

	qn->is_closing = 1;
	qn->conn_close_err = err_code;


	lwsl_wsi_warn(nwsi, "QUIC: Entering Closing State (err 0x%llx)", (unsigned long long)err_code);

	/* Determine highest available encryption level to send CONNECTION_CLOSE */
	int start_level = qn->highest_rx_level;
	for (level = start_level; level >= LWS_QUIC_LEVEL_INITIAL; level--) {
		if (qn->keys[level] && qn->keys[level]->valid) {
			target_level = level;
			break;
		}
	}

	/* Clear pending queues, we are closing, but keep CRYPTO frames so peer can derive keys! */
	for (level = 0; level < LWS_QUIC_LEVEL_COUNT; level++) {
		lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, qn->pending_tx[level].head) {
			struct lws_quic_tx_frame *tf = lws_container_of(d, struct lws_quic_tx_frame, list);
			if (tf->type != LWS_QUIC_FT_CRYPTO && tf->type != LWS_QUIC_FT_HANDSHAKE_DONE) {
				lws_dll2_remove(&tf->list);
				lws_free(tf);
			}
		} lws_end_foreach_dll_safe(d, d1);
	}

	/* Enqueue a single CONNECTION_CLOSE frame */
	f = lws_zalloc(sizeof(*f) + 16, "quic tx cc");
	if (f) {
		uint8_t *p = (uint8_t *)&f[1];
		f->type = is_app_error ? LWS_QUIC_FT_CONNECTION_CLOSE_APP : LWS_QUIC_FT_CONNECTION_CLOSE;
		
		lwsl_wsi_warn(nwsi, "QUIC TX: Enqueueing CONNECTION_CLOSE (type 0x%x, err 0x%llx) at level %d",
			f->type, (unsigned long long)err_code, target_level);

		/* Encode the error code (varint) */
		p += lws_quic_write_varint(p, 8, err_code);

		/* Frame type (varint) - only for Transport Errors (0x1c) */
		if (!is_app_error) {
			p += lws_quic_write_varint(p, 8, frame_type);
		}

		/* Reason phrase length (0) */
		p += lws_quic_write_varint(p, 8, 0);

		f->data = (uint8_t *)&f[1];
		f->len = (size_t)(p - f->data);

		lwsl_wsi_warn(nwsi, "QUIC TX: Enqueueing CONNECTION_CLOSE (type 0x%x, err 0x%llx) at level %d",
			f->type, (unsigned long long)err_code, target_level);
		lwsl_hexdump_warn(f->data, f->len);

		lws_dll2_add_tail(&f->list, &qn->pending_tx[target_level]);
	}

	/* Wait 3 seconds, then drop the socket */
	lws_set_timeout(nwsi, PENDING_TIMEOUT_KILLED_BY_SSL_INFO, 3);
	lws_callback_on_writable(nwsi);
}

static lws_handling_result_t
rops_handle_POLLOUT_quic(struct lws *wsi)
{
	struct lws_quic_netconn *qn = wsi->quic.qn;
	int level, n;
	int blocked = 0;
	uint8_t pkt[2048]; memset(pkt, 0, sizeof(pkt));

	// lwsl_notice("QUIC TX: POLLOUT called for %s, qn=%p, is_server=%d\n", lws_wsi_tag(wsi), qn, qn ? qn->is_server : -1);

	if (!qn) {
		struct lws *w;
		if (wsi->mux.child_list) {
			w = wsi->mux.child_list;
			while (w) {
				struct lws *next = w->mux.sibling_list;
				if (w->mux.requested_POLLOUT) {
					w->mux.requested_POLLOUT = 0;
					rops_handle_POLLOUT_quic(w);
				}
				w = next;
			}
		}
		return LWS_HP_RET_DROP_POLLOUT;
	}

	lws_usec_t pto_delay = LWS_QUIC_DEFAULT_PTO_US << qn->pto_count;
	if (pto_delay > 10000000)
		pto_delay = 10000000;

	if (!wsi->quic.initialized && !qn->is_server) {
		wsi->quic.initialized = 1;

#if defined(LWS_WITH_TLS) && defined(LWS_WITH_CLIENT)
		if (wsi->tls.use_ssl & LCCSCF_USE_SSL) {
			if (!wsi->tls.ssl) {
				const char *cce = NULL;
				if (lws_client_create_tls(wsi, &cce, 0) == CCTLS_RETURN_ERROR) {
					lwsl_wsi_err(wsi, "Failed to create TLS BIO: %s", cce ? cce : "unknown");
					return LWS_HP_RET_BAIL_DIE;
				}
			}

			/* The BIO was already created, just init QUIC TLS */
			if (lws_tls_quic_init(wsi, quic_secret_cb)) {
				lwsl_wsi_err(wsi, "Failed to init QUIC TLS");
				return LWS_HP_RET_BAIL_DIE;
			}
			/* Kick off the handshake */
			lwsl_wsi_notice(wsi, "Kicking off QUIC TLS handshake");
			lws_tls_quic_rx_crypto(wsi, LWS_QUIC_LEVEL_INITIAL, NULL, 0);
		}
#endif
	}

	if (qn->is_closing) {
		/* We are in the Closing State. Only process the CONNECTION_CLOSE frame. */
		/* The frame is queued in pending_tx by lws_quic_enter_closing_state. */
		/* Skip PTO sweep and just let the normal frame generation send it. */
		goto send_frames;
	}

	/*
	 * PTO Sweep: Check for dropped/unacknowledged packets
	 */
	lws_usec_t now = lws_now_usecs();
	size_t total_bytes_lost = 0;
	uint64_t last_lost_pn = (uint64_t)-1;
	for (level = 0; level < LWS_QUIC_LEVEL_COUNT; level++) {
		if (!qn->in_flight[level].count)
			continue;

		lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, qn->in_flight[level].head) {
			struct lws_quic_tx_frame *f = lws_container_of(d, struct lws_quic_tx_frame, list);

			lwsl_debug("PTO Sweep: checking packet %llu: now=%llu, sent=%llu, diff=%lld\n",
				(unsigned long long)f->sent_in_pn, (unsigned long long)now, (unsigned long long)f->sent_time_us,
				(long long)(now - f->sent_time_us));

			/* Allow a 5ms epsilon for timer jitter */
			if (now + 5000 >= f->sent_time_us + pto_delay) {
				lwsl_notice("PTO Sweep: Packet %llu (type 0x%02x) lost! Retransmitting!\n", (unsigned long long)f->sent_in_pn, f->type);

				/* PMTUD Black Hole Detection */
				if (f->sent_in_pn != last_lost_pn) {
					last_lost_pn = f->sent_in_pn;
					if (f->sent_in_pn == qn->pmtud_probe_pn) {
						/* Active probe was lost */
						qn->pmtud_probe_pn = 0;
					} else if (f->packet_size >= qn->current_mtu - 16) {
						qn->consecutive_mtu_losses++;
						if (qn->consecutive_mtu_losses >= 3) {
							lwsl_wsi_warn(wsi, "QUIC PMTUD: Black Hole detected! Reverting MTU to 1280.");
							qn->current_mtu = 1280;
							qn->pmtud_state = 0;
							qn->consecutive_mtu_losses = 0;
						}
					}
				}

				/* Packet lost! Move it back to pending_tx */
				lws_dll2_remove(&f->list);
				lws_dll2_add_head(&f->list, &qn->pending_tx[level]);
				total_bytes_lost += f->wire_len;
				f->wire_len = 0;
			}
		} lws_end_foreach_dll_safe(d, d1);
	}
	if (total_bytes_lost && qn->cc_ops && qn->cc_ops->on_loss)
		qn->cc_ops->on_loss(wsi, total_bytes_lost);

send_frames:
	/*
	 * Iterate through the encryption levels in priority order.
	 * Initial > Handshake > Application Data.
	 */
	for (level = 0; level < LWS_QUIC_LEVEL_COUNT; level++) {
		if (!qn->keys[level]) {
			continue;
		}

		if (!qn->keys[level]->valid) {
			continue;
		}

		if (!qn->pending_tx[level].count && !qn->needs_ack[level]) {
			continue;
		}

		lwsl_wsi_info(wsi, "QUIC TX: Processing level %d. pending=%d, needs_ack=%d", level, qn->pending_tx[level].count, qn->needs_ack[level]);

		uint32_t mtu = qn->current_mtu ? qn->current_mtu : 1280;

		/* Enforce RFC 9000 Anti-Amplification Limit (Section 8.1) for servers */
		if (qn->is_server && !qn->address_validated) {
			if (qn->bytes_sent + mtu > 3 * qn->bytes_received) {
				lwsl_notice("QUIC TX: Anti-Amplification limit reached! Sent: %llu, Recv: %llu. Blocking send.\n",
					    (unsigned long long)qn->bytes_sent, (unsigned long long)qn->bytes_received);
				blocked = 1;
				break; /* Block sending further datagrams */
			}
		}

		/* Check congestion window */
		if (!qn->pto_probe_needed && !qn->needs_ack[level] && qn->cc_ops && qn->cc_ops->can_send && !qn->cc_ops->can_send(wsi, mtu)) {
#if (_LWS_ENABLED_LOGS & LLL_INFO)
			LWS_RATELIMIT_DEFINE_STATIC(rl);
			lwsl_ratelimit_info(&rl, 1000000, "QUIC TX: Congestion window full, blocking POLLOUT\n");
#endif
			blocked = 1;
			break; /* Stop processing sending loops */
		}

		/* Check pacing */
		if (!qn->needs_ack[level] && qn->cc_ops && qn->cc_ops->get_pacing_delay) {
			lws_usec_t delay = qn->cc_ops->get_pacing_delay(wsi, mtu);
			if (delay > 0) {
				lws_sul_schedule(wsi->a.context, 0, &qn->pacer_sul, lws_quic_pacer_cb, delay);
				blocked = 1;
				break; /* Stop processing sending loops */
			}
		}

		/* AEAD Confidentiality Limits Check (RFC 9001 Section 6.6) */
		if (level == LWS_QUIC_LEVEL_APP && qn->tx_packets_since_update > (1ULL << 20)) {
			lws_quic_initiate_key_update(wsi);
		}

		/* We have frames to send at this encryption level! */
		uint8_t *p = pkt;
		uint64_t my_pn = qn->keys[level]->pn_tx++;

		/* 1. Serialize Header */
		size_t pn_offset = 0;
		size_t header_len = 0;

		if (level == LWS_QUIC_LEVEL_INITIAL || level == LWS_QUIC_LEVEL_HANDSHAKE) {
			if (level == LWS_QUIC_LEVEL_INITIAL)
				*p++ = 0xc0 | 0x00 | 0x01; /* Long Header, Initial, 2-byte PN */
			else
				*p++ = 0xc0 | 0x20 | 0x01; /* Long Header, Handshake, 2-byte PN */

			/* Version */
			*p++ = (uint8_t)(qn->version >> 24);
			*p++ = (uint8_t)(qn->version >> 16);
			*p++ = (uint8_t)(qn->version >> 8);
			*p++ = (uint8_t)(qn->version);
			/* DCID */
			*p++ = qn->rem_cid.len;
			if (qn->rem_cid.len) { memcpy(p, qn->rem_cid.id, qn->rem_cid.len); p += qn->rem_cid.len; }
			/* SCID */
			*p++ = qn->loc_cid.len;
			if (qn->loc_cid.len) { memcpy(p, qn->loc_cid.id, qn->loc_cid.len); p += qn->loc_cid.len; }

			if (level == LWS_QUIC_LEVEL_INITIAL) {
				/* Token Length */
				*p++ = 0x00;
			}
			/* Length (2-byte varint, will fill in later) */
			*p++ = 0x40; *p++ = 0x00;

			pn_offset = (size_t)(p - pkt);
			header_len = pn_offset + 2; /* 2-byte PN */
			p += 2; /* Skip PN bytes */
		} else {
			uint8_t sh = 0x40 | 0x01; /* Short Header, Fixed bit, 2-byte PN */
			if (qn->tx_key_phase)
				sh |= 0x04; /* Key Phase bit */
			*p++ = sh;
			/* DCID */
			if (qn->rem_cid.len) { memcpy(p, qn->rem_cid.id, qn->rem_cid.len); p += qn->rem_cid.len; }

			pn_offset = (size_t)(p - pkt);
			header_len = pn_offset + 2;
			p += 2;
		}

		/* 1.5 Generate ACK frame if needed */
		if (qn->needs_ack[level]) {
			*p++ = LWS_QUIC_FT_ACK;
			p += lws_quic_write_varint(p, sizeof(pkt) - (size_t)(p - pkt), qn->highest_rx_pn[level]); /* Largest Acknowledged */
			p += lws_quic_write_varint(p, sizeof(pkt) - (size_t)(p - pkt), 0); /* ACK Delay (0 for now) */
			p += lws_quic_write_varint(p, sizeof(pkt) - (size_t)(p - pkt), 0); /* ACK Range Count */
			uint64_t first_ack_range = 0;
			uint64_t bm = qn->rx_pn_bitmask[level] >> 1;
			while (bm & 1) {
				first_ack_range++;
				bm >>= 1;
			}
			p += lws_quic_write_varint(p, sizeof(pkt) - (size_t)(p - pkt), first_ack_range); /* First ACK Range */
			qn->needs_ack[level] = 0;
		}

		/* 2. Bundle frames from pending_tx until MTU is reached */
		lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, qn->pending_tx[level].head) {
			struct lws_quic_tx_frame *f = lws_container_of(d, struct lws_quic_tx_frame, list);

			/* Check if frame fits in remaining MTU (leaving room for headers and 16-byte AEAD tag) */
			size_t frame_header_max_len = 1 + 8 + 8;
			size_t max_udp_payload = qn->current_mtu ? (qn->current_mtu > 48 ? qn->current_mtu - 48 : 1200) : 1200;
			if (max_udp_payload > 1200 && !qn->handshake_done) max_udp_payload = 1200; /* RFC 9000 Section 14.1 */
			if (max_udp_payload > sizeof(pkt)) max_udp_payload = sizeof(pkt);

			if ((size_t)(p - pkt) + frame_header_max_len + 32 >= max_udp_payload)
				break;

			size_t send_len = f->len;
			if ((size_t)(p - pkt) + frame_header_max_len + send_len + 32 > max_udp_payload) {
				send_len = max_udp_payload - (size_t)(p - pkt) - frame_header_max_len - 32;
			}
			if (send_len == 0 && f->len > 0)
				break;

			/* Serialize the frame type */
			uint8_t type = f->type;
			if (send_len < f->len && (type & 0xf8) == LWS_QUIC_FT_STREAM) {
				type &= 0xfe; /* Clear FIN bit for intermediate fragment */
			}
			*p++ = type;

			/* Serialize frame-specific headers */
			if (type == LWS_QUIC_FT_CRYPTO) {
				p += lws_quic_write_varint(p, sizeof(pkt) - (size_t)(p - pkt), f->offset);
				p += lws_quic_write_varint(p, sizeof(pkt) - (size_t)(p - pkt), send_len);
			} else if ((type & 0xf8) == LWS_QUIC_FT_STREAM) {
				/* Stream ID */
				//lwsl_notice( "QUIC TX: Formatting MAX_STREAM_DATA for stream %llu", (unsigned long long)f->stream_id);
                                p += lws_quic_write_varint(p, sizeof(pkt) - (size_t)(p - pkt), f->stream_id);
				if (type & 0x04) /* OFF */
					p += lws_quic_write_varint(p, sizeof(pkt) - (size_t)(p - pkt), f->offset);
				if (type & 0x02) /* LEN */
					p += lws_quic_write_varint(p, sizeof(pkt) - (size_t)(p - pkt), send_len);
			} else if ((type & 0xfe) == LWS_QUIC_FT_DATAGRAM) {
				if (type & 0x01) /* LEN */
					p += lws_quic_write_varint(p, sizeof(pkt) - (size_t)(p - pkt), send_len);
			} else if (type == LWS_QUIC_FT_MAX_DATA || type == LWS_QUIC_FT_DATA_BLOCKED) {
				p += lws_quic_write_varint(p, sizeof(pkt) - (size_t)(p - pkt), f->limit);
			} else if (type == LWS_QUIC_FT_MAX_STREAM_DATA || type == LWS_QUIC_FT_STREAM_DATA_BLOCKED) {
				//lwsl_notice( "QUIC TX: Formatting MAX_STREAM_DATA for stream %llu", (unsigned long long)f->stream_id);
                                p += lws_quic_write_varint(p, sizeof(pkt) - (size_t)(p - pkt), f->stream_id);
				p += lws_quic_write_varint(p, sizeof(pkt) - (size_t)(p - pkt), f->limit);
			} else if (type == LWS_QUIC_FT_RESET_STREAM) {
				//lwsl_notice( "QUIC TX: Formatting MAX_STREAM_DATA for stream %llu", (unsigned long long)f->stream_id);
                                p += lws_quic_write_varint(p, sizeof(pkt) - (size_t)(p - pkt), f->stream_id);
				p += lws_quic_write_varint(p, sizeof(pkt) - (size_t)(p - pkt), f->offset); /* app_err_code */
				p += lws_quic_write_varint(p, sizeof(pkt) - (size_t)(p - pkt), f->limit); /* final_size */
			} else if (type == LWS_QUIC_FT_STOP_SENDING) {
				//lwsl_notice( "QUIC TX: Formatting MAX_STREAM_DATA for stream %llu", (unsigned long long)f->stream_id);
                                p += lws_quic_write_varint(p, sizeof(pkt) - (size_t)(p - pkt), f->stream_id);
				p += lws_quic_write_varint(p, sizeof(pkt) - (size_t)(p - pkt), f->offset); /* app_err_code */
			} else if (type == LWS_QUIC_FT_MAX_STREAMS_BIDI || type == LWS_QUIC_FT_MAX_STREAMS_UNIDI ||
				   type == LWS_QUIC_FT_STREAMS_BLOCKED_BIDI || type == LWS_QUIC_FT_STREAMS_BLOCKED_UNIDI) {
				p += lws_quic_write_varint(p, sizeof(pkt) - (size_t)(p - pkt), f->limit);
			} else if (type == LWS_QUIC_FT_NEW_CONNECTION_ID) {
				//lwsl_notice( "QUIC TX: Formatting MAX_STREAM_DATA for stream %llu", (unsigned long long)f->stream_id);
                                p += lws_quic_write_varint(p, sizeof(pkt) - (size_t)(p - pkt), f->stream_id); /* seq */
				p += lws_quic_write_varint(p, sizeof(pkt) - (size_t)(p - pkt), f->offset); /* retire_prior_to */
				/* cid + token in data */
			} else if (type == LWS_QUIC_FT_RETIRE_CONNECTION_ID) {
				//lwsl_notice( "QUIC TX: Formatting MAX_STREAM_DATA for stream %llu", (unsigned long long)f->stream_id);
                                p += lws_quic_write_varint(p, sizeof(pkt) - (size_t)(p - pkt), f->stream_id); /* seq */
			}

			if (send_len) {
				memcpy(p, f->data, send_len);
				p += send_len;
			}

			if (send_len < f->len) {
				/* Fragmentation! Duplicate into in_flight */
				struct lws_quic_tx_frame *f_sent = lws_malloc(sizeof(*f_sent) + send_len, "quic tx frag");
				if (!f_sent) return LWS_HPI_RET_HANDLED;
				*f_sent = *f;
				lws_dll2_clear(&f_sent->list);
				f_sent->len = send_len;
				f_sent->data = (uint8_t *)&f_sent[1];
				memcpy(f_sent->data, f->data, send_len);

				f_sent->sent_in_pn = my_pn;
				f_sent->sent_time_us = lws_now_usecs();
				f_sent->wire_len = 0;

				/* Clear the FIN bit from intermediate fragment */
				if ((f_sent->type & 0xf8) == LWS_QUIC_FT_STREAM)
					f_sent->type &= 0xfe;

				lws_dll2_add_tail(&f_sent->list, &qn->in_flight[level]);

				/* Update original f in pending_tx */
				f->offset += send_len;
				f->len -= send_len;
				f->data += send_len;

				/* Schedule PTO timer since we have data in-flight */
				lws_sul_schedule(wsi->a.context, 0, &qn->pto_sul, lws_quic_pto_cb, pto_delay);

				break; /* We filled the MTU */
			} else {
				/* Sent entirely */
				lws_dll2_remove(&f->list);
				f->sent_in_pn = my_pn;
				f->sent_time_us = lws_now_usecs();
				f->wire_len = 0;
				lws_dll2_add_tail(&f->list, &qn->in_flight[level]);

				/* Schedule PTO timer since we have data in-flight */
				lws_sul_schedule(wsi->a.context, 0, &qn->pto_sul, lws_quic_pto_cb, pto_delay);
			}

		} lws_end_foreach_dll_safe(d, d1);

		size_t payload_len = (size_t)(p - (pkt + header_len));
		if (payload_len == 0)
			continue;

		/* Ensure payload is at least 4 bytes for header protection sampling (RFC 9000 Section 5.4.2) */
		if (payload_len < 4) {
			memset(p, LWS_QUIC_FT_PADDING, 4 - payload_len);
			p += (4 - payload_len);
			payload_len = 4;
		}

		/* pad out to 1200 minimum total tx length for client initial */
		if (level == LWS_QUIC_LEVEL_INITIAL && !qn->is_server) {
			size_t target_payload_len = 1200 - header_len - 16;
			if (payload_len < target_payload_len) {
				memset(p, LWS_QUIC_FT_PADDING, target_payload_len - payload_len);
				p += (target_payload_len - payload_len);
				payload_len = target_payload_len;
			}
		}

		/* PMTUD: Send a probe if we are searching and don't currently have a probe in flight */
		if (level == LWS_QUIC_LEVEL_APP && qn->pmtud_state == 1 && qn->pmtud_probe_pn == 0) {
			size_t target_payload_len = qn->probed_mtu - header_len - 16;
			if (payload_len < target_payload_len) {
				memset(p, LWS_QUIC_FT_PADDING, target_payload_len - payload_len);
				p += (target_payload_len - payload_len);
				payload_len = target_payload_len;
				qn->pmtud_probe_pn = my_pn;
				lwsl_wsi_notice(wsi, "QUIC TX: Sending PMTUD probe %llu (size %d)", (unsigned long long)my_pn, (int)qn->probed_mtu);
			}
		}

		/* Fill in Length for Initial/Handshake packets */
		if (level == LWS_QUIC_LEVEL_INITIAL || level == LWS_QUIC_LEVEL_HANDSHAKE) {
			uint16_t quic_len = (uint16_t)(payload_len + 2 + 16); /* PN (2) + AEAD Tag (16) */
			uint8_t *len_ptr = pkt + 1 + 4 + 1 + qn->rem_cid.len + 1 + qn->loc_cid.len;
			if (level == LWS_QUIC_LEVEL_INITIAL)
				len_ptr++; /* Skip Token Length */
			len_ptr[0] = (uint8_t)(0x40 | ((quic_len >> 8) & 0x3F));
			len_ptr[1] = (uint8_t)(quic_len & 0xFF);
		}

		/* Fill in Packet Number */
		pkt[pn_offset]     = (uint8_t)((my_pn >> 8) & 0xFF);
		pkt[pn_offset + 1] = (uint8_t)(my_pn & 0xFF);

		/* 3. Encrypt payload and mask header */
		n = lws_quic_encrypt_payload(qn->keys[level], pkt, (size_t)(p - pkt), pn_offset, 2, my_pn);
		if (n < 0) {
			lwsl_wsi_err(wsi, "QUIC TX: Payload encryption failed");
			return LWS_HP_RET_BAIL_OK;
		}

		if (level == LWS_QUIC_LEVEL_APP)
			qn->tx_packets_since_update++;

		/* 4. Transmit UDP Datagram */

		lws_sockfd_type fd = wsi->mux_substream ? wsi->mux.parent_wsi->desc.sockfd : wsi->desc.sockfd;
		size_t send_len = (size_t)(p - pkt) + 16;
		
		/* PMTUD: tag in-flight frames with this packet's wire length so we can track MTU losses */
		struct lws_dll2 *d = qn->in_flight[level].tail;
		while (d) {
			struct lws_quic_tx_frame *f = lws_container_of(d, struct lws_quic_tx_frame, list);
			if (f->sent_in_pn == my_pn)
				f->packet_size = (uint16_t)send_len;
			else
				break;
			d = d->prev;
		}

		lwsl_wsi_debug(wsi, "QUIC TX TELEMETRY: Sending packet of %d bytes to network (level %d)", (int)send_len, level);

		/* Fault Injection for dropping UDP packets (simulating packet loss) */
		if (lws_fi(&wsi->fic, "quic_tx_drop")) {
			lwsl_wsi_debug(wsi, "QUIC TX: Dropping packet via lws_fi fault injection!");
			n = (int)send_len; /* Pretend it succeeded */
		} else {
#if defined(WIN32) || defined(_WIN32)
			if (wsi->mux_substream && wsi->udp)
				n = sendto(fd, (const char *)pkt, (int)send_len, 0,
					   sa46_sockaddr(&wsi->udp->sa46), sa46_socklen(&wsi->udp->sa46));
			else
				n = send(fd, (const char *)pkt, (int)send_len, 0);
#else
			if (wsi->mux_substream && wsi->udp)
				n = (int)sendto(fd, (const void *)pkt, send_len, 0,
						sa46_sockaddr(&wsi->udp->sa46), sa46_socklen(&wsi->udp->sa46));
			else
				n = (int)send(fd, (const void *)pkt, send_len, 0);
#endif
		}
		if (n < 0) {
			int e = LWS_ERRNO;
			if (e == LWS_EAGAIN || e == LWS_EWOULDBLOCK || e == LWS_EINTR
#if defined(EPIPE)
			    || e == EPIPE
#endif
#if defined(EHOSTUNREACH)
			    || e == EHOSTUNREACH
#endif
#if defined(ENETDOWN)
			    || e == ENETDOWN
#endif
#if defined(ENETUNREACH)
			    || e == ENETUNREACH
#endif
#if defined(EADDRNOTAVAIL)
			    || e == EADDRNOTAVAIL
#endif
#if defined(EDESTADDRREQ)
			    || e == EDESTADDRREQ
#endif
#if defined(ENOBUFS)
			    || e == ENOBUFS
#endif
			) {
				lwsl_wsi_info(wsi, "QUIC TX: dropping packet (transient tx error), errno=%d", e);
				n = (int)send_len;
			} else {
				lwsl_wsi_err(wsi, "QUIC TX: Write failed, errno=%d", e);
				return LWS_HP_RET_BAIL_OK;
			}
		}

		qn->bytes_sent += (uint64_t)n;

		/* Find the first frame we sent in this packet to attach wire_len to */
		int ack_eliciting = 0;
		if (qn->in_flight[level].tail) {
			/* Start from the end, which is the most recently added frame */
			lws_start_foreach_dll(struct lws_dll2 *, d, qn->in_flight[level].tail) {
				struct lws_quic_tx_frame *f = lws_container_of(d, struct lws_quic_tx_frame, list);
				if (f->sent_in_pn == my_pn) {
					f->wire_len = send_len;
					ack_eliciting = 1;
					break;
				}
				/* If we find a different PN, we didn't add any frames for this packet */
				if (f->sent_in_pn != my_pn)
					break;
			} lws_end_foreach_dll(d);
		}

		if (ack_eliciting && qn->cc_ops && qn->cc_ops->on_sent)
			qn->cc_ops->on_sent(wsi, send_len);

		lwsl_wsi_info(wsi, "QUIC TX: Sent %d bytes, bundled frames into PN %llu",
				n, (unsigned long long)my_pn);

		/*
		 * If we still have pending frames we couldn't fit, request another POLLOUT
		 */
		if (qn->pending_tx[level].count)
			lws_callback_on_writable(wsi);
	}

	qn->pto_probe_needed = 0;

	/* If we handled all pending crypto/internal frames, give the user a chance to write */
	struct lws *nwsi = lws_get_quic_network_wsi(wsi);
	lwsl_info("QUIC TX POLLOUT: handshake_done=%d, tx_cr=%d, nwsi_tx_cr=%d\n",
		qn->handshake_done, (int)wsi->txc.tx_cr, (nwsi ? (int)nwsi->txc.tx_cr : 0));
	if (qn && qn->handshake_done) {
		if (lws_wsi_txc_check_skint(&wsi->txc, (int32_t)wsi->txc.tx_cr))
			return LWS_HP_RET_DROP_POLLOUT;
		if (nwsi && lws_wsi_txc_check_skint(&nwsi->txc, (int32_t)nwsi->txc.tx_cr))
			return LWS_HP_RET_DROP_POLLOUT;

		struct lws **wsi2 = &wsi->mux.child_list;

        {
                struct lws *curr = wsi->mux.child_list;
                int sanity = 1000;
                lwsl_info("QUIC TX POLLOUT: nwsi=%s, tx_cr=%d\n", lws_wsi_tag(wsi), (int)wsi->txc.tx_cr);
                while (curr && sanity--) {
                        lwsl_info("QUIC TX POLLOUT:   child: %s, requested_POLLOUT=%d, tx_cr=%d\n", 
                                    lws_wsi_tag(curr), curr->mux.requested_POLLOUT, (int)curr->txc.tx_cr);
                        curr = curr->mux.sibling_list;
                }
        }
		if (*wsi2) {
			int sanity = 1000;
			do {
				struct lws *w, **wa;
				
				if (!sanity--) {
					lwsl_wsi_warn(wsi, "POLLOUT multiplexer loop sanity limit reached, closing");
					return LWS_HP_RET_BAIL_DIE;
				}

				wa = &(*wsi2)->mux.sibling_list;
				
				lwsl_info("QUIC TX POLLOUT: visiting child %s, requested_POLLOUT=%d\n", lws_wsi_tag(*wsi2), (*wsi2)->mux.requested_POLLOUT);

				if (!(*wsi2)->mux.requested_POLLOUT)
					goto next_child;

				w = lws_wsi_mux_move_child_to_tail(wsi2);
				if (!w) {
					wa = &wsi->mux.child_list;
					goto next_child;
				}
				
                                  wa = wsi2; /* wsi2 is updated to point to the next element by move_child_to_tail */
				w->mux.requested_POLLOUT = 0;

				int32_t usable_credit = w->txc.tx_cr;
				if (lws_rops_fidx(w->role_ops, LWS_ROPS_tx_credit)) {
					usable_credit = lws_rops_func_fidx(w->role_ops, LWS_ROPS_tx_credit).
								tx_credit(w, LWSTXCR_US_TO_PEER, 0);
				}
				if (lws_wsi_txc_check_skint(&w->txc, usable_credit)) {
					if (!w->quic.tx_blocked_sent) {
						struct lws_quic_tx_frame *f_sdb = lws_zalloc(sizeof(*f_sdb), "quic sdb");
						if (f_sdb) {
							f_sdb->type = LWS_QUIC_FT_STREAM_DATA_BLOCKED;
							f_sdb->stream_id = w->mux.my_sid;
							f_sdb->limit = w->quic.qs ? w->quic.qs->tx_offset : 0;
							lws_dll2_add_head(&f_sdb->list, &qn->pending_tx[LWS_QUIC_LEVEL_APP]);
						}
						w->quic.tx_blocked_sent = 1;
						lws_callback_on_writable(wsi); // request POLLOUT for nwsi to send the frame
					}
					goto next_child;
				}

				lwsl_info("QUIC TX POLLOUT: calling perform_user_POLLOUT/lws_callback_as_writeable for child %s\n", lws_wsi_tag(w));
				if (lws_rops_fidx(w->role_ops, LWS_ROPS_perform_user_POLLOUT)) {
					if (lws_rops_func_fidx(w->role_ops, LWS_ROPS_perform_user_POLLOUT).
									perform_user_POLLOUT(w) == -1) {
						lwsl_wsi_info(w, "QUIC TX: child perform_user_POLLOUT requested close");
						int _found = 0;
						lws_start_foreach_ll(struct lws *, _w1, wsi->mux.child_list) {
							if (_w1 == w) { _found = 1; break; }
						} lws_end_foreach_ll(_w1, mux.sibling_list);
						if (_found)
							lws_close_free_wsi(w, LWS_CLOSE_STATUS_NOSTATUS, "quic child write close");
						wa = &wsi->mux.child_list;
					}
				} else {
					if (lws_callback_as_writeable(w)) {
						lwsl_wsi_info(w, "QUIC TX: child writeable callback requested close");
						int _found = 0;
						lws_start_foreach_ll(struct lws *, _w1, wsi->mux.child_list) {
							if (_w1 == w) { _found = 1; break; }
						} lws_end_foreach_ll(_w1, mux.sibling_list);
						if (_found)
							lws_close_free_wsi(w, LWS_CLOSE_STATUS_NOSTATUS, "quic child write close");
						wa = &wsi->mux.child_list;
					}
				}
next_child:
				wsi2 = wa;
			} while (wsi2 && *wsi2 && wsi->txc.tx_cr > 0 && (!nwsi || nwsi->txc.tx_cr > 0));
		}

		lwsl_info("QUIC TX POLLOUT: calling lws_wsi_mux_action_pending_writeable_reqs\n");
		
		int can_process_children = (qn->handshake_done && wsi->txc.tx_cr > 0 && (!nwsi || nwsi->txc.tx_cr > 0));
		int have_pending_tx = 0;
		for (level = 0; level < LWS_QUIC_LEVEL_COUNT; level++) {
			if (qn->pending_tx[level].count) {
				have_pending_tx = 1;
				break;
			}
		}

		if (blocked || (!have_pending_tx && !can_process_children)) {
			/* We are blocked by QUIC limits, or have nothing to send and children can't write.
			 * Stop asking the OS for POLLOUT. We will re-enable it when POLLIN brings ACKs. */
			if (lws_change_pollfd(wsi, LWS_POLLOUT, 0))
				return LWS_HP_RET_BAIL_DIE;
		} else {
			if (lws_wsi_mux_action_pending_writeable_reqs(wsi))
				return LWS_HP_RET_BAIL_DIE;
		}
	}

	return LWS_HP_RET_DROP_POLLOUT;
}

static int
rops_write_role_protocol_quic(struct lws *wsi, unsigned char *buf, size_t len,
			      enum lws_write_protocol *wp)
{
	struct lws *nwsi = lws_get_quic_network_wsi(wsi);
	struct lws_quic_netconn *qn = nwsi ? nwsi->quic.qn : wsi->quic.qn;
	struct lws_quic_tx_frame *f;

	if (!qn)
		return -1;

	if (len == 0 && !((*wp) & LWS_WRITE_H2_STREAM_END)) {
		return 0;
	}

	/* Enforce stream and connection flow control limits */
	if (len > 0) {
		lwsl_info("QUIC TX WRITE: wsi->txc.tx_cr=%d, nwsi->txc.tx_cr=%d\n", (int)wsi->txc.tx_cr, nwsi ? (int)nwsi->txc.tx_cr : -1);
		if (wsi->txc.tx_cr < (int)len || wsi->txc.tx_cr <= 0 ||
		    (nwsi && (nwsi->txc.tx_cr < (int)len || nwsi->txc.tx_cr <= 0))) {
			int did_enqueue = 0;
			if ((wsi->txc.tx_cr < (int)len || wsi->txc.tx_cr <= 0) && !wsi->quic.tx_blocked_sent) {
				/* Generate STREAM_DATA_BLOCKED */
				struct lws_quic_tx_frame *f_sdb = lws_zalloc(sizeof(*f_sdb), "quic sdb");
				if (f_sdb) {
					f_sdb->type = LWS_QUIC_FT_STREAM_DATA_BLOCKED;
					f_sdb->stream_id = wsi->mux.my_sid;
					f_sdb->limit = wsi->quic.qs ? wsi->quic.qs->tx_offset : 0;
					lws_dll2_add_head(&f_sdb->list, &qn->pending_tx[LWS_QUIC_LEVEL_APP]);
				}
				wsi->quic.tx_blocked_sent = 1;
				did_enqueue = 1;
			}

			if (nwsi && nwsi != wsi && (nwsi->txc.tx_cr < (int)len || nwsi->txc.tx_cr <= 0) && !nwsi->quic.tx_blocked_sent) {
				/* Generate DATA_BLOCKED */
				struct lws_quic_tx_frame *f_db = lws_zalloc(sizeof(*f_db), "quic db");
				if (f_db) {
					f_db->type = LWS_QUIC_FT_DATA_BLOCKED;
					f_db->limit = qn->tx_conn_offset;
					lws_dll2_add_head(&f_db->list, &qn->pending_tx[LWS_QUIC_LEVEL_APP]);
				}
				nwsi->quic.tx_blocked_sent = 1;
				did_enqueue = 1;
			}

			/* Kick output to send these control frames */
			if (did_enqueue)
				lws_callback_on_writable(nwsi ? nwsi : wsi);

			return 0; /* Consumed 0 bytes, caller should yield and try again later */
		}
	}

	lwsl_info("QUIC TX WRITE: Stream %llu. Requested: %d, Stream tx_cr: %d, Conn tx_cr: %d\n", wsi->quic.qs ? (unsigned long long)wsi->quic.qs->stream_id : 0, (int)len, (int)wsi->txc.tx_cr, nwsi ? (int)nwsi->txc.tx_cr : -1);

	/* Allocate frame struct + payload buffer natively */
	f = lws_zalloc(sizeof(*f) + len, "quic tx frame");
	if (!f)
		return -1;

	f->type = LWS_QUIC_FT_STREAM | 0x02 | 0x04; /* STREAM | OFF | LEN */
	if ((*wp) & LWS_WRITE_H2_STREAM_END) {
		f->type |= 0x01; /* FIN */
		/* wsi->quic.qs->sent_fin = 1; could do if we had sent_fin flag */
	}
	f->data = (uint8_t *)&f[1];
	f->len = len;

	/* Copy the user payload */
	memcpy(f->data, buf, len);

	if (((*wp) & 0x1f) == LWS_WRITE_QUIC_DATAGRAM) {
		/* It's a DATAGRAM frame */
		f->type = LWS_QUIC_FT_DATAGRAM + 1; /* with LEN */
		f->stream_id = 0; /* Datagrams aren't attached to a stream ID */
		f->offset = 0;
		lwsl_info("QUIC TX WRITE: Datagram len=%u\n", (unsigned int)f->len);
	} else {
		if (!wsi->quic.qs) {
			lwsl_wsi_err(wsi, "QUIC: Cannot send stream data without a quic stream structure!");
			lws_free(f);
			return -1;
		}
		f->stream_id = wsi->quic.qs->stream_id;
		f->offset = wsi->quic.qs->tx_offset;
		wsi->quic.qs->tx_offset += len;

		lwsl_info("QUIC TX WRITE: stream_id=%llu, offset=%llu, len=%u, fin=%d\n",
			    (unsigned long long)f->stream_id, (unsigned long long)f->offset, (unsigned int)f->len, (f->type & 0x01));

		/* Deduct credit */
		wsi->txc.tx_cr -= (int)len;
		if (nwsi && nwsi != wsi) {
			nwsi->txc.tx_cr -= (int)len;
		}
		if (nwsi) {
			qn->tx_conn_offset += len;
		}
	}

	wsi->quic.tx_blocked_sent = 0;
	if (nwsi && nwsi != wsi)
		nwsi->quic.tx_blocked_sent = 0;

	/* Stream frames usually go in Application level, but check for 0-RTT */
	int tx_level = LWS_QUIC_LEVEL_APP;
	if (!qn->is_server && !qn->handshake_done &&
	    qn->early_data_status == LWS_0RTT_STATUS_ATTEMPTED &&
	    wsi->quic.qs && wsi->quic.qs->opted_into_early_data) {
		tx_level = LWS_QUIC_LEVEL_EARLY;
	}

	lwsl_info("QUIC TX: Enqueued STREAM frame for sid %llu, len %d, FIN=%d (level %d)\n", 
		(unsigned long long)f->stream_id, (int)f->len, (f->type & 0x01), tx_level);
	lws_dll2_add_tail(&f->list, &qn->pending_tx[tx_level]);

	/* Wake up the event loop to send the packet */
	lws_callback_on_writable(wsi);

	return (int)len;
}

#if defined(LWS_WITH_CLIENT)
static int
rops_client_bind_quic(struct lws *wsi, const struct lws_client_connect_info *i)
{
	if (!i) {
		/* finalize */
		if (!wsi->user_space && wsi->stash && wsi->stash->cis[CIS_METHOD])
			if (lws_ensure_user_space(wsi))
				return 0;
		return 0;
	}

	if ((i->method && !strcmp(i->method, "QUIC")) ||
	    (i->alpn && !strcmp(i->alpn, "h3"))) {
		struct lws_quic_cid dcid;

		if (!wsi->udp) {
			wsi->udp = lws_malloc(sizeof(*wsi->udp), "udp struct");
			if (!wsi->udp)
				return 1;
			memset(wsi->udp, 0, sizeof(*wsi->udp));
		}

		/* Allocate QUIC netconn for client! */
		if (!wsi->quic.qn) {
			wsi->quic.qn = lws_zalloc(sizeof(*wsi->quic.qn), "quic_netconn");
			if (!wsi->quic.qn)
				return 1;
		}

		wsi->quic.qn->nwsi = wsi;
		wsi->quic.qn->is_server = 0;
		wsi->quic.qn->version = LWS_QUIC_VERSION_1;
		wsi->quic.qn->max_streams_bidi_local = 1024;
		wsi->quic.qn->max_streams_unidi_local = 1024;

		wsi->quic.qn->current_mtu = 1280;
		wsi->quic.qn->probed_mtu = 1380; /* first probe size */
		wsi->quic.qn->pmtud_state = 1; /* SEARCHING */

		if (wsi->a.context->quic_cc_ops)
			wsi->quic.qn->cc_ops = wsi->a.context->quic_cc_ops;
		else
			wsi->quic.qn->cc_ops = &lws_cc_ops_newreno;

		if (wsi->quic.qn->cc_ops->init)
			wsi->quic.qn->cc_ops->init(wsi);

		/* Initialize Flow Control Credits */
		int32_t init_cr = i->manual_initial_tx_credit;
		if (!init_cr)
			init_cr = 65535;
		wsi->txc.peer_tx_cr_est = init_cr;
		wsi->txc.tx_cr = init_cr;
		
		wsi->quic.qn->rx_max_data = LWS_QUIC_DEFAULT_WINDOW;
		wsi->quic.qn->rx_window_size = LWS_QUIC_DEFAULT_WINDOW;
		wsi->quic.qn->last_rx_update_us = lws_now_usecs();

		/* Generate random CIDs */
		dcid.len = 8;
		lws_get_random(wsi->a.context, dcid.id, 8);
		wsi->quic.qn->rem_cid = dcid;

		wsi->quic.qn->loc_cid.len = 8;
		lws_get_random(wsi->a.context, wsi->quic.qn->loc_cid.id, 8);

		/* Derive Initial Keys */
		if (lws_quic_derive_initial_keys(wsi, &dcid)) {
			lwsl_wsi_err(wsi, "Failed to derive initial keys");
			return 1;
		}

		{
			uint8_t *tp = wsi->quic.qn->local_tp_buf;
			uint8_t *tp_end = tp + sizeof(wsi->quic.qn->local_tp_buf);

#define LWS_QUIC_WRITE_TP_VARINT(_id, _val) \
	do { \
		int _vlen; \
		if (lws_ptr_diff_size_t(tp_end, tp) < 2) goto tp_overflow2; \
		*tp++ = (_id); \
		_vlen = (int)lws_quic_write_varint(tp + 1, lws_ptr_diff_size_t(tp_end, tp + 1), (_val)); \
		if (!_vlen) goto tp_overflow2; \
		*tp++ = (uint8_t)_vlen; \
		tp += _vlen; \
	} while (0)

#define LWS_QUIC_WRITE_TP_BUF(_id, _buf, _len) \
	do { \
		if (lws_ptr_diff_size_t(tp_end, tp) < (size_t)(2 + (_len))) goto tp_overflow2; \
		*tp++ = (_id); \
		*tp++ = (uint8_t)(_len); \
		memcpy(tp, (_buf), (_len)); \
		tp += (_len); \
	} while (0)

			LWS_QUIC_WRITE_TP_VARINT(0x04, 1048576);
			LWS_QUIC_WRITE_TP_VARINT(0x05, 1048576);
			LWS_QUIC_WRITE_TP_VARINT(0x06, 1048576);
			LWS_QUIC_WRITE_TP_VARINT(0x07, 1048576);
			LWS_QUIC_WRITE_TP_VARINT(0x08, 1024);
			LWS_QUIC_WRITE_TP_VARINT(0x09, 1024);
			LWS_QUIC_WRITE_TP_VARINT(0x20, 65535);
			LWS_QUIC_WRITE_TP_VARINT(0x01, 30000);

			LWS_QUIC_WRITE_TP_BUF(0x0F, wsi->quic.qn->loc_cid.id, wsi->quic.qn->loc_cid.len);

			lws_tls_quic_set_transport_parameters(wsi, wsi->quic.qn->local_tp_buf, (size_t)(tp - wsi->quic.qn->local_tp_buf));
			
			goto tp_ok2;
tp_overflow2:
			lwsl_wsi_err(wsi, "QUIC TX: tp buffer overflow");
			return 1;
tp_ok2:
			;
#undef LWS_QUIC_WRITE_TP_VARINT
#undef LWS_QUIC_WRITE_TP_BUF
		}

		lws_role_transition(wsi, LWSIFR_CLIENT, LRS_UNCONNECTED, &role_ops_quic);
		lws_callback_on_writable(wsi);
		return 1;
	}
	return 0;
}
#endif

static int
rops_adoption_bind_quic(struct lws *wsi, int type, const char *vh_prot_name)
{
	if (!(type & LWS_ADOPT_FLAG_UDP))
		return 0;

	if ((wsi->a.vhost && wsi->a.vhost->listen_accept_role &&
	     !strcmp(wsi->a.vhost->listen_accept_role, "quic")) ||
	    (vh_prot_name && !strcmp(vh_prot_name, "quic")) ||
	    (wsi->role_ops == &role_ops_quic)) {
#if defined(LWS_WITH_UDP)
		if (!wsi->udp) {
			wsi->udp = lws_malloc(sizeof(*wsi->udp), "udp struct");
			if (!wsi->udp)
				return 0;
			memset(wsi->udp, 0, sizeof(*wsi->udp));
		}
#endif

		/* Initialize Flow Control Credits */
		int32_t init_cr = wsi->txc.manual_initial_tx_credit;
		if (!init_cr)
			init_cr = 65535;
		wsi->txc.peer_tx_cr_est = init_cr;
		wsi->txc.tx_cr = init_cr;

		lws_role_transition(wsi, LWSIFR_SERVER, LRS_ESTABLISHED, &role_ops_quic);
		lws_bind_protocol(wsi, wsi->a.protocol, __func__);

		if ((type & _LWS_ADOPT_FINISH) && wsi->do_bind) {
			wsi->listener = 1;
#if defined(LWS_WITH_SERVER)
			if (!wsi->listen_list.owner)
				lws_dll2_add_tail(&wsi->listen_list, &wsi->a.vhost->listen_wsi);
#endif
		}

		return 1;
	}
	return 0;
}

static int
rops_callback_on_writable_quic(struct lws *wsi)
{
	struct lws *nwsi = lws_get_quic_network_wsi(wsi);

	if (wsi->mux.requested_POLLOUT) {
		lwsl_info("rops_callback_on_writable_quic: %s already pending writable\n", lws_wsi_tag(wsi));
	} else {
		lwsl_info("rops_callback_on_writable_quic: marking %s as pending writable (nwsi=%s)\n", lws_wsi_tag(wsi), lws_wsi_tag(nwsi));
	}

	lws_wsi_mux_mark_parents_needing_writeable(wsi);

	/* for network action, act only on the network wsi */
	if (nwsi && nwsi != wsi)
		return lws_callback_on_writable(nwsi);

	/* If we are the network wsi but we have a listener parent (shared UDP port), propagate to it */
	if (wsi->mux.parent_wsi)
		return lws_callback_on_writable(wsi->mux.parent_wsi);

	return 0; /* not handled, let core handle it */
}

void
lws_quic_stream_cleanup(struct lws *wsi)
{
	struct lws *nwsi = lws_get_network_wsi(wsi);
	struct lws_quic_netconn *qn = nwsi ? nwsi->quic.qn : NULL;
	int i;

	if (!wsi->quic.qs)
		return;

	lwsl_info("%s: stream_id %llu\n", __func__, (unsigned long long)wsi->quic.qs->stream_id);

	/* 1. Free RX chunks */
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, wsi->quic.qs->rx_chunks.head) {
		struct lws_quic_rx_chunk *c = lws_container_of(d, struct lws_quic_rx_chunk, list);
		lws_dll2_remove(&c->list);
		lws_free(c);
	} lws_end_foreach_dll_safe(d, d1);

	/* 2. Purge pending and in-flight TX frames for this stream from parent network connection */
	if (qn) {
		uint64_t sid = wsi->quic.qs->stream_id;

		/* If we're closing the stream before FINs were exchanged, notify the peer */
		if (!wsi->quic.qs->fin_received || !wsi->quic.qs->fin_delivered) {
			/* Send RESET_STREAM to notify the peer that we're abandoning the stream */
			struct lws_quic_tx_frame *f_reset = lws_zalloc(sizeof(*f_reset), "quic reset");
			if (f_reset) {
				f_reset->type = LWS_QUIC_FT_RESET_STREAM;
				f_reset->stream_id = sid;
				f_reset->offset = 0; /* app error code */
				f_reset->limit = wsi->quic.qs->tx_offset; /* final size */
				lws_dll2_add_head(&f_reset->list, &qn->pending_tx[LWS_QUIC_LEVEL_APP]);
			}
			
			/* Send STOP_SENDING to tell peer to stop sending data to us */
			struct lws_quic_tx_frame *f_stop = lws_zalloc(sizeof(*f_stop), "quic stop_sending");
			if (f_stop) {
				f_stop->type = LWS_QUIC_FT_STOP_SENDING;
				f_stop->stream_id = sid;
				f_stop->offset = 0; /* app error code */
				lws_dll2_add_head(&f_stop->list, &qn->pending_tx[LWS_QUIC_LEVEL_APP]);
			}
			
			if (nwsi) lws_callback_on_writable(nwsi);
		}

		for (i = 0; i < LWS_QUIC_LEVEL_COUNT; i++) {
			/* Purge pending_tx */
			lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, qn->pending_tx[i].head) {
				struct lws_quic_tx_frame *f = lws_container_of(d, struct lws_quic_tx_frame, list);
				if (f->stream_id == sid && f->type != LWS_QUIC_FT_RESET_STREAM && f->type != LWS_QUIC_FT_STOP_SENDING) {
					lws_dll2_remove(&f->list);
					lws_free(f);
				}
			} lws_end_foreach_dll_safe(d, d1);

			/* Purge in_flight */
			lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, qn->in_flight[i].head) {
				struct lws_quic_tx_frame *f = lws_container_of(d, struct lws_quic_tx_frame, list);
				if (f->stream_id == sid) {
					lws_dll2_remove(&f->list);
					lws_free(f);
				}
			} lws_end_foreach_dll_safe(d, d1);
		}
	}

	lws_free_set_NULL(wsi->quic.qs);
}

static int
rops_close_kill_connection_quic(struct lws *wsi, enum lws_close_status reason)
{
	struct lws_quic_netconn *qn = wsi->quic.qn;
	int i;

	lwsl_info("QUIC close_kill_connection called on wsi %p, qn %p (qn->nwsi %p)\n", wsi, qn, qn ? qn->nwsi : NULL);

	if (wsi->mux.child_list)
		lws_wsi_mux_close_children(wsi, (int)reason);

	if (wsi->mux.parent_wsi) {
		struct lws *nwsi = wsi->mux.parent_wsi;
		lws_wsi_mux_sibling_disconnect(wsi);
		if (nwsi->mux.child_count == 0)
			lws_set_timeout(nwsi, PENDING_TIMEOUT_HTTP_KEEPALIVE_IDLE,
					nwsi->a.vhost->keepalive_timeout ?
					nwsi->a.vhost->keepalive_timeout : 5);
	}

	lws_quic_stream_cleanup(wsi);

	if (!qn) {
#if defined(LWS_WITH_UDP)
		if (wsi->udp)
			lws_free_set_NULL(wsi->udp);
#endif
		return 0;
	}

	/* If we are the network wsi, free the qn and all resources */
	if (qn->nwsi == wsi) {
		lws_sul_cancel(&qn->pto_sul);
		lws_sul_cancel(&qn->pacer_sul);

#if defined(LWS_ROLE_H3)
		if (wsi->h3.h3n)
			lws_free_set_NULL(wsi->h3.h3n);
#endif

		for (i = 0; i < LWS_QUIC_LEVEL_COUNT; i++) {
			/* Free keys */
			if (qn->keys[i]) {
				lws_quic_keys_destroy(qn->keys[i]);
				qn->keys[i] = NULL;
			}

			int pend_count = 0, flt_count = 0;

			/* Free pending tx */
			lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, qn->pending_tx[i].head) {
				struct lws_quic_tx_frame *f = lws_container_of(d, struct lws_quic_tx_frame, list);
				lws_dll2_remove(&f->list);
				lws_free(f);
				pend_count++;
			} lws_end_foreach_dll_safe(d, d1);

			/* Free in flight */
			lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, qn->in_flight[i].head) {
				struct lws_quic_tx_frame *f = lws_container_of(d, struct lws_quic_tx_frame, list);
				lws_dll2_remove(&f->list);
				lws_free(f);
				flt_count++;
			} lws_end_foreach_dll_safe(d, d1);

			/* Free RX Crypto chunks */
			lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, qn->rx_crypto_chunks[i].head) {
				struct lws_quic_rx_chunk *c = lws_container_of(d, struct lws_quic_rx_chunk, list);
				lws_dll2_remove(&c->list);
				lws_free(c);
			} lws_end_foreach_dll_safe(d, d1);

			if (pend_count || flt_count)
				lwsl_debug("QUIC freed frames on level %d: pending %d, in_flight %d\n", i, pend_count, flt_count);
		}



		if (qn->cc_state)
			lws_free_set_NULL(qn->cc_state);

		lws_free_set_NULL(wsi->quic.qn);
	}

#if defined(LWS_WITH_UDP)
	if (wsi->udp)
		lws_free_set_NULL(wsi->udp);
#endif

	return 0;
}

int
rops_tx_credit_quic(struct lws *wsi, char peer_to_us, int add)
{
	struct lws *nwsi = lws_get_quic_network_wsi(wsi);
	struct lws_quic_netconn *qn = nwsi ? nwsi->quic.qn : NULL;
	int n;

	if (!qn) {
		lwsl_notice("rops_tx_credit_quic: qn is NULL! wsi=%s, p1=%s, p2=%s\n", 
			lws_wsi_tag(wsi), 
			wsi->mux.parent_wsi ? lws_wsi_tag(wsi->mux.parent_wsi) : "null",
			wsi->mux.parent_wsi && wsi->mux.parent_wsi->mux.parent_wsi ? lws_wsi_tag(wsi->mux.parent_wsi->mux.parent_wsi) : "null");
		return 0;
	}

	if (add) {
		if (peer_to_us == LWSTXCR_PEER_TO_US) {
			/* We want to tell the peer they can write an additional "add" bytes to us */
			wsi->txc.peer_tx_cr_est += add;
			if (nwsi)
				nwsi->txc.peer_tx_cr_est += add;

			lws_usec_t now = lws_now_usecs();

			if (wsi->quic.qs) {
				wsi->quic.qs->rx_max_data += (uint64_t)(add > 0 ? add : 0);
				uint64_t ungranted = wsi->quic.qs->rx_max_data - wsi->quic.qs->highest_rx_offset;
				
				if (nwsi && nwsi->a.context->quic_tx_credit_cb) {
					uint64_t new_win = nwsi->a.context->quic_tx_credit_cb(
						wsi, wsi->quic.qs->rx_window_size, (uint64_t)(add > 0 ? add : 0), 
						(uint64_t)(now - wsi->quic.qs->last_rx_update_us));
					if (new_win > wsi->quic.qs->rx_window_size && new_win <= LWS_QUIC_MAX_WINDOW) {
						wsi->quic.qs->rx_max_data += (new_win - wsi->quic.qs->rx_window_size);
						wsi->quic.qs->rx_window_size = new_win;
						ungranted = wsi->quic.qs->rx_max_data - wsi->quic.qs->highest_rx_offset;
					}
				}

				if (ungranted < wsi->quic.qs->rx_window_size / 2) {
					wsi->quic.qs->last_rx_update_us = now;
					struct lws_quic_tx_frame *f_msd = lws_zalloc(sizeof(*f_msd), "quic msd");
					if (f_msd) {
						f_msd->type = LWS_QUIC_FT_MAX_STREAM_DATA;
						f_msd->stream_id = wsi->mux.my_sid;
						f_msd->limit = wsi->quic.qs->rx_max_data;
						lws_dll2_add_head(&f_msd->list, &qn->pending_tx[LWS_QUIC_LEVEL_APP]);
					}
				}
			}

			if (nwsi) {
				qn->rx_max_data += (uint64_t)(add > 0 ? add : 0);
				uint64_t ungranted = qn->rx_max_data - qn->highest_rx_offset;

				if (nwsi->a.context->quic_tx_credit_cb) {
					uint64_t new_win = nwsi->a.context->quic_tx_credit_cb(
						nwsi, qn->rx_window_size, (uint64_t)(add > 0 ? add : 0), 
						(uint64_t)(now - qn->last_rx_update_us));
					if (new_win > qn->rx_window_size && new_win <= LWS_QUIC_MAX_WINDOW) {
						qn->rx_max_data += (new_win - qn->rx_window_size);
						qn->rx_window_size = new_win;
						ungranted = qn->rx_max_data - qn->highest_rx_offset;
					}
				}

				if (ungranted < qn->rx_window_size / 2) {
					qn->last_rx_update_us = now;
					struct lws_quic_tx_frame *f_md = lws_zalloc(sizeof(*f_md), "quic md");
					if (f_md) {
						f_md->type = LWS_QUIC_FT_MAX_DATA;
						f_md->limit = qn->rx_max_data;
						lws_dll2_add_head(&f_md->list, &qn->pending_tx[LWS_QUIC_LEVEL_APP]);
					}
					lws_callback_on_writable(nwsi);
				}
			}

			lws_callback_on_writable(nwsi ? nwsi : wsi);
			return 0;
		}

		/* We're being told we can write an additional "add" bytes to the peer */
		wsi->txc.tx_cr += add;
		wsi->quic.tx_blocked_sent = 0;
		if (nwsi && nwsi != wsi) {
			nwsi->txc.tx_cr += add;
			nwsi->quic.tx_blocked_sent = 0;
		}

		/* Unblock if blocked */
		if (wsi->txc.tx_cr > 0) {
			struct lws *w = wsi->mux.child_list;

			lws_callback_on_writable(wsi);

			while (w) {
				lws_callback_on_writable(w);
				w = w->mux.sibling_list;
			}
		}
		return 0;
	}

	if (peer_to_us == LWSTXCR_US_TO_PEER) {
		int cr = wsi->txc.tx_cr;
		if (nwsi && nwsi->txc.tx_cr < cr)
			cr = nwsi->txc.tx_cr;

		/*
		 * Accounts for H3 framing overhead (DATA/HEADERS frame type + length: max 9 bytes).
		 * If we don't subtract this, the caller reads `cr` bytes of payload, and then
		 * H3 frames it (adding overhead), resulting in a write request of `cr + overhead` bytes,
		 * which exceeds the flow control window and blocks, causing issues on non-seekable streams.
		 */
		if (cr > 9)
			cr -= 9;
		else
			cr = 0;

		if (cr < 0)
			cr = 0;
		lwsl_info("rops_tx_credit_quic: LWSTXCR_US_TO_PEER returning %d (wsi->txc.tx_cr=%d, nwsi->txc.tx_cr=%d)\n",
			  cr, (int)wsi->txc.tx_cr, nwsi ? (int)nwsi->txc.tx_cr : -1);
		return cr; /* how much we can write to peer */
	}

	n = wsi->txc.peer_tx_cr_est; /* how much peer can write to us */
	if (nwsi && n > nwsi->txc.peer_tx_cr_est)
		n = nwsi->txc.peer_tx_cr_est;

	lwsl_info("rops_tx_credit_quic: returning %d\n", n);
	return n;
}

static int
rops_alpn_negotiated_quic(struct lws *wsi, const char *alpn)
{
	struct lws *nwsi;
	const struct lws_role_ops *role;

#if defined(LWS_WITH_CLIENT)
	if (lwsi_role_client(wsi))
		lws_sul_cancel(&wsi->sul_h3_grace);
#endif

	if (strcmp(alpn, "h3") && strcmp(alpn, "lws-quic"))
		return 0;

	lwsl_info("ENTER rops_alpn_negotiated_quic: wsi=%p\n", wsi);

	lwsl_wsi_info(wsi, "QUIC negotiated %s, migrating network connection to new wsi", alpn);

	role = lws_role_by_name(alpn);
	if (!role) {
		role = &role_ops_quic;
	}

	/* If it's already migrated or it's a stream, don't migrate again! */
	if (!wsi->quic.qn || wsi->quic.qn->alpn_migrated)
		return 0;

	/* Create the new network WSI */
	nwsi = lws_create_new_server_wsi(wsi->a.vhost, wsi->tsi, 0, "quic_nwsi");
	if (!nwsi)
		return 1;

	/* Transfer the socket fd and fds table entry if valid */
	nwsi->desc = wsi->desc;
	if (lws_socket_is_valid(wsi->desc.sockfd)) {
		struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];

		lws_pt_lock(pt, __func__);
		if (__remove_wsi_socket_from_fds(wsi)) {
			lws_pt_unlock(pt);
			lws_close_free_wsi(nwsi, LWS_CLOSE_STATUS_NOSTATUS, "fd table fail");
			return 1;
		}
		wsi->desc.sockfd = LWS_SOCK_INVALID;
		if (__insert_wsi_socket_into_fds(wsi->a.context, nwsi)) {
			lws_pt_unlock(pt);
			lws_close_free_wsi(nwsi, LWS_CLOSE_STATUS_NOSTATUS, "fd table fail");
			return 1;
		}
		lws_pt_unlock(pt);
	}

	/* Transfer the udp and quic contexts */
#if defined(LWS_WITH_UDP)
	nwsi->udp = wsi->udp;
	wsi->udp = NULL;
#endif
	nwsi->quic = wsi->quic;
	nwsi->txc = wsi->txc;
	nwsi->tls = wsi->tls;
	nwsi->sa46_peer = wsi->sa46_peer;
	memset(&wsi->quic, 0, sizeof(wsi->quic));
	memset(&wsi->tls, 0, sizeof(wsi->tls));
	lws_tls_quic_migrate_wsi(wsi, nwsi);
	wsi->quic.qs = lws_zalloc(sizeof(*wsi->quic.qs), "quic stream");
	if (wsi->quic.qs) {
		wsi->quic.qs->rx_max_data = LWS_QUIC_DEFAULT_WINDOW;
		wsi->quic.qs->rx_window_size = LWS_QUIC_DEFAULT_WINDOW;
		wsi->quic.qs->last_rx_update_us = lws_now_usecs();
	} else {
		lws_close_free_wsi(nwsi, LWS_CLOSE_STATUS_NOSTATUS, "quic stream oom");
		return 1;
	}

	/* Initialize flow control credits for the new child stream */
	int32_t init_cr = nwsi->txc.manual_initial_tx_credit;
	if (!init_cr) {
		if (nwsi->quic.qn && nwsi->quic.qn->peer_initial_max_stream_data_bidi_remote)
			init_cr = (int32_t)nwsi->quic.qn->peer_initial_max_stream_data_bidi_remote;
		else
			init_cr = 65535;
	}
	wsi->txc.peer_tx_cr_est = init_cr;
	wsi->txc.tx_cr = init_cr;

	lwsl_info("rops_alpn_negotiated_quic: old_wsi=%p\n", wsi);
	lwsl_info("rops_alpn_negotiated_quic: new_nwsi=%p\n", nwsi);
	lwsl_info("rops_alpn_negotiated_quic: qn=%p\n", nwsi->quic.qn);

	/* Important: the network WSI must point back to itself */
	if (nwsi->quic.qn)
		nwsi->quic.qn->nwsi = nwsi;

	/* Setup role and state for nwsi */
	lws_role_transition(nwsi, lwsi_role_client(wsi) ? LWSIFR_CLIENT : LWSIFR_SERVER, LRS_ESTABLISHED, &role_ops_quic);
	if (!strcmp(alpn, "h3")) {
		nwsi->upgraded_to_http2 = 1;
	}

	/* Transition wsi to HTTP/3 and link as a child of nwsi */
	lws_role_transition(wsi, lwsi_role_client(wsi) ? LWSIFR_CLIENT : LWSIFR_SERVER, (!strcmp(alpn, "h3") && lwsi_role_client(wsi)) ? LRS_H2_WAITING_TO_SEND_HEADERS : LRS_ESTABLISHED, role);
#if defined(LWS_ROLE_H3)
	if (!strcmp(alpn, "h3")) {
		memset(&wsi->h3, 0, sizeof(wsi->h3));
	}
#endif
#if defined(LWS_WITH_CLIENT)
	if (!strcmp(alpn, "h3") && lwsi_role_client(wsi)) {
		wsi->client_h2_alpn = 1;
		wsi->client_mux_migrated = 1;
		wsi->hdr_parsing_completed = 0;
	}
#endif

	wsi->mux_substream = 1;
#if defined(LWS_WITH_CLIENT)
        if (lwsi_role_client(wsi))
                wsi->client_mux_substream = 1;
        else
                wsi->client_mux_substream = 0;
#endif
	nwsi->quic.qn->alpn_migrated = 1;

#if defined(LWS_WITH_CLIENT)
	/* 
	 * QUIC succeeded! Resolve the race by killing parallel TCP connections. 
	 */
	if (lwsi_role_client(wsi)) {
		
		for (int i = 0; i < wsi->parallel_count; i++) {
			if (wsi->parallel_conns[i].is_valid) {
				lws_remove_parallel_fd_safely(wsi, i);
			}
		}
		wsi->parallel_count = 0;

		if (wsi->a.context->h3_cap_cache && wsi->stash && wsi->stash->cis[CIS_HOST]) {
			lws_h3_cap_info_t cap;
			cap.state = LWS_H3_STATE_KNOWN_GOOD;
			cap.latency_us = (uint32_t)(lws_now_usecs() - wsi->quic.quic_race_start_us);

			lws_cache_write_through(wsi->a.context->h3_cap_cache, wsi->stash->cis[CIS_HOST],
						(const uint8_t *)&cap, sizeof(cap),
						lws_now_usecs() + (3600ll * LWS_US_PER_SEC), NULL);
		}
	}
#endif

	/* 
	 * The quic child stream is migrating to be a child of nwsi. 
	 * So we disconnect it from the listener socket first. 
	 */
	/* 
	 * Important: The new network connection nwsi must be in the listener's 
	 * child list so it can receive incoming UDP packets! 
	 * We must get the listener socket BEFORE we disconnect the wsi.
	 */
	struct lws *listener = wsi->mux.parent_wsi;

	if (wsi->mux.parent_wsi)
                lws_wsi_mux_sibling_disconnect(wsi);

        lws_wsi_mux_insert(wsi, nwsi, 0); /* client first request is stream ID 0 */
        lws_set_timeout(nwsi, NO_PENDING_TIMEOUT, 0);

	if (listener) {
		nwsi->mux_substream = 1;
		nwsi->mux.parent_wsi = listener;
		nwsi->mux.sibling_list = listener->mux.child_list;
		listener->mux.child_list = nwsi;
		listener->mux.child_count++;
	}

	/* Inform the H3 role that it negotiated ALPN */
	lws_role_call_alpn_negotiated(wsi, alpn);

	/* We are ready to send headers! */
	lws_callback_on_writable(wsi);

	return 0;
}

static const lws_rops_t rops_table_quic[] = {
	/*  1 */ { .handle_POLLIN	  = rops_handle_POLLIN_quic },
	/*  2 */ { .handle_POLLOUT	  = rops_handle_POLLOUT_quic },
	/*  3 */ { .callback_on_writable  = rops_callback_on_writable_quic },
	/*  4 */ { .tx_credit		  = rops_tx_credit_quic },
	/*  5 */ { .write_role_protocol	  = rops_write_role_protocol_quic },
	/*  6 */ { .alpn_negotiated	  = rops_alpn_negotiated_quic },
	/*  7 */ { .close_kill_connection = rops_close_kill_connection_quic },
	/*  8 */ { .adoption_bind	  = rops_adoption_bind_quic },
#if defined(LWS_WITH_CLIENT)
	/*  9 */ { .client_bind		  = rops_client_bind_quic },
#endif
};

const struct lws_role_ops role_ops_quic = {
	/* role name */			"quic",
	/* alpn id */			"h3",

	/* rops_table */		rops_table_quic,
	/* rops_idx */			{
	  /* LWS_ROPS_check_upgrades */
	  /* LWS_ROPS_pt_init_destroy */		0x00,
	  /* LWS_ROPS_init_vhost */
	  /* LWS_ROPS_destroy_vhost */			0x00,
	  /* LWS_ROPS_service_flag_pending */
	  /* LWS_ROPS_handle_POLLIN */			0x01,
	  /* LWS_ROPS_handle_POLLOUT */
	  /* LWS_ROPS_perform_user_POLLOUT */		0x20,
	  /* LWS_ROPS_callback_on_writable */
	  /* LWS_ROPS_tx_credit */			0x34,
	  /* LWS_ROPS_write_role_protocol */
	  /* LWS_ROPS_encapsulation_parent */		0x50,
	  /* LWS_ROPS_alpn_negotiated */
	  /* LWS_ROPS_close_via_role_protocol */	0x60,
	  /* LWS_ROPS_close_role */
	  /* LWS_ROPS_close_kill_connection */		0x07,
	  /* LWS_ROPS_destroy_role */
	  /* LWS_ROPS_adoption_bind */			0x08,
#if defined(LWS_WITH_CLIENT)
	  /* LWS_ROPS_client_bind */                    0x90,
	  /* LWS_ROPS_issue_keepalive */
#else
	  /* LWS_ROPS_client_bind */                    0x00,
	  /* LWS_ROPS_issue_keepalive */
#endif
					},

	/* adoption_cb clnt, srv */	{ LWS_CALLBACK_CLIENT_ESTABLISHED,
					  LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED },
	/* rx_cb clnt, srv */		{ LWS_CALLBACK_QT_CLIENT_RECEIVE,
					  LWS_CALLBACK_QT_SERVER_RECEIVE },
	/* writeable cb clnt, srv */	{ LWS_CALLBACK_CLIENT_WRITEABLE,
					  LWS_CALLBACK_SERVER_WRITEABLE },
	/* close cb clnt, srv */	{ LWS_CALLBACK_CLOSED_CLIENT_HTTP,
					  LWS_CALLBACK_CLOSED },
	/* protocol_bind_cb c,s */	{ LWS_CALLBACK_CLIENT_HTTP_BIND_PROTOCOL,
					  LWS_CALLBACK_HTTP_BIND_PROTOCOL },
	/* protocol_unbind_cb c,s */	{ LWS_CALLBACK_CLIENT_HTTP_DROP_PROTOCOL,
					  LWS_CALLBACK_HTTP_DROP_PROTOCOL },
	/* file_handle */		0,
};
