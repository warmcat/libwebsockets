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
		qn->pto_probe_needed = 1;
		lwsl_notice("QUIC PTO Timer Fired! Forcing POLLOUT for retransmission sweep\n");
		lws_callback_on_writable(qn->nwsi);

		/* Always ensure the timer is running as long as there is data in flight! */
		for (int i = 0; i < LWS_QUIC_LEVEL_COUNT; i++) {
			if (qn->in_flight[i].count) {
				lws_sul_schedule(qn->nwsi->a.context, 0, &qn->pto_sul, lws_quic_pto_cb, LWS_QUIC_DEFAULT_PTO_US);
				break;
			}
		}
	}
}

void
lws_quic_handle_ack(struct lws *nwsi, int level, uint64_t acked_pn)
{
	struct lws_quic_netconn *qn = nwsi->quic.qn;
	if (!qn) return;

	size_t bytes_acked = 0;
	lws_usec_t rtt = 0;
	lws_usec_t now = lws_now_usecs();

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, qn->in_flight[level].head) {
		struct lws_quic_tx_frame *f = lws_container_of(d, struct lws_quic_tx_frame, list);

		if (f->sent_in_pn == acked_pn) {
			bytes_acked += f->wire_len;
			rtt = now > f->sent_time_us ? now - f->sent_time_us : 0;
			/* Packet was received successfully, free the frame! */
			lws_dll2_remove(&f->list);
			lws_free(f);
		}
	} lws_end_foreach_dll_safe(d, d1);

	if (bytes_acked && qn->cc_ops && qn->cc_ops->on_ack)
		qn->cc_ops->on_ack(nwsi, bytes_acked, rtt);

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
		lwsl_wsi_notice(wsi, "QUIC RX: recv returned %d (errno %d)", n, errno);
		return LWS_HPI_RET_HANDLED;
	}

	lwsl_wsi_debug(wsi, "QUIC RX: read %d bytes from UDP", n);

	if (n < 2)
		return LWS_HPI_RET_HANDLED;

	p = pt->serv_buf;

	/* DEBUG: Print first 16 bytes */
	lwsl_wsi_debug(wsi, "QUIC RX: First 16 bytes: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
			p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);

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
				break;
			}
			/* Also match against the original DCID if the client hasn't switched to our loc_cid yet */
			if (w->quic.qn && w->quic.qn->orig_dcid.len == dcid_len &&
			    !memcmp(w->quic.qn->orig_dcid.id, dcid.id, dcid_len)) {
				nwsi = w;
				break;
			}
			w = w->mux.sibling_list;
		}
	}


	if (!nwsi) {
		if (!(p[0] & 0x80) || ((p[0] & 0x30) >> 4) != 0) {
			lwsl_wsi_notice(wsi, "QUIC RX: Unknown DCID and not Initial, dropping");
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
		nwsi->quic.qn->version = 1;

		nwsi->quic.qn->cc_ops = &lws_cc_ops_newreno;
		if (nwsi->quic.qn->cc_ops->init)
			nwsi->quic.qn->cc_ops->init(nwsi);

		/* Initialize Flow Control Credits so we can actually send STREAM data */
		nwsi->txc.peer_tx_cr_est = 65535;
		nwsi->txc.tx_cr = 65535;

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

		lwsl_wsi_notice(wsi, "QUIC RX: Created new connection! (loc_cid len %d)", nwsi->quic.qn->loc_cid.len);
	}

	if (nwsi && nwsi->udp)
		nwsi->udp->sa46 = sa46;

	if (nwsi && nwsi->quic.qn) {
		nwsi->quic.qn->bytes_received += (uint64_t)n;
	}

	/* We have the connection! Grab the appropriate keys based on packet type */
	int level = LWS_QUIC_LEVEL_APP;
	if (p[0] & 0x80) {
		uint8_t type = (p[0] & 0x30) >> 4;
		if (type == 0) level = LWS_QUIC_LEVEL_INITIAL;
		else if (type == 2) level = LWS_QUIC_LEVEL_HANDSHAKE;
		else {
			lwsl_wsi_notice(wsi, "QUIC RX: Unsupported long header type %d", type);
			return LWS_HPI_RET_HANDLED;
		}
	}

	/* Enforce 1200-byte padding for subsequent client-to-server Initial packets (RFC 9000 Section 14.1) */
	if (level == LWS_QUIC_LEVEL_INITIAL && nwsi && nwsi->quic.qn && nwsi->quic.qn->is_server && n < 1200) {
		lwsl_wsi_notice(wsi, "QUIC RX: Dropping under-padded Initial packet (len %d)", n);
		return LWS_HPI_RET_HANDLED;
	}

	struct lws_quic_keys *k = nwsi->quic.qn->keys[level];

	if (!k || !k->valid) {
		lwsl_wsi_notice(wsi, "QUIC RX: No valid keys for this packet level %d", level);
		return LWS_HPI_RET_HANDLED;
	}

	/* 2. Parsing: Safely find the Packet Number offset */
	size_t payload_len_stated;
	size_t pn_offset = lws_quic_get_pn_offset(p, (size_t)n, &payload_len_stated);
	if (!pn_offset) {
		lwsl_wsi_notice(wsi, "QUIC RX: Malformed or truncated packet");
		return LWS_HPI_RET_HANDLED;
	}

	/* 3. Unmasking: Reveal the true Packet Number */
	int pn_len = lws_quic_unmask_header(k, p, (size_t)n, pn_offset);
	if (pn_len < 0) {
		lwsl_wsi_notice(wsi, "QUIC RX: Header unmask failed");
		return LWS_HPI_RET_HANDLED;
	}

	/*
	 * Reconstruct full 62-bit PN.
	 * (Note: We just read it raw here for the very first packets; proper
	 * decoding uses the RFC 9000 algorithm based on pn_rx_largest).
	 */
	uint64_t full_pn = 0;
	for (int i = 0; i < pn_len; i++)
		full_pn = (full_pn << 8) | p[pn_offset + (size_t)i];

	/* 4. Decryption: Authenticate and decrypt the payload in-place! */
	int dec_len = lws_quic_decrypt_payload(k, p, (size_t)n, pn_offset, (uint8_t)pn_len, full_pn);
	if (dec_len < 0) {
		lwsl_wsi_notice(wsi, "QUIC RX: AEAD Decryption failed (bad tag or truncated)");
		return LWS_HPI_RET_HANDLED;
	}

	if (nwsi->quic.qn && (level == LWS_QUIC_LEVEL_HANDSHAKE || level == LWS_QUIC_LEVEL_APP)) {
		nwsi->quic.qn->address_validated = 1;
	}

	lwsl_wsi_info(wsi, "QUIC RX: SUCCESS! Decrypted %d bytes of payload", dec_len);

	/* Check for duplicate/replayed packet numbers (Security Fix) */
	if (nwsi->quic.qn) {
		uint64_t highest = nwsi->quic.qn->highest_rx_pn[level];
		if ((nwsi->quic.qn->rx_pn_bitmask[level] != 0 || highest != 0) && full_pn <= highest) {
			uint64_t diff = highest - full_pn;
			if (diff >= 64 || (nwsi->quic.qn->rx_pn_bitmask[level] & (1ULL << diff))) {
				lwsl_wsi_notice(wsi, "QUIC RX: Dropping duplicated or very old packet %llu", (unsigned long long)full_pn);
				return LWS_HPI_RET_HANDLED;
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

		nwsi->quic.qn->needs_ack[level] = 1;
		lws_callback_on_writable(nwsi); /* Ensure POLLOUT fires so we send the ACK! */
	}

	/* 5. Parse the plaintext frames */
	if (lws_quic_parse_frames(nwsi, level, &p[pn_offset + (size_t)pn_len], (size_t)dec_len) < 0) {
		lwsl_wsi_notice(wsi, "QUIC RX: Frame parsing aborted");
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

	lwsl_info("QUIC TLS TX: %s generated %d bytes of crypto data for level %d\n", lws_wsi_tag(wsi), (int)len, level);
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
	lwsl_info("QUIC TLS: Extracted secret type %d (len %d)", type, (int)secret_len);
	if (lws_quic_set_keys(wsi, type, secret, secret_len)) {
		lwsl_wsi_err(wsi, "Failed to set QUIC keys for type %d", type);
		return -1;
	}
	return 0;
}

static lws_handling_result_t
rops_handle_POLLOUT_quic(struct lws *wsi)
{
	struct lws_quic_netconn *qn = wsi->quic.qn;
	int level, n;
	uint8_t pkt[1280]; /* Max QUIC UDP payload for now */

	// lwsl_notice("QUIC TX: POLLOUT called for %s, qn=%p, is_server=%d\n", lws_wsi_tag(wsi), qn, qn ? qn->is_server : -1);

	if (!qn) {
		struct lws *w;
		if (wsi->mux.child_list) {
			w = wsi->mux.child_list;
			while (w) {
				if (w->mux.requested_POLLOUT) {
					w->mux.requested_POLLOUT = 0;
					rops_handle_POLLOUT_quic(w);
				}
				w = w->mux.sibling_list;
			}
		}
		return LWS_HP_RET_DROP_POLLOUT;
	}

	if (!wsi->quic.initialized && !qn->is_server) {
		wsi->quic.initialized = 1;

#if defined(LWS_WITH_TLS)
		if (wsi->tls.use_ssl & LCCSCF_USE_SSL) {
			/* The BIO was already created in connect.c, just init QUIC TLS */
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

	/*
	 * PTO Sweep: Check for dropped/unacknowledged packets
	 */
	lws_usec_t now = lws_now_usecs();
	size_t total_bytes_lost = 0;
	for (level = 0; level < LWS_QUIC_LEVEL_COUNT; level++) {
		if (!qn->in_flight[level].count)
			continue;

		lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, qn->in_flight[level].head) {
			struct lws_quic_tx_frame *f = lws_container_of(d, struct lws_quic_tx_frame, list);

			lwsl_debug("PTO Sweep: checking packet %llu: now=%llu, sent=%llu, diff=%lld\n",
				(unsigned long long)f->sent_in_pn, (unsigned long long)now, (unsigned long long)f->sent_time_us,
				(long long)(now - f->sent_time_us));

			/* Allow a 5ms epsilon for timer jitter */
			if (now + 5000 >= f->sent_time_us + LWS_QUIC_DEFAULT_PTO_US) {
				lwsl_debug("PTO Sweep: Packet %llu (type 0x%02x) lost! Retransmitting!\n", (unsigned long long)f->sent_in_pn, f->type);
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

	/*
	 * Iterate through the encryption levels in priority order.
	 * Initial > Handshake > Application Data.
	 */
	for (level = 0; level < LWS_QUIC_LEVEL_COUNT; level++) {
		if (!qn->keys[level] || !qn->keys[level]->valid)
			continue;

		if (!qn->pending_tx[level].count && !qn->needs_ack[level])
			continue;

		struct lws_vhost *vh = lws_get_vhost(wsi);
		uint32_t mtu = vh->quic_mtu ? vh->quic_mtu : 1280;

		/* Enforce RFC 9000 Anti-Amplification Limit (Section 8.1) for servers */
		if (qn->is_server && !qn->address_validated) {
			if (qn->bytes_sent + mtu > 3 * qn->bytes_received) {
				lwsl_notice("QUIC TX: Anti-Amplification limit reached! Sent: %llu, Recv: %llu. Blocking send.\n",
					    (unsigned long long)qn->bytes_sent, (unsigned long long)qn->bytes_received);
				break; /* Block sending further datagrams */
			}
		}

		/* Check congestion window */
		if (!qn->pto_probe_needed && !qn->needs_ack[level] && qn->cc_ops && qn->cc_ops->can_send && !qn->cc_ops->can_send(wsi, mtu)) {
			LWS_RATELIMIT_DEFINE_STATIC(rl);
			lwsl_ratelimit_notice(&rl, 1000000, "QUIC TX: Congestion window full, blocking POLLOUT\n");
			break; /* Stop processing sending loops */
		}

		/* Check pacing */
		if (!qn->needs_ack[level] && qn->cc_ops && qn->cc_ops->get_pacing_delay) {
			lws_usec_t delay = qn->cc_ops->get_pacing_delay(wsi, mtu);
			if (delay > 0) {
				lws_sul_schedule(wsi->a.context, 0, &qn->pacer_sul, lws_quic_pacer_cb, delay);
				break; /* Stop processing sending loops */
			}
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

			/* Version (1) */
			*p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x01;
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
			*p++ = 0x40 | 0x01; /* Short Header, 2-byte PN */
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
			p += lws_quic_write_varint(p, sizeof(pkt) - (size_t)(p - pkt), 0); /* First ACK Range (Only ACK the single largest PN for now) */
			qn->needs_ack[level] = 0;
		}

		/* 2. Bundle frames from pending_tx until MTU is reached */
		lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, qn->pending_tx[level].head) {
			struct lws_quic_tx_frame *f = lws_container_of(d, struct lws_quic_tx_frame, list);

			/* Check if frame fits in remaining MTU (leaving room for headers and 16-byte AEAD tag) */
			size_t frame_header_max_len = 1 + 8 + 8;
			if ((size_t)(p - pkt) + frame_header_max_len + 32 >= sizeof(pkt))
				break;

			size_t send_len = f->len;
			if ((size_t)(p - pkt) + frame_header_max_len + send_len + 32 > sizeof(pkt)) {
				send_len = sizeof(pkt) - (size_t)(p - pkt) - frame_header_max_len - 32;
			}
			if (send_len == 0 && f->len > 0)
				break;

			/* Serialize the frame type */
			*p++ = f->type;

			/* Serialize frame-specific headers */
			if (f->type == LWS_QUIC_FT_CRYPTO) {
				p += lws_quic_write_varint(p, sizeof(pkt) - (size_t)(p - pkt), f->offset);
				p += lws_quic_write_varint(p, sizeof(pkt) - (size_t)(p - pkt), send_len);
			} else if ((f->type & 0xf8) == LWS_QUIC_FT_STREAM) {
				/* Stream ID */
				p += lws_quic_write_varint(p, sizeof(pkt) - (size_t)(p - pkt), f->stream_id);
				if (f->type & 0x04) /* OFF */
					p += lws_quic_write_varint(p, sizeof(pkt) - (size_t)(p - pkt), f->offset);
				if (f->type & 0x02) /* LEN */
					p += lws_quic_write_varint(p, sizeof(pkt) - (size_t)(p - pkt), send_len);
			} else if (f->type == LWS_QUIC_FT_MAX_DATA || f->type == LWS_QUIC_FT_DATA_BLOCKED) {
				p += lws_quic_write_varint(p, sizeof(pkt) - (size_t)(p - pkt), f->limit);
			} else if (f->type == LWS_QUIC_FT_MAX_STREAM_DATA || f->type == LWS_QUIC_FT_STREAM_DATA_BLOCKED) {
				p += lws_quic_write_varint(p, sizeof(pkt) - (size_t)(p - pkt), f->stream_id);
				p += lws_quic_write_varint(p, sizeof(pkt) - (size_t)(p - pkt), f->limit);
			} else if (f->type == LWS_QUIC_FT_RESET_STREAM) {
				p += lws_quic_write_varint(p, sizeof(pkt) - (size_t)(p - pkt), f->stream_id);
				p += lws_quic_write_varint(p, sizeof(pkt) - (size_t)(p - pkt), f->offset); /* app_err_code */
				p += lws_quic_write_varint(p, sizeof(pkt) - (size_t)(p - pkt), f->limit); /* final_size */
			} else if (f->type == LWS_QUIC_FT_STOP_SENDING) {
				p += lws_quic_write_varint(p, sizeof(pkt) - (size_t)(p - pkt), f->stream_id);
				p += lws_quic_write_varint(p, sizeof(pkt) - (size_t)(p - pkt), f->offset); /* app_err_code */
			} else if (f->type == LWS_QUIC_FT_MAX_STREAMS_BIDI || f->type == LWS_QUIC_FT_MAX_STREAMS_UNIDI ||
				   f->type == LWS_QUIC_FT_STREAMS_BLOCKED_BIDI || f->type == LWS_QUIC_FT_STREAMS_BLOCKED_UNIDI) {
				p += lws_quic_write_varint(p, sizeof(pkt) - (size_t)(p - pkt), f->limit);
			} else if (f->type == LWS_QUIC_FT_NEW_CONNECTION_ID) {
				p += lws_quic_write_varint(p, sizeof(pkt) - (size_t)(p - pkt), f->stream_id); /* seq */
				p += lws_quic_write_varint(p, sizeof(pkt) - (size_t)(p - pkt), f->offset); /* retire_prior_to */
				/* cid + token in data */
			} else if (f->type == LWS_QUIC_FT_RETIRE_CONNECTION_ID) {
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
				lws_dll2_add_tail(&f_sent->list, &qn->in_flight[level]);

				/* Update original f in pending_tx */
				f->offset += send_len;
				f->len -= send_len;
				f->data += send_len;

				/* Schedule PTO timer since we have data in-flight */
				lws_sul_schedule(wsi->a.context, 0, &qn->pto_sul, lws_quic_pto_cb, LWS_QUIC_DEFAULT_PTO_US);

				break; /* We filled the MTU */
			} else {
				/* Sent entirely */
				lws_dll2_remove(&f->list);
				f->sent_in_pn = my_pn;
				f->sent_time_us = lws_now_usecs();
				f->wire_len = 0;
				lws_dll2_add_tail(&f->list, &qn->in_flight[level]);

				/* Schedule PTO timer since we have data in-flight */
				lws_sul_schedule(wsi->a.context, 0, &qn->pto_sul, lws_quic_pto_cb, LWS_QUIC_DEFAULT_PTO_US);
			}

		} lws_end_foreach_dll_safe(d, d1);

		size_t payload_len = (size_t)(p - (pkt + header_len));
		if (payload_len == 0)
			continue;

		/* pad out to 1200 minimum total tx length for client initial */
		if (level == LWS_QUIC_LEVEL_INITIAL && !qn->is_server) {
			size_t target_payload_len = 1200 - header_len - 16;
			if (payload_len < target_payload_len) {
				memset(p, LWS_QUIC_FT_PADDING, target_payload_len - payload_len);
				p += (target_payload_len - payload_len);
				payload_len = target_payload_len;
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

		/* 4. Transmit UDP Datagram */

		/* DEBUG: Print first 16 bytes sent */
		lwsl_wsi_debug(wsi, "QUIC TX: First 16 bytes sent: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
			pkt[0], pkt[1], pkt[2], pkt[3], pkt[4], pkt[5], pkt[6], pkt[7], pkt[8], pkt[9], pkt[10], pkt[11], pkt[12], pkt[13], pkt[14], pkt[15]);

		lws_sockfd_type fd = wsi->mux_substream ? wsi->mux.parent_wsi->desc.sockfd : wsi->desc.sockfd;
		size_t send_len = (size_t)(p - pkt) + 16;

		lwsl_wsi_debug(wsi, "QUIC TX: Sending %d bytes to fd %d (mux=%d)", (int)send_len, (int)(intptr_t)fd, wsi->mux_substream);

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
			lwsl_wsi_err(wsi, "QUIC TX: Write failed, errno=%d", LWS_ERRNO);
			return LWS_HP_RET_BAIL_OK;
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

		lwsl_wsi_debug(wsi, "QUIC TX: Sent %d bytes, bundled frames into PN %llu",
				n, (unsigned long long)my_pn);

		/*
		 * If we still have pending frames we couldn't fit, request another POLLOUT
		 */
		if (qn->pending_tx[level].count)
			lws_callback_on_writable(wsi);
	}

	qn->pto_probe_needed = 0;

	/* If we handled all pending crypto/internal frames, give the user a chance to write */
	struct lws *nwsi = lws_get_network_wsi(wsi);
	if (qn->handshake_done && wsi->txc.tx_cr > 0 && (!nwsi || nwsi->txc.tx_cr > 0)) {
		enum lws_callback_reasons cb_reason = (enum lws_callback_reasons)wsi->role_ops->writeable_cb[lwsi_role_server(wsi)];
		// lwsl_notice("QUIC TX: Calling user writeable callback with reason %d (server=%d)\n", cb_reason, lwsi_role_server(wsi));
		n = user_callback_handle_rxflow(wsi->a.protocol->callback,
				wsi, cb_reason,
				wsi->user_space, NULL, 0);
		if (n < 0)
			return LWS_HP_RET_BAIL_DIE;
	}

	return LWS_HP_RET_DROP_POLLOUT;
}

static int
rops_write_role_protocol_quic(struct lws *wsi, unsigned char *buf, size_t len,
			      enum lws_write_protocol *wp)
{
	struct lws_quic_netconn *qn = wsi->quic.qn;
	struct lws *nwsi = lws_get_network_wsi(wsi);
	struct lws_quic_tx_frame *f;

	if (!qn)
		return -1;

	/* Enforce stream and connection flow control limits */
	if (wsi->txc.tx_cr <= 0 || (nwsi && nwsi->txc.tx_cr <= 0)) {
		int did_enqueue = 0;
		if (wsi->txc.tx_cr <= 0 && !wsi->quic.tx_blocked_sent) {
			/* Generate STREAM_DATA_BLOCKED */
			struct lws_quic_tx_frame *f_sdb = lws_zalloc(sizeof(*f_sdb), "quic sdb");
			if (f_sdb) {
				f_sdb->type = LWS_QUIC_FT_STREAM_DATA_BLOCKED;
				f_sdb->stream_id = wsi->mux.my_sid;
				f_sdb->limit = wsi->quic.tx_stream_offset;
				lws_dll2_add_tail(&f_sdb->list, &qn->pending_tx[LWS_QUIC_LEVEL_APP]);
			}
			wsi->quic.tx_blocked_sent = 1;
			did_enqueue = 1;
		}

		if (nwsi && nwsi != wsi && nwsi->txc.tx_cr <= 0 && !nwsi->quic.tx_blocked_sent) {
			/* Generate DATA_BLOCKED */
			struct lws_quic_tx_frame *f_db = lws_zalloc(sizeof(*f_db), "quic db");
			if (f_db) {
				f_db->type = LWS_QUIC_FT_DATA_BLOCKED;
				f_db->limit = qn->tx_conn_offset;
				lws_dll2_add_tail(&f_db->list, &qn->pending_tx[LWS_QUIC_LEVEL_APP]);
			}
			nwsi->quic.tx_blocked_sent = 1;
			did_enqueue = 1;
		}

		/* Kick output to send these control frames */
		if (did_enqueue)
			lws_callback_on_writable(nwsi ? nwsi : wsi);

		return 0; /* Consumed 0 bytes, caller should yield and try again later */
	}

	/* Truncate len to available credit if it's too large */
	if (len > (size_t)wsi->txc.tx_cr)
		len = (size_t)wsi->txc.tx_cr;
	if (nwsi && len > (size_t)nwsi->txc.tx_cr)
		len = (size_t)nwsi->txc.tx_cr;

	/* Allocate frame struct + payload buffer natively */
	f = lws_zalloc(sizeof(*f) + len, "quic tx frame");
	if (!f)
		return -1;

	f->type = LWS_QUIC_FT_STREAM | 0x02 | 0x04; /* STREAM | OFF | LEN */
	f->data = (uint8_t *)&f[1];
	f->len = len;

	/* Copy the user payload */
	memcpy(f->data, buf, len);

	f->offset = wsi->quic.tx_stream_offset;
	wsi->quic.tx_stream_offset += len;
	f->stream_id = wsi->mux.my_sid;

	/* Deduct credit */
	wsi->txc.tx_cr -= (int)len;
	if (nwsi && nwsi != wsi) {
		nwsi->txc.tx_cr -= (int)len;
	}
	if (nwsi) {
		qn->tx_conn_offset += len;
	}

	wsi->quic.tx_blocked_sent = 0;
	if (nwsi && nwsi != wsi)
		nwsi->quic.tx_blocked_sent = 0;

	/* Stream frames always go in Application level */
	lws_dll2_add_tail(&f->list, &qn->pending_tx[LWS_QUIC_LEVEL_APP]);

	/* Wake up the event loop to send the packet */
	lws_callback_on_writable(wsi);

	return (int)len;
}

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

	if (i->method && !strcmp(i->method, "QUIC")) {
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
		wsi->quic.qn->version = 1;

		wsi->quic.qn->cc_ops = &lws_cc_ops_newreno;
		if (wsi->quic.qn->cc_ops->init)
			wsi->quic.qn->cc_ops->init(wsi);

		/* Initialize Flow Control Credits */
		int32_t init_cr = i->manual_initial_tx_credit;
		if (!init_cr)
			init_cr = 65535;
		wsi->txc.peer_tx_cr_est = init_cr;
		wsi->txc.tx_cr = init_cr;

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

		lws_role_transition(wsi, LWSIFR_CLIENT, LRS_UNCONNECTED, &role_ops_quic);
		return 1;
	}
	return 0;
}

static int
rops_adoption_bind_quic(struct lws *wsi, int type, const char *vh_prot_name)
{
	if (!(type & LWS_ADOPT_FLAG_UDP))
		return 0;

	if (wsi->a.vhost && wsi->a.vhost->listen_accept_role &&
	    !strcmp(wsi->a.vhost->listen_accept_role, "quic")) {
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
		return 1;
	}
	return 0;
}

static int
rops_callback_on_writable_quic(struct lws *wsi)
{
	// lwsl_wsi_notice(wsi, "QUIC TX: mux_sub=%d, parent=%s\n", wsi->mux_substream, wsi->mux.parent_wsi ? lws_wsi_tag(wsi->mux.parent_wsi) : "none");
	if (wsi->mux_substream && wsi->mux.parent_wsi) {
		wsi->mux.requested_POLLOUT = 1;
		if (lws_change_pollfd(wsi->mux.parent_wsi, 0, LWS_POLLOUT))
			return -1;
		return 1; /* handled */
	}
	return 0; /* not handled, let core handle it */
}

static int
rops_close_kill_connection_quic(struct lws *wsi, enum lws_close_status reason)
{
	struct lws_quic_netconn *qn = wsi->quic.qn;
	int i;

	lwsl_info("QUIC close_kill_connection called on wsi %p, qn %p (qn->nwsi %p)\n", wsi, qn, qn ? qn->nwsi : NULL);

	if (wsi->mux.child_list)
		lws_wsi_mux_close_children(wsi, (int)reason);

	if (wsi->mux_substream && wsi->mux.parent_wsi)
		lws_wsi_mux_sibling_disconnect(wsi);

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

		for (i = 0; i < LWS_QUIC_LEVEL_COUNT; i++) {
			/* Free keys */
			if (qn->keys[i]) {
				lws_free(qn->keys[i]);
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

		/* Free RX Stream chunks */
		lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, qn->rx_stream_chunks.head) {
			struct lws_quic_rx_chunk *c = lws_container_of(d, struct lws_quic_rx_chunk, list);
			lws_dll2_remove(&c->list);
			lws_free(c);
		} lws_end_foreach_dll_safe(d, d1);

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

static int
rops_tx_credit_quic(struct lws *wsi, char peer_to_us, int add)
{
	struct lws_quic_netconn *qn = wsi->quic.qn;
	struct lws *nwsi = lws_get_network_wsi(wsi);
	int n;

	if (!qn)
		return 0;

	if (add) {
		if (peer_to_us == LWSTXCR_PEER_TO_US) {
			/* We want to tell the peer they can write an additional "add" bytes to us */
			wsi->txc.peer_tx_cr_est += add;
			if (nwsi)
				nwsi->txc.peer_tx_cr_est += add;

			struct lws_quic_tx_frame *f_msd = lws_zalloc(sizeof(*f_msd), "quic msd");
			if (f_msd) {
				f_msd->type = LWS_QUIC_FT_MAX_STREAM_DATA;
				f_msd->stream_id = wsi->mux.my_sid;
				f_msd->limit = (uint64_t)wsi->txc.peer_tx_cr_est;
				lws_dll2_add_tail(&f_msd->list, &qn->pending_tx[LWS_QUIC_LEVEL_APP]);
			}

			if (nwsi) {
				struct lws_quic_tx_frame *f_md = lws_zalloc(sizeof(*f_md), "quic md");
				if (f_md) {
					f_md->type = LWS_QUIC_FT_MAX_DATA;
					f_md->limit = (uint64_t)nwsi->txc.peer_tx_cr_est;
					lws_dll2_add_tail(&f_md->list, &qn->pending_tx[LWS_QUIC_LEVEL_APP]);
				}
			}

			lws_callback_on_writable(nwsi ? nwsi : wsi);
			return 0;
		}

		/* We're being told we can write an additional "add" bytes to the peer */
		wsi->txc.tx_cr += add;
		if (nwsi)
			nwsi->txc.tx_cr += add;

		/* Unblock if blocked */
		if (wsi->txc.tx_cr > 0)
			lws_callback_on_writable(wsi);

		return 0;
	}

	if (peer_to_us == LWSTXCR_US_TO_PEER)
		return wsi->txc.tx_cr; /* how much we can write to peer */

	n = wsi->txc.peer_tx_cr_est; /* how much peer can write to us */
	if (nwsi && n > nwsi->txc.peer_tx_cr_est)
		n = nwsi->txc.peer_tx_cr_est;

	return n;
}

static const lws_rops_t rops_table_quic[] = {
	/*  1 */ { .handle_POLLIN	  = rops_handle_POLLIN_quic },
	/*  2 */ { .handle_POLLOUT	  = rops_handle_POLLOUT_quic },
	/*  3 */ { .adoption_bind	  = rops_adoption_bind_quic },
#if defined(LWS_WITH_CLIENT)
	/*  4 */ { .client_bind		  = rops_client_bind_quic },
#endif
	/*  5 */ { .write_role_protocol	  = rops_write_role_protocol_quic },
	/*  6 */ { .callback_on_writable  = rops_callback_on_writable_quic },
	/*  7 */ { .close_kill_connection = rops_close_kill_connection_quic },
	/*  8 */ { .tx_credit             = rops_tx_credit_quic },
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
	  /* LWS_ROPS_tx_credit */			0x68,
	  /* LWS_ROPS_write_role_protocol */
	  /* LWS_ROPS_encapsulation_parent */		0x50,
	  /* LWS_ROPS_alpn_negotiated */
	  /* LWS_ROPS_close_via_role_protocol */	0x00,
	  /* LWS_ROPS_close_role */
	  /* LWS_ROPS_close_kill_connection */		0x07,
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
