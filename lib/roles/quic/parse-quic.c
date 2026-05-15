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
#include "roles/quic/private-lib-roles-quic.h"

/*
 * Safely parse a QUIC Variable-Length Integer (RFC 9000, Section 16).
 * Returns the number of bytes consumed (1, 2, 4, or 8), or 0 if the buffer
 * is too small (truncated). The parsed value is written to *val.
 */
size_t
lws_quic_parse_varint(const uint8_t *buf, size_t len, uint64_t *val)
{
	uint8_t type;

	if (len < 1)
		return 0;

	type = buf[0] >> 6;
	switch (type) {
	case 0:
		*val = buf[0] & 0x3f;
		return 1;
	case 1:
		if (len < 2) return 0;
		*val = ((uint64_t)(buf[0] & 0x3f) << 8) | buf[1];
		return 2;
	case 2:
		if (len < 4) return 0;
		*val = ((uint64_t)(buf[0] & 0x3f) << 24) |
		       ((uint64_t)buf[1] << 16) |
		       ((uint64_t)buf[2] << 8) | buf[3];
		return 4;
	case 3:
		if (len < 8) return 0;
		*val = ((uint64_t)(buf[0] & 0x3f) << 56) |
		       ((uint64_t)buf[1] << 48) |
		       ((uint64_t)buf[2] << 40) |
		       ((uint64_t)buf[3] << 32) |
		       ((uint64_t)buf[4] << 24) |
		       ((uint64_t)buf[5] << 16) |
		       ((uint64_t)buf[6] << 8) | buf[7];
		return 8;
	}
	return 0;
}

/*
 * Calculates the exact offset of the Packet Number field and the payload length.
 * Returns the offset in bytes, or 0 if the packet is malformed/truncated.
 */
size_t
lws_quic_get_pn_offset(const uint8_t *buf, size_t len, size_t *payload_len)
{
	size_t pos = 1;
	uint64_t token_len, p_len;
	size_t consumed;
	uint8_t type, dcid_len, scid_len;

	if (len < 6)
		return 0;

	if (!(buf[0] & 0x80)) {
		/* Short Header: pn_offset immediately follows the 1-byte header + DCID */
		/* Assuming an 8-byte DCID for LWS endpoints */
		*payload_len = len - (1 + 8);
		return 1 + 8;
	}

	/* Long Header (Form = 1) */
	type = (buf[0] & 0x30) >> 4;

	/* Skip Version (4 bytes) */
	pos += 4;

	/* DCID */
	dcid_len = buf[pos++];
	if (pos + dcid_len > len) return 0;
	pos += dcid_len;

	/* SCID */
	if (pos >= len) return 0;
	scid_len = buf[pos++];
	if (pos + scid_len > len) return 0;
	pos += scid_len;

	if (type == 0) { /* Initial Packet */
		consumed = lws_quic_parse_varint(&buf[pos], len - pos, &token_len);
		if (!consumed) return 0;
		pos += consumed;
		if (pos + token_len > len) return 0;
		pos += (size_t)token_len;
	}

	/* Length field (covers Packet Number + Payload) */
	consumed = lws_quic_parse_varint(&buf[pos], len - pos, &p_len);
	if (!consumed) return 0;
	pos += consumed;

	if (pos + p_len > len) return 0; /* Packet is truncated based on stated length */

	*payload_len = (size_t)p_len;
	return pos; /* This is the exact offset where the Packet Number begins */
}

/*
 * Serialize a value into a QUIC Variable-Length Integer.
 * Returns the number of bytes written, or 0 if the buffer is too small.
 */
size_t
lws_quic_write_varint(uint8_t *buf, size_t len, uint64_t val)
{
	if (val <= 0x3f) {
		if (len < 1) return 0;
		buf[0] = (uint8_t)val;
		return 1;
	}
	if (val <= 0x3fff) {
		if (len < 2) return 0;
		buf[0] = 0x40 | (uint8_t)(val >> 8);
		buf[1] = (uint8_t)(val);
		return 2;
	}
	if (val <= 0x3fffffff) {
		if (len < 4) return 0;
		buf[0] = 0x80 | (uint8_t)(val >> 24);
		buf[1] = (uint8_t)(val >> 16);
		buf[2] = (uint8_t)(val >> 8);
		buf[3] = (uint8_t)(val);
		return 4;
	}
	if (val <= 0x3fffffffffffffffULL) {
		if (len < 8) return 0;
		buf[0] = 0xc0 | (uint8_t)(val >> 56);
		buf[1] = (uint8_t)(val >> 48);
		buf[2] = (uint8_t)(val >> 40);
		buf[3] = (uint8_t)(val >> 32);
		buf[4] = (uint8_t)(val >> 24);
		buf[5] = (uint8_t)(val >> 16);
		buf[6] = (uint8_t)(val >> 8);
		buf[7] = (uint8_t)(val);
		return 8;
	}
	return 0; /* Value too large for QUIC varint */
}

/*
 * QUIC RX Reassembly Engine
 *
 * Takes an incoming chunk of data, buffers it if it's out of order, or
 * delivers it immediately if it's sequential. If delivery fills a gap,
 * it will also flush any previously buffered contiguous chunks.
 */
void
lws_quic_rx_reassemble(struct lws *nwsi, lws_dll2_owner_t *owner,
		       uint64_t *expected_offset, uint64_t offset,
		       uint8_t *buf, size_t len, int is_crypto, int level)
{
	/* 1. If it's a past or overlapping frame, ignore it (simple version) */
	if (offset + len <= *expected_offset)
		return;

	if (offset < *expected_offset) {
		/* Partial overlap - trim it */
		size_t overlap = (size_t)(*expected_offset - offset);
		buf += overlap;
		len -= overlap;
		offset += overlap;
	}

	/* 2. If it's the exact expected piece, deliver it immediately! */
	if (offset == *expected_offset) {
		if (is_crypto) {
			lws_tls_quic_rx_crypto(nwsi, level, buf, len);
		} else {
			/* Application Stream Data */
			/* Wait until we bind the stream to a child wsi to deliver it.
			 * For our minimal test, we assume nwsi->a.protocol->callback handles it */
			struct lws *child = nwsi;
			if (nwsi->mux.child_list) child = nwsi->mux.child_list;

			if (child && child->a.protocol && child->a.protocol->callback) {
				enum lws_callback_reasons reason = lwsi_role_client(child) ?
					LWS_CALLBACK_QT_CLIENT_RECEIVE : LWS_CALLBACK_QT_SERVER_RECEIVE;
				int n = child->a.protocol->callback(child, reason, child->user_space, buf, len);
				if (n == 0) {
					/* Data consumed by application, replenish rx credit to generate MAX_DATA! */
					lws_wsi_tx_credit(child, LWSTXCR_PEER_TO_US, (int)len);
				}
			}
		}

		*expected_offset += len;

		/* 3. Check if this unblocks any previously buffered future chunks! */
		int flushed = 0;
		do {
			flushed = 0;
			lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, owner->head) {
				struct lws_quic_rx_chunk *c = lws_container_of(d, struct lws_quic_rx_chunk, list);

				if (c->offset == *expected_offset) {
					/* We found the next contiguous piece! */
					if (is_crypto) {
						lws_tls_quic_rx_crypto(nwsi, level, c->data, c->len);
					} else {
						struct lws *child = nwsi;
						if (nwsi->mux.child_list) child = nwsi->mux.child_list;
						if (child && child->a.protocol && child->a.protocol->callback) {
							enum lws_callback_reasons reason = lwsi_role_client(child) ?
								LWS_CALLBACK_QT_CLIENT_RECEIVE : LWS_CALLBACK_QT_SERVER_RECEIVE;
							int n = child->a.protocol->callback(child, reason, child->user_space, c->data, c->len);
							if (n == 0) {
								/* Data consumed by application, replenish rx credit to generate MAX_DATA! */
								lws_wsi_tx_credit(child, LWSTXCR_PEER_TO_US, (int)c->len);
							}
						}
					}

					*expected_offset += c->len;
					lws_dll2_remove(&c->list);
					lws_free(c);
					flushed = 1;
					break; /* Restart the sweep since we modified the list */
				}
			} lws_end_foreach_dll_safe(d, d1);
		} while (flushed);

		return;
	}

	/* 4. It's in the future. We must buffer it! */
	struct lws_quic_rx_chunk *c = lws_malloc(sizeof(*c) + len, "quic rx chunk");
	if (!c) return; /* OOM */

	c->offset = offset;
	c->len = len;
	c->data = (uint8_t *)&c[1];
	memcpy(c->data, buf, len);
	lws_dll2_clear(&c->list);

	/* Insert sorted by offset */
	struct lws_dll2 *p = NULL;
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, owner->head) {
		struct lws_quic_rx_chunk *existing = lws_container_of(d, struct lws_quic_rx_chunk, list);
		if (existing->offset == offset) {
			/* Duplicate future chunk, just ignore */
			lws_free(c);
			return;
		}
		if (existing->offset > offset)
			break;
		p = d;
	} lws_end_foreach_dll_safe(d, d1);

	if (p) {
		/* Insert after p */
		c->list.prev = p;
		c->list.next = p->next;
		c->list.owner = owner;
		if (p->next) p->next->prev = &c->list;
		else owner->tail = &c->list;
		p->next = &c->list;
		owner->count++;
	} else {
		/* Insert at head */
		lws_dll2_add_head(&c->list, owner);
	}
}

/*
 * Parses QUIC frames from a decrypted payload and routes them.
 */
int
lws_quic_parse_frames(struct lws *nwsi, int level, uint8_t *payload, size_t payload_len)
{
	size_t pos = 0;
	uint64_t type, offset, len;
	size_t consumed;

	while (pos < payload_len) {
		/* Parse Frame Type */
		consumed = lws_quic_parse_varint(&payload[pos], payload_len - pos, &type);
		if (!consumed) return -1;
		pos += consumed;

		switch (type) {
		case LWS_QUIC_FT_PADDING:
			/* Padding frame is exactly 1 byte. Just continue. */
			break;

		case LWS_QUIC_FT_CRYPTO:
			/* 1. Offset */
			consumed = lws_quic_parse_varint(&payload[pos], payload_len - pos, &offset);
			if (!consumed) return -1;
			pos += consumed;

			/* 2. Length */
			consumed = lws_quic_parse_varint(&payload[pos], payload_len - pos, &len);
			if (!consumed) return -1;
			pos += consumed;

			/* 3. Validation */
			if (pos + len > payload_len) {
				lwsl_wsi_notice(nwsi, "QUIC RX: Truncated CRYPTO frame");
				return -1;
			}

			lwsl_wsi_info(nwsi, "QUIC RX: Parsed CRYPTO frame! level %d, offset %llu, len %llu",
				level, (unsigned long long)offset, (unsigned long long)len);

			/* 4. Action: Pass the TLS handshake data to the OpenSSL QUIC method */
			lws_quic_rx_reassemble(nwsi, &nwsi->quic.qn->rx_crypto_chunks[level],
					       &nwsi->quic.qn->rx_crypto_offset[level],
					       offset, &payload[pos], (size_t)len, 1, level);

			pos += (size_t)len;
			break;

		case LWS_QUIC_FT_ACK:
		case LWS_QUIC_FT_ACK_ECN: {
			uint64_t largest_ack, ack_delay, ack_range_count, first_ack_range;

			/* 1. Largest Acknowledged */
			consumed = lws_quic_parse_varint(&payload[pos], payload_len - pos, &largest_ack);
			if (!consumed) return -1;
			pos += consumed;

			/* 2. ACK Delay */
			consumed = lws_quic_parse_varint(&payload[pos], payload_len - pos, &ack_delay);
			if (!consumed) return -1;
			pos += consumed;

			/* 3. ACK Range Count */
			consumed = lws_quic_parse_varint(&payload[pos], payload_len - pos, &ack_range_count);
			if (!consumed) return -1;
			pos += consumed;

			/* 4. First ACK Range */
			consumed = lws_quic_parse_varint(&payload[pos], payload_len - pos, &first_ack_range);
			if (!consumed) return -1;
			pos += consumed;

			/* Process the First ACK Range */
			uint64_t pn = largest_ack;
			for (uint64_t i = 0; i <= first_ack_range; i++) {
				lws_quic_handle_ack(nwsi, level, pn - i);
			}
			pn -= (first_ack_range + 1);

			/* 5. Additional ACK Ranges */
			for (uint64_t r = 0; r < ack_range_count; r++) {
				uint64_t gap, ack_range;

				consumed = lws_quic_parse_varint(&payload[pos], payload_len - pos, &gap);
				if (!consumed) return -1;
				pos += consumed;

				consumed = lws_quic_parse_varint(&payload[pos], payload_len - pos, &ack_range);
				if (!consumed) return -1;
				pos += consumed;

				pn -= gap + 1;
				for (uint64_t i = 0; i <= ack_range; i++) {
					lws_quic_handle_ack(nwsi, level, pn - i);
				}
				pn -= (ack_range + 1);
			}

			/* 6. ECN Counts (if type == 0x03) */
			if (type == LWS_QUIC_FT_ACK_ECN) {
				uint64_t ecn;
				/* ECT0, ECT1, ECN-CE */
				for (int i = 0; i < 3; i++) {
					consumed = lws_quic_parse_varint(&payload[pos], payload_len - pos, &ecn);
					if (!consumed) return -1;
					pos += consumed;
				}
			}
			break;
		}

		case LWS_QUIC_FT_PING:
			lwsl_wsi_notice(nwsi, "QUIC RX: Parsed PING frame!");
			break;

		case LWS_QUIC_FT_RESET_STREAM: {
			uint64_t stream_id, app_err_code, final_size;
			consumed = lws_quic_parse_varint(&payload[pos], payload_len - pos, &stream_id);
			if (!consumed) return -1;
			pos += consumed;
			consumed = lws_quic_parse_varint(&payload[pos], payload_len - pos, &app_err_code);
			if (!consumed) return -1;
			pos += consumed;
			consumed = lws_quic_parse_varint(&payload[pos], payload_len - pos, &final_size);
			if (!consumed) return -1;
			pos += consumed;
			lwsl_wsi_info(nwsi, "QUIC RX: Parsed RESET_STREAM! stream_id %llu, err %llu",
				(unsigned long long)stream_id, (unsigned long long)app_err_code);
			struct lws *child = nwsi->mux.child_list;
			while (child) {
				if (child->mux.my_sid == stream_id) {
					lwsl_wsi_notice(child, "QUIC RX: Stream closed by peer via RESET_STREAM");
					lws_close_free_wsi(child, LWS_CLOSE_STATUS_ABNORMAL_CLOSE, "quic reset stream");
					break;
				}
				child = child->mux.sibling_list;
			}
			break;
		}

		case LWS_QUIC_FT_STOP_SENDING: {
			uint64_t stream_id, app_err_code;
			consumed = lws_quic_parse_varint(&payload[pos], payload_len - pos, &stream_id);
			if (!consumed) return -1;
			pos += consumed;
			consumed = lws_quic_parse_varint(&payload[pos], payload_len - pos, &app_err_code);
			if (!consumed) return -1;
			pos += consumed;
			lwsl_wsi_info(nwsi, "QUIC RX: Parsed STOP_SENDING! stream_id %llu", (unsigned long long)stream_id);
			struct lws *child = nwsi->mux.child_list;
			while (child) {
				if (child->mux.my_sid == stream_id) {
					lwsl_wsi_notice(child, "QUIC RX: Stream closed by peer via STOP_SENDING");
					lws_close_free_wsi(child, LWS_CLOSE_STATUS_ABNORMAL_CLOSE, "quic stop sending");
					break;
				}
				child = child->mux.sibling_list;
			}
			break;
		}

		case LWS_QUIC_FT_MAX_STREAMS_BIDI:
		case LWS_QUIC_FT_MAX_STREAMS_UNIDI:
		case LWS_QUIC_FT_STREAMS_BLOCKED_BIDI:
		case LWS_QUIC_FT_STREAMS_BLOCKED_UNIDI: {
			uint64_t max_streams;
			consumed = lws_quic_parse_varint(&payload[pos], payload_len - pos, &max_streams);
			if (!consumed) return -1;
			pos += consumed;
			lwsl_wsi_info(nwsi, "QUIC RX: Parsed MAX/BLOCKED STREAMS! max_streams %llu", (unsigned long long)max_streams);
			if (type == LWS_QUIC_FT_MAX_STREAMS_BIDI)
				nwsi->quic.qn->max_streams_bidi_remote = max_streams;
			else if (type == LWS_QUIC_FT_MAX_STREAMS_UNIDI)
				nwsi->quic.qn->max_streams_unidi_remote = max_streams;
			break;
		}

		case LWS_QUIC_FT_NEW_CONNECTION_ID: {
			uint64_t seq, retire_prior_to;
			consumed = lws_quic_parse_varint(&payload[pos], payload_len - pos, &seq);
			if (!consumed) return -1;
			pos += consumed;
			consumed = lws_quic_parse_varint(&payload[pos], payload_len - pos, &retire_prior_to);
			if (!consumed) return -1;
			pos += consumed;
			if (pos >= payload_len) return -1;
			uint8_t cid_len = payload[pos++];
			if (pos + cid_len + 16 > payload_len) return -1;
			pos += cid_len + 16;
			lwsl_wsi_info(nwsi, "QUIC RX: Parsed NEW_CONNECTION_ID! seq %llu", (unsigned long long)seq);
			break;
		}

		case LWS_QUIC_FT_RETIRE_CONNECTION_ID: {
			uint64_t seq;
			consumed = lws_quic_parse_varint(&payload[pos], payload_len - pos, &seq);
			if (!consumed) return -1;
			pos += consumed;
			lwsl_wsi_info(nwsi, "QUIC RX: Parsed RETIRE_CONNECTION_ID! seq %llu", (unsigned long long)seq);
			break;
		}

		case LWS_QUIC_FT_PATH_CHALLENGE:
		case LWS_QUIC_FT_PATH_RESPONSE: {
			if (pos + 8 > payload_len) return -1;
			uint8_t path_data[8];
			memcpy(path_data, &payload[pos], 8);
			pos += 8;
			lwsl_wsi_info(nwsi, "QUIC RX: Parsed PATH_CHALLENGE/RESPONSE!");

			if (type == LWS_QUIC_FT_PATH_CHALLENGE && nwsi->quic.qn) {
				struct lws_quic_tx_frame *f_pr = lws_zalloc(sizeof(*f_pr) + 8, "quic path_resp");
				if (f_pr) {
					f_pr->type = LWS_QUIC_FT_PATH_RESPONSE;
					f_pr->len = 8;
					f_pr->data = (uint8_t *)&f_pr[1];
					memcpy(f_pr->data, path_data, 8);
					lws_dll2_add_tail(&f_pr->list, &nwsi->quic.qn->pending_tx[level]);
					lws_callback_on_writable(nwsi);
				}
			}
			break;
		}

		default:
			if ((type & 0xf8) == LWS_QUIC_FT_STREAM) {
				uint64_t stream_id;
				consumed = lws_quic_parse_varint(&payload[pos], payload_len - pos, &stream_id);
				if (!consumed) return -1;
				pos += consumed;

				if (type & 0x04) { /* OFF */
					consumed = lws_quic_parse_varint(&payload[pos], payload_len - pos, &offset);
					if (!consumed) return -1;
					pos += consumed;
				} else {
					offset = 0;
				}

				if (type & 0x02) { /* LEN */
					consumed = lws_quic_parse_varint(&payload[pos], payload_len - pos, &len);
					if (!consumed) return -1;
					pos += consumed;
				} else {
					len = payload_len - pos;
				}

				if (pos + len > payload_len) {
					lwsl_wsi_notice(nwsi, "QUIC RX: Truncated STREAM frame");
					return -1;
				}

				lwsl_wsi_info(nwsi, "QUIC RX: Parsed STREAM frame! id %llu, offset %llu, len %llu",
						(unsigned long long)stream_id, (unsigned long long)offset, (unsigned long long)len);

				/* Deliver stream data via Reassembly Buffer */
				if (len) {
					lws_quic_rx_reassemble(nwsi, &nwsi->quic.qn->rx_stream_chunks,
							       &nwsi->quic.qn->rx_stream_offset,
							       offset, &payload[pos], (size_t)len, 0, level);
				}

				pos += (size_t)len;
				break;
			} else if (type == LWS_QUIC_FT_ACK || type == 0x03 /* ACK with ECN */) {
				uint64_t largest_ack, ack_delay, ack_range_count, first_ack_range;
				consumed = lws_quic_parse_varint(&payload[pos], payload_len - pos, &largest_ack);
				if (!consumed) return -1;
				pos += consumed;
				consumed = lws_quic_parse_varint(&payload[pos], payload_len - pos, &ack_delay);
				if (!consumed) return -1;
				pos += consumed;
				consumed = lws_quic_parse_varint(&payload[pos], payload_len - pos, &ack_range_count);
				if (!consumed) return -1;
				pos += consumed;
				consumed = lws_quic_parse_varint(&payload[pos], payload_len - pos, &first_ack_range);
				if (!consumed) return -1;
				pos += consumed;

				for (uint64_t i = 0; i < ack_range_count; i++) {
					uint64_t gap, ack_range;
					consumed = lws_quic_parse_varint(&payload[pos], payload_len - pos, &gap);
					if (!consumed) return -1;
					pos += consumed;
					consumed = lws_quic_parse_varint(&payload[pos], payload_len - pos, &ack_range);
					if (!consumed) return -1;
					pos += consumed;
				}

				if (type == 0x03) { /* ECN */
					uint64_t ect0, ect1, ecn_ce;
					consumed = lws_quic_parse_varint(&payload[pos], payload_len - pos, &ect0);
					if (!consumed) return -1;
					pos += consumed;
					consumed = lws_quic_parse_varint(&payload[pos], payload_len - pos, &ect1);
					if (!consumed) return -1;
					pos += consumed;
					consumed = lws_quic_parse_varint(&payload[pos], payload_len - pos, &ecn_ce);
					if (!consumed) return -1;
					pos += consumed;
				}

				lwsl_wsi_info(nwsi, "QUIC RX: Parsed ACK frame! largest %llu", (unsigned long long)largest_ack);
				break;
			} else if (type == LWS_QUIC_FT_MAX_DATA || type == LWS_QUIC_FT_DATA_BLOCKED) {
				uint64_t max_data;
				consumed = lws_quic_parse_varint(&payload[pos], payload_len - pos, &max_data);
				if (!consumed) return -1;
				pos += consumed;

				lwsl_wsi_info(nwsi, "QUIC RX: Parsed %s frame! max_data %llu",
					type == LWS_QUIC_FT_MAX_DATA ? "MAX_DATA" : "DATA_BLOCKED", (unsigned long long)max_data);

				if (type == LWS_QUIC_FT_MAX_DATA) {
					int32_t current_max = (int32_t)(nwsi->quic.qn->tx_conn_offset + (uint64_t)nwsi->txc.tx_cr);
					int32_t delta = (int32_t)max_data - current_max;
					if (delta > 0)
						lws_wsi_tx_credit(nwsi, LWSTXCR_US_TO_PEER, delta);
				}
				break;
			} else if (type == LWS_QUIC_FT_MAX_STREAM_DATA || type == LWS_QUIC_FT_STREAM_DATA_BLOCKED) {
				uint64_t stream_id, max_stream_data;
				consumed = lws_quic_parse_varint(&payload[pos], payload_len - pos, &stream_id);
				if (!consumed) return -1;
				pos += consumed;
				consumed = lws_quic_parse_varint(&payload[pos], payload_len - pos, &max_stream_data);
				if (!consumed) return -1;
				pos += consumed;

				lwsl_wsi_info(nwsi, "QUIC RX: Parsed %s frame! stream_id %llu, max_stream_data %llu",
					type == LWS_QUIC_FT_MAX_STREAM_DATA ? "MAX_STREAM_DATA" : "STREAM_DATA_BLOCKED",
					(unsigned long long)stream_id, (unsigned long long)max_stream_data);

				if (type == LWS_QUIC_FT_MAX_STREAM_DATA) {
					/* Assuming stream 0 for now until full mux is implemented */
					int32_t current_max = (int32_t)(nwsi->quic.tx_stream_offset + (uint64_t)nwsi->txc.tx_cr);
					int32_t delta = (int32_t)max_stream_data - current_max;
					if (delta > 0)
						lws_wsi_tx_credit(nwsi, LWSTXCR_US_TO_PEER, delta);
				}
				break;
			}

			lwsl_wsi_notice(nwsi, "QUIC RX: Unhandled frame type 0x%x, aborting parse",
				      (unsigned int)type);
			/* Unknown frame: we MUST abort parsing because we don't know its length! */
			return -1;
		}
	}

	return 0;
}
