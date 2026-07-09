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

	uint32_t version = (uint32_t)((buf[1] << 24) | (buf[2] << 16) | (buf[3] << 8) | buf[4]);
	if (version == LWS_QUIC_VERSION_2) {
		if (type == 1) type = 0;
		else if (type == 0) type = 3;
		else if (type == 2) type = 1;
		else if (type == 3) type = 2;
	}

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
		if (token_len > len - pos) return 0;
		pos += (size_t)token_len;
	}

	/* Length field (covers Packet Number + Payload) */
	consumed = lws_quic_parse_varint(&buf[pos], len - pos, &p_len);
	if (!consumed) return 0;
	pos += consumed;

	if (p_len > len - pos) return 0; /* Packet is truncated based on stated length */

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
lws_quic_rx_reassemble(struct lws *nwsi, struct lws *wsi_child, struct lws_quic_stream *qs,
		       uint64_t offset, uint8_t *buf, size_t len, int is_crypto, int level)
{
	uint64_t *expected_offset = is_crypto ? &nwsi->quic.qn->rx_crypto_offset[level] : &qs->rx_offset;
	lws_dll2_owner_t *owner = is_crypto ? &nwsi->quic.qn->rx_crypto_chunks[level] : &qs->rx_chunks;

	/* 1. If it's a past or overlapping frame, ignore it (simple version) */
	if (offset + len <= *expected_offset && !(len == 0 && offset == *expected_offset))
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
			if (lws_tls_quic_rx_crypto(nwsi, level, buf, len) < 0) {
				lwsl_wsi_notice(nwsi, "QUIC RX: TLS Crypto processing failed");
				lws_quic_enter_closing_state(nwsi, LWS_QUIC_ERR_PROTOCOL_VIOLATION, 0, 0);
				return;
			}
			if (nwsi && !nwsi->quic.qn) {
				nwsi = lws_get_quic_network_wsi(nwsi);
				if (nwsi && nwsi->quic.qn) {
					expected_offset = &nwsi->quic.qn->rx_crypto_offset[level];
					owner = &nwsi->quic.qn->rx_crypto_chunks[level];
				}
			}
		} else if (wsi_child) {
			int is_final = (wsi_child && qs && qs->fin_received && *expected_offset + len == qs->rx_final_size && !qs->fin_delivered);
			if (is_final) {
				qs->fin_delivered = 1;
			}

#if defined(LWS_ROLE_H3)
			lwsl_wsi_info(wsi_child, "QUIC RX: rx_reassemble for stream ID, role_ops=%p, role_ops_h3=%p, len=%d", wsi_child ? wsi_child->role_ops : NULL, &role_ops_h3, (int)len);
			if (wsi_child && wsi_child->role_ops == &role_ops_h3) {
				lwsl_wsi_info(wsi_child, "QUIC RX: Delivering %d bytes to H3!", (int)len);
				if (lws_h3_rx_stream_data(wsi_child, buf, len)) {
					wsi_child = NULL;
				}
			} else
#endif
			if (wsi_child && wsi_child->a.protocol && wsi_child->a.protocol->callback) {
				/* Application Stream Data */
				enum lws_callback_reasons reason = lwsi_role_client(wsi_child) ?
					LWS_CALLBACK_QT_CLIENT_RECEIVE : LWS_CALLBACK_QT_SERVER_RECEIVE;
				int n = wsi_child->a.protocol->callback(wsi_child, reason, wsi_child->user_space, buf, len);
				if (n == 0) {
					/* Data consumed by application, replenish rx credit to generate MAX_DATA! */
					lws_wsi_tx_credit(wsi_child, LWSTXCR_PEER_TO_US, (int)len);
				}
			}

			if (is_final && wsi_child) {
#if defined(LWS_ROLE_H3)
				if (wsi_child->role_ops == &role_ops_h3) {
					if (!qs->is_unidirectional) {
						if (lwsi_role_client(wsi_child)) {
#if defined(LWS_WITH_CLIENT)
							wsi_child->client_mux_substream = 1;
							if (lws_http_transaction_completed_client(wsi_child)) {
								lwsl_info("Transaction completed and wsi closed\n");
								wsi_child = NULL;
							} else {
								lwsl_wsi_info(wsi_child, "Transaction completed! Closing QUIC stream WSI");
								lws_close_free_wsi(wsi_child, LWS_CLOSE_STATUS_NOSTATUS, "quic client stream fin");
								wsi_child = NULL;
							}
#endif
						} else {
#if defined(LWS_WITH_CLIENT)
							wsi_child->client_mux_substream = 0;
#endif
                                                }
                                        } else {
                                                if (wsi_child->h3.type_set && (wsi_child->h3.stream_type == 0x00 || wsi_child->h3.stream_type == 0x02 || wsi_child->h3.stream_type == 0x03)) {
                                                        lws_quic_enter_closing_state(nwsi, 0x0104 /* LWS_H3_CLOSED_CRITICAL_STREAM */, 0, 1);
                                                        return;
                                                }
                                        }
                                }
#endif
                        }
		}

		if (!is_crypto && !wsi_child)
			return;

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
						if (lws_tls_quic_rx_crypto(nwsi, level, c->data, c->len) < 0) {
							lwsl_wsi_notice(nwsi, "QUIC RX: TLS Crypto processing failed");
							lws_quic_enter_closing_state(nwsi, LWS_QUIC_ERR_PROTOCOL_VIOLATION, 0, 0);
							return;
						}
						if (nwsi && !nwsi->quic.qn) {
							nwsi = lws_get_quic_network_wsi(nwsi);
							if (nwsi && nwsi->quic.qn) {
								expected_offset = &nwsi->quic.qn->rx_crypto_offset[level];
								owner = &nwsi->quic.qn->rx_crypto_chunks[level];
							}
						}
					} else if (wsi_child) {
#if defined(LWS_ROLE_H3)
						if (wsi_child->role_ops == &role_ops_h3) {
							lwsl_wsi_info(wsi_child, "QUIC RX: Delivering chunk %d bytes to H3!", (int)c->len);
							if (lws_h3_rx_stream_data(wsi_child, c->data, c->len)) {
								wsi_child = NULL;
							}
						} else
#endif
						if (wsi_child->a.protocol && wsi_child->a.protocol->callback) {
							enum lws_callback_reasons reason = lwsi_role_client(wsi_child) ?
								LWS_CALLBACK_QT_CLIENT_RECEIVE : LWS_CALLBACK_QT_SERVER_RECEIVE;
							int n = wsi_child->a.protocol->callback(wsi_child, reason, wsi_child->user_space, c->data, c->len);
							if (n == 0) {
								/* Data consumed by application, replenish rx credit to generate MAX_DATA! */
								lws_wsi_tx_credit(wsi_child, LWSTXCR_PEER_TO_US, (int)c->len);
							}
						}

						if (wsi_child && qs && qs->fin_received && *expected_offset + c->len == qs->rx_final_size && !qs->fin_delivered) {
							qs->fin_delivered = 1;
#if defined(LWS_ROLE_H3)
							if (wsi_child->role_ops == &role_ops_h3) {
								if (!qs->is_unidirectional) {
									if (lwsi_role_client(wsi_child)) {
#if defined(LWS_WITH_CLIENT)
										wsi_child->client_mux_substream = 1;
										if (lws_http_transaction_completed_client(wsi_child)) {
											lwsl_info("Transaction completed and wsi closed\n");
											wsi_child = NULL;
										} else {
											lwsl_wsi_info(wsi_child, "Transaction completed! Closing QUIC stream WSI");
											lws_close_free_wsi(wsi_child, LWS_CLOSE_STATUS_NOSTATUS, "quic client stream fin");
											wsi_child = NULL;
										}
#endif
									} else {
#if defined(LWS_WITH_CLIENT)
										wsi_child->client_mux_substream = 0;
#endif
									}
								}
							}
#endif
						}
					}

					if (!is_crypto && !wsi_child) {
                                                /*
                                                 * The WSI was closed and freed. Its cleanup routine
                                                 * already freed all buffered chunks, including c.
                                                 * We must not touch c, qs or the list anymore.
                                                 */
						return;
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
#if defined(LWS_WITH_FREERTOS)
	if (owner->count >= 16)
#else
	if (owner->count >= 4096)
#endif
	{
		lwsl_wsi_notice(nwsi, "QUIC RX: Dropping future chunk, reassembly buffer full");
		return;
	}

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
 * Finds a child WSI for a given QUIC Stream ID, or returns NULL.
 */
struct lws *
lws_quic_stream_find(struct lws *nwsi, uint64_t stream_id)
{
	struct lws_quic_netconn *qn = nwsi ? nwsi->quic.qn : NULL;
	struct lws *wsi_child;

	if (!qn) {
		wsi_child = nwsi ? nwsi->mux.child_list : NULL;
		while (wsi_child) {
			if (wsi_child->quic.qs && wsi_child->quic.qs->stream_id == stream_id)
				return wsi_child;
			if (wsi_child->mux.my_sid == (unsigned int)stream_id)
				return wsi_child;
			wsi_child = wsi_child->mux.sibling_list;
		}
		return NULL;
	}

	if (qn->nwsi) {
		wsi_child = qn->nwsi->mux.child_list;
		while (wsi_child) {
			if (wsi_child->quic.qs && wsi_child->quic.qs->stream_id == stream_id)
				return wsi_child;
			if (wsi_child->mux.my_sid == (unsigned int)stream_id)
				return wsi_child;
			wsi_child = wsi_child->mux.sibling_list;
		}
	}

	if (qn->migration_probing_wsi) {
		wsi_child = qn->migration_probing_wsi->mux.child_list;
		while (wsi_child) {
			if (wsi_child->quic.qs && wsi_child->quic.qs->stream_id == stream_id)
				return wsi_child;
			if (wsi_child->mux.my_sid == (unsigned int)stream_id)
				return wsi_child;
			wsi_child = wsi_child->mux.sibling_list;
		}
	}

	return NULL;
}


/*
 * Parses QUIC frames from a decrypted payload and routes them.
 */
int
lws_quic_parse_frames(struct lws *nwsi, int level, uint8_t *payload, size_t payload_len, const lws_sockaddr46 *sa46)
{
	size_t pos = 0;
	uint64_t type, offset, len;
	size_t consumed;
	int ack_eliciting = 0;

	while (pos < payload_len) {
		struct lws_quic_netconn *qn;
		/* ALPN negotiation during a previous frame might have migrated the network WSI! */
		if (nwsi && !nwsi->quic.qn) {
			nwsi = lws_get_quic_network_wsi(nwsi);
		}
		qn = nwsi ? nwsi->quic.qn : NULL;
		
		if (!nwsi || !qn)
			return -1;


		if (qn && qn->is_closing) {
			/* If the connection is closing (e.g. critical stream closed), stop parsing frames */
			return -1;
		}

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
			if (len > payload_len - pos) {
				lwsl_wsi_notice(nwsi, "QUIC RX: Truncated CRYPTO frame");
				return -1;
			}

			lwsl_wsi_info(nwsi, "QUIC RX: Parsed CRYPTO frame! level %d, offset %llu, len %llu",
				level, (unsigned long long)offset, (unsigned long long)len);

			/* 4. Action: Pass the TLS handshake data to the OpenSSL QUIC method */
			lws_quic_rx_reassemble(nwsi, NULL, NULL,
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

			lwsl_wsi_info(nwsi, "QUIC RX TELEMETRY: Parsed ACK frame! Largest = %llu, First Range = %llu",
				(unsigned long long)largest_ack, (unsigned long long)first_ack_range);

			/* Process the First ACK Range */
			uint64_t pn = largest_ack;
			if (first_ack_range > pn) {
				lws_quic_enter_closing_state(nwsi, LWS_QUIC_ERR_FRAME_ENCODING_ERROR, type, 0);
				return -1;
			}
			for (uint64_t i = 0; i <= first_ack_range; i++) {
				lws_quic_handle_ack(nwsi, level, pn - i);
			}
			pn -= (first_ack_range + 1);

			/* 5. Additional ACK Ranges */
			if (ack_range_count > (payload_len - pos) / 2) {
				lws_quic_enter_closing_state(nwsi, LWS_QUIC_ERR_FRAME_ENCODING_ERROR, type, 0);
				return -1;
			}

			for (uint64_t r = 0; r < ack_range_count; r++) {
				uint64_t gap, ack_range;

				consumed = lws_quic_parse_varint(&payload[pos], payload_len - pos, &gap);
				if (!consumed) return -1;
				pos += consumed;

				consumed = lws_quic_parse_varint(&payload[pos], payload_len - pos, &ack_range);
				if (!consumed) return -1;
				pos += consumed;

				if (gap + 1 > pn) {
					lws_quic_enter_closing_state(nwsi, LWS_QUIC_ERR_FRAME_ENCODING_ERROR, type, 0);
					return -1;
				}
				pn -= gap + 1;

				if (ack_range > pn) {
					lws_quic_enter_closing_state(nwsi, LWS_QUIC_ERR_FRAME_ENCODING_ERROR, type, 0);
					return -1;
				}
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
			lws_quic_detect_loss(nwsi, level, largest_ack);
			break;
		}

		case LWS_QUIC_FT_PING:
			lwsl_wsi_info(nwsi, "QUIC RX: Parsed PING frame!");
			break;

		case LWS_QUIC_FT_RESET_STREAM: {
			uint64_t stream_id, app_err_code, final_size;
			consumed = lws_quic_parse_varint(&payload[pos], payload_len - pos, &stream_id);
			if (!consumed) return -1;
			
			int is_peer_initiated = (stream_id & 1) != (qn->is_server ? 1 : 0);
			int is_unidirectional = (stream_id & 2);
			struct lws *wsi_child = lws_quic_stream_find(nwsi, stream_id);
			
			if (is_peer_initiated) {
				uint64_t limit = is_unidirectional ? qn->max_streams_unidi_local : qn->max_streams_bidi_local;
				if ((stream_id >> 2) >= limit) {
					lwsl_wsi_notice(nwsi, "QUIC RX: Stream ID %llu exceeds limit", (unsigned long long)stream_id);
					lws_quic_enter_closing_state(nwsi, LWS_QUIC_ERR_STREAM_LIMIT_ERROR, type, 0);
					return -1;
				}
			}

			if (!is_peer_initiated) {
				if (is_unidirectional) {
					lwsl_wsi_notice(nwsi, "QUIC RX: Invalid RESET_STREAM on stream ID %llu", (unsigned long long)stream_id);
					lws_quic_enter_closing_state(nwsi, LWS_QUIC_ERR_STREAM_STATE_ERROR, type, 0);
					return -1;
				}
				if (!wsi_child) {
					/* It could be a stream we already closed and freed, or one we never created.
					 * Check if we created it by comparing with next_stream_id. */
					uint64_t next_id = is_unidirectional ? qn->next_stream_id_unidi_local : qn->next_stream_id_bidi_local;
					if (stream_id >= next_id) {
						lwsl_wsi_notice(nwsi, "QUIC RX: RESET_STREAM on uncreated stream ID %llu", (unsigned long long)stream_id);
						lws_quic_enter_closing_state(nwsi, LWS_QUIC_ERR_STREAM_STATE_ERROR, type, 0);
						return -1;
					}
				}
			}
			pos += consumed;
			consumed = lws_quic_parse_varint(&payload[pos], payload_len - pos, &app_err_code);
			if (!consumed) return -1;
			pos += consumed;
			consumed = lws_quic_parse_varint(&payload[pos], payload_len - pos, &final_size);
			if (!consumed) return -1;
			pos += consumed;
			lwsl_wsi_info(nwsi, "QUIC RX: Parsed RESET_STREAM! stream_id %llu, err %llu, final_size %llu",
				(unsigned long long)stream_id, (unsigned long long)app_err_code, (unsigned long long)final_size);
			
			if (wsi_child && wsi_child->quic.qs) {
				if (wsi_child->quic.qs->fin_received && wsi_child->quic.qs->rx_final_size != final_size) {
					lws_quic_enter_closing_state(nwsi, LWS_QUIC_ERR_FINAL_SIZE_ERROR, type, 0);
					return -1;
				}
				wsi_child->quic.qs->fin_received = 1;
				wsi_child->quic.qs->rx_final_size = final_size;
				
				if (final_size > wsi_child->quic.qs->rx_max_data) {
					lws_quic_enter_closing_state(nwsi, LWS_QUIC_ERR_FLOW_CONTROL_ERROR, type, 0);
					return -1;
				}
				if (final_size > wsi_child->quic.qs->highest_rx_offset) {
					uint64_t diff = final_size - wsi_child->quic.qs->highest_rx_offset;
					wsi_child->quic.qs->highest_rx_offset = final_size;
					nwsi->quic.qn->highest_rx_offset += diff;
					if (nwsi->quic.qn->highest_rx_offset > nwsi->quic.qn->rx_max_data) {
						lws_quic_enter_closing_state(nwsi, LWS_QUIC_ERR_FLOW_CONTROL_ERROR, type, 0);
						return -1;
					}
				}
			}

			struct lws *child = nwsi->mux.child_list;
			while (child) {
				if (child->mux.my_sid == stream_id) {
					lwsl_wsi_notice(child, "QUIC RX: Stream closed by peer via RESET_STREAM");
#if defined(LWS_ROLE_H3)
					if (child->role_ops == &role_ops_h3 && child->quic.qs && child->quic.qs->is_unidirectional) {
						if (child->h3.type_set && (child->h3.stream_type == 0x00 || child->h3.stream_type == 0x02 || child->h3.stream_type == 0x03)) {
							lws_quic_enter_closing_state(nwsi, 0x0104 /* LWS_H3_CLOSED_CRITICAL_STREAM */, 0, 1);
							return -1;
						}
					}
#endif
					lws_close_free_wsi(child, LWS_CLOSE_STATUS_ABNORMAL_CLOSE, "quic reset stream");
					break;
				}
				child = child->mux.sibling_list;
			}
			break;
		}

		case 0x1c: /* CONNECTION_CLOSE */
		case 0x1d: { /* CONNECTION_CLOSE (Application) */
			uint64_t err_code, frame_type = 0, reason_len;
			consumed = lws_quic_parse_varint(&payload[pos], payload_len - pos, &err_code);
			if (!consumed) return -1;
			pos += consumed;
			if (type == 0x1c) {
				consumed = lws_quic_parse_varint(&payload[pos], payload_len - pos, &frame_type);
				if (!consumed) return -1;
				pos += consumed;
			}
			consumed = lws_quic_parse_varint(&payload[pos], payload_len - pos, &reason_len);
			if (!consumed) return -1;
			pos += consumed;
			if (reason_len > payload_len - pos) return -1;
			lwsl_wsi_notice(nwsi, "QUIC RX: CONNECTION_CLOSE (err=%llu, frame_type=%llu, reason_len=%llu)", 
				(unsigned long long)err_code, (unsigned long long)frame_type, (unsigned long long)reason_len);
			
			if (reason_len) {
				char chunk[128];
				size_t printed = 0;
				while (printed < reason_len) {
					size_t chunk_len = reason_len - printed;
					if (chunk_len > sizeof(chunk) - 1)
						chunk_len = sizeof(chunk) - 1;
					memcpy(chunk, &payload[pos + printed], chunk_len);
					chunk[chunk_len] = '\0';
					lwsl_wsi_notice(nwsi, "QUIC RX REASON: %s", chunk);
					printed += chunk_len;
				}
			}
			
			pos += (size_t)reason_len;
			(void)pos;
			return -3; /* Terminate parsing and connection cleanly (Peer closed) */
		}

		case LWS_QUIC_FT_STOP_SENDING: {
			uint64_t stream_id, app_err_code;
			consumed = lws_quic_parse_varint(&payload[pos], payload_len - pos, &stream_id);
			if (!consumed) return -1;
			
			int is_peer_initiated = (stream_id & 1) != (qn->is_server ? 1 : 0);
			int is_unidirectional = (stream_id & 2);
			struct lws *wsi_child = lws_quic_stream_find(nwsi, stream_id);
			
			if (is_peer_initiated) {
				uint64_t limit = is_unidirectional ? qn->max_streams_unidi_local : qn->max_streams_bidi_local;
				if ((stream_id >> 2) >= limit) {
					lwsl_wsi_notice(nwsi, "QUIC RX: Stream ID %llu exceeds limit", (unsigned long long)stream_id);
					lws_quic_enter_closing_state(nwsi, LWS_QUIC_ERR_STREAM_LIMIT_ERROR, type, 0);
					return -1;
				}
			}

			if (!is_peer_initiated) {
				if (!wsi_child) {
					/* It could be a stream we already closed and freed, or one we never created.
					 * Check if we created it by comparing with next_stream_id. */
					uint64_t next_id = is_unidirectional ? qn->next_stream_id_unidi_local : qn->next_stream_id_bidi_local;
					if (stream_id >= next_id) {
						lwsl_wsi_notice(nwsi, "QUIC RX: STOP_SENDING on uncreated stream ID %llu", (unsigned long long)stream_id);
						lws_quic_enter_closing_state(nwsi, LWS_QUIC_ERR_STREAM_STATE_ERROR, type, 0);
						return -1;
					}
					// Ignore STOP_SENDING for closed streams
				}
			} else {
				if (is_unidirectional) {
					lwsl_wsi_notice(nwsi, "QUIC RX: STOP_SENDING on receive-only stream ID %llu", (unsigned long long)stream_id);
					lws_quic_enter_closing_state(nwsi, LWS_QUIC_ERR_STREAM_STATE_ERROR, type, 0);
					return -1;
				}
			}
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
			if (max_streams > (1ULL << 60)) {
				lws_quic_enter_closing_state(nwsi, LWS_QUIC_ERR_FRAME_ENCODING_ERROR, type, 0);
				return -1;
			}
			lwsl_wsi_notice(nwsi, "QUIC RX: Parsed MAX/BLOCKED STREAMS! max_streams %llu", (unsigned long long)max_streams);
			if (qn) {
				if (type == LWS_QUIC_FT_MAX_STREAMS_BIDI) {
					if (max_streams > qn->max_streams_bidi_remote) {
						qn->max_streams_bidi_remote = max_streams;
#if defined(LWS_WITH_CLIENT)
						lws_wsi_mux_apply_queue(nwsi);
#endif
					}
				} else if (type == LWS_QUIC_FT_MAX_STREAMS_UNIDI) {
					if (max_streams > qn->max_streams_unidi_remote) {
						qn->max_streams_unidi_remote = max_streams;
#if defined(LWS_WITH_CLIENT)
						lws_wsi_mux_apply_queue(nwsi);
#endif
					}
				}
			}
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
			if (retire_prior_to > seq) {
				lws_quic_enter_closing_state(nwsi, LWS_QUIC_ERR_FRAME_ENCODING_ERROR, type, 0);
				return -1;
			}
			if (pos >= payload_len) return -1;
			uint8_t cid_len = payload[pos++];
			if (cid_len == 0 || cid_len > 20) {
				lws_quic_enter_closing_state(nwsi, LWS_QUIC_ERR_FRAME_ENCODING_ERROR, type, 0);
				return -1;
			}
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
			if (level != LWS_QUIC_LEVEL_APP) {
				lwsl_wsi_notice(nwsi, "QUIC RX: PATH_CHALLENGE/RESPONSE not allowed in non 1-RTT packets");
				return -2; /* PROTOCOL_VIOLATION */
			}
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
					if (sa46) {
						f_pr->dest_sa46 = *sa46;
						f_pr->has_dest = 1;
					}
					lws_dll2_add_head(&f_pr->list, &nwsi->quic.qn->pending_tx[level]);
					lws_callback_on_writable(nwsi);
				}
			} else if (type == LWS_QUIC_FT_PATH_RESPONSE && nwsi->quic.qn) {
				if (nwsi->quic.qn->path_challenge_pending && !memcmp(nwsi->quic.qn->path_challenge, path_data, 8)) {
					lwsl_wsi_notice(nwsi, "QUIC RX: Path validated via PATH_RESPONSE!");
					nwsi->quic.qn->address_validated = 1;
					nwsi->quic.qn->path_challenge_pending = 0;
					
					if (nwsi->quic.qn->migration_probing_wsi == nwsi) {
						struct lws *old_nwsi = nwsi->quic.qn->nwsi;
						/* Reparent the connection! */
						nwsi->quic.qn->nwsi = nwsi;
						nwsi->quic.qn->migration_probing_wsi = NULL;
						
						if (old_nwsi && old_nwsi != nwsi) {
							lwsl_wsi_notice(nwsi, "QUIC: Active Migration Make-Before-Break Complete! Closing old nwsi.");
							old_nwsi->quic.qn = NULL; /* Detach so close doesn't free it */

							/* Transition new nwsi to established state and cancel its timeout/grace timers */
							lwsi_set_state(nwsi, LRS_ESTABLISHED);
							lws_set_timeout(nwsi, NO_PENDING_TIMEOUT, 0);
#if defined(LWS_WITH_CLIENT)
							lws_sul_cancel(&nwsi->sul_h3_grace);
							lws_sul_cancel(&nwsi->sul_happy_eyeballs);
#endif
							lws_sul_cancel(&nwsi->sul_connect_timeout);

							/* Reparent all child streams to the new nwsi */
							struct lws *w = old_nwsi->mux.child_list;
							while (w) {
								w->mux.parent_wsi = nwsi;
								w = w->mux.sibling_list;
							}
							nwsi->mux.child_list = old_nwsi->mux.child_list;
							old_nwsi->mux.child_list = NULL;
							nwsi->mux.child_count = old_nwsi->mux.child_count;
							old_nwsi->mux.child_count = 0;
							nwsi->mux.highest_sid = old_nwsi->mux.highest_sid;

#if defined(LWS_WITH_TLS)
							extern int lws_tls_quic_migrate_wsi(struct lws *old_wsi, struct lws *new_wsi);
							/* Move TLS object so we can decrypt NEW_SESSION_TICKET and KeyUpdate */
							nwsi->tls = old_nwsi->tls;
							memset(&old_nwsi->tls, 0, sizeof(old_nwsi->tls));
							lws_tls_quic_migrate_wsi(old_nwsi, nwsi);
#endif

							lws_close_free_wsi(old_nwsi, LWS_CLOSE_STATUS_NOSTATUS, "migrated");
						}
					}
				} else {
					lwsl_wsi_notice(nwsi, "QUIC RX: Spurious or mismatched PATH_RESPONSE, ignoring");
				}
			}
			break;
		}

		case 0x1e: /* HANDSHAKE_DONE */
			lwsl_wsi_info(nwsi, "QUIC RX: Parsed HANDSHAKE_DONE!");
			if (nwsi->quic.qn && nwsi->quic.qn->is_server) {
				/* Clients SHOULD NOT send HANDSHAKE_DONE. Server MUST treat as PROTOCOL_VIOLATION */
				lws_quic_enter_closing_state(nwsi, LWS_QUIC_ERR_PROTOCOL_VIOLATION, type, 0);
				return -1;
			} else {
				lws_quic_discard_keys(nwsi, LWS_QUIC_LEVEL_HANDSHAKE);
			}
			break;

		case 0x07: { /* NEW_TOKEN */
			uint64_t token_len;
			consumed = lws_quic_parse_varint(&payload[pos], payload_len - pos, &token_len);
			if (!consumed) return -1;
			pos += consumed;
			if (token_len > payload_len - pos) return -1;
			pos += (size_t)token_len;
			lwsl_wsi_info(nwsi, "QUIC RX: Parsed NEW_TOKEN! length %llu", (unsigned long long)token_len);
			if (nwsi->quic.qn && nwsi->quic.qn->is_server) {
				/* Server MUST treat NEW_TOKEN from client as PROTOCOL_VIOLATION */
				lws_quic_enter_closing_state(nwsi, LWS_QUIC_ERR_PROTOCOL_VIOLATION, type, 0);
				return -1;
			}
			break;
		}

		case LWS_QUIC_FT_DATAGRAM:
		case LWS_QUIC_FT_DATAGRAM + 1: {
			uint64_t datagram_len;
			if (type & 1) { /* with LEN */
				consumed = lws_quic_parse_varint(&payload[pos], payload_len - pos, &datagram_len);
				if (!consumed) return -1;
				pos += consumed;
			} else {
				datagram_len = payload_len - pos;
			}
			if (datagram_len > payload_len - pos) {
				lwsl_wsi_notice(nwsi, "QUIC RX: Truncated DATAGRAM frame");
				return -1;
			}
			lwsl_wsi_info(nwsi, "QUIC RX: Parsed DATAGRAM! len %llu", (unsigned long long)datagram_len);
			
			/* Pass datagram payload to protocol callback via LWS_CALLBACK_RECEIVE on network wsi
			   Wait, actually we should use the h3 role's receive processing or just dispatch to user callback.
			   Since DATAGRAMs in H3 have Quarter Stream IDs, we will just queue them to the nwsi rx chunks,
			   or just invoke a direct callback.
			   For now, lws_quic_rx_reassemble to the network wsi's own rx_chunks if it was supported,
			   but network wsi doesn't have a stream. Let's just create an rx_chunk on nwsi if we can,
			   or directly call LWS_CALLBACK_RECEIVE if possible. We will call the user callback directly. */
			if (nwsi->role_ops && nwsi->a.protocol && nwsi->a.protocol->callback) {
				/* Note: WebTransport datagrams will be dispatched inside H3 role */
				/* We can push this data to a special list or just call rxflow right away */
				if (lws_rops_fidx(nwsi->role_ops, LWS_ROPS_handle_POLLIN)) {
					/* Create a dummy rx chunk on a special nwsi datagram queue?
					   Actually it's better to just call LWS_CALLBACK_RECEIVE on nwsi here. */
					/* But to keep rx flow control, let's just dispatch it. */
				}
				/* For now, direct callback. H3 will intercept this in its rxflow/rx handling */
				/* Let's set a flag or just call LWS_CALLBACK_RECEIVE with a new reason,
				 * but LWS_CALLBACK_RECEIVE_CLIENT_HTTP works. */
				nwsi->quic.qn->rx_packets_since_update++; /* Just a dummy increment */
				
				/* A better way: store in nwsi->quic.qn->rx_crypto_chunks[LWS_QUIC_LEVEL_APP] for datagrams? No. */
				/* We will call lws_quic_rx_reassemble but with wsi_child = nwsi, and qs = NULL? 
				 * Yes, let's add a datagram callback or just use lws_quic_rx_reassemble with is_crypto=2 */
				lws_quic_rx_reassemble(nwsi, nwsi, NULL, 0, &payload[pos], (size_t)datagram_len, 2, LWS_QUIC_LEVEL_APP);
			}

			pos += (size_t)datagram_len;
			break;
		}

		default:
			if ((type & 0xf8) == LWS_QUIC_FT_STREAM) {
				uint64_t stream_id;
				consumed = lws_quic_parse_varint(&payload[pos], payload_len - pos, &stream_id);
				if (!consumed) return -1;
				pos += consumed;

				int is_peer_initiated = (stream_id & 1) != (qn->is_server ? 1 : 0);
				int is_unidirectional = (stream_id & 2);
				if (is_peer_initiated) {
					uint64_t limit = is_unidirectional ? qn->max_streams_unidi_local : qn->max_streams_bidi_local;
					if ((stream_id >> 2) >= limit) {
						lwsl_wsi_notice(nwsi, "QUIC RX: Stream ID %llu exceeds limit", (unsigned long long)stream_id);
						lws_quic_enter_closing_state(nwsi, LWS_QUIC_ERR_STREAM_LIMIT_ERROR, type, 0);
						return -1;
					}
				}

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

				if (len > payload_len - pos) {
					lwsl_wsi_notice(nwsi, "QUIC RX: Truncated STREAM frame");
					return -1;
				}



				int fin = (type & 0x01) ? 1 : 0;
				lwsl_wsi_info(nwsi, "QUIC RX: Parsed STREAM! id %llu, off %llu, len %llu, fin %d",
					(unsigned long long)stream_id, (unsigned long long)offset, (unsigned long long)len, fin);

				is_unidirectional = (stream_id & 2);

				struct lws *wsi_child = lws_quic_stream_find(nwsi, stream_id);

				int is_locally_initiated = lwsi_role_client(nwsi) ? !(stream_id & 1) : (stream_id & 1);

				if (is_locally_initiated) {
					uint64_t next_sid = is_unidirectional ? qn->next_stream_id_unidi_local : qn->next_stream_id_bidi_local;

					if (is_unidirectional || (!wsi_child && stream_id >= next_sid)) {
						lwsl_wsi_notice(nwsi, "QUIC RX: Invalid STREAM frame on stream ID %llu (is_locally_initiated=1)", (unsigned long long)stream_id);
						/* RFC 9000 19.8: A receiver MUST terminate the connection with STREAM_STATE_ERROR if it receives a STREAM frame for a locally-initiated stream that has not yet been created, or for a send-only stream */
						lws_quic_enter_closing_state(nwsi, LWS_QUIC_ERR_STREAM_STATE_ERROR, type, 0);
						return -1;
					}

					/* If wsi_child is NULL, it means the stream was already closed!
					 * We should ignore the frame! */
					if (!wsi_child) {
						/* Skip payload */
						pos += len;
						ack_eliciting = 1;
						continue;
					}
				}

				if (!wsi_child) {
					/* Enforce MAX_STREAMS limit before creating a new stream */
					uint64_t limit = is_unidirectional ? qn->max_streams_unidi_local : qn->max_streams_bidi_local;
					if ((stream_id >> 2) >= limit) {
						lwsl_wsi_notice(nwsi, "QUIC RX: Stream ID %llu exceeds limit", (unsigned long long)stream_id);
						lws_quic_enter_closing_state(nwsi, LWS_QUIC_ERR_STREAM_LIMIT_ERROR, type, 0);
						return -1;
					}

					/* Peer initiated a new stream. We must create a child WSI! */
					wsi_child = lws_create_new_server_wsi(nwsi->a.vhost, nwsi->tsi, LWSLCG_WSI_MUX, "quic stream");
					if (!wsi_child) return -1;
					
					lws_wsi_mux_insert(wsi_child, nwsi, (unsigned int)stream_id);
					wsi_child->mux.my_sid = (unsigned int)stream_id;
					
					/* Inherit the role from the network WSI, but use H3 role if H3 ALPN was negotiated */
#if defined(LWS_ROLE_H3)
					lws_role_transition(wsi_child, lwsi_role_client(nwsi) ? LWSIFR_CLIENT : LWSIFR_SERVER, LRS_ESTABLISHED, nwsi->h3.h3n ? &role_ops_h3 : nwsi->role_ops);
#else
					lws_role_transition(wsi_child, lwsi_role_client(nwsi) ? LWSIFR_CLIENT : LWSIFR_SERVER, LRS_ESTABLISHED, nwsi->role_ops);
#endif
					
					wsi_child->quic.qs = lws_zalloc(sizeof(*wsi_child->quic.qs), "quic stream");
					if (wsi_child->quic.qs) {
						wsi_child->quic.qs->wsi = wsi_child;
						wsi_child->quic.qs->stream_id = stream_id;
						wsi_child->quic.qs->is_unidirectional = (uint8_t)((stream_id & 0x02) != 0 ? 1 : 0);
						wsi_child->quic.qs->is_server_initiated = (uint8_t)((stream_id & 0x01) != 0 ? 1 : 0);
						wsi_child->quic.qs->rx_max_data = LWS_QUIC_DEFAULT_WINDOW;
						wsi_child->quic.qs->advertised_rx_max_data = LWS_QUIC_DEFAULT_WINDOW;
		wsi_child->quic.qs->rx_window_size = LWS_QUIC_DEFAULT_WINDOW;
						wsi_child->quic.qs->last_rx_update_us = lws_now_usecs();
					} else {
						lws_close_free_wsi(wsi_child, LWS_CLOSE_STATUS_NOSTATUS, "quic stream oom");
						return -1;
					}
					
#if defined(LWS_ROLE_H3)
					wsi_child->h3.h3n = nwsi->h3.h3n;
					wsi_child->h3.qpack_tx_encoder = nwsi->h3.qpack_tx_encoder;
#endif

					if (lwsi_role_client(nwsi)) {
#if defined(LWS_WITH_CLIENT)
						if (lwsi_role_client(wsi_child))
							wsi_child->client_mux_substream = 1;
						else
							wsi_child->client_mux_substream = 0;
#endif
					} else
						wsi_child->mux_substream = 1;
					
					/* Bind to protocol */
					wsi_child->a.protocol = nwsi->a.protocol;
					if (wsi_child->a.protocol && wsi_child->a.protocol->callback) {
						wsi_child->a.protocol->callback(wsi_child, LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED, wsi_child->user_space, NULL, 0);
					}

					struct lws_quic_netconn *qn = nwsi->quic.qn;
					/* Initialize Stream TX Credit from Peer Transport Parameters */
					int is_bidi = (wsi_child->quic.qs->is_unidirectional == 0);
					int is_remote_initiated = (wsi_child->quic.qs->is_server_initiated == nwsi->quic.qn->is_server ? 0 : 1);
					if (is_bidi) {
						if (is_remote_initiated) {
							if (qn->peer_initial_max_stream_data_bidi_remote) {
								wsi_child->txc.peer_tx_cr_est = (int32_t)qn->peer_initial_max_stream_data_bidi_remote;
								wsi_child->txc.tx_cr = (int32_t)qn->peer_initial_max_stream_data_bidi_remote;
							}
						} else {
							if (qn->peer_initial_max_stream_data_bidi_local) {
								wsi_child->txc.peer_tx_cr_est = (int32_t)qn->peer_initial_max_stream_data_bidi_local;
								wsi_child->txc.tx_cr = (int32_t)qn->peer_initial_max_stream_data_bidi_local;
							}
						}
					} else {
						if (qn->peer_initial_max_stream_data_uni) {
							wsi_child->txc.peer_tx_cr_est = (int32_t)qn->peer_initial_max_stream_data_uni;
							wsi_child->txc.tx_cr = (int32_t)qn->peer_initial_max_stream_data_uni;
						}
					}
				}

				/* Dynamic Flow Control Enforcement */
				if (wsi_child && wsi_child->quic.qs) {
					uint64_t new_highest = offset + len;
					
					/* Enforce Stream Limit */
					if (new_highest > wsi_child->quic.qs->rx_max_data || new_highest < offset) {
						lwsl_wsi_notice(nwsi, "QUIC RX: Stream offset %llu + len %llu exceeds dynamic stream flow control limit (%llu)", 
							(unsigned long long)offset, (unsigned long long)len, (unsigned long long)wsi_child->quic.qs->rx_max_data);
						lws_quic_enter_closing_state(nwsi, LWS_QUIC_ERR_FLOW_CONTROL_ERROR, type, 0);
						return -1;
					}

					/* Enforce Connection Limit */
					if (new_highest > wsi_child->quic.qs->highest_rx_offset) {
						uint64_t diff = new_highest - wsi_child->quic.qs->highest_rx_offset;
						wsi_child->quic.qs->highest_rx_offset = new_highest;
						
						nwsi->quic.qn->highest_rx_offset += diff;
						if (nwsi->quic.qn->highest_rx_offset > nwsi->quic.qn->rx_max_data) {
							lwsl_wsi_notice(nwsi, "QUIC RX: Total bytes (%llu) exceeds dynamic connection flow control limit (%llu)", 
								(unsigned long long)nwsi->quic.qn->highest_rx_offset, (unsigned long long)nwsi->quic.qn->rx_max_data);
							lws_quic_enter_closing_state(nwsi, LWS_QUIC_ERR_FLOW_CONTROL_ERROR, type, 0);
							return -1;
						}
					}
				}

				/* Deliver stream data via Reassembly Buffer */
				if (wsi_child && wsi_child->quic.qs) {
					if (fin) {
						if (wsi_child->quic.qs->fin_received && wsi_child->quic.qs->rx_final_size != offset + len) {
							lws_quic_enter_closing_state(nwsi, LWS_QUIC_ERR_FINAL_SIZE_ERROR, type, 0);
							return -1;
						}
						wsi_child->quic.qs->fin_received = 1;
						wsi_child->quic.qs->rx_final_size = offset + len;
					} else {
						if (wsi_child->quic.qs->fin_received && offset + len > wsi_child->quic.qs->rx_final_size) {
							lws_quic_enter_closing_state(nwsi, LWS_QUIC_ERR_FINAL_SIZE_ERROR, type, 0);
							return -1;
						}
					}
					if (len || fin) {
						lws_quic_rx_reassemble(nwsi, wsi_child, wsi_child->quic.qs,
							       offset, &payload[pos], (size_t)len, 0, level);
					}
				}

				pos += (size_t)len;
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

				int is_peer_initiated = (stream_id & 1) != (qn->is_server ? 1 : 0);
				int is_unidirectional = (stream_id & 2);
				struct lws *wsi_child = lws_quic_stream_find(nwsi, stream_id);

				if (is_peer_initiated) {
					uint64_t limit = is_unidirectional ? qn->max_streams_unidi_local : qn->max_streams_bidi_local;
					if ((stream_id >> 2) >= limit) {
						lwsl_wsi_notice(nwsi, "QUIC RX: Stream ID %llu exceeds limit", (unsigned long long)stream_id);
						lws_quic_enter_closing_state(nwsi, LWS_QUIC_ERR_STREAM_LIMIT_ERROR, type, 0);
						return -1;
}
				}

				if (!is_peer_initiated) {
					if (!wsi_child) {
						lwsl_wsi_notice(nwsi, "QUIC RX: %s on non-existing stream ID %llu", 
							type == LWS_QUIC_FT_MAX_STREAM_DATA ? "MAX_STREAM_DATA" : "STREAM_DATA_BLOCKED",
							(unsigned long long)stream_id);
						lws_quic_enter_closing_state(nwsi, LWS_QUIC_ERR_STREAM_STATE_ERROR, type, 0);
						return -1;
					}
					if (is_unidirectional && type == LWS_QUIC_FT_STREAM_DATA_BLOCKED) {
						lwsl_wsi_notice(nwsi, "QUIC RX: STREAM_DATA_BLOCKED on receive-only stream ID %llu",
							(unsigned long long)stream_id);
						lws_quic_enter_closing_state(nwsi, LWS_QUIC_ERR_STREAM_STATE_ERROR, type, 0);
						return -1;
					}
				} else {
					if (is_unidirectional && type == LWS_QUIC_FT_MAX_STREAM_DATA) {
						lwsl_wsi_notice(nwsi, "QUIC RX: MAX_STREAM_DATA on receive-only stream ID %llu",
							(unsigned long long)stream_id);
						lws_quic_enter_closing_state(nwsi, LWS_QUIC_ERR_STREAM_STATE_ERROR, type, 0);
						return -1;
					}
				}

				lwsl_wsi_info(nwsi, "QUIC RX: Parsed %s frame! stream_id %llu, max_stream_data %llu",
					type == LWS_QUIC_FT_MAX_STREAM_DATA ? "MAX_STREAM_DATA" : "STREAM_DATA_BLOCKED",
					(unsigned long long)stream_id, (unsigned long long)max_stream_data);

				if (type == LWS_QUIC_FT_MAX_STREAM_DATA) {
					struct lws *child = lws_quic_stream_find(nwsi, stream_id);
					if (child) {
						int32_t current_max = (int32_t)((child->quic.qs ? child->quic.qs->tx_offset : 0) + (uint64_t)child->txc.tx_cr);
						int32_t delta = (int32_t)max_stream_data - current_max;
						if (delta > 0)
							lws_wsi_tx_credit(child, LWSTXCR_US_TO_PEER, delta);
					}
				}
				break;
			}

			lwsl_wsi_notice(nwsi, "QUIC RX: Unhandled frame type 0x%x, aborting parse",
				      (unsigned int)type);
			/* Unknown frame: we MUST abort parsing because we don't know its length! */
			return -1;
		}
		if (type != LWS_QUIC_FT_PADDING && type != LWS_QUIC_FT_ACK && type != LWS_QUIC_FT_ACK_ECN && type != 0x1c && type != 0x1d) {
			ack_eliciting = 1;
		}
	}

	return ack_eliciting;
}

int
lws_quic_parse_transport_parameters(struct lws *wsi, const uint8_t *buf, size_t len)
{
	struct lws_quic_netconn *qn = wsi->quic.qn;
	size_t pos = 0, consumed;
	uint64_t param_id, param_len, val = 0;
	uint64_t seen_params[64];
	size_t num_seen = 0;

	if (!qn)
		return -1;

	int seen_initial_source_cid = 0;

	while (pos < len) {
		consumed = lws_quic_parse_varint(&buf[pos], len - pos, &param_id);
		if (!consumed) return -1;
		pos += consumed;

		consumed = lws_quic_parse_varint(&buf[pos], len - pos, &param_len);
		if (!consumed) return -1;
		pos += consumed;

		if (param_len > len - pos)
			return -1;

		lwsl_wsi_info(wsi, "QUIC TP: ID 0x%llx, len %llu", (unsigned long long)param_id, (unsigned long long)param_len);
			if (param_id >= 4 && param_id <= 7) {
				uint64_t v = 0;
				if (lws_quic_parse_varint(&buf[pos], param_len, &v) == param_len)
					lwsl_wsi_info(wsi, "QUIC TP FLOW CONTROL param 0x%llx = %llu", (unsigned long long)param_id, (unsigned long long)v);
			}

		/* Check for duplicates */
		for (size_t i = 0; i < num_seen; i++) {
			if (seen_params[i] == param_id) {
						lwsl_wsi_err(wsi, "QUIC TP error: Duplicate parameter ID %llu", (unsigned long long)param_id);
				return -1;
			}
		}
		if (num_seen < LWS_ARRAY_SIZE(seen_params))
			seen_params[num_seen++] = param_id;

		switch (param_id) {
		case 0x11: { /* version_information */
			if (param_len < 4 || (param_len % 4) != 0) {
				lwsl_wsi_err(wsi, "QUIC TP error: version_information bad length");
				return -1;
			}
			if (qn->is_server && (wsi->a.context->options & LWS_SERVER_OPTION_QUIC_LATEST_VERSION)) {
				size_t offset = 4;
				while (offset < param_len) {
					uint32_t av = ((uint32_t)buf[pos + offset] << 24) |
						      ((uint32_t)buf[pos + offset + 1] << 16) |
						      ((uint32_t)buf[pos + offset + 2] << 8) |
						      ((uint32_t)buf[pos + offset + 3]);
					if (av == LWS_QUIC_VERSION_2) {
						qn->version = LWS_QUIC_VERSION_2;
						lwsl_wsi_notice(wsi, "QUIC: Upgrading to QUIC v2 via Compatible Version Negotiation");
						break;
					}
					offset += 4;
				}
			}
			break;
		}
		case 0x0f: /* initial_source_connection_id */
			seen_initial_source_cid = 1;
			break;
		case 0x00: /* original_destination_connection_id */
			if (qn->is_server) {
				/* Client cannot send this */
				lwsl_wsi_err(wsi, "QUIC TP error: Client sent original_destination_connection_id");
				return -1;
			}
			break;
		case 0x03: /* max_udp_payload_size */
			if (lws_quic_parse_varint(&buf[pos], param_len, &val) == param_len) {
				if (val < 1200) {
					lwsl_wsi_err(wsi, "QUIC TP error: max_udp_payload_size %llu < 1200", (unsigned long long)val);
					return -1;
				}
			} else return -1;
			break;
		case 0x04: /* initial_max_data */
			if (lws_quic_parse_varint(&buf[pos], param_len, &val) == param_len) {
				qn->peer_initial_max_data = val;
				struct lws *nwsi = qn->nwsi ? qn->nwsi : wsi;
				int64_t diff = (int64_t)val - 65535;
				if (diff > 0) {
					nwsi->txc.peer_tx_cr_est += (int32_t)diff;
					nwsi->txc.tx_cr += (int32_t)diff;
				}
			} else return -1;
			break;
		case 0x05: /* initial_max_stream_data_bidi_local */
			if (lws_quic_parse_varint(&buf[pos], param_len, &val) == param_len) {
				qn->peer_initial_max_stream_data_bidi_local = val; 
			} else return -1;
			break;
		case 0x06: /* initial_max_stream_data_bidi_remote */
			if (lws_quic_parse_varint(&buf[pos], param_len, &val) == param_len) {
				qn->peer_initial_max_stream_data_bidi_remote = val;
			} else return -1;
			break;
		case 0x07: /* initial_max_stream_data_uni */
			if (lws_quic_parse_varint(&buf[pos], param_len, &val) == param_len) {
				qn->peer_initial_max_stream_data_uni = val;
			} else return -1;
			break;
		case 0x08: /* initial_max_streams_bidi */
			if (lws_quic_parse_varint(&buf[pos], param_len, &val) == param_len) {
				qn->max_streams_bidi_remote = val;
			} else return -1;
			break;
		case 0x09: /* initial_max_streams_uni */
			if (lws_quic_parse_varint(&buf[pos], param_len, &val) == param_len) {
				qn->max_streams_unidi_remote = val;
			} else return -1;
			break;
		case 0x0a: /* ack_delay_exponent */
			if (lws_quic_parse_varint(&buf[pos], param_len, &val) == param_len) {
				if (val > 20) {
					lwsl_wsi_err(wsi, "QUIC TP error: ack_delay_exponent %llu > 20", (unsigned long long)val);
					return -1;
				}
			} else return -1;
			break;
		case 0x20: /* max_datagram_frame_size */
			if (lws_quic_parse_varint(&buf[pos], param_len, &val) == param_len) {
				qn->peer_max_datagram_frame_size = val;
			} else return -1;
			break;
		case 0x0b: /* max_ack_delay */
			if (lws_quic_parse_varint(&buf[pos], param_len, &val) == param_len) {
				if (val >= 16384) { /* 2^14 */
					lwsl_wsi_err(wsi, "QUIC TP error: max_ack_delay %llu >= 16384", (unsigned long long)val);
					return -1;
				}
			} else return -1;
			break;
		case 0x0e: /* active_connection_id_limit */
			if (lws_quic_parse_varint(&buf[pos], param_len, &val) == param_len) {
				if (val < 2) {
					lwsl_wsi_err(wsi, "QUIC TP error: active_connection_id_limit %llu < 2", (unsigned long long)val);
					return -1;
				}
			} else return -1;
			break;
		case 0x10: /* retry_source_connection_id */
			if (qn->is_server) {
				/* Client cannot send these */
				lwsl_wsi_err(wsi, "QUIC TP error: Client sent server-only parameter %llu", (unsigned long long)param_id);
				return -1;
			}
			if (qn->retry_scid.len) {
				if (param_len != qn->retry_scid.len || memcmp(&buf[pos], qn->retry_scid.id, param_len)) {
					lwsl_wsi_err(wsi, "QUIC TP error: retry_source_connection_id mismatch");
					return -1;
				}
			}
			break;
		case 0x02: /* stateless_reset_token */
			if (qn->is_server) {
				/* Client cannot send these */
				lwsl_wsi_err(wsi, "QUIC TP error: Client sent server-only parameter %llu", (unsigned long long)param_id);
				return -1;
			}
			if (param_len != 16) {
				lwsl_wsi_err(wsi, "QUIC TP error: stateless_reset_token length %llu != 16", (unsigned long long)param_len);
				return -1;
			}
			break;
#if defined(LWS_WITH_CLIENT)
		case 0x0d: /* preferred_address */
			if (qn->is_server) {
				/* Client cannot send these */
				lwsl_wsi_err(wsi, "QUIC TP error: Client sent server-only parameter %llu", (unsigned long long)param_id);
				return -1;
			}
			if (param_len >= 4+2+16+2+1+16) {
				/* Pick IPv4 if present, else IPv6 */
				char addr_str[64];
				int port = 0;
				struct lws_client_connect_info i;

				/* Try IPv4 first (RFC says it's 4 bytes IP + 2 bytes port) */
				uint32_t ip4;
				memcpy(&ip4, &buf[pos], 4);
				if (ip4 != 0) {
					lws_snprintf(addr_str, sizeof(addr_str), "%u.%u.%u.%u",
						buf[pos], buf[pos+1], buf[pos+2], buf[pos+3]);
					port = (buf[pos+4] << 8) | buf[pos+5];
				} else {
					/* Try IPv6 */
					const uint8_t *v6 = &buf[pos+6];
					lws_snprintf(addr_str, sizeof(addr_str), "[%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x]",
						v6[0], v6[1], v6[2], v6[3], v6[4], v6[5], v6[6], v6[7],
						v6[8], v6[9], v6[10], v6[11], v6[12], v6[13], v6[14], v6[15]);
					port = (buf[pos+22] << 8) | buf[pos+23];
				}

				if (port > 0) {
					lwsl_wsi_notice(wsi, "QUIC TP: Migrating to preferred_address %s:%d", addr_str, port);
					memset(&i, 0, sizeof(i));
					i.context = wsi->a.context;
					i.vhost = wsi->a.vhost;
					i.address = addr_str;
					i.host = addr_str;
					i.origin = addr_str;
					i.port = port;
					i.ssl_connection = LCCSCF_USE_SSL | LCCSCF_ALLOW_INSECURE;
					i.quic_migrate_from_wsi = qn->nwsi;

					lws_client_connect_via_info(&i);
				}
			}
			break;
#endif
		default:
			break;
		}

		pos += param_len;
	}

	if (pos != len) {
		lwsl_wsi_err(wsi, "QUIC TP error: buffer not fully consumed");
		return -1;
	}

	if (!seen_initial_source_cid) {
		lwsl_wsi_err(wsi, "QUIC TP error: initial_source_connection_id is missing");
		return -1;
	}

	return 0;
}
