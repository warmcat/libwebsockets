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

extern const struct lws_role_ops role_ops_h3;

static const uint8_t quic_v1_initial_salt[20] = {
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
	0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
	0xcc, 0xbb, 0x7f, 0x0a
};

static const uint8_t quic_v2_initial_salt[20] = {
	0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb,
	0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
	0xf9, 0xbd, 0x2e, 0xd9
};

/*
 * RFC 9001 5.3 / 5.4: the QUIC packet-protection AEAD and the header-protection
 * cipher are both fixed by the negotiated TLS 1.3 cipher suite:
 *
 *   TLS_AES_128_GCM_SHA256       -> AEAD AES-128-GCM,       HP AES-128-ECB
 *   TLS_AES_256_GCM_SHA384       -> AEAD AES-256-GCM,       HP AES-256-ECB
 *   TLS_CHACHA20_POLY1305_SHA256 -> AEAD ChaCha20-Poly1305, HP ChaCha20
 *
 * They must NOT be inferred from the traffic-secret length: AES-128-GCM and
 * ChaCha20-Poly1305 both use SHA-256, so both yield a 32-byte secret.  The TLS
 * backend reports the negotiated AEAD in wsi->tls.quic_aead; only when it did
 * not (LWS_TLS_QUIC_AEAD_UNKNOWN, e.g. a backend that doesn't plumb it through)
 * do we fall back to the length heuristic, which can still tell AES-256-GCM
 * (48-byte / SHA-384) from AES-128-GCM but is blind to ChaCha20.
 *
 * Maps to the internal cipher_type used throughout this file:
 *   0 = AES-128-GCM, 1 = ChaCha20-Poly1305, 2 = AES-256-GCM.
 */
static uint8_t
lws_quic_cipher_type(struct lws *wsi, size_t secret_len)
{
	switch (wsi->tls.quic_aead) {
	case LWS_TLS_QUIC_AEAD_AES_128_GCM:
		return 0;
	case LWS_TLS_QUIC_AEAD_CHACHA20_POLY1305:
		return 1;
	case LWS_TLS_QUIC_AEAD_AES_256_GCM:
		return 2;
	default:
		return (secret_len == 48) ? 2 : 0;
	}
}

static int
lws_quic_derive_key_iv_hp(uint8_t *secret, size_t secret_len, uint8_t cipher_type,
			  uint8_t *iv, size_t iv_len,
			  struct lws_gencrypto_keyelem *el_aead, uint8_t *key_aead,
			  struct lws_gencrypto_keyelem *el_hp, uint8_t *key_hp)
{
	int ret = -1;
	size_t key_len = (cipher_type == 1 || cipher_type == 2) ? 32 : 16;
	enum lws_genhmac_types hash_type = (secret_len == 48) ? LWS_GENHMAC_TYPE_SHA384 : LWS_GENHMAC_TYPE_SHA256;

	/* 1. Derive "quic key" */
	if (lws_genhkdf_expand_label(hash_type, secret, secret_len,
				     "quic key", NULL, 0, key_aead, key_len))
		goto bail;

	/* 2. Derive "quic iv" (12 bytes) */
	if (lws_genhkdf_expand_label(hash_type, secret, secret_len,
				     "quic iv", NULL, 0, iv, iv_len))
		goto bail;

	/* 3. Derive "quic hp" */
	if (lws_genhkdf_expand_label(hash_type, secret, secret_len,
				     "quic hp", NULL, 0, key_hp, key_len))
		goto bail;

	el_aead->buf = key_aead;
	el_aead->len = (uint32_t)key_len;

	el_hp->buf = key_hp;
	el_hp->len = (uint32_t)key_len;

	ret = 0;
bail:
	return ret;
}

int
lws_quic_derive_initial_keys(struct lws *wsi, const struct lws_quic_cid *dcid)
{
	struct lws_quic_netconn *qn = wsi->quic.qn;
	uint8_t initial_secret[32];
	uint8_t client_secret[32];
	uint8_t server_secret[32];
	struct lws_quic_keys *k;
	int ret = -1;

	const uint8_t *salt;
	size_t salt_len;

	if (!qn)
		return -1;
	k = lws_zalloc(sizeof(*k), "quic_keys_initial");
	if (!k)
		return -1;

	if (wsi->quic.qn->original_version == LWS_QUIC_VERSION_2) {
		salt = quic_v2_initial_salt;
		salt_len = sizeof(quic_v2_initial_salt);
	} else {
		salt = quic_v1_initial_salt;
		salt_len = sizeof(quic_v1_initial_salt);
	}

	/* 1. Extract Initial Secret from DCID and Fixed Salt */
	if (lws_genhkdf_extract(LWS_GENHMAC_TYPE_SHA256, salt,
				salt_len, dcid->id, dcid->len,
				initial_secret))
		goto bail;

	/* 2. Expand into Client and Server Secrets */
	if (lws_genhkdf_expand_label(LWS_GENHMAC_TYPE_SHA256, initial_secret,
				     sizeof(initial_secret), "client in", NULL, 0,
				     client_secret, sizeof(client_secret)))
		goto bail;

	if (lws_genhkdf_expand_label(LWS_GENHMAC_TYPE_SHA256, initial_secret,
				     sizeof(initial_secret), "server in", NULL, 0,
				     server_secret, sizeof(server_secret)))
		goto bail;

	/* 3. Derive Key, IV, and HP context for both directions */
	if (qn->is_server) {
		/* Server RX is Client secret, TX is Server secret */
		if (lws_quic_derive_key_iv_hp(client_secret, 32, 0, k->iv_rx, sizeof(k->iv_rx),
					      &k->el_aead_rx, k->key_aead_rx, &k->el_hp_rx, k->key_hp_rx))
			goto bail;
		if (lws_quic_derive_key_iv_hp(server_secret, 32, 0, k->iv_tx, sizeof(k->iv_tx),
					      &k->el_aead_tx, k->key_aead_tx, &k->el_hp_tx, k->key_hp_tx))
			goto bail;
	} else {
		/* Client RX is Server secret, TX is Client secret */
		if (lws_quic_derive_key_iv_hp(server_secret, 32, 0, k->iv_rx, sizeof(k->iv_rx),
					      &k->el_aead_rx, k->key_aead_rx, &k->el_hp_rx, k->key_hp_rx))
			goto bail;
		if (lws_quic_derive_key_iv_hp(client_secret, 32, 0, k->iv_tx, sizeof(k->iv_tx),
					      &k->el_aead_tx, k->key_aead_tx, &k->el_hp_tx, k->key_hp_tx))
			goto bail;
	}
	k->valid = 1;

	qn->keys[LWS_QUIC_LEVEL_INITIAL] = k;

	ret = 0;

bail:
	lws_explicit_bzero(initial_secret, sizeof(initial_secret));
	lws_explicit_bzero(client_secret, sizeof(client_secret));
	lws_explicit_bzero(server_secret, sizeof(server_secret));

	if (ret) {
		lws_free(k);
	}

	return ret;
}

int
lws_quic_initiate_key_update(struct lws *wsi)
{
	struct lws *nwsi = lws_get_quic_network_wsi(wsi);
	struct lws_quic_netconn *qn;

	if (!nwsi || !nwsi->quic.qn)
		return -1;
	
	qn = nwsi->quic.qn;
	
	/* We only update keys if the handshake is done and we have APP keys */
	if (!qn->handshake_done || !qn->keys[LWS_QUIC_LEVEL_APP]) {
		lwsl_wsi_notice(wsi, "QUIC Key Update failed: handshake_done=%d, app_keys=%p",
			qn->handshake_done, qn->keys[LWS_QUIC_LEVEL_APP]);
		return -1;
	}
		
	/* If an update is already pending, wait for it to be echoed/completed */
	if (qn->key_update_pending) {
		lwsl_wsi_notice(wsi, "QUIC Key Update ignored: pending");
		return -1;
	}

	/* Derive the new TX keys */
	if (lws_quic_update_keys(qn->keys[LWS_QUIC_LEVEL_APP], 0)) {
		lwsl_wsi_err(wsi, "QUIC Key Update failed: lws_quic_update_keys error");
		return -1;
	}
		
	/* Flip the TX key phase bit */
	qn->tx_key_phase ^= 1;
	
	/* Mark that we initiated it, so we expect the peer to echo it back in RX */
	qn->key_update_pending = 1;
	
	/* Reset the packet counter for AEAD limits */
	qn->tx_packets_since_update = 0;

	lwsl_wsi_notice(wsi, "QUIC TX: Key Update Initiated! tx_key_phase is now %d", qn->tx_key_phase);

	return 0;
}

int
lws_quic_set_keys(struct lws *wsi, enum lws_tls_quic_secret_type type, const uint8_t *secret, size_t secret_len)
{
	struct lws_quic_netconn *qn = wsi->quic.qn;
	struct lws_quic_keys *k;
	int level = LWS_QUIC_LEVEL_APP;
	int is_rx = 0;

	if (!qn)
		return -1;





	/* Determine level and direction */
	switch (type) {
	case LWS_TLS_QUIC_SECRET_CLIENT_EARLY:
		level = LWS_QUIC_LEVEL_EARLY;
		is_rx = qn->is_server ? 1 : 0;
		// lwsl_notice("lws_quic_set_keys: CLIENT_EARLY (is_rx=%d, len=%d)\n", is_rx, (int)secret_len);
		break;
	case LWS_TLS_QUIC_SECRET_CLIENT_HANDSHAKE:
		level = LWS_QUIC_LEVEL_HANDSHAKE;
		is_rx = qn->is_server ? 1 : 0;
		// lwsl_notice("lws_quic_set_keys: CLIENT_HANDSHAKE (is_rx=%d, len=%d)\n", is_rx, (int)secret_len);
		break;
	case LWS_TLS_QUIC_SECRET_SERVER_HANDSHAKE:
		level = LWS_QUIC_LEVEL_HANDSHAKE;
		is_rx = qn->is_server ? 0 : 1;
		// lwsl_notice("lws_quic_set_keys: SERVER_HANDSHAKE (is_rx=%d, len=%d)\n", is_rx, (int)secret_len);
		break;
	case LWS_TLS_QUIC_SECRET_CLIENT_APPLICATION:
		level = LWS_QUIC_LEVEL_APP;
		is_rx = qn->is_server ? 1 : 0;
		// lwsl_notice("lws_quic_set_keys: CLIENT_APP (is_rx=%d, len=%d)\n", is_rx, (int)secret_len);
		break;
	case LWS_TLS_QUIC_SECRET_SERVER_APPLICATION:
		level = LWS_QUIC_LEVEL_APP;
		is_rx = qn->is_server ? 0 : 1;
		// lwsl_notice("lws_quic_set_keys: SERVER_APP (is_rx=%d, len=%d)\n", is_rx, (int)secret_len);
		break;
	default:
		return -1;
	}

	if (!qn->keys[level]) {
		k = lws_zalloc(sizeof(*k), "quic_keys");
		if (!k) return -1;
		qn->keys[level] = k;

		/* Inherit packet number spaces between 0-RTT and 1-RTT */
		if (level == LWS_QUIC_LEVEL_APP && qn->keys[LWS_QUIC_LEVEL_EARLY]) {
			k->pn_tx = qn->keys[LWS_QUIC_LEVEL_EARLY]->pn_tx;
		}
	} else {
		k = qn->keys[level];
	}

        if (is_rx) {
                if (level == LWS_QUIC_LEVEL_APP && k->valid && k->secret_rx[0]) {
                        lwsl_notice("%s: ignoring post-handshake TLS secret_rx update for APP level\n", __func__);
                        return 0;
                }
                k->secret_len = secret_len > 48 ? 48 : secret_len;
                memcpy(k->secret_rx, secret, k->secret_len);
                k->cipher_type = lws_quic_cipher_type(wsi, k->secret_len);
                if (lws_quic_derive_key_iv_hp(k->secret_rx, k->secret_len, k->cipher_type, k->iv_rx, sizeof(k->iv_rx),
                                              &k->el_aead_rx, k->key_aead_rx, &k->el_hp_rx, k->key_hp_rx))
                        return -1;
        } else {
                if (level == LWS_QUIC_LEVEL_APP && k->valid && k->secret_tx[0]) {
                        lwsl_notice("%s: ignoring post-handshake TLS secret_tx update for APP level\n", __func__);
                        return 0;
                }
                k->secret_len = secret_len > 48 ? 48 : secret_len;
                memcpy(k->secret_tx, secret, k->secret_len);
                k->cipher_type = lws_quic_cipher_type(wsi, k->secret_len);
                if (lws_quic_derive_key_iv_hp(k->secret_tx, k->secret_len, k->cipher_type, k->iv_tx, sizeof(k->iv_tx),
                                              &k->el_aead_tx, k->key_aead_tx, &k->el_hp_tx, k->key_hp_tx))
                        return -1;
        }

	/* We mark it valid once BOTH directions are derived (or if we only need one direction for early data) */
	/* For simplicity, we just mark valid and rely on tx/rx logic */
	k->valid = 1;

#if defined(LWS_WITH_CLIENT)
	/* If this is the client deriving the early secret, check if the stream opts in */
	if (type == LWS_TLS_QUIC_SECRET_CLIENT_EARLY && !qn->is_server) {
		qn->early_data_status = LWS_0RTT_STATUS_ATTEMPTED;

		/* Trigger ALPN migration immediately to create nwsi and transition wsi to h3 */
		lws_role_call_alpn_negotiated(wsi, "h3");

		struct lws *nwsi = lws_get_network_wsi(wsi);
		if (nwsi) {
			lws_wsi_mux_apply_queue(nwsi);
			struct lws *w = nwsi->mux.child_list;
			while (w) {
				if (w->a.protocol && w->a.protocol->callback) {
					int ret = w->a.protocol->callback(w,
							LWS_CALLBACK_CLIENT_ESTABLISHED_EARLY,
							w->user_space, NULL, 0);
					if (ret == 1) {
						lwsl_wsi_notice(w, "Stream %s opted into 0-RTT", lws_wsi_tag(w));
						
						if (!w->quic.qs) {
							w->quic.qs = lws_zalloc(sizeof(*w->quic.qs), "quic stream");
							if (w->quic.qs) {
								w->quic.qs->wsi = w;
								w->quic.qs->stream_id = (w == wsi) ? 0 : w->mux.my_sid;
								w->quic.qs->rx_max_data = LWS_QUIC_DEFAULT_WINDOW;
								w->quic.qs->advertised_rx_max_data = LWS_QUIC_DEFAULT_WINDOW;
								w->quic.qs->rx_window_size = LWS_QUIC_DEFAULT_WINDOW;
								w->quic.qs->last_rx_update_us = lws_now_usecs();
							}
						}

						lws_role_transition(w, LWSIFR_CLIENT, LRS_H2_WAITING_TO_SEND_HEADERS, &role_ops_h3);

						if (w->quic.qs)
							w->quic.qs->opted_into_early_data = 1;

						lws_callback_on_writable(w);
					} else {
						lwsl_wsi_notice(w, "Stream %s ignored 0-RTT", lws_wsi_tag(w));
					}
				}
				w = w->mux.sibling_list;
			}
		}
	} else
#endif
	if (type == LWS_TLS_QUIC_SECRET_CLIENT_EARLY && qn->is_server) {
		qn->early_data_status = LWS_0RTT_STATUS_ACCEPTED;
		
		/* On server, migrate connection to H3 immediately to support 0-RTT stream adoption */
		const unsigned char *prot = NULL;
		unsigned int plen = 0;
#if defined(LWS_WITH_GNUTLS)
		gnutls_datum_t dt;
		if (gnutls_alpn_get_selected_protocol(wsi->tls.ssl, &dt) >= 0) {
			prot = dt.data;
			plen = dt.size;
		}
#endif
		if (plen) {
			lws_strncpy(wsi->alpn, (const char *)prot, plen + 1);
		} else {
			lws_strncpy(wsi->alpn, "h3", sizeof(wsi->alpn));
		}
		lwsl_wsi_notice(wsi, "QUIC Server 0-RTT ALPN: %s", wsi->alpn);
		lws_role_call_alpn_negotiated(wsi, wsi->alpn);
	}

	return 0;
}

void
lws_quic_keys_destroy(struct lws_quic_keys *keys)
{
        if (!keys) return;

#if defined(LWS_WITH_GNUTLS)
        if (keys->aead_rx)
                gnutls_aead_cipher_deinit((gnutls_aead_cipher_hd_t)keys->aead_rx);
        if (keys->aead_tx)
                gnutls_aead_cipher_deinit((gnutls_aead_cipher_hd_t)keys->aead_tx);
#endif

        lws_explicit_bzero(keys, sizeof(*keys));
        lws_free(keys);
}

void lws_quic_keys_release_aead_rx(struct lws_quic_keys *keys) {
#if defined(LWS_WITH_GNUTLS)
        if (keys->aead_rx) {
                gnutls_aead_cipher_deinit((gnutls_aead_cipher_hd_t)keys->aead_rx);
                keys->aead_rx = NULL;
        }
#endif
}

void lws_quic_keys_release_aead_tx(struct lws_quic_keys *keys) {
#if defined(LWS_WITH_GNUTLS)
        if (keys->aead_tx) {
                gnutls_aead_cipher_deinit((gnutls_aead_cipher_hd_t)keys->aead_tx);
                keys->aead_tx = NULL;
        }
#endif
}

int
lws_quic_update_keys(struct lws_quic_keys *k, int is_rx)
{
	uint8_t new_secret[48];

	size_t key_len = (k->cipher_type == 0) ? 16 : 32;

	if (is_rx) {
                enum lws_genhmac_types hash_type = (k->secret_len == 48) ? LWS_GENHMAC_TYPE_SHA384 : LWS_GENHMAC_TYPE_SHA256;
                if (lws_genhkdf_expand_label(hash_type, k->secret_rx, k->secret_len, "quic ku", NULL, 0, new_secret, k->secret_len)) return -1;
                memcpy(k->secret_rx, new_secret, k->secret_len);

                if (lws_genhkdf_expand_label(hash_type, new_secret, k->secret_len, "quic key", NULL, 0, k->key_aead_rx, key_len)) return -1;
                if (lws_genhkdf_expand_label(hash_type, new_secret, k->secret_len, "quic iv", NULL, 0, k->iv_rx, 12)) return -1;

                k->el_aead_rx.buf = k->key_aead_rx;
                k->el_aead_rx.len = (uint32_t)key_len;
#if defined(LWS_WITH_GNUTLS)
                if (k->aead_rx) {
                        gnutls_aead_cipher_deinit((gnutls_aead_cipher_hd_t)k->aead_rx);
                        k->aead_rx = NULL;
                }
#endif
        } else {
                enum lws_genhmac_types hash_type = (k->secret_len == 48) ? LWS_GENHMAC_TYPE_SHA384 : LWS_GENHMAC_TYPE_SHA256;
                if (lws_genhkdf_expand_label(hash_type, k->secret_tx, k->secret_len, "quic ku", NULL, 0, new_secret, k->secret_len)) return -1;
                memcpy(k->secret_tx, new_secret, k->secret_len);

                if (lws_genhkdf_expand_label(hash_type, new_secret, k->secret_len, "quic key", NULL, 0, k->key_aead_tx, key_len)) return -1;
                if (lws_genhkdf_expand_label(hash_type, new_secret, k->secret_len, "quic iv", NULL, 0, k->iv_tx, 12)) return -1;

                k->el_aead_tx.buf = k->key_aead_tx;
                k->el_aead_tx.len = (uint32_t)key_len;
#if defined(LWS_WITH_GNUTLS)
                if (k->aead_tx) {
                        gnutls_aead_cipher_deinit((gnutls_aead_cipher_hd_t)k->aead_tx);
                        k->aead_tx = NULL;
                }
#endif
        }

	lws_explicit_bzero(new_secret, sizeof(new_secret));
	return 0;
}

int
lws_quic_unmask_header(struct lws_quic_keys *keys, uint8_t *packet, size_t packet_len, size_t pn_offset)
{
	uint8_t sample[16], mask[16];
	size_t sample_offset = pn_offset + 4;
	uint8_t pn_len;

	if (sample_offset + 16 > packet_len)
		{ lwsl_notice("unmask: Truncated\n"); return -1; }

	memcpy(sample, &packet[sample_offset], 16);

	if (keys->cipher_type == 0 || keys->cipher_type == 2) {
		/* AES-GCM uses AES-ECB for Header Protection */
		struct lws_genaes_ctx hp;
		if (lws_genaes_create(&hp, LWS_GAESO_ENC, LWS_GAESM_ECB, &keys->el_hp_rx, LWS_GAESP_NO_PADDING, NULL)) {
                        lwsl_notice("unmask: genaes_create failed, el_hp_rx.len=%d, cipher_type=%d, valid=%d, el_aead_rx.len=%d\n", (int)keys->el_hp_rx.len, (int)keys->cipher_type, (int)keys->valid, (int)keys->el_aead_rx.len);
                        return -1;
                }
		if (lws_genaes_crypt(&hp, sample, 16, mask, NULL, NULL, NULL, 0)) {
                        lwsl_notice("unmask: genaes_crypt failed\n");
			lws_genaes_destroy(&hp, NULL, 0);
			return -1;
		}
		lws_genaes_destroy(&hp, NULL, 0);
	} else {
		/* ChaCha20-Poly1305 uses ChaCha20 for Header Protection */
		struct lws_genchacha_ctx hp;
		if (lws_genchacha_create(&hp, LWS_GAESO_ENC, &keys->el_hp_rx, NULL))
			return -1;
		uint8_t zeroes[5] = {0};
		if (lws_genchacha_stream(&hp, zeroes, 5, mask, sample, 16)) {
			lws_genchacha_destroy(&hp);
			return -1;
		}
		lws_genchacha_destroy(&hp);
	}

	/* Apply the mask to the first byte */
	if (packet[0] & 0x80)
		packet[0] ^= (mask[0] & 0x0f); /* Long header */
	else
		packet[0] ^= (mask[0] & 0x1f); /* Short header */

	/* Extract the unmasked PN length (bottom 2 bits + 1) */
	pn_len = (packet[0] & 0x03) + 1;

	/* Apply the mask to the packet number bytes */
	if (pn_len >= 1) packet[pn_offset]     ^= mask[1];
	if (pn_len >= 2) packet[pn_offset + 1] ^= mask[2];
	if (pn_len >= 3) packet[pn_offset + 2] ^= mask[3];
	if (pn_len >= 4) packet[pn_offset + 3] ^= mask[4];

	return pn_len;
}

int
lws_quic_decrypt_payload(struct lws_quic_keys *keys, uint8_t *packet, size_t packet_len,
			 size_t pn_offset, uint8_t pn_len, uint64_t full_pn)
{
	uint8_t nonce[12];
	uint8_t tag[16];
	size_t payload_offset = pn_offset + pn_len;
	size_t payload_len = packet_len - payload_offset;
	int i;

	if (payload_len < 16)
		return -1; /* Too short to contain AEAD authentication tag */

	/* 1. Construct the AEAD Nonce: IV ^ full_pn */
	memcpy(nonce, keys->iv_rx, 12);
	for (i = 0; i < 8; i++)
		nonce[11 - i] ^= (uint8_t)(full_pn >> (i * 8));

	/* 2. The tag is the last 16 bytes of the payload */
	payload_len -= 16;
	memcpy(tag, &packet[payload_offset + payload_len], 16);

	/* 3. Decrypt the payload and authenticate the header (AAD) */
#if !defined(LWS_WITH_GNUTLS)
	size_t iv_len = 12;
#endif
	if (keys->cipher_type == 0 || keys->cipher_type == 2) {
#if defined(LWS_WITH_GNUTLS)
                gnutls_aead_cipher_hd_t hd;
                gnutls_datum_t key;
                key.data = keys->el_aead_rx.buf;
                key.size = keys->el_aead_rx.len;
                gnutls_cipher_algorithm_t alg = (keys->cipher_type == 2) ? GNUTLS_CIPHER_AES_256_GCM : GNUTLS_CIPHER_AES_128_GCM;

                if (!keys->aead_rx) {
                        if (gnutls_aead_cipher_init((gnutls_aead_cipher_hd_t *)&keys->aead_rx, alg, &key) < 0)
                                return -1;
                }
                hd = (gnutls_aead_cipher_hd_t)keys->aead_rx;

                size_t ct_len = payload_len + 16;
                size_t pt_len = payload_len;
                uint8_t tmp[4096];
                if (ct_len > sizeof(tmp))
                        return -1;
                memcpy(tmp, &packet[payload_offset], ct_len);
                if (gnutls_aead_cipher_decrypt(hd, nonce, 12, packet, payload_offset,
                                               16, tmp, ct_len,
                                               &packet[payload_offset], &pt_len) < 0) {
                        lwsl_err("DECRYPT GCM tag check failed via gnutls_aead_cipher_decrypt\n");
                        lws_explicit_bzero(&packet[payload_offset], payload_len);
                        return -1;
                }
#else
		struct lws_genaes_ctx aead;
		if (lws_genaes_create(&aead, LWS_GAESO_DEC, LWS_GAESM_GCM, &keys->el_aead_rx, LWS_GAESP_NO_PADDING, NULL))
			return -1;

		/* Feed AAD (the unmasked header up to the payload) */
		if (lws_genaes_crypt(&aead, packet, payload_offset, NULL, nonce, tag, &iv_len, 16)) {
			lws_genaes_destroy(&aead, NULL, 0);
			return -1;
		}
		/* Decrypt Payload */
		if (lws_genaes_crypt(&aead, &packet[payload_offset], payload_len,
				     &packet[payload_offset], nonce, tag, &iv_len, 16)) {
			lws_genaes_destroy(&aead, NULL, 0);
			lws_explicit_bzero(&packet[payload_offset], payload_len);
			return -1;
		}

		if (lws_genaes_destroy(&aead, tag, 16)) { /* Checks tag */
			lwsl_err("DECRYPT GCM tag check failed\n");
			lws_explicit_bzero(&packet[payload_offset], payload_len);
			return -1;
		}
#endif
	} else {
		struct lws_genchacha_ctx aead;
		if (lws_genchacha_create(&aead, LWS_GAESO_DEC, &keys->el_aead_rx, NULL))
			return -1;

		lwsl_info("DECRYPT CHACHA: payload_offset=%d, payload_len=%d, full_pn=%llu", (int)payload_offset, (int)payload_len, (unsigned long long)full_pn);

		/* Decrypt Payload and verify tag */
		if (lws_genchacha_crypt(&aead, &packet[payload_offset], payload_len,
				     &packet[payload_offset], nonce, packet, payload_offset, tag, 16)) {
			lws_genchacha_destroy(&aead);
			lws_explicit_bzero(&packet[payload_offset], payload_len);
			return -1;
		}

		if (lws_genchacha_destroy(&aead)) {
			lws_explicit_bzero(&packet[payload_offset], payload_len);
			return -1;
		}
	}

	return (int)payload_len; /* Return the decrypted payload length */
}

int
lws_quic_encrypt_payload(struct lws_quic_keys *keys, uint8_t *packet, size_t packet_len,
			 size_t pn_offset, uint8_t pn_len, uint64_t full_pn)
{
	uint8_t nonce[12];
	uint8_t tag[16];
	size_t payload_offset = pn_offset + pn_len;
	size_t payload_len = packet_len - payload_offset;
	int i;

       /* Set the PN length bits (pn_len is 1 to 4) BEFORE any AAD or encryption */
       packet[0] |= (pn_len - 1);

	/* 1. Construct the AEAD Nonce: IV ^ full_pn */
	memcpy(nonce, keys->iv_tx, 12);
	for (i = 0; i < 8; i++)
		nonce[11 - i] ^= (uint8_t)(full_pn >> (i * 8));

	/* 2. Encrypt the payload and authenticate the header (AAD) */
#if !defined(LWS_WITH_GNUTLS)
	size_t iv_len = 12;
#endif
	if (keys->cipher_type == 0 || keys->cipher_type == 2) {
#if defined(LWS_WITH_GNUTLS)
                gnutls_aead_cipher_hd_t hd;
                gnutls_datum_t key;
                key.data = keys->el_aead_tx.buf;
                key.size = keys->el_aead_tx.len;
                gnutls_cipher_algorithm_t alg = (keys->cipher_type == 2) ? GNUTLS_CIPHER_AES_256_GCM : GNUTLS_CIPHER_AES_128_GCM;

                if (!keys->aead_tx) {
                        if (gnutls_aead_cipher_init((gnutls_aead_cipher_hd_t *)&keys->aead_tx, alg, &key) < 0)
                                return -1;
                }
                hd = (gnutls_aead_cipher_hd_t)keys->aead_tx;

                size_t ct_len = payload_len + 16;
                uint8_t tmp[4096];
                if (payload_len > sizeof(tmp))
                        return -1;
                memcpy(tmp, &packet[payload_offset], payload_len);
                lwsl_debug("GnuTLS AEAD TX: full_pn=%llu, pn_offset=%d, payload_offset=%d, payload_len=%d\n",
                            (unsigned long long)full_pn, (int)pn_offset, (int)payload_offset, (int)payload_len);
                lwsl_hexdump_debug(packet, payload_offset); /* Print AAD */
                lwsl_hexdump_debug(keys->iv_tx, 12); /* Print IV */
                lwsl_hexdump_debug(nonce, 12); /* Print Nonce */
                if (gnutls_aead_cipher_encrypt(hd, nonce, 12, packet, payload_offset,
                                               16, tmp, payload_len,
                                               &packet[payload_offset], &ct_len) < 0) {
                        lwsl_err("ENCRYPT GCM failed via gnutls_aead_cipher_encrypt\n");
                        return -1;
                }

                /* GnuTLS automatically appends the tag to the end of the ciphertext output */
                /* We copy it to 'tag' just for the debug dump */
                memcpy(tag, &packet[payload_offset + payload_len], 16);
                lwsl_debug("GnuTLS AEAD TX TAG:\n");
                lwsl_hexdump_debug(tag, 16);
#else
		struct lws_genaes_ctx aead;
		if (lws_genaes_create(&aead, LWS_GAESO_ENC, LWS_GAESM_GCM, &keys->el_aead_tx, LWS_GAESP_NO_PADDING, NULL)) {
			lwsl_err("lws_genaes_create GCM failed\n");
			return -1;
		}

		/* Feed AAD (the unmasked header up to the payload) */
		if (lws_genaes_crypt(&aead, packet, payload_offset, NULL, nonce, tag, &iv_len, 16)) {
			lwsl_err("lws_genaes_crypt GCM AAD failed\n");
			lws_genaes_destroy(&aead, NULL, 0);
			return -1;
		}
		/* Encrypt Payload */
		if (lws_genaes_crypt(&aead, &packet[payload_offset], payload_len,
				     &packet[payload_offset], nonce, tag, &iv_len, 16)) {
			lwsl_err("lws_genaes_crypt GCM payload failed\n");
			lws_genaes_destroy(&aead, NULL, 0);
			return -1;
		}
		if (lws_genaes_destroy(&aead, tag, 16)) {
			lwsl_err("lws_genaes_destroy GCM failed\n");
			return -1;
		}

		/* 3. Append the 16-byte authentication tag */
		memcpy(&packet[payload_offset + payload_len], tag, 16);
#endif
	} else {
		struct lws_genchacha_ctx aead;
		if (lws_genchacha_create(&aead, LWS_GAESO_ENC, &keys->el_aead_tx, NULL)) {
			lwsl_err("lws_genchacha_create failed\n");
			return -1;
		}

		if (lws_genchacha_crypt(&aead, &packet[payload_offset], payload_len,
				     &packet[payload_offset], nonce, packet, payload_offset, tag, 16)) {
			lwsl_err("lws_genchacha_crypt failed\n");
			lws_genchacha_destroy(&aead);
			return -1;
		}
		if (lws_genchacha_destroy(&aead)) {
			lwsl_err("lws_genchacha_destroy failed\n");
			return -1;
		}

		/* 3. Append the 16-byte authentication tag */
		memcpy(&packet[payload_offset + payload_len], tag, 16);
	}

	/* Tag appending is handled in the respective cipher blocks above */

	/* 4. Mask the Header (Header Protection) */
	uint8_t sample[16], mask[16];
	size_t sample_offset = pn_offset + 4;

	/* The sample for masking is taken from the ENCRYPTED payload (including tag) */
	memcpy(sample, &packet[sample_offset], 16);

	if (keys->cipher_type == 0 || keys->cipher_type == 2) {
		struct lws_genaes_ctx hp;
		if (lws_genaes_create(&hp, LWS_GAESO_ENC, LWS_GAESM_ECB, &keys->el_hp_tx, LWS_GAESP_NO_PADDING, NULL)) {
			lwsl_err("lws_genaes_create ECB failed\n");
			return -1;
		}
		if (lws_genaes_crypt(&hp, sample, 16, mask, NULL, NULL, NULL, 0)) {
			lwsl_err("lws_genaes_crypt ECB failed\n");
			lws_genaes_destroy(&hp, NULL, 0);
			return -1;
		}
		lws_genaes_destroy(&hp, NULL, 0);
	} else {
		struct lws_genchacha_ctx hp;
		if (lws_genchacha_create(&hp, LWS_GAESO_ENC, &keys->el_hp_tx, NULL))
			return -1;
		uint8_t zeroes[5] = {0};
		if (lws_genchacha_stream(&hp, zeroes, 5, mask, sample, 16)) {
			lws_genchacha_destroy(&hp);
			return -1;
		}
		lws_genchacha_destroy(&hp);
	}

	/* Apply the mask to the first byte */
	if (packet[0] & 0x80)
		packet[0] ^= (mask[0] & 0x0f); /* Long header */
	else
		packet[0] ^= (mask[0] & 0x1f); /* Short header */

	/* Apply the mask to the packet number bytes */
	if (pn_len >= 1) packet[pn_offset]     ^= mask[1];
	if (pn_len >= 2) packet[pn_offset + 1] ^= mask[2];
	if (pn_len >= 3) packet[pn_offset + 2] ^= mask[3];
	if (pn_len >= 4) packet[pn_offset + 3] ^= mask[4];

	return (int)(payload_len + 16); /* Return the length of the encrypted payload + tag */
}

int
lws_tls_quic_rx_crypto(struct lws *wsi, int level, const uint8_t *buf, size_t len)
{
	struct lws *orig_wsi = wsi;
	int n;

	if (len > 0 && wsi->quic.qn) {
		if (wsi->quic.qn->crypto_rx_buf_len[level] + len > 262144) {
			lwsl_wsi_err(wsi, "QUIC: CRYPTO reassembly buffer size limit exceeded on level %d", level);
			return -1;
		}
		if (wsi->quic.qn->crypto_rx_buf_len[level] > 0) {
			uint8_t *new_buf = lws_realloc(wsi->quic.qn->crypto_rx_buf[level],
						       wsi->quic.qn->crypto_rx_buf_len[level] + len,
						       "crypto rx buf");
			if (!new_buf) {
				return -1;
			}
			memcpy(new_buf + wsi->quic.qn->crypto_rx_buf_len[level], buf, len);
			wsi->quic.qn->crypto_rx_buf[level] = new_buf;
			wsi->quic.qn->crypto_rx_buf_len[level] += len;
			
			buf = wsi->quic.qn->crypto_rx_buf[level];
			len = wsi->quic.qn->crypto_rx_buf_len[level];
		}

		size_t scan = 0;
		size_t complete_len = 0;
		while (scan < len) {
			if (len - scan < 4) {
				break;
			}

			uint8_t type = buf[scan];
			if (type == 24 || type == 5) {
				lwsl_wsi_notice(wsi, "QUIC RX CRYPTO: Illegal TLS Handshake type %d", type);
				lws_quic_enter_closing_state(wsi, 0x0100 + 10 /* unexpected_message */, 0, 0);
				return -1;
			}

			uint32_t msg_len = ((uint32_t)buf[scan+1] << 16) | ((uint32_t)buf[scan+2] << 8) | buf[scan+3];
			if (scan + 4 + msg_len > len) {
				break;
			}
			
			scan += 4 + msg_len;
			complete_len = scan;
		}

		if (complete_len == 0) {
			if (wsi->quic.qn->crypto_rx_buf_len[level] == 0) {
				uint8_t *new_buf = lws_malloc(len, "crypto rx buf");
				if (!new_buf) {
					return -1;
				}
				memcpy(new_buf, buf, len);
				wsi->quic.qn->crypto_rx_buf[level] = new_buf;
				wsi->quic.qn->crypto_rx_buf_len[level] = len;
			}
			return 0;
		}

		n = lws_tls_quic_advance_handshake(wsi, level, buf, complete_len, NULL, NULL);

		{
			struct lws *nwsi = lws_get_quic_network_wsi(wsi);
			if (nwsi) wsi = nwsi;
		}

		if (n < 0) {
			goto error_handling;
		}

		size_t remainder = len - complete_len;
		if (remainder > 0) {
			if (wsi->quic.qn->crypto_rx_buf_len[level] == 0) {
				uint8_t *new_buf = lws_malloc(remainder, "crypto rx buf");
				if (new_buf) {
					memcpy(new_buf, buf + complete_len, remainder);
					wsi->quic.qn->crypto_rx_buf[level] = new_buf;
				}
			} else {
				memmove(wsi->quic.qn->crypto_rx_buf[level], buf + complete_len, remainder);
			}
			wsi->quic.qn->crypto_rx_buf_len[level] = remainder;
		} else {
			if (wsi->quic.qn->crypto_rx_buf_len[level] > 0) {
				lws_free(wsi->quic.qn->crypto_rx_buf[level]);
				wsi->quic.qn->crypto_rx_buf[level] = NULL;
				wsi->quic.qn->crypto_rx_buf_len[level] = 0;
			}
		}
	} else {
		n = lws_tls_quic_advance_handshake(wsi, level, buf, len, NULL, NULL);
		{
			struct lws *nwsi = lws_get_quic_network_wsi(wsi);
			if (nwsi) wsi = nwsi;
		}
	}

error_handling:
	if (n < 0) {
#if defined(LWS_WITH_GNUTLS)
		int alert_level = 0;
		int alert = gnutls_error_to_alert(n, &alert_level);
		if (alert >= 0) {
			lwsl_wsi_notice(wsi, "GnuTLS error %d mapped to alert %d (level %d)", n, alert, alert_level);
			lws_quic_enter_closing_state(wsi, 0x0100 + (uint64_t)alert, 0, 0);
		} else {
			int alert_got = wsi->tls.ssl ? (int)gnutls_alert_get((gnutls_session_t)wsi->tls.ssl) : 0;
			if (alert_got > 0) {
				lwsl_wsi_notice(wsi, "GnuTLS generated alert %d", alert_got);
				lws_quic_enter_closing_state(wsi, 0x0100 + (uint64_t)alert_got, 0, 0);
			} else {
				lws_quic_enter_closing_state(wsi, 0x0100 + 10 /* unexpected_message fallback */, 0, 0);
			}
		}
#else
		if (wsi->tls.quic_alert > 0) {
			lwsl_wsi_notice(wsi, "OpenSSL/BoringSSL generated alert %d", wsi->tls.quic_alert);
			lws_quic_enter_closing_state(wsi, 0x0100 + (uint64_t)wsi->tls.quic_alert, 0, 0);
		} else {
			lws_quic_enter_closing_state(wsi, 0x0100 + 10 /* unexpected_message fallback */, 0, 0);
		}
#endif
		return -1;
	}


	lwsl_wsi_debug(wsi, "lws_tls_quic_advance_handshake returned %d, tp_parsed=%d", n, wsi->quic.qn ? wsi->quic.qn->tp_parsed : -1);

	if (wsi->quic.qn && !wsi->quic.qn->tp_parsed) {
		const uint8_t *peer_tp = NULL;
		size_t peer_tp_len = 0;
		if (lws_tls_quic_get_transport_parameters(wsi, &peer_tp, &peer_tp_len) == 0 && peer_tp) {
			lwsl_wsi_debug(wsi, "Got peer_tp, len %zu, parsing...", peer_tp_len);
			wsi->quic.qn->tp_parsed = 1;
			if (lws_quic_parse_transport_parameters(wsi, peer_tp, peer_tp_len) < 0) {
				lwsl_wsi_err(wsi, "QUIC transport parameters validation failed");
				lws_quic_enter_closing_state(wsi, LWS_QUIC_ERR_TRANSPORT_PARAMETER_ERROR, 0, 0);
				return -1;
			}
		} else {
			lwsl_wsi_debug(wsi, "lws_tls_quic_get_transport_parameters returned non-zero or NULL");
		}
		if (wsi->quic.qn->is_server && wsi->quic.qn->crypto_tx_offset[LWS_QUIC_LEVEL_INITIAL] > 0 && !wsi->quic.qn->tp_parsed) {
			lwsl_wsi_err(wsi, "QUIC Peer provided no transport parameters in ClientHello!");
			lws_quic_enter_closing_state(wsi, 0x0100 + 109 /* missing_extension */, 0, 0);
			return -1;
		}
	}

	if (n == 0 && wsi->quic.qn && !wsi->quic.qn->handshake_done) {
		lwsl_wsi_info(wsi, "QUIC TLS Handshake Complete!");

		if (!wsi->quic.qn->tp_parsed) {
			lwsl_wsi_err(wsi, "QUIC Peer provided no transport parameters!");
			lws_quic_enter_closing_state(wsi, 0x0100 + 109 /* missing_extension */, 0, 0);
			return -1;
		}

		wsi->quic.qn->handshake_done = 1;

		/*
		 * If the client deferred its preferred_address migration until
		 * the handshake was complete, execute it now: both sides have
		 * APP keys so the PATH_CHALLENGE/RESPONSE will succeed.
		 */
		if (!wsi->quic.qn->is_server && wsi->quic.qn->prefaddr_pending) {
			wsi->quic.qn->prefaddr_pending = 0;
			lws_quic_client_probe_preferred_address(wsi,
						&wsi->quic.qn->probing_sa46,
						&wsi->quic.qn->prefaddr_rem_cid,
						wsi->quic.qn->prefaddr_rem_token);
		}

		if (wsi->quic.qn->is_server) {
			struct lws_quic_tx_frame *f_hd = lws_zalloc(sizeof(*f_hd), "HANDSHAKE_DONE");
			if (f_hd) {
				f_hd->type = LWS_QUIC_FT_HANDSHAKE_DONE;
				f_hd->len = 0; /* No payload */
				lws_dll2_add_tail(&f_hd->list, &wsi->quic.qn->pending_tx[LWS_QUIC_LEVEL_APP]);
				lws_callback_on_writable(wsi);
			}
		}

		lwsi_set_state(wsi, LRS_ESTABLISHED);

#if defined(LWS_WITH_TLS)
		{
			const unsigned char *prot = NULL;
			unsigned int plen = 0;

#if defined(USE_WOLFSSL)
			wolfSSL_get0_alpn_selected(wsi->tls.ssl, &prot, &plen);
#elif defined(LWS_WITH_MBEDTLS)
#if defined(LWS_HAVE_mbedtls_ssl_get_alpn_protocol)
			const char *alpn = mbedtls_ssl_get_alpn_protocol(&wsi->tls.ssl->ssl);
			if (alpn) {
				prot = (const unsigned char *)alpn;
				plen = (unsigned int)strlen(alpn);
			}
#endif
#elif defined(LWS_WITH_GNUTLS)
			gnutls_datum_t dt;
			if (gnutls_alpn_get_selected_protocol(wsi->tls.ssl, &dt) >= 0) {
				prot = dt.data;
				plen = dt.size;
			}
#elif defined(LWS_HAVE_SSL_get0_alpn_selected) || defined(OPENSSL_IS_AWSLC)
			SSL_get0_alpn_selected(wsi->tls.ssl, &prot, &plen);
#endif
			if (plen) {
				lws_strncpy(wsi->alpn, (const char *)prot, plen + 1);
				// lwsl_wsi_notice(wsi, "QUIC ALPN negotiated: %s", wsi->alpn);
				lws_role_call_alpn_negotiated(wsi, wsi->alpn);
                       } else if (wsi->alpn[0]) {
                                lwsl_wsi_notice(wsi, "QUIC ALPN already negotiated: %s", wsi->alpn);
                                lws_role_call_alpn_negotiated(wsi, wsi->alpn);
			} else {
				lwsl_wsi_warn(wsi, "QUIC requires ALPN, but none was negotiated!");
				lws_quic_enter_closing_state(wsi, 0x0100 + 120 /* no_application_protocol */, 0, 0);
				return -1;
			}
		}
#endif

		if (orig_wsi->role_ops) {
			enum lws_callback_reasons cb = (enum lws_callback_reasons)orig_wsi->role_ops->adoption_cb[lwsi_role_server(orig_wsi)];
			if (cb && orig_wsi->a.protocol && orig_wsi->a.protocol->callback)
				orig_wsi->a.protocol->callback(orig_wsi, cb, orig_wsi->user_space, NULL, 0);
		}

		lws_callback_on_writable(orig_wsi);
	}

	return 0;
}

LWS_VISIBLE LWS_EXTERN enum lws_0rtt_status
lws_tls_0rtt_status(struct lws *wsi)
{
	struct lws_quic_netconn *qn;

	if (!wsi)
		return LWS_0RTT_STATUS_NONE;

	qn = wsi->quic.qn;
	if (!qn) {
		/* Maybe it's a stream, let's get the network connection */
		struct lws *nwsi = lws_get_quic_network_wsi(wsi);
		if (nwsi)
			qn = nwsi->quic.qn;
	}

	if (!qn)
		return LWS_0RTT_STATUS_NONE;

	return (enum lws_0rtt_status)qn->early_data_status;
}

LWS_VISIBLE LWS_EXTERN int
lws_rx_is_early_data(struct lws *wsi)
{
	struct lws_quic_stream *qs = NULL;

	if (!wsi)
		return 0;

	qs = wsi->quic.qs;
	if (!qs)
		return 0;

	/* In LWS, the transport layer determines if the currently processed RX
	 * frame arrived in a 0-RTT packet. For QUIC streams, we can track if
	 * the stream's current RX packet was at the LWS_QUIC_LEVEL_EARLY level.
	 * Wait, we just need to know if the connection is still in the early data
	 * phase (handshake not done yet) and we are the server, OR if the specific
	 * packet was decrypted using the early secret.
	 */
	struct lws *nwsi = lws_get_quic_network_wsi(wsi);
	if (!nwsi || !nwsi->quic.qn)
		return 0;

	/* If we are the server, and the handshake is not yet complete, any
	 * application data we process MUST be 0-RTT early data.
	 */
	if (nwsi->quic.qn->is_server && !nwsi->quic.qn->handshake_done)
		return 1;

	return 0;
}

static const uint8_t quic_v1_retry_key[] = {
        0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
        0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e
};
static const uint8_t quic_v1_retry_nonce[] = {
        0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2,
        0x23, 0x98, 0x25, 0xbb
};

int
lws_quic_validate_retry_tag(struct lws_quic_netconn *qn,
			    const uint8_t *orig_dcid, size_t orig_dcid_len,
			    const uint8_t *pkt, size_t len, const uint8_t *tag)
{
        struct lws_genaes_ctx aead;
        uint8_t computed_tag[16];
        uint8_t pseudo_pkt[2048];
        size_t pseudo_len;

        if (!orig_dcid_len || len + 1 + orig_dcid_len > sizeof(pseudo_pkt))
                return -1;

        pseudo_pkt[0] = (uint8_t)orig_dcid_len;
        memcpy(pseudo_pkt + 1, orig_dcid, orig_dcid_len);
        memcpy(pseudo_pkt + 1 + orig_dcid_len, pkt, len);
        pseudo_len = 1 + orig_dcid_len + len;

        struct lws_gencrypto_keyelem keys[1];
        keys[0].buf = (uint8_t *)quic_v1_retry_key;
        keys[0].len = sizeof(quic_v1_retry_key);

        if (lws_genaes_create(&aead, LWS_GAESO_ENC, LWS_GAESM_GCM, keys, LWS_GAESP_NO_PADDING, NULL))
                return -1;

        size_t iv_len = 12;
        if (lws_genaes_crypt(&aead, pseudo_pkt, pseudo_len,
                             NULL, (uint8_t *)quic_v1_retry_nonce, computed_tag, &iv_len, 16)) {
                lws_genaes_destroy(&aead, NULL, 0);
                return -1;
        }

        if (lws_genaes_destroy(&aead, computed_tag, 16))
                return -1;

        if (lws_timingsafe_bcmp(tag, computed_tag, 16))
                return -1;

        return 0;
}

int
lws_quic_create_retry_token(struct lws *wsi,
                            const uint8_t *client_dcid, size_t dcid_len,
                            const uint8_t *retry_scid, size_t rscid_len,
                            const uint8_t *client_ip, size_t ip_len,
                            uint8_t *out_token, size_t *out_token_len)
{
        struct lws_genaes_ctx aead;
        uint8_t pt[256];
        size_t pt_len = 0;
        uint8_t nonce[12];
        uint64_t now = (uint64_t)lws_now_usecs();

        lws_get_random(wsi->a.context, nonce, 12);

        pt[pt_len++] = (uint8_t)dcid_len;
        memcpy(&pt[pt_len], client_dcid, dcid_len);
        pt_len += dcid_len;

        pt[pt_len++] = (uint8_t)rscid_len;
        memcpy(&pt[pt_len], retry_scid, rscid_len);
        pt_len += rscid_len;

        pt[pt_len++] = (uint8_t)ip_len;
        memcpy(&pt[pt_len], client_ip, ip_len);
        pt_len += ip_len;

        if (pt_len + 8 > sizeof(pt))
                return -1;
        pt[pt_len++] = (uint8_t)(now >> 56);
        pt[pt_len++] = (uint8_t)(now >> 48);
        pt[pt_len++] = (uint8_t)(now >> 40);
        pt[pt_len++] = (uint8_t)(now >> 32);
        pt[pt_len++] = (uint8_t)(now >> 24);
        pt[pt_len++] = (uint8_t)(now >> 16);
        pt[pt_len++] = (uint8_t)(now >> 8);
        pt[pt_len++] = (uint8_t)now;

        struct lws_gencrypto_keyelem keys[1];
        keys[0].buf = wsi->a.context->quic_retry_secret;
        keys[0].len = 16;

        if (lws_genaes_create(&aead, LWS_GAESO_ENC, LWS_GAESM_GCM, keys, LWS_GAESP_NO_PADDING, NULL))
                return -1;

        memcpy(out_token, nonce, 12);
        size_t iv_len = 12;
        if (lws_genaes_crypt(&aead, pt, pt_len, out_token + 12, nonce, out_token + 12 + pt_len, &iv_len, 16)) {
                lws_genaes_destroy(&aead, NULL, 0);
                return -1;
        }
        if (lws_genaes_destroy(&aead, out_token + 12 + pt_len, 16))
                return -1;

        *out_token_len = 12 + pt_len + 16;
        return 0;
}

int
lws_quic_validate_retry_token(struct lws *wsi, const uint8_t *token, size_t token_len,
                              const uint8_t *client_ip, size_t ip_len,
                              struct lws_quic_cid *orig_dcid,
                              struct lws_quic_cid *retry_scid)
{
        struct lws_genaes_ctx aead;
        uint8_t pt[256];
        size_t ct_len;
        uint8_t tag[16];

        if (token_len < 12 + 16 + 1)
                return -1;
        ct_len = token_len - 12 - 16;
        if (ct_len > sizeof(pt))
                return -1;

        struct lws_gencrypto_keyelem keys[1];
        keys[0].buf = wsi->a.context->quic_retry_secret;
        keys[0].len = 16;

        if (lws_genaes_create(&aead, LWS_GAESO_DEC, LWS_GAESM_GCM, keys, LWS_GAESP_NO_PADDING, NULL))
                return -1;

        size_t iv_len = 12;
        memcpy(tag, token + 12 + ct_len, 16);
        if (lws_genaes_crypt(&aead, token + 12, ct_len, pt, (uint8_t *)token, tag, &iv_len, 16)) {
                lws_genaes_destroy(&aead, NULL, 0);
                return -1;
        }
        if (lws_genaes_destroy(&aead, tag, 16))
                return -1;

        size_t p = 0;
        orig_dcid->len = pt[p++];
        if (p + orig_dcid->len > ct_len || p + orig_dcid->len > sizeof(pt)) return -1;
        if (orig_dcid->len > sizeof(orig_dcid->id)) return -1;
        if (orig_dcid->len)
                memcpy(orig_dcid->id, pt + p, orig_dcid->len);
        p += orig_dcid->len;

        if (p >= ct_len || p >= sizeof(pt)) return -1;
        retry_scid->len = pt[p++];
        if (p + retry_scid->len > ct_len || p + retry_scid->len > sizeof(pt)) return -1;
        if (retry_scid->len > sizeof(retry_scid->id)) return -1;
        if (retry_scid->len)
                memcpy(retry_scid->id, pt + p, retry_scid->len);
        p += retry_scid->len;

        if (p >= ct_len || p >= sizeof(pt)) return -1;
        if (pt[p++] != ip_len) return -1;
        if (p + ip_len > ct_len || p + ip_len > sizeof(pt)) return -1;
        if (ip_len && memcmp(pt + p, client_ip, ip_len)) return -1;
        p += ip_len;

        if (p + 8 > ct_len || p + 8 > sizeof(pt)) return -1;
        uint64_t token_time = ((uint64_t)pt[p] << 56) |
                              ((uint64_t)pt[p+1] << 48) |
                              ((uint64_t)pt[p+2] << 40) |
                              ((uint64_t)pt[p+3] << 32) |
                              ((uint64_t)pt[p+4] << 24) |
                              ((uint64_t)pt[p+5] << 16) |
                              ((uint64_t)pt[p+6] << 8) |
                              pt[p+7];

        uint64_t now = (uint64_t)lws_now_usecs();
        if (now < token_time || now - token_time > 60ULL * 1000000ULL) {
                lwsl_wsi_notice(wsi, "QUIC: Retry token expired. age = %lld us", (long long)(now - token_time));
                return -1;
        }

        return 0;
}

int
lws_quic_create_retry_tag(const uint8_t *client_dcid, size_t dcid_len,
                          const uint8_t *pkt, size_t len, uint8_t *tag_out)
{
        struct lws_genaes_ctx aead;
        uint8_t pseudo_pkt[2048];
        size_t pseudo_len;

        if (!dcid_len || len + 1 + dcid_len > sizeof(pseudo_pkt))
                return -1;

        pseudo_pkt[0] = (uint8_t)dcid_len;
        memcpy(pseudo_pkt + 1, client_dcid, dcid_len);
        memcpy(pseudo_pkt + 1 + dcid_len, pkt, len);
        pseudo_len = 1 + dcid_len + len;

        struct lws_gencrypto_keyelem keys[1];
        keys[0].buf = (uint8_t *)quic_v1_retry_key;
        keys[0].len = sizeof(quic_v1_retry_key);

        if (lws_genaes_create(&aead, LWS_GAESO_ENC, LWS_GAESM_GCM, keys, LWS_GAESP_NO_PADDING, NULL))
                return -1;

        size_t iv_len = 12;
        if (lws_genaes_crypt(&aead, pseudo_pkt, pseudo_len,
                             NULL, (uint8_t *)quic_v1_retry_nonce, tag_out, &iv_len, 16)) {
                lws_genaes_destroy(&aead, NULL, 0);
                return -1;
        }
        if (lws_genaes_destroy(&aead, tag_out, 16))
                return -1;

        return 0;
}
