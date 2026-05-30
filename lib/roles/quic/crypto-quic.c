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

static const uint8_t quic_v1_initial_salt[20] = {
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
	0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
	0xcc, 0xbb, 0x7f, 0x0a
};

static const uint8_t quic_v2_initial_salt[32] = {
	0x0c, 0x20, 0x34, 0xeb, 0x2d, 0xcf, 0xeb, 0x4a,
	0x14, 0x4e, 0x1b, 0x82, 0xf0, 0x93, 0x14, 0x06,
	0xcb, 0xb9, 0x2e, 0xd3, 0x5b, 0x3e, 0x64, 0xf2,
	0x71, 0xbc, 0x60, 0x7e, 0xb3, 0x26, 0x89, 0xc1
};

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

	if (wsi->quic.qn->version == LWS_QUIC_VERSION_2) {
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
	if (!qn->handshake_done || !qn->keys[LWS_QUIC_LEVEL_APP])
		return -1;
		
	/* If an update is already pending, wait for it to be echoed/completed */
	if (qn->key_update_pending)
		return -1;

	/* Derive the new TX keys */
	if (lws_quic_update_keys(qn->keys[LWS_QUIC_LEVEL_APP], 0))
		return -1;
		
	/* Flip the TX key phase bit */
	qn->tx_key_phase ^= 1;
	
	/* Mark that we initiated it, so we expect the peer to echo it back in RX */
	qn->key_update_pending = 1;
	
	/* Reset the packet counter for AEAD limits */
	qn->tx_packets_since_update = 0;

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

	if (qn->handshake_done && (type == LWS_TLS_QUIC_SECRET_CLIENT_APPLICATION || type == LWS_TLS_QUIC_SECRET_SERVER_APPLICATION)) {
		lwsl_info("lws_quic_set_keys: ignoring post-handshake application secret update\n");
		return 0;
	}




	/* Determine level and direction */
	switch (type) {
	case LWS_TLS_QUIC_SECRET_CLIENT_EARLY:
		level = LWS_QUIC_LEVEL_EARLY;
		is_rx = qn->is_server ? 1 : 0;
		break;
	case LWS_TLS_QUIC_SECRET_CLIENT_HANDSHAKE:
		level = LWS_QUIC_LEVEL_HANDSHAKE;
		is_rx = qn->is_server ? 1 : 0;
		break;
	case LWS_TLS_QUIC_SECRET_SERVER_HANDSHAKE:
		level = LWS_QUIC_LEVEL_HANDSHAKE;
		is_rx = qn->is_server ? 0 : 1;
		break;
	case LWS_TLS_QUIC_SECRET_CLIENT_APPLICATION:
		level = LWS_QUIC_LEVEL_APP;
		is_rx = qn->is_server ? 1 : 0;
		break;
	case LWS_TLS_QUIC_SECRET_SERVER_APPLICATION:
		level = LWS_QUIC_LEVEL_APP;
		is_rx = qn->is_server ? 0 : 1;
		break;
	default:
		return -1;
	}

	if (!qn->keys[level]) {
		k = lws_zalloc(sizeof(*k), "quic_keys");
		if (!k) return -1;
		qn->keys[level] = k;
	} else {
		k = qn->keys[level];
	}

	if (is_rx) {
		memcpy(k->secret_rx, secret, secret_len > 48 ? 48 : secret_len);
		k->secret_len = secret_len;
		if (secret_len == 48) k->cipher_type = 2; /* AES-256-GCM */
		if (lws_quic_derive_key_iv_hp(k->secret_rx, secret_len, k->cipher_type, k->iv_rx, sizeof(k->iv_rx),
					      &k->el_aead_rx, k->key_aead_rx, &k->el_hp_rx, k->key_hp_rx))
			return -1;
	} else {
		memcpy(k->secret_tx, secret, secret_len > 48 ? 48 : secret_len);
		k->secret_len = secret_len;
		if (secret_len == 48) k->cipher_type = 2; /* AES-256-GCM */
		if (lws_quic_derive_key_iv_hp(k->secret_tx, secret_len, k->cipher_type, k->iv_tx, sizeof(k->iv_tx),
					      &k->el_aead_tx, k->key_aead_tx, &k->el_hp_tx, k->key_hp_tx))
			return -1;
	}

	/* We mark it valid once BOTH directions are derived (or if we only need one direction for early data) */
	/* For simplicity, we just mark valid and rely on tx/rx logic */
	k->valid = 1;

	/* If this is the client deriving the early secret, check if the stream opts in */
	if (type == LWS_TLS_QUIC_SECRET_CLIENT_EARLY && !qn->is_server) {
		qn->early_data_status = LWS_0RTT_STATUS_ATTEMPTED;

		/* The initial stream is currently also the network wsi, because ALPN
		 * hasn't migrated it yet. If it returns 1, it opts into 0-RTT. */
		if (wsi->a.protocol && wsi->a.protocol->callback) {
			int ret = wsi->a.protocol->callback(wsi,
					LWS_CALLBACK_CLIENT_ESTABLISHED_EARLY,
					wsi->user_space, NULL, 0);
			if (ret == 1) {
				lwsl_wsi_notice(wsi, "Stream %s opted into 0-RTT", lws_wsi_tag(wsi));
				if (wsi->quic.qs)
					wsi->quic.qs->opted_into_early_data = 1;
				lws_callback_on_writable(wsi);
			} else {
				lwsl_wsi_notice(wsi, "Stream %s ignored 0-RTT", lws_wsi_tag(wsi));
			}
		}
	} else if (type == LWS_TLS_QUIC_SECRET_CLIENT_EARLY && qn->is_server) {
		qn->early_data_status = LWS_0RTT_STATUS_ACCEPTED;
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

        lws_free(keys);
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
	} else {
		enum lws_genhmac_types hash_type = (k->secret_len == 48) ? LWS_GENHMAC_TYPE_SHA384 : LWS_GENHMAC_TYPE_SHA256;
		if (lws_genhkdf_expand_label(hash_type, k->secret_tx, k->secret_len, "quic ku", NULL, 0, new_secret, k->secret_len)) return -1;
		memcpy(k->secret_tx, new_secret, k->secret_len);
		
		if (lws_genhkdf_expand_label(hash_type, new_secret, k->secret_len, "quic key", NULL, 0, k->key_aead_tx, key_len)) return -1;
		if (lws_genhkdf_expand_label(hash_type, new_secret, k->secret_len, "quic iv", NULL, 0, k->iv_tx, 12)) return -1;
		
		k->el_aead_tx.buf = k->key_aead_tx;
		k->el_aead_tx.len = (uint32_t)key_len;
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
		return -1; /* Truncated packet */

	memcpy(sample, &packet[sample_offset], 16);

	if (keys->cipher_type == 0 || keys->cipher_type == 2) {
		/* AES-GCM uses AES-ECB for Header Protection */
		struct lws_genaes_ctx hp;
		if (lws_genaes_create(&hp, LWS_GAESO_ENC, LWS_GAESM_ECB, &keys->el_hp_rx, LWS_GAESP_NO_PADDING, NULL))
			return -1;
		if (lws_genaes_crypt(&hp, sample, 16, mask, NULL, NULL, NULL, 0)) {
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
                uint8_t tmp[2048];
                if (ct_len > sizeof(tmp))
                        return -1;
                memcpy(tmp, &packet[payload_offset], ct_len);
                if (gnutls_aead_cipher_decrypt(hd, nonce, 12, packet, payload_offset,
                                               16, tmp, ct_len,
                                               &packet[payload_offset], &pt_len) < 0) {
                        lwsl_err("DECRYPT GCM tag check failed via gnutls_aead_cipher_decrypt\n");
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
			return -1;
		}

		if (lws_genaes_destroy(&aead, tag, 16)) { /* Checks tag */
			lwsl_err("DECRYPT GCM tag check failed\n");
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
			return -1;
		}

		if (lws_genchacha_destroy(&aead))
			return -1;
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
                uint8_t tmp[2048];
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
	uint8_t *out = lws_malloc(32768, "quic rx crypto");
	size_t out_len = 32768;
	int n;

	if (!out)
		return -1;

	if (len > 0 && wsi->quic.qn) {
		size_t i = 0;
		while (i < len) {
			if (wsi->quic.qn->crypto_rx_expected_msg_len[level] > 0) {
				size_t consume = wsi->quic.qn->crypto_rx_expected_msg_len[level];
				if (consume > len - i)
					consume = len - i;
				wsi->quic.qn->crypto_rx_expected_msg_len[level] -= consume;
				i += consume;
				continue;
			}
			
			/* We are at the start of a new Handshake message! */
			uint8_t type = buf[i];
			if (type == 24 || type == 5) {
				lwsl_wsi_notice(wsi, "QUIC RX CRYPTO: Illegal TLS Handshake type %d", type);
				lws_quic_enter_closing_state(wsi, 0x0100 + 10 /* unexpected_message */, 0, 0);
				lws_free(out);
				return -1;
			}
			
			if (i + 3 >= len) {
				/* Fragmented header - extremely rare in h3spec, but we'd need to handle it.
				 * For now, assume headers are not fragmented across chunks. */
				break;
			}
			
			uint32_t msg_len = ((uint32_t)buf[i+1] << 16) | ((uint32_t)buf[i+2] << 8) | buf[i+3];
			wsi->quic.qn->crypto_rx_expected_msg_len[level] = msg_len;
			i += 4;
		}
	}

	n = lws_tls_quic_advance_handshake(wsi, level, buf, len, out, &out_len);

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
		lws_free(out);
		return -1;
	}

	if (out_len > 0) {
		/* Pass the generated TX CRYPTO data back to the QUIC transport queues */
		lws_tls_quic_tx_crypto_cb(wsi, level, out, out_len);
	}


	lwsl_wsi_debug(wsi, "lws_tls_quic_advance_handshake returned %d, tp_parsed=%d", n, wsi->quic.qn ? wsi->quic.qn->tp_parsed : -1);

	if (wsi->quic.qn && !wsi->quic.qn->tp_parsed) {
#if !defined(LWS_WITH_MBEDTLS)
		const uint8_t *peer_tp = NULL;
		size_t peer_tp_len = 0;
		if (lws_tls_quic_get_transport_parameters(wsi, &peer_tp, &peer_tp_len) == 0 && peer_tp) {
			lwsl_wsi_debug(wsi, "Got peer_tp, len %zu, parsing...", peer_tp_len);
			wsi->quic.qn->tp_parsed = 1;
			if (lws_quic_parse_transport_parameters(wsi, peer_tp, peer_tp_len) < 0) {
				lwsl_wsi_err(wsi, "QUIC transport parameters validation failed");
				lws_quic_enter_closing_state(wsi, LWS_QUIC_ERR_TRANSPORT_PARAMETER_ERROR, 0, 0);
				lws_free(out);
				return -1;
			}
		} else {
			lwsl_wsi_debug(wsi, "lws_tls_quic_get_transport_parameters returned non-zero or NULL");
		}
#else
		/* MbedTLS 4.x has no custom extension API, so QUIC transport parameters are not supported natively yet */
		wsi->quic.qn->tp_parsed = 1;
		wsi->quic.qn->peer_initial_max_data = 10485760;
		wsi->quic.qn->peer_initial_max_stream_data_bidi_local = 10485760;
		wsi->quic.qn->peer_initial_max_stream_data_bidi_remote = 10485760;
		wsi->quic.qn->peer_initial_max_stream_data_uni = 10485760;
		wsi->quic.qn->max_streams_bidi_remote = 100;
		wsi->quic.qn->max_streams_unidi_remote = 100;
		if (wsi->quic.qn->nwsi) {
			wsi->quic.qn->nwsi->txc.peer_tx_cr_est += (10485760 - 65535);
			wsi->quic.qn->nwsi->txc.tx_cr += (10485760 - 65535);
		}
#endif
#if !defined(LWS_WITH_MBEDTLS)
		if (wsi->quic.qn->is_server && out_len > 0 && !wsi->quic.qn->tp_parsed) {
			lwsl_wsi_err(wsi, "QUIC Peer provided no transport parameters in ClientHello!");
			lws_quic_enter_closing_state(wsi, 0x0100 + 109 /* missing_extension */, 0, 0);
			lws_free(out);
			return -1;
		}
#endif
	}

	if (n == 0 && wsi->quic.qn && !wsi->quic.qn->handshake_done) {
		lwsl_wsi_info(wsi, "QUIC TLS Handshake Complete!");

#if !defined(LWS_WITH_MBEDTLS)
		if (!wsi->quic.qn->tp_parsed) {
			lwsl_wsi_err(wsi, "QUIC Peer provided no transport parameters!");
			lws_quic_enter_closing_state(wsi, 0x0100 + 109 /* missing_extension */, 0, 0);
			lws_free(out);
			return -1;
		}
#endif

		wsi->quic.qn->handshake_done = 1;

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
			const char *alpn = mbedtls_ssl_get_alpn_protocol(SSL_mbedtls_ssl_context_from_SSL(wsi->tls.ssl));
			if (alpn) {
				prot = (const unsigned char *)alpn;
				plen = (unsigned int)strlen(alpn);
			}
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
				lwsl_wsi_notice(wsi, "QUIC ALPN negotiated: %s", wsi->alpn);
				lws_role_call_alpn_negotiated(wsi, wsi->alpn);
			} else {
#if !defined(LWS_WITH_MBEDTLS)
				lwsl_wsi_err(wsi, "QUIC requires ALPN, but none was negotiated!");
				lws_quic_enter_closing_state(wsi, 0x0100 + 120 /* no_application_protocol */, 0, 0);
				lws_free(out);
				return -1;
#else
				lws_strncpy(wsi->alpn, "lws-quic", sizeof(wsi->alpn));
				lwsl_wsi_notice(wsi, "QUIC ALPN mocked for MbedTLS: %s", wsi->alpn);
				lws_role_call_alpn_negotiated(wsi, wsi->alpn);
#endif
			}
		}
#endif

		if (wsi->role_ops) {
			enum lws_callback_reasons cb = (enum lws_callback_reasons)wsi->role_ops->adoption_cb[lwsi_role_server(wsi)];
			if (cb && wsi->a.protocol && wsi->a.protocol->callback) {
				wsi->a.protocol->callback(wsi, cb, wsi->user_space, NULL, 0);
			}
		}

		lws_callback_on_writable(wsi);
	}

	lws_free(out);
	return n < 0 ? -1 : 0;
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
