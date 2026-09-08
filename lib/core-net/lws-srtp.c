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

#include <private-lib-core.h>
#include <libwebsockets/lws-srtp.h>
#include <libwebsockets/lws-genhash.h>

static int
lws_srtp_prf(const uint8_t *key, const uint8_t *salt, uint8_t label, uint8_t *out, size_t out_len)
{
	struct lws_genaes_ctx aes_ctx;
	struct lws_gencrypto_keyelem el;
	uint8_t iv[16], zero[32] = {0};
	uint8_t iv_in[16];
	size_t nc = 0;

	memset(iv, 0, 16);
	memcpy(iv, salt, 14);
	/*
	 * RFC 3711 4.3.3: label << 48.
	 * Most implementations (libsrtp, etc.) XOR at Byte 7.
	 * We revert to Byte 7 for compatibility.
	 */
	iv[7] ^= label;

	el.buf = (uint8_t *)key;
	el.len = 16;

	if (lws_genaes_create(&aes_ctx, LWS_GAESO_ENC, LWS_GAESM_CTR, &el, LWS_GAESP_NO_PADDING, NULL))
		return -1;

	memcpy(iv_in, iv, 16);
	/* Use a single call for all bytes to ensure counter state is maintained */
	if (lws_genaes_crypt(&aes_ctx, zero, out_len, out, iv_in, NULL, &nc, 0)) {
		lws_genaes_destroy(&aes_ctx, NULL, 0);
		return -1;
	}

	lws_genaes_destroy(&aes_ctx, NULL, 0);

	lwsl_debug("SRTP PRF (label 0x%02x): Derived %d bytes\n", label, (int)out_len);
	// lwsl_hexdump_debug(out, out_len);

	return 0;
}

static struct lws_srtp_src_ctx *
lws_srtp_get_src_ctx(struct lws_srtp_ctx *ctx, uint32_t ssrc, int create)
{
	int i;
	/* Try to find existing first */
	for (i = 0; i < 4; i++) {
		if (ctx->src[i].any_packet_received && ctx->src[i].ssrc == ssrc)
			return &ctx->src[i];
	}

	/* If creation allowed, find first empty slot */
	if (create) {
		for (i = 0; i < 4; i++) {
			if (!ctx->src[i].any_packet_received) {
				ctx->src[i].ssrc = ssrc;
				ctx->src[i].any_packet_received = 1;
				/* roc/last_seq are 0 by default (memset) */
				return &ctx->src[i];
			}
		}
		lwsl_err("SRTP: No free SSRC slots for SSRC %u\n", ssrc);
	}

	return NULL;
}

/*
 * RFC 3711 3.3.2 replay list: a 64-entry sliding window of the indexes we
 * already accepted.  Bit n of the bitmap means "base - n" was seen, so bit 0
 * is the base itself.  Only ever consulted after the auth tag verified.
 */

static int
lws_srtp_replay_seen(uint64_t base, uint64_t bitmap, uint64_t index)
{
	uint64_t delta;

	if (index > base)
		return 0; /* newer than anything we accepted */

	delta = base - index;
	if (delta >= 64)
		return 1; /* too old for us to be able to tell: discard */

	return !!(bitmap & (1ull << delta));
}

static void
lws_srtp_replay_update(uint64_t *base, uint64_t *bitmap, uint64_t index)
{
	uint64_t delta;

	if (index > *base) {
		delta = index - *base;
		*bitmap = delta >= 64 ? 0 : *bitmap << delta;
		*base = index;
		*bitmap |= 1;

		return;
	}

	delta = *base - index;
	if (delta < 64)
		*bitmap |= 1ull << delta;
}

int
lws_srtp_init(struct lws_srtp_ctx *ctx, enum lws_srtp_profiles profile,
	      const uint8_t *master_key, const uint8_t *master_salt)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->profile = profile;
	memcpy(ctx->master_key, master_key, 16);
	memcpy(ctx->master_salt, master_salt, 14);

	/* Derive session keys (RFC 3711 4.3.1) */
	/* Label 0x00: SRTP Encryption */
	if (lws_srtp_prf(ctx->master_key, ctx->master_salt, 0x00, ctx->session_key, 16))
		return -1;
	/* Label 0x01: SRTP Authentication */
	if (lws_srtp_prf(ctx->master_key, ctx->master_salt, 0x01, ctx->session_auth, 20))
		return -1;
	/* Label 0x02: SRTP Salt */
	if (lws_srtp_prf(ctx->master_key, ctx->master_salt, 0x02, ctx->session_salt, 14))
		return -1;

	/* Label 0x03: SRTCP Encryption */
	if (lws_srtp_prf(ctx->master_key, ctx->master_salt, 0x03, ctx->srtcp_session_key, 16))
		return -1;
	/* Label 0x04: SRTCP Authentication */
	if (lws_srtp_prf(ctx->master_key, ctx->master_salt, 0x04, ctx->srtcp_session_auth, 20))
		return -1;
	/* Label 0x05: SRTCP Salt */
	if (lws_srtp_prf(ctx->master_key, ctx->master_salt, 0x05, ctx->srtcp_session_salt, 14))
		return -1;

	ctx->keys_derived = 1;
	return 0;
}

int
lws_srtp_protect_rtp(struct lws_srtp_ctx *ctx, uint8_t *pkt, size_t *len, size_t max_len)
{
	struct lws_genaes_ctx aes_ctx;
	struct lws_genhmac_ctx hmac_ctx;
	struct lws_gencrypto_keyelem el;
	uint16_t seq;
	uint32_t ssrc;
	uint64_t index;
	uint8_t iv[16];
	uint8_t tag[20];
	size_t nc = 0;
	size_t tag_len = (ctx->profile == LWS_SRTP_PROFILE_AES128_CM_HMAC_SHA1_80) ? 10 : 4;
	struct lws_srtp_src_ctx *sctx;

	if (!ctx->keys_derived)
		return -1;

	/*
	 * There must be a whole RTP header there before we may read it, and
	 * room to append the tag... *len - 12 below is a size_t
	 */

	if (*len < 12 || *len + tag_len > max_len)
		return -1;

	seq = (uint16_t)((pkt[2] << 8) | pkt[3]);
	ssrc = (uint32_t)((pkt[8] << 24) | (pkt[9] << 16) | (pkt[10] << 8) | pkt[11]);

	sctx = lws_srtp_get_src_ctx(ctx, ssrc, 1);
	if (!sctx)
		return -1;

	/* ROC management (Sender Side) */
    /* Robust check for wrap-around (per SSRC) */
    int32_t diff = (int32_t)seq - (int32_t)sctx->last_seq;
	if (diff < -32768)
		sctx->roc++;
	sctx->last_seq = seq;

	index = ((uint64_t)sctx->roc << 16) | seq;

	/* IV calculation for CTR */
	memset(iv, 0, 16);
	iv[4] = (uint8_t)(ssrc >> 24);
	iv[5] = (uint8_t)(ssrc >> 16);
	iv[6] = (uint8_t)(ssrc >> 8);
	iv[7] = (uint8_t)(ssrc & 0xff);

	iv[8] = (uint8_t)(index >> 40);
	iv[9] = (uint8_t)(index >> 32);
	iv[10] = (uint8_t)(index >> 24);
	iv[11] = (uint8_t)(index >> 16);
	iv[12] = (uint8_t)(index >> 8);
	iv[13] = (uint8_t)(index & 0xff);

	for (int i = 0; i < 14; i++)
		iv[i] ^= ctx->session_salt[i];

	/* Encryption */
	el.buf = ctx->session_key;
	el.len = 16;
	if (lws_genaes_create(&aes_ctx, LWS_GAESO_ENC, LWS_GAESM_CTR, &el, LWS_GAESP_NO_PADDING, NULL))
		return -1;

	if (lws_genaes_crypt(&aes_ctx, pkt + 12, *len - 12, pkt + 12, iv, NULL, &nc, 0)) {
		lws_genaes_destroy(&aes_ctx, NULL, 0);
		return -1;
	}
	lws_genaes_destroy(&aes_ctx, NULL, 0);

	/* Authentication */
	if (lws_genhmac_init(&hmac_ctx, LWS_GENHMAC_TYPE_SHA1, ctx->session_auth, 20))
		return -1;

	if (lws_genhmac_update(&hmac_ctx, pkt, *len)) {
		lws_genhmac_destroy(&hmac_ctx, NULL);
		return -1;
	}

	/* ROC is authenticated as well */
	uint8_t roc_bytes[4];
	roc_bytes[0] = (uint8_t)(sctx->roc >> 24);
	roc_bytes[1] = (uint8_t)(sctx->roc >> 16);
	roc_bytes[2] = (uint8_t)(sctx->roc >> 8);
	roc_bytes[3] = (uint8_t)(sctx->roc & 0xff);

	if (lws_genhmac_update(&hmac_ctx, roc_bytes, 4)) {
		lws_genhmac_destroy(&hmac_ctx, NULL);
		return -1;
	}

	if (lws_genhmac_destroy(&hmac_ctx, tag))
		return -1;

	memcpy(pkt + *len, tag, tag_len);
	*len += tag_len;

	return 0;
}

int
lws_srtp_protect_rtcp(struct lws_srtp_ctx *ctx, uint8_t *pkt, size_t *len, size_t max_len)
{
	struct lws_genaes_ctx aes_ctx;
	struct lws_genhmac_ctx hmac_ctx;
	struct lws_gencrypto_keyelem el;
	uint32_t ssrc;
	uint64_t index;
	uint8_t iv[16], tag[20];
	size_t nc = 0;
	size_t tag_len = (ctx->profile == LWS_SRTP_PROFILE_AES128_CM_HMAC_SHA1_80) ? 10 : 4;

	/*
	 * There must be a whole RTCP header there before we may read it, and
	 * room to append the index and the tag... *len - 8 below is a size_t
	 */

	if (!ctx->keys_derived || *len < 8 || *len + 4 + tag_len > max_len)
		return -1;

	/*
	 * The SRTCP index is only 31 bits on the wire; if we let it wrap we
	 * would reuse the (key, IV) pair on new plaintext.  Fail instead, the
	 * session must be rekeyed.
	 */

	if (ctx->srtcp_index > 0x7ffffffful)
		return -1;

	ssrc = (uint32_t)((pkt[4] << 24) | (pkt[5] << 16) | (pkt[6] << 8) | pkt[7]);

	index = ctx->srtcp_index++;

	/* IV calculation for CTR */
	memset(iv, 0, 16);
	iv[4] = (uint8_t)(ssrc >> 24);
	iv[5] = (uint8_t)(ssrc >> 16);
	iv[6] = (uint8_t)(ssrc >> 8);
	iv[7] = (uint8_t)(ssrc & 0xff);

	iv[8] = (uint8_t)(index >> 40);
	iv[9] = (uint8_t)(index >> 32);
	iv[10] = (uint8_t)(index >> 24);
	iv[11] = (uint8_t)(index >> 16);
	iv[12] = (uint8_t)(index >> 8);
	iv[13] = (uint8_t)(index & 0xff);

	for (int i = 0; i < 14; i++)
		iv[i] ^= ctx->srtcp_session_salt[i];

	/* Encryption (header 8 bytes not encrypted) */
	el.buf = ctx->srtcp_session_key;
	el.len = 16;
	if (lws_genaes_create(&aes_ctx, LWS_GAESO_ENC, LWS_GAESM_CTR, &el, LWS_GAESP_NO_PADDING, NULL))
		return -1;

	if (lws_genaes_crypt(&aes_ctx, pkt + 8, *len - 8, pkt + 8, iv, NULL, &nc, 0)) {
		lws_genaes_destroy(&aes_ctx, NULL, 0);
		return -1;
	}
	lws_genaes_destroy(&aes_ctx, NULL, 0);

	/* Append Index and E bit */
	uint8_t *p_index = pkt + *len;
	p_index[0] = (uint8_t)(0x80 | ((index >> 24) & 0x7f)); /* E=1 */
	p_index[1] = (uint8_t)(index >> 16);
	p_index[2] = (uint8_t)(index >> 8);
	p_index[3] = (uint8_t)(index & 0xff);
	*len += 4;

	/* Authentication */
	if (lws_genhmac_init(&hmac_ctx, LWS_GENHMAC_TYPE_SHA1, ctx->srtcp_session_auth, 20))
		return -1;

	if (lws_genhmac_update(&hmac_ctx, pkt, *len) ||
	    lws_genhmac_destroy(&hmac_ctx, tag))
		return -1;

	memcpy(pkt + *len, tag, tag_len);
	*len += tag_len;

	return 0;
}

int
lws_srtp_unprotect_rtp(struct lws_srtp_ctx *ctx, uint8_t *pkt, size_t *len)
{
	struct lws_genaes_ctx aes_ctx;
	struct lws_genhmac_ctx hmac_ctx;
	struct lws_gencrypto_keyelem el;
	uint16_t seq;
	uint32_t ssrc, roc, s_l, roc_est;
	uint64_t index, v, highest_index;
	int32_t diff;
	uint8_t iv[16], computed_tag[20];
	size_t nc = 0;
	size_t tag_len = (ctx->profile == LWS_SRTP_PROFILE_AES128_CM_HMAC_SHA1_80) ? 10 : 4;
	struct lws_srtp_src_ctx *sctx;

	/* check the length before reading any header field out of the packet */

	if (!ctx->keys_derived || *len < 12 + tag_len)
		return -1;

	seq = (uint16_t)((pkt[2] << 8) | pkt[3]);
	ssrc = (uint32_t)((pkt[8] << 24) | (pkt[9] << 16) | (pkt[10] << 8) | pkt[11]);

	/*
	 * Don't take a per-SSRC slot for an SSRC we haven't authenticated
	 * yet... else a handful of forged datagrams with random SSRCs claim
	 * every slot for good and deny the real peer's streams.  An unknown
	 * SSRC is estimated against ROC 0 the same as a fresh slot would be.
	 */

	sctx = lws_srtp_get_src_ctx(ctx, ssrc, 0);
	roc = sctx ? sctx->roc : 0;
	s_l = sctx ? sctx->last_seq : 0;

	/*
	 * RFC 3711 Section 3.3.1 Index Estimation (Per SSRC)
	 */
	diff = (int32_t)seq - (int32_t)s_l;

	if (s_l < 32768) {
		/*
		 * ROC can't go below zero... at the start of a stream, a peer
		 * that chose a high random initial seq (RFC 3550 recommends
		 * it) must not underflow us to ROC 0xffffffff
		 */
		if (diff > 32768 && roc) {
			v = ((uint64_t)(roc - 1) << 16) | seq;
		} else {
			v = ((uint64_t)roc << 16) | seq;
		}
	} else {
		if (diff < -32768) {
			v = ((uint64_t)(roc + 1) << 16) | seq;
		} else {
			v = ((uint64_t)roc << 16) | seq;
		}
	}

	index = v;
	highest_index = ((uint64_t)roc << 16) | s_l;

	/* 1. Verify Authentication Tag */
	if (lws_genhmac_init(&hmac_ctx, LWS_GENHMAC_TYPE_SHA1, ctx->session_auth, 20))
		return -1;

	if (lws_genhmac_update(&hmac_ctx, pkt, *len - tag_len)) {
		lws_genhmac_destroy(&hmac_ctx, NULL);
		return -1;
	}

    /* Use ESTIMATED ROC (from v), not current context ROC */
	{
		uint8_t roc_bytes[4];

		roc_est = (uint32_t)(v >> 16);
		roc_bytes[0] = (uint8_t)(roc_est >> 24);
		roc_bytes[1] = (uint8_t)(roc_est >> 16);
		roc_bytes[2] = (uint8_t)(roc_est >> 8);
		roc_bytes[3] = (uint8_t)(roc_est & 0xff);

		if (lws_genhmac_update(&hmac_ctx, roc_bytes, 4) ||
		    lws_genhmac_destroy(&hmac_ctx, computed_tag))
			return -1;
	}

	/* the tag is secret-derived, compare it in constant time */
	if (lws_timingsafe_bcmp(pkt + *len - tag_len, computed_tag,
				(uint32_t)tag_len)) {
		/* any peer can drive this, so it can't be at err level */
		lwsl_info("SRTP: Auth tag mismatch! SSRC %u, Seq %d, ROC %u (Est ROC %u)\n",
			  ssrc, seq, roc, roc_est);

		return -2;
	}

	/*
	 * RFC 3711 3.3.2: the replay list check happens once the tag has
	 * verified and before we hand the packet on, so a captured datagram
	 * can't be re-decrypted and re-delivered to the media consumer
	 */

	if (sctx && lws_srtp_replay_seen(sctx->replay_base,
					 sctx->replay_bitmap, v)) {
		lwsl_info("SRTP: replayed index, SSRC %u, Seq %d\n", ssrc, seq);

		return -3;
	}

	/* authenticated: now it's safe to commit a slot to this SSRC */

	if (!sctx) {
		sctx = lws_srtp_get_src_ctx(ctx, ssrc, 1);
		if (!sctx)
			return -1;
	}

	/* 2. Decrypt */
	memset(iv, 0, 16);
	iv[4] = (uint8_t)(ssrc >> 24);
	iv[5] = (uint8_t)(ssrc >> 16);
	iv[6] = (uint8_t)(ssrc >> 8);
	iv[7] = (uint8_t)(ssrc & 0xff);

	iv[8] = (uint8_t)(index >> 40);
	iv[9] = (uint8_t)(index >> 32);
	iv[10] = (uint8_t)(index >> 24);
	iv[11] = (uint8_t)(index >> 16);
	iv[12] = (uint8_t)(index >> 8);
	iv[13] = (uint8_t)(index & 0xff);

	for (int i = 0; i < 14; i++)
		iv[i] ^= ctx->session_salt[i];

	el.buf = ctx->session_key;
	el.len = 16;
	if (lws_genaes_create(&aes_ctx, LWS_GAESO_ENC, LWS_GAESM_CTR, &el, LWS_GAESP_NO_PADDING, NULL))
		return -1;

	if (lws_genaes_crypt(&aes_ctx, pkt + 12, *len - tag_len - 12, pkt + 12, iv, NULL, &nc, 0)) {
		lws_genaes_destroy(&aes_ctx, NULL, 0);
		return -1;
	}
	lws_genaes_destroy(&aes_ctx, NULL, 0);

	/* Update Context State on Success */
	if (v > highest_index) {
		sctx->roc = roc_est;
		sctx->last_seq = seq;
	}

	lws_srtp_replay_update(&sctx->replay_base, &sctx->replay_bitmap, v);

	*len -= tag_len;
	return 0;
}

int
lws_srtp_unprotect_rtcp(struct lws_srtp_ctx *ctx, uint8_t *pkt, size_t *len)
{
	struct lws_genaes_ctx aes_ctx;
	struct lws_genhmac_ctx hmac_ctx;
	struct lws_gencrypto_keyelem el;
	uint32_t ssrc;
	uint32_t srtcp_index_v;
	uint64_t index;
	uint8_t iv[16], tag[20], computed_tag[20];
	size_t nc = 0, rtcp_len;
	size_t tag_len = (ctx->profile == LWS_SRTP_PROFILE_AES128_CM_HMAC_SHA1_80) ? 10 : 4;
	uint8_t *p_index;

	/* check the length before reading any header field out of the packet */

	if (!ctx->keys_derived || *len < 8 + 4 + tag_len)
		return -1;

	ssrc = (uint32_t)((pkt[4] << 24) | (pkt[5] << 16) | (pkt[6] << 8) | pkt[7]);

	/* 1. Extract Index and Tag */
	rtcp_len = *len - tag_len - 4;
	p_index = pkt + rtcp_len;
	srtcp_index_v = (uint32_t)((p_index[0] << 24) | (p_index[1] << 16) | (p_index[2] << 8) | p_index[3]);
	/* The E bit is the MSB of the index word */
	int encrypted = !!(srtcp_index_v & 0x80000000);
	srtcp_index_v &= 0x7FFFFFFF;
	index = srtcp_index_v;

	memcpy(tag, pkt + *len - tag_len, tag_len);

	/* 2. Verify Authentication Tag */
	if (lws_genhmac_init(&hmac_ctx, LWS_GENHMAC_TYPE_SHA1, ctx->srtcp_session_auth, 20))
		return -1;

	if (lws_genhmac_update(&hmac_ctx, pkt, *len - tag_len)) {
		lws_genhmac_destroy(&hmac_ctx, NULL);
		return -1;
	}

	if (lws_genhmac_destroy(&hmac_ctx, computed_tag))
		return -1;

	/* the tag is secret-derived, compare it in constant time */
	if (lws_timingsafe_bcmp(tag, computed_tag, (uint32_t)tag_len)) {
		/* any peer can drive this, so it can't be at err level */
		lwsl_info("SRTCP: Auth tag mismatch!\n");

		return -2;
	}

	/*
	 * RFC 3711 3.3.2: replay list check on the SRTCP index, after the tag
	 * verified... else a captured RTCP datagram (eg, a PLI) can be
	 * replayed at will to force keyframes on demand
	 */

	if (lws_srtp_replay_seen(ctx->srtcp_rx_base, ctx->srtcp_rx_bitmap,
				 index)) {
		lwsl_info("SRTCP: replayed index %u\n", srtcp_index_v);

		return -3;
	}

	lws_srtp_replay_update(&ctx->srtcp_rx_base, &ctx->srtcp_rx_bitmap,
			       index);

	if (!encrypted) {
		*len = rtcp_len;
		return 0;
	}

	/* 3. Decrypt payload (bytes 8 onwards) */
	memset(iv, 0, 16);
	iv[4] = (uint8_t)(ssrc >> 24);
	iv[5] = (uint8_t)(ssrc >> 16);
	iv[6] = (uint8_t)(ssrc >> 8);
	iv[7] = (uint8_t)(ssrc & 0xff);
	iv[8] = (uint8_t)(index >> 40);
	iv[9] = (uint8_t)(index >> 32);
	iv[10] = (uint8_t)(index >> 24);
	iv[11] = (uint8_t)(index >> 16);
	iv[12] = (uint8_t)(index >> 8);
	iv[13] = (uint8_t)(index & 0xff);

	for (int i = 0; i < 14; i++)
		iv[i] ^= ctx->srtcp_session_salt[i];

	el.buf = ctx->srtcp_session_key;
	el.len = 16;
	if (lws_genaes_create(&aes_ctx, LWS_GAESO_ENC, LWS_GAESM_CTR, &el, LWS_GAESP_NO_PADDING, NULL))
		return -1;

	/* Decrypt from byte 8 onwards */
	if (lws_genaes_crypt(&aes_ctx, pkt + 8, rtcp_len - 8, pkt + 8, iv, NULL, &nc, 0)) {
		lws_genaes_destroy(&aes_ctx, NULL, 0);
		return -1;
	}
	lws_genaes_destroy(&aes_ctx, NULL, 0);

	*len = rtcp_len;
	return 0;
}
