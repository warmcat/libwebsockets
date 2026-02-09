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
	uint16_t seq = (uint16_t)((pkt[2] << 8) | pkt[3]);
	uint32_t ssrc = (uint32_t)((pkt[8] << 24) | (pkt[9] << 16) | (pkt[10] << 8) | pkt[11]);
	uint64_t index;
	uint8_t iv[16];
	uint8_t tag[20];
	size_t nc = 0;
	size_t tag_len = (ctx->profile == LWS_SRTP_PROFILE_AES128_CM_HMAC_SHA1_80) ? 10 : 4;

	if (!ctx->keys_derived)
		return -1;

	if (*len + tag_len > max_len)
		return -1;

	/* ROC management (simplistic) */
	if (ctx->last_seq > 0xff00 && seq < 0x00ff)
		ctx->roc++;
	ctx->last_seq = seq;

	index = ((uint64_t)ctx->roc << 16) | seq;

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
	roc_bytes[0] = (uint8_t)(ctx->roc >> 24);
	roc_bytes[1] = (uint8_t)(ctx->roc >> 16);
	roc_bytes[2] = (uint8_t)(ctx->roc >> 8);
	roc_bytes[3] = (uint8_t)(ctx->roc & 0xff);

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
	uint32_t ssrc = (uint32_t)((pkt[4] << 24) | (pkt[5] << 16) | (pkt[6] << 8) | pkt[7]);
	uint64_t index;
	uint8_t iv[16], tag[20];
	size_t nc = 0;
	size_t tag_len = (ctx->profile == LWS_SRTP_PROFILE_AES128_CM_HMAC_SHA1_80) ? 10 : 4;

	if (!ctx->keys_derived || *len + 4 + tag_len > max_len)
		return -1;

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
	p_index[0] = (uint8_t)(0x80 | (index >> 24)); /* E=1 */
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
	uint16_t seq = (uint16_t)((pkt[2] << 8) | pkt[3]);
	uint32_t ssrc = (uint32_t)((pkt[8] << 24) | (pkt[9] << 16) | (pkt[10] << 8) | pkt[11]);
	uint64_t index;
	uint8_t iv[16], computed_tag[20];
	size_t nc = 0;
	size_t tag_len = (ctx->profile == LWS_SRTP_PROFILE_AES128_CM_HMAC_SHA1_80) ? 10 : 4;

	if (!ctx->keys_derived || *len < 12 + tag_len)
		return -1;

	/* Simplified ROC management for RX */
	if (ctx->last_seq > 0xff00 && seq < 0x00ff)
		ctx->roc++;
	ctx->last_seq = seq;
	index = ((uint64_t)ctx->roc << 16) | seq;

	/* 1. Verify Authentication Tag */
	if (lws_genhmac_init(&hmac_ctx, LWS_GENHMAC_TYPE_SHA1, ctx->session_auth, 20))
		return -1;

	if (lws_genhmac_update(&hmac_ctx, pkt, *len - tag_len)) {
		lws_genhmac_destroy(&hmac_ctx, NULL);
		return -1;
	}

	uint8_t roc_bytes[4];
	roc_bytes[0] = (uint8_t)(ctx->roc >> 24);
	roc_bytes[1] = (uint8_t)(ctx->roc >> 16);
	roc_bytes[2] = (uint8_t)(ctx->roc >> 8);
	roc_bytes[3] = (uint8_t)(ctx->roc & 0xff);

	if (lws_genhmac_update(&hmac_ctx, roc_bytes, 4) ||
	    lws_genhmac_destroy(&hmac_ctx, computed_tag))
		return -1;

	if (memcmp(pkt + *len - tag_len, computed_tag, tag_len)) {
		lwsl_err("SRTP: Auth tag mismatch!\n");
		return -2;
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

	*len -= tag_len;
	return 0;
}

int
lws_srtp_unprotect_rtcp(struct lws_srtp_ctx *ctx, uint8_t *pkt, size_t *len)
{
	struct lws_genaes_ctx aes_ctx;
	struct lws_genhmac_ctx hmac_ctx;
	struct lws_gencrypto_keyelem el;
	uint32_t ssrc = (uint32_t)((pkt[4] << 24) | (pkt[5] << 16) | (pkt[6] << 8) | pkt[7]);
	uint32_t srtcp_index_v;
	uint64_t index;
	uint8_t iv[16], tag[20], computed_tag[20];
	size_t nc = 0;
	size_t tag_len = (ctx->profile == LWS_SRTP_PROFILE_AES128_CM_HMAC_SHA1_80) ? 10 : 4;
	uint8_t *p_index;

	if (!ctx->keys_derived || *len < 8 + 4 + tag_len)
		return -1;

	/* 1. Extract Index and Tag */
	size_t rtcp_len = *len - tag_len - 4;
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

	if (memcmp(tag, computed_tag, tag_len)) {
		lwsl_err("SRTCP: Auth tag mismatch!\n");
		return -2;
	}

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
