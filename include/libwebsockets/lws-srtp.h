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

#ifndef __LWS_SRTP_H__
#define __LWS_SRTP_H__

enum lws_srtp_profiles {
	LWS_SRTP_PROFILE_AES128_CM_HMAC_SHA1_80 = 0x01,
	LWS_SRTP_PROFILE_AES128_CM_HMAC_SHA1_32 = 0x02,
};

struct lws_srtp_ctx {
	uint8_t master_key[16];
	uint8_t master_salt[14];

	uint8_t session_key[16];
	uint8_t session_salt[14];
	uint8_t session_auth[20];

	uint8_t srtcp_session_key[16];
	uint8_t srtcp_session_salt[14];
	uint8_t srtcp_session_auth[20];

	/* Multi-SSRC support (RFC 3711 requires per-SSRC ROC/Seq) */
    struct lws_srtp_src_ctx {
        uint32_t ssrc; /* 0 = unused slot */
        uint32_t roc;
        uint16_t last_seq;
        uint8_t  any_packet_received;
    } src[4]; /* Support up to 4 streams (Video, Audio, RTX, etc) */

	uint32_t srtcp_index;

	enum lws_srtp_profiles profile;
	int keys_derived;
};

/**
 * lws_srtp_init() - Initialize SRTP context
 *
 * \param ctx: SRTP context
 * \param profile: SRTP profile to use
 * \param master_key: 16-byte master key
 * \param master_salt: 14-byte master salt
 */
LWS_VISIBLE LWS_EXTERN int
lws_srtp_init(struct lws_srtp_ctx *ctx, enum lws_srtp_profiles profile,
	      const uint8_t *master_key, const uint8_t *master_salt);

/**
 * lws_srtp_protect() - Encrypt and authenticate RTP packet
 *
 * \param ctx: SRTP context
 * \param pkt: RTP packet (header + payload), must have space for auth tag
 * \param len: Pointer to packet length (updated on success)
 * \param max_len: Maximum size of pkt buffer
 *
 * Returns 0 for OK or nonzero for error.
 */
/**
 * lws_srtp_protect_rtp() - Encrypt and authenticate RTP packet
 *
 * \param ctx: SRTP context
 * \param pkt: RTP packet (header + payload), must have space for auth tag
 * \param len: Pointer to packet length (updated on success)
 * \param max_len: Maximum size of pkt buffer
 *
 * Returns 0 for OK or nonzero for error.
 * Note: lws_srtp_protect() is an alias for this.
 */
LWS_VISIBLE LWS_EXTERN int
lws_srtp_protect_rtp(struct lws_srtp_ctx *ctx, uint8_t *pkt, size_t *len, size_t max_len);

#define lws_srtp_protect lws_srtp_protect_rtp

/**
 * lws_srtp_protect_rtcp() - Encrypt and authenticate RTCP packet
 *
 * \param ctx: SRTP context
 * \param pkt: RTCP packet (header + payload), must have space for index and tag
 * \param len: Pointer to packet length (updated on success)
 * \param max_len: Maximum size of pkt buffer
 *
 * Returns 0 for OK or nonzero for error.
 */
LWS_VISIBLE LWS_EXTERN int
lws_srtp_protect_rtcp(struct lws_srtp_ctx *ctx, uint8_t *pkt, size_t *len, size_t max_len);

/**
 * lws_srtp_unprotect_rtp() - Decrypt and authenticate RTP packet
 *
 * \param ctx: SRTP context
 * \param pkt: Protected RTP packet (header + payload + tag)
 * \param len: Pointer to packet length (updated on success to reflect decrypted payload)
 *
 * Returns 0 for OK or nonzero for error.
 */
LWS_VISIBLE LWS_EXTERN int
lws_srtp_unprotect_rtp(struct lws_srtp_ctx *ctx, uint8_t *pkt, size_t *len);

/**
 * lws_srtp_unprotect_rtcp() - Decrypt and authenticate RTCP packet
 *
 * \param ctx: SRTP context
 * \param pkt: Protected RTCP packet (header + payload + index/E + tag)
 * \param len: Pointer to packet length (updated on success to reflect decrypted payload)
 *
 * Returns 0 for OK or nonzero for error.
 */
LWS_VISIBLE LWS_EXTERN int
lws_srtp_unprotect_rtcp(struct lws_srtp_ctx *ctx, uint8_t *pkt, size_t *len);

#endif /* __LWS_SRTP_H__ */
