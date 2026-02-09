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

#ifndef __LWS_RTP_H__
#define __LWS_RTP_H__

/* RTP Header (RFC 3550) length */
#define LWS_RTP_HEADER_LEN 12

struct lws_rtp_ctx {
	uint32_t ssrc;
	uint32_t ts;
	uint16_t seq;
	uint8_t pt; /* Payload Type */
};

typedef void (*lws_rtp_cb_t)(void *priv, const uint8_t *pkt, size_t len, int marker);

/**
 * lws_rtp_init() - Initialize RTP context
 *
 * \param ctx: RTP context to initialize
 * \param ssrc: SSRC for this stream
 * \param pt: Payload type
 */
LWS_VISIBLE LWS_EXTERN void
lws_rtp_init(struct lws_rtp_ctx *ctx, uint32_t ssrc, uint8_t pt);

/**
 * lws_rtp_write_header() - Write RTP header to buffer
 *
 * \param ctx: RTP context
 * \param buf: Buffer to write header to (must be at least LWS_RTP_HEADER_LEN)
 * \param marker: Marker bit
 *
 * Updates sequence number in context.
 */
LWS_VISIBLE LWS_EXTERN void
lws_rtp_write_header(struct lws_rtp_ctx *ctx, uint8_t *buf, int marker);

/**
 * lws_rtp_h264_packetize() - Fragment H.264 NALU into RTP packets
 *
 * \param ctx: RTP context
 * \param nal: NALU data (excluding start code)
 * \param len: NALU length
 * \param last_nal: true if this is the last NALU of the frame
 * \param mtu: MTU for the transport
 * \param cb: Callback for each generated packet
 * \param priv: Private pointer for callback
 *
 * Handles FU-A fragmentation if NALU exceeds MTU.
 */
LWS_VISIBLE LWS_EXTERN int
lws_rtp_h264_packetize(struct lws_rtp_ctx *ctx, const uint8_t *nal, size_t len,
		       int last_nal, size_t mtu, lws_rtp_cb_t cb, void *priv);

#endif /* __LWS_RTP_H__ */
