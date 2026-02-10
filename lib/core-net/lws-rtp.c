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
#include <libwebsockets/lws-rtp.h>

void
lws_rtp_init(struct lws_rtp_ctx *ctx, uint32_t ssrc, uint8_t pt)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->ssrc = ssrc;
	ctx->pt = pt;
	/* Start with randomish seq and ts if desired, or just 0 */
}

void
lws_rtp_write_header(struct lws_rtp_ctx *ctx, uint8_t *buf, int marker)
{
	if (ctx->ts != ctx->last_ts) {
		ctx->new_frame = 1;
		ctx->last_ts = ctx->ts;
	}

	buf[0] = 0x80; /* V=2, P=0, X=0, CC=0 */
	buf[1] = (uint8_t)((marker ? 0x80 : 0) | (ctx->pt & 0x7f));
	buf[2] = (uint8_t)(ctx->seq >> 8);
	buf[3] = (uint8_t)(ctx->seq & 0xff);
	ctx->seq++;

	buf[4] = (uint8_t)(ctx->ts >> 24);
	buf[5] = (uint8_t)(ctx->ts >> 16);
	buf[6] = (uint8_t)(ctx->ts >> 8);
	buf[7] = (uint8_t)(ctx->ts & 0xff);

	buf[8] = (uint8_t)(ctx->ssrc >> 24);
	buf[9] = (uint8_t)(ctx->ssrc >> 16);
	buf[10] = (uint8_t)(ctx->ssrc >> 8);
	buf[11] = (uint8_t)(ctx->ssrc & 0xff);
}

int
lws_rtp_h264_packetize(struct lws_rtp_ctx *ctx, const uint8_t *nal, size_t len,
		       int last_nal, size_t mtu, lws_rtp_cb_t cb, void *priv)
{
	uint8_t pkt[2048]; /* Should be enough for MTU + RTP header + FU header */
	size_t rtp_mtu = mtu - LWS_RTP_HEADER_LEN;

	if (len <= rtp_mtu) {
		lws_rtp_write_header(ctx, pkt, last_nal);
		memcpy(pkt + LWS_RTP_HEADER_LEN, nal, len);
		cb(priv, pkt, LWS_RTP_HEADER_LEN + len, last_nal);
		return 0;
	}

	/* FU-A Fragmentation (RFC 6184 Section 5.8) */
	uint8_t nal_type = nal[0] & 0x1f;
	uint8_t nal_nri = nal[0] & 0x60;
	const uint8_t *p = nal + 1;
	size_t left = len - 1;
	int first = 1;

	while (left > 0) {
		size_t chunk = left > (rtp_mtu - 2) ? (rtp_mtu - 2) : left;
		int last_frag = (left == chunk);

		lws_rtp_write_header(ctx, pkt, last_frag && last_nal);

		/* FU indicator */
		pkt[LWS_RTP_HEADER_LEN] = (uint8_t)(nal_nri | 28); /* FU-A type 28 */
		/* FU header */
		pkt[LWS_RTP_HEADER_LEN + 1] = (uint8_t)((first ? 0x80 : 0) | (last_frag ? 0x40 : 0) | nal_type);

		memcpy(pkt + LWS_RTP_HEADER_LEN + 2, p, chunk);
		cb(priv, pkt, LWS_RTP_HEADER_LEN + 2 + chunk, last_frag && last_nal);

		p += chunk;
		left -= chunk;
		first = 0;
	}

	return 0;
}

int
lws_rtp_av1_packetize(struct lws_rtp_ctx *ctx, const uint8_t *obu, size_t len,
		       int last_obu, size_t mtu, lws_rtp_cb_t cb, void *priv)
{
	uint8_t pkt[2048];
	size_t rtp_mtu = mtu - LWS_RTP_HEADER_LEN;

	if (len <= rtp_mtu - 1) {
		lws_rtp_write_header(ctx, pkt, last_obu);
		/* Annex B Aggregation Header: [ Z | Y | W | N | - - - - ]
		 * Single OBU Element Packet (W=1 -> 0x10)
		 */
		uint8_t n_bit = (len > 0 && ((obu[0] >> 3) & 0x0f) == 1) ? 0x08 : 0x00;
		pkt[LWS_RTP_HEADER_LEN] = (uint8_t)(0x10 | n_bit);

		memcpy(pkt + LWS_RTP_HEADER_LEN + 1, obu, len);
		cb(priv, pkt, LWS_RTP_HEADER_LEN + 1 + len, last_obu);
	} else {
		/* Fragmented OBU */
		size_t written = 0;
		int first = 1;

		while (written < len) {
			size_t frag = len - written;
			int last_frag = 1;

			if (frag > rtp_mtu - 1) {
				frag = rtp_mtu - 1;
				last_frag = 0;
			}

			lws_rtp_write_header(ctx, pkt, last_frag && last_obu);

			if (first) {
				uint8_t n_bit = ((obu[0] >> 3) & 0x0f) == 1 ? 0x08 : 0x00;
				/* First Fragment: Z=0, Y=1 (0x40), W=1 (0x10) -> 0x50 | n_bit */
				pkt[LWS_RTP_HEADER_LEN] = (uint8_t)(0x50 | n_bit);
			} else if (!last_frag) {
				/* Middle Fragment: Z=1 (0x80), Y=1 (0x40), W=1 (0x10) -> 0xD0 */
				pkt[LWS_RTP_HEADER_LEN] = 0xD0;
			} else {
				/* Last Fragment: Z=1 (0x80), Y=0, W=1 (0x10) -> 0x90 */
				pkt[LWS_RTP_HEADER_LEN] = 0x90;
			}



			memcpy(pkt + LWS_RTP_HEADER_LEN + 1, obu + written, frag);
			cb(priv, pkt, LWS_RTP_HEADER_LEN + 1 + frag, last_frag && last_obu);

			written += frag;
			first = 0;
		}
	}

	return 0;
}
