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
 *
 * RTP video depacketisers for the mixer: they turn the RTP payloads a peer
 * sends into the access units its decoder is fed.  These do not depend on
 * GStreamer, so api-test-webrtc-mixer-depkt can run them.
 */

#if !defined(__LWS_MIXER_DEPKT_H__)
#define __LWS_MIXER_DEPKT_H__

#include <stdint.h>
#include <stddef.h>

/* the assembled access unit and a reassembled AV1 OBU are both capped */
#define MIXER_VIDEO_BUF_CAP		(16 * 1024 * 1024)

/* a growable buffer, never holding more than MIXER_VIDEO_BUF_CAP */
struct mixer_vbuf {
	uint8_t				*buf;
	size_t				len;
	size_t				alloc;
};

struct mixer_depkt {
	struct mixer_vbuf		frame;	/* access unit for the decoder:
						 * Annex-B H.264, or AV1 low
						 * overhead bitstream format */
	struct mixer_vbuf		obu;	/* AV1 OBU fragmented over
						 * several packets */
	char				fu_a_active; /* H.264 FU-A in progress */
};

/*
 * Append `n` bytes, growing the buffer as needed.  Returns 0 if they were
 * appended.  If they could not be (the cap would be exceeded, or the buffer
 * could not grow), it returns 1 having appended nothing and dropped what was
 * already in the buffer: the caller must stop appending to it.
 */
int
mixer_vbuf_append(struct mixer_vbuf *b, const uint8_t *d, size_t n);

/* drop any partly-assembled access unit and OBU fragment */
void
mixer_depkt_reset(struct mixer_depkt *d);

/* free the buffers and zero `d` */
void
mixer_depkt_destroy(struct mixer_depkt *d);

/*
 * Decode an AV1 leb128() (at most 8 bytes) from the start of `p`.  Returns
 * how many bytes it used, or 0 if it did not end within `len` (or 8) bytes.
 * The value is always decoded at 64 bits, whatever the width of size_t.
 */
size_t
mixer_leb128(const uint8_t *p, size_t len, uint64_t *val);

/* RFC 6184 H.264 payload: single NAL, STAP-A and FU-A */
void
mixer_depkt_h264(struct mixer_depkt *d, const uint8_t *in, size_t len);

/* AV1 RTP payload format: aggregation header and OBU elements */
void
mixer_depkt_av1(struct mixer_depkt *d, const uint8_t *in, size_t len);

#endif
