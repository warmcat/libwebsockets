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
 * RTP video depacketisers for the mixer.
 *
 * Every length here comes from the peer.  Bounds are checked by comparing
 * against what is left, never by adding a peer-chosen length to an offset:
 * on a 32-bit size_t, off + len wraps for a len near 4GB (which a 5-byte AV1
 * leb128 can express) and passes a check against the packet length.
 */

#include <libwebsockets.h>

#include <string.h>
#include <stdlib.h>

#include "mixer-depkt.h"

int
mixer_vbuf_append(struct mixer_vbuf *b, const uint8_t *d, size_t n)
{
	size_t needed;

	/* b->len never exceeds the cap, so this can't wrap */
	if (n > MIXER_VIDEO_BUF_CAP || b->len > MIXER_VIDEO_BUF_CAP - n)
		goto drop;

	needed = b->len + n;

	if (b->alloc < needed) {
		size_t na = needed + 4096;
		uint8_t *tmp = realloc(b->buf, na);

		if (!tmp)
			goto drop;

		b->buf = tmp;
		b->alloc = na;
	}

	if (n)
		memcpy(b->buf + b->len, d, n);
	b->len = needed;

	return 0;

drop:
	/*
	 * The old buffer is still valid but too small: writing into it
	 * anyway would be a heap overflow of peer-chosen length, and what is
	 * in it is an incomplete unit nobody can use
	 */
	b->len = 0;

	return 1;
}

void
mixer_depkt_reset(struct mixer_depkt *d)
{
	d->frame.len = 0;
	d->obu.len = 0;
	d->fu_a_active = 0;
}

void
mixer_depkt_destroy(struct mixer_depkt *d)
{
	free(d->frame.buf);
	free(d->obu.buf);
	memset(d, 0, sizeof(*d));
}

size_t
mixer_leb128(const uint8_t *p, size_t len, uint64_t *val)
{
	uint64_t v = 0;
	size_t j;

	for (j = 0; j < 8 && j < len; j++) {
		v |= (uint64_t)(p[j] & 0x7f) << (j * 7);
		if (!(p[j] & 0x80)) {
			*val = v;
			return j + 1;
		}
	}

	return 0;
}

static const uint8_t annexb_start[4] = { 0, 0, 0, 1 };

void
mixer_depkt_h264(struct mixer_depkt *d, const uint8_t *in, size_t len)
{
	uint8_t type;

	if (!in || !len)
		return;

	type = in[0] & 0x1f;

	if (type >= 1 && type <= 23) {
		/* Single NAL Unit */
		if (!mixer_vbuf_append(&d->frame, annexb_start, 4))
			mixer_vbuf_append(&d->frame, in, len);

		return;
	}

	if (type == 24) {
		/* STAP-A: Single-Time Aggregation Packet */
		size_t off = 1;

		while (len - off >= 2) {
			size_t nal_size = (size_t)((in[off] << 8) | in[off + 1]);

			off += 2;
			if (!nal_size || nal_size > len - off) {
				lwsl_info("%s: STAP-A: bad NAL size %u\n",
					  __func__, (unsigned int)nal_size);
				break;
			}

			if (mixer_vbuf_append(&d->frame, annexb_start, 4) ||
			    mixer_vbuf_append(&d->frame, in + off, nal_size))
				break;

			off += nal_size;
		}

		return;
	}

	if (type == 28 && len >= 2) {
		/* FU-A: Fragmentation Unit */
		uint8_t fu_header = in[1];

		if (fu_header & 0x80) {
			/* Start: start code + reconstructed NAL header */
			uint8_t nal_hdr = (uint8_t)((in[0] & 0xe0) |
						    (fu_header & 0x1f));

			d->fu_a_active = 1;
			if (mixer_vbuf_append(&d->frame, annexb_start, 4) ||
			    mixer_vbuf_append(&d->frame, &nal_hdr, 1) ||
			    mixer_vbuf_append(&d->frame, in + 2, len - 2))
				d->fu_a_active = 0;
		} else if (d->frame.len && d->fu_a_active) {
			/* Middle or end: we don't decode on 'E', but on marker */
			if (mixer_vbuf_append(&d->frame, in + 2, len - 2))
				d->fu_a_active = 0;
		}
	}
}

/*
 * Append one whole OBU to the access unit, in the low overhead bitstream
 * format (AV1 spec section 5), which the decoder expects: header with
 * obu_has_size_field set, extension header if any, leb128 payload size,
 * payload.  An access unit starts with a temporal delimiter.
 */
static void
mixer_av1_obu_to_frame(struct mixer_depkt *d, const uint8_t *data, size_t len)
{
	static const uint8_t td[2] = { 0x12, 0x00 }; /* temporal delimiter */
	uint8_t hdr, ext = 0, leb[8];
	size_t hdr_len, off, payload_len, leb_len = 0, v;
	uint64_t isz;

	if (!len || len > MIXER_VIDEO_BUF_CAP)
		return;

	hdr = data[0];
	hdr_len = (hdr & 0x04) ? 2 : 1;
	if (len < hdr_len)
		return;
	if (hdr_len == 2)
		ext = data[1];

	off = hdr_len;

	/*
	 * If the OBU has its own size field, strip it: we write our own.  If
	 * it's not a valid leb128, take the rest of the element as payload.
	 */
	if (hdr & 0x02)
		off += mixer_leb128(data + off, len - off, &isz);

	payload_len = len - off;

	/* payload_len < 16MiB, so this needs at most 4 bytes of leb[] */
	v = payload_len;
	do {
		leb[leb_len] = (uint8_t)(v & 0x7f);
		v >>= 7;
		if (v)
			leb[leb_len] |= 0x80;
		leb_len++;
	} while (v);

	hdr |= 0x02;

	/* any append failing drops the whole access unit, so stop there */
	if (!d->frame.len && ((hdr & 0x78) >> 3) != 2 &&
	    mixer_vbuf_append(&d->frame, td, sizeof(td)))
		return;

	if (mixer_vbuf_append(&d->frame, &hdr, 1) ||
	    (hdr_len == 2 && mixer_vbuf_append(&d->frame, &ext, 1)) ||
	    mixer_vbuf_append(&d->frame, leb, leb_len))
		return;

	mixer_vbuf_append(&d->frame, data + off, payload_len);
}

void
mixer_depkt_av1(struct mixer_depkt *d, const uint8_t *in, size_t len)
{
	uint8_t z, y, w;
	size_t off = 1;
	int elem = 0, drop_fragment;

	if (!in || len < 2)
		return;

	z = (in[0] >> 7) & 1;	/* first element continues an OBU */
	y = (in[0] >> 6) & 1;	/* last element continues into next packet */
	w = (in[0] >> 4) & 3;	/* element count, 0 = all have a size */

	lwsl_debug("%s: Z=%d Y=%d W=%d len %zu\n", __func__, z, y, w, len);

	/* a packet that starts a fresh OBU discards any incomplete fragment */
	if (!z)
		d->obu.len = 0;

	/* a continuation of a fragment we don't have can't be used */
	drop_fragment = z && !d->obu.len;

	while (off < len) {
		size_t rem = len - off, leb_len = 0, obu_size = rem;
		int has_size = !w || elem != w - 1, last;
		uint64_t sz = 0;

		/*
		 * Every element has a leb128 size before it, except the last
		 * of W elements, which takes the rest of the packet.  A size
		 * that is not a valid leb128, or claims more than is left, can
		 * only be the last element without one
		 */
		if (has_size) {
			leb_len = mixer_leb128(in + off, rem, &sz);
			if (leb_len && sz <= (uint64_t)(rem - leb_len))
				obu_size = (size_t)sz;
			else
				leb_len = 0;
		}

		off += leb_len;
		rem -= leb_len;
		last = obu_size == rem;

		if (!elem && z) {
			/* continuation of an OBU from the previous packet */
			if (!drop_fragment &&
			    !mixer_vbuf_append(&d->obu, in + off, obu_size) &&
			    !(last && y)) {
				/* ... and it completes here */
				mixer_av1_obu_to_frame(d, d->obu.buf,
						       d->obu.len);
				d->obu.len = 0;
			}
		} else if (last && y) {
			/* an OBU starting here and continuing in the next */
			d->obu.len = 0;
			if (obu_size)
				mixer_vbuf_append(&d->obu, in + off, obu_size);
		} else
			/* an OBU wholly in this packet */
			mixer_av1_obu_to_frame(d, in + off, obu_size);

		/* each turn uses at least one byte: a leb128, or the rest */
		off += obu_size;
		elem++;
	}
}
