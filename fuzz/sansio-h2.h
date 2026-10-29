/*
 * lws fuzzing: h2 framing done right, as a sansio-peer.h harness op
 *
 * Written in 2010 - 2026 Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Bytes mutated one at a time rarely stay h2 frames: the length in each
 * frame header no longer matches, and the connection is gone at the first
 * frame.  So the program's op 7 (../sansio-peer.h) is h2 framing done
 * right, with what the frame is about from the input:
 *
 *   op 7, argument a:
 *    a & 15 = 0 .. 9:  a frame of that type: flags, stream, length (a 255
 *		       means a u16 follows), then that much payload
 *    a & 15 = 10:      HEADERS whose hpack is right, then more hpack: its
 *		       length, and it.  From a client peer, a request: stream,
 *		       method byte, path length, path; method bit 0 POST, bit
 *		       1 END_STREAM, bit 2 an RFC 8441 ws CONNECT for "echo".
 *		       From a server peer, an answer: stream, status byte; bits
 *		       0 - 3 pick a :status, good or not, bit 1 END_STREAM, bit
 *		       5 a content-length of the next byte * 64
 *    a & 15 = 11:      DATA of (byte + 1) * 64 bytes on stream, END_STREAM if
 *		       a & 16
 *    a & 15 = 12:      WINDOW_UPDATE on stream of the next 4 bytes
 *    a & 15 = 13 .. 15: a frame of type (a & 15) - 10, as for 0 .. 9
 *
 * A stream byte s is stream 0 for 0, else for s < 128 the s-th stream a
 * client may open, 2s - 1, else s & 127, so the ids of the client's
 * streams, that both sides' frames are mostly about, come easily, and the
 * others can still be had.
 */

#define H2_FRAME_MAX		(9 + 65535)

static uint8_t frame[H2_FRAME_MAX];
/* the peer is the client, sending requests, or the server, answering */
static int h2_peer_is_server;

/* the input, read without going past its end */
struct rd {
	const uint8_t	*p;
	size_t		len, pos;
};

static uint8_t
rd_u8(struct rd *r)
{
	return r->pos < r->len ? r->p[r->pos++] : 0;
}

static uint32_t
rd_sid(struct rd *r)
{
	uint8_t s = rd_u8(r);

	if (!s)
		return 0;

	/* the client's streams, which either side's frames are mostly on */
	if (s < 128)
		return (uint32_t)s * 2 - 1;

	return (uint32_t)(s & 127);
}

/* the next n bytes of the input, or as many of them as there are */
static size_t
rd_bytes(struct rd *r, uint8_t *dest, size_t n)
{
	if (n > r->len - r->pos)
		n = r->len - r->pos;
	memcpy(dest, r->p + r->pos, n);
	r->pos += n;

	return n;
}

static void
frame_send(struct fzp_transport *t, uint8_t type, uint8_t flags,
	   uint32_t sid, size_t len)
{
	frame[0] = (uint8_t)(len >> 16);
	frame[1] = (uint8_t)(len >> 8);
	frame[2] = (uint8_t)len;
	frame[3] = type;
	frame[4] = flags;
	frame[5] = (uint8_t)(sid >> 24) & 0x7f;
	frame[6] = (uint8_t)(sid >> 16);
	frame[7] = (uint8_t)(sid >> 8);
	frame[8] = (uint8_t)sid;

	fzp_rx(t, frame, 9 + len);
}

/* an hpack integer with an n-bit prefix, RFC 7541 5.1 */
static size_t
hp_int(uint8_t *p, uint8_t first, int bits, size_t v)
{
	size_t lim = ((size_t)1 << bits) - 1, n = 0;

	if (v < lim) {
		p[n++] = (uint8_t)(first | v);
		return n;
	}
	p[n++] = (uint8_t)(first | lim);
	v -= lim;
	while (v >= 128) {
		p[n++] = (uint8_t)(0x80 | (v & 0x7f));
		v >>= 7;
	}
	p[n++] = (uint8_t)v;

	return n;
}

/* a literal not indexed, of static name index idx, or a new name if 0 */
static size_t
hp_lit(uint8_t *p, size_t idx, const char *name, const uint8_t *v,
       size_t vlen)
{
	size_t n = hp_int(p, 0, 4, idx);

	if (!idx) {
		n += hp_int(p + n, 0, 7, strlen(name));
		memcpy(p + n, name, strlen(name));
		n += strlen(name);
	}
	n += hp_int(p + n, 0, 7, vlen);
	memcpy(p + n, v, vlen);

	return n + vlen;
}

static size_t
h2_op(struct fzp_transport *t, int a, const uint8_t *in, size_t len)
{
	struct rd r = { in, len, 0 };
	uint8_t *pl = frame + 9, m, type, flags, path[255];
	size_t n, k;
	uint32_t sid;

	switch (a & 15) {
	case 10:
		if (h2_peer_is_server) {
			/* an answer whose hpack is right */
			static const char * const st[] = {
				"200", "204", "206", "304", "400", "404",
				"500", "100", "101", "199", "999", "20",
				"2000", "", "+20", "abc",
			};

			sid = rd_sid(&r);
			m = rd_u8(&r);
			n = 0;
			n += hp_lit(pl + n, 8, NULL,
				    (const uint8_t *)st[m & 15],
				    strlen(st[m & 15]));
			if (m & 0x20) {
				k = (size_t)lws_snprintf((char *)path,
						sizeof(path), "%u",
						(unsigned int)rd_u8(&r) * 64);
				n += hp_lit(pl + n, 28, NULL, path, k);
			}
		} else {
			/* a request whose hpack is right */
			sid = rd_sid(&r);
			m = rd_u8(&r);
			k = rd_bytes(&r, path, rd_u8(&r));
			n = 0;
			if (m & 4) {
				n += hp_lit(pl + n, 2, NULL,
					    (const uint8_t *)"CONNECT", 7);
				n += hp_lit(pl + n, 0, ":protocol",
					    (const uint8_t *)"websocket", 9);
				n += hp_lit(pl + n, 0, "sec-websocket-version",
					    (const uint8_t *)"13", 2);
				n += hp_lit(pl + n, 0, "sec-websocket-protocol",
					    (const uint8_t *)"echo", 4);
			} else
				/* POST : GET */
				pl[n++] = (m & 1) ? 0x83 : 0x82;
			pl[n++] = 0x86; /* :scheme http */
			n += hp_lit(pl + n, 1, NULL,
				    (const uint8_t *)"fuzz", 4);
			n += hp_lit(pl + n, 4, NULL,
				    k ? path : (const uint8_t *)"/", k ? k : 1);
		}
		n += rd_bytes(&r, pl + n, rd_u8(&r));
		frame_send(t, 1, (uint8_t)(4 | ((m & 2) ? 1 : 0)), sid, n);
		break;

	case 11: /* bulk DATA */
		sid = rd_sid(&r);
		n = ((size_t)rd_u8(&r) + 1) * 64;
		memset(pl, 'd', n);
		frame_send(t, 0, (a & 16) ? 1 : 0, sid, n);
		break;

	case 12:
		sid = rd_sid(&r);
		n = rd_bytes(&r, pl, 4);
		memset(pl + n, 0, 4 - n);
		frame_send(t, 8, 0, sid, 4);
		break;

	default:
		type = (uint8_t)((a & 15) >= 13 ? (a & 15) - 10 : (a & 15));
		flags = rd_u8(&r);
		sid = rd_sid(&r);
		n = rd_u8(&r);
		if (n == 255)
			n = ((size_t)rd_u8(&r) << 8) | rd_u8(&r);
		n = rd_bytes(&r, pl, n);
		frame_send(t, type, flags, sid, n);
		break;
	}

	return r.pos;
}
