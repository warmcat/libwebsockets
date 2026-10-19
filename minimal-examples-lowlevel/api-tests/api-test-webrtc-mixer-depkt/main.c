/*
 * lws-api-test-webrtc-mixer-depkt
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 * Note: CC0 1.0 Universal Public Domain Dedication
 *
 * Runs the webrtc mixer plugin's RTP video depacketisers
 * (plugins/protocol_lws_webrtc_mixer/mixer-depkt.c) on crafted payloads.
 *
 * The AV1 one once checked an element's leb128 size as
 * off + leb_len + obu_size > len, which on a 32-bit size_t wraps for a size
 * near 4GB (5 leb128 bytes, eg fc ff ff ff 0f), accepted it, and copied ~4GB
 * into the frame buffer.  Sizes are now decoded at 64 bits and compared with
 * what is left, so the same packets are handled the same on any width; the
 * cases here use the sizes that wrapped.
 *
 * Covered behaviours:
 *
 *  - leb128 decodes 1 to 8 bytes at 64 bits, including the 5-byte value
 *    that wraps a 32-bit size_t, and refuses an unterminated one
 *  - AV1 elements claiming 4GB - 4, 2^56 - 1 or more than the cap are not
 *    taken at their word: the access unit stays the size of the packet
 *  - AV1 W=0 and W=2 aggregation, an OBU's own size field and extension
 *    header, an OBU fragmented over two packets, and a continuation with no
 *    start, give the expected low overhead bitstream access unit
 *  - H.264 single NAL, STAP-A (and STAP-A NAL sizes over the packet), and
 *    FU-A start / continuation (and a continuation with no start) give the
 *    expected Annex-B access unit
 *  - the growable buffer takes up to the cap, and refuses lengths over it
 *    and lengths that would wrap when added, dropping what it held
 */

#include <libwebsockets.h>

#include <string.h>
#include <stdlib.h>

#include "mixer-depkt.h"

static int fails, oks;

struct dpt_buf {
	const uint8_t		*p;
	size_t			len;
};

struct dpt_case {
	const char		*name;
	int			av1;
	struct dpt_buf		pkt[2];
	struct dpt_buf		exp;	/* .p NULL: the access unit is empty */
};

#define P(...) { (const uint8_t []){ __VA_ARGS__ }, \
		 sizeof((const uint8_t []){ __VA_ARGS__ }) }

/* AV1 OBU headers: type << 3, 0x04 extension, 0x02 has size field */
#define SEQ	0x08
#define FRM	0x30

static const struct dpt_case cases[] = {

	/* the G-265 packets: sizes that wrap 32-bit, or are just too big */

	{ "av1 leb 4GB-4", 1, { P(0x00, 0xfc, 0xff, 0xff, 0xff, 0x0f,
				  SEQ, 0x11, 0x22) },
	  /*
	   * not a usable size, so the rest of the packet is the element: its
	   * "OBU header" is the leb128's first byte, fc, with an extension
	   */
	  P(0x12, 0x00, 0xfe, 0xff, 0x06, 0xff, 0xff, 0x0f, SEQ, 0x11, 0x22) },
	{ "av1 leb 2^56-1", 1, { P(0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
				   0xff, 0x7f, SEQ) },
	  P(0x12, 0x00, 0xff, 0xff, 0x01, SEQ) },
	{ "av1 leb over packet", 1, { P(0x00, 0x81, 0x80, 0x80, 0x09, SEQ, 0x11) },
	  P(0x12, 0x00, 0x83, 0x05, 0x80, 0x80, 0x09, SEQ, 0x11) },
	{ "av1 leb unterminated", 1, { P(0x00, 0x80, 0x80, 0x80, 0x80, 0x80,
					 0x80, 0x80, 0x80, 0x80, 0x01) },
	  P(0x12, 0x00, 0x82, 0x09, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
	    0x80, 0x80, 0x01) },

	/* well-formed AV1 */

	{ "av1 W=0", 1, { P(0x00, 0x03, SEQ, 0x11, 0x22, 0x02, FRM, 0x44) },
	  P(0x12, 0x00, SEQ | 2, 0x02, 0x11, 0x22, FRM | 2, 0x01, 0x44) },
	{ "av1 W=2", 1, { P(0x20, 0x03, SEQ, 0x11, 0x22, FRM, 0x44) },
	  P(0x12, 0x00, SEQ | 2, 0x02, 0x11, 0x22, FRM | 2, 0x01, 0x44) },
	{ "av1 own size field", 1, { P(0x10, SEQ | 2, 0x02, 0x11, 0x22) },
	  P(0x12, 0x00, SEQ | 2, 0x02, 0x11, 0x22) },
	{ "av1 extension", 1, { P(0x10, SEQ | 4, 0x55, 0x66) },
	  P(0x12, 0x00, SEQ | 6, 0x55, 0x01, 0x66) },
	{ "av1 fragmented", 1, { P(0x50, SEQ, 0x11), P(0x90, 0x22, 0x33) },
	  P(0x12, 0x00, SEQ | 2, 0x03, 0x11, 0x22, 0x33) },
	{ "av1 continuation, no start", 1, { P(0x90, SEQ, 0x22, 0x33) },
	  { NULL, 0 } },
	{ "av1 temporal delimiter", 1, { P(0x10, 0x10) },
	  P(0x12, 0x00) },

	/* H.264 */

	{ "h264 single", 0, { P(0x65, 0xaa, 0xbb) },
	  P(0, 0, 0, 1, 0x65, 0xaa, 0xbb) },
	{ "h264 stap-a", 0, { P(0x18, 0x00, 0x02, 0x67, 0xaa,
				0x00, 0x03, 0x68, 0xbb, 0xcc) },
	  P(0, 0, 0, 1, 0x67, 0xaa, 0, 0, 0, 1, 0x68, 0xbb, 0xcc) },
	{ "h264 stap-a size over packet", 0, { P(0x18, 0x00, 0x02, 0x67, 0xaa,
						 0xff, 0xff, 0x68) },
	  P(0, 0, 0, 1, 0x67, 0xaa) },
	{ "h264 stap-a truncated size", 0, { P(0x18, 0x00, 0x01, 0x67, 0x00) },
	  P(0, 0, 0, 1, 0x67) },
	{ "h264 fu-a", 0, { P(0x7c, 0x85, 0xaa), P(0x7c, 0x45, 0xbb) },
	  P(0, 0, 0, 1, 0x65, 0xaa, 0xbb) },
	{ "h264 fu-a, no start", 0, { P(0x7c, 0x05, 0xbb) },
	  { NULL, 0 } },
};

static int
test_case(const struct dpt_case *c)
{
	struct mixer_depkt d;
	int n, bad = 0;

	memset(&d, 0, sizeof(d));

	for (n = 0; n < 2 && c->pkt[n].p; n++)
		if (c->av1)
			mixer_depkt_av1(&d, c->pkt[n].p, c->pkt[n].len);
		else
			mixer_depkt_h264(&d, c->pkt[n].p, c->pkt[n].len);

	if (d.frame.len != c->exp.len ||
	    (c->exp.len && memcmp(d.frame.buf, c->exp.p, c->exp.len))) {
		lwsl_err("%s: access unit differs\n", c->name);
		if (d.frame.len)
			lwsl_hexdump_err(d.frame.buf, d.frame.len);
		bad = 1;
	}

	mixer_depkt_destroy(&d);

	return bad;
}

static int
test_leb128(void)
{
	static const struct {
		uint8_t		b[9];
		size_t		len;
		size_t		used;
		uint64_t	val;
	} l[] = {
		{ { 0x00 }, 1, 1, 0 },
		{ { 0x7f }, 1, 1, 0x7f },
		{ { 0x80, 0x01 }, 2, 2, 0x80 },
		/* wraps to 2 when added to an offset of 6 on a 32-bit size_t */
		{ { 0xfc, 0xff, 0xff, 0xff, 0x0f }, 5, 5, 0xfffffffcull },
		{ { 0x80, 0x80, 0x80, 0x80, 0x10 }, 5, 5, 0x100000000ull },
		{ { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f }, 8, 8,
		  0xffffffffffffffull },
		/* no more than 8 bytes */
		{ { 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01 },
		  9, 0, 0 },
		/* not ended within the input */
		{ { 0x80, 0x80, 0x01 }, 2, 0, 0 },
		{ { 0x00 }, 0, 0, 0 },
	};
	uint64_t v;
	size_t n, u;

	for (n = 0; n < LWS_ARRAY_SIZE(l); n++) {
		v = 0x5a5a;
		u = mixer_leb128(l[n].b, l[n].len, &v);
		if (u != l[n].used || (u && v != l[n].val)) {
			lwsl_err("leb128 case %d: used %d, val 0x%llx\n", (int)n,
				 (int)u, (unsigned long long)v);
			return 1;
		}
	}

	return 0;
}

static int
test_vbuf(void)
{
	static const uint8_t b[16];
	struct mixer_vbuf vb;
	uint8_t *big;
	int bad = 0;

	memset(&vb, 0, sizeof(vb));

	if (mixer_vbuf_append(&vb, b, sizeof(b)) || vb.len != sizeof(b))
		bad |= 1;

	/* a length that wraps when added to what is there is refused... */
	if (!mixer_vbuf_append(&vb, b, (size_t)-8) || vb.len)
		bad |= 2;

	/* ... and so is one just over the cap, but the cap itself fits */
	if (mixer_vbuf_append(&vb, b, sizeof(b)) ||
	    !mixer_vbuf_append(&vb, b, MIXER_VIDEO_BUF_CAP - sizeof(b) + 1) ||
	    vb.len)
		bad |= 4;

	/* exactly the cap fits */
	big = calloc(1, MIXER_VIDEO_BUF_CAP);
	if (!big)
		return 1;
	if (mixer_vbuf_append(&vb, b, sizeof(b)) ||
	    mixer_vbuf_append(&vb, big, MIXER_VIDEO_BUF_CAP - sizeof(b)) ||
	    vb.len != MIXER_VIDEO_BUF_CAP ||
	    !mixer_vbuf_append(&vb, b, 1) || vb.len)
		bad |= 8;

	free(big);
	free(vb.buf);

	if (bad)
		lwsl_err("%s: 0x%x\n", __func__, bad);

	return bad;
}

static void
result(const char *name, int bad)
{
	if (bad) {
		lwsl_err("%s: FAIL\n", name);
		fails++;
	} else
		oks++;
}

int
main(int argc, const char **argv)
{
	size_t n;

	lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN, NULL);
	lwsl_user("LWS API selftest: webrtc mixer RTP depacketisers\n");

	result("leb128", test_leb128());
	result("vbuf", test_vbuf());

	for (n = 0; n < LWS_ARRAY_SIZE(cases); n++)
		result(cases[n].name, test_case(&cases[n]));

	lwsl_user("Completed: PASS: %d, FAIL: %d\n", oks, fails);

	return !(oks && !fails);
}
