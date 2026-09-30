/*
 * lws-api-test-upng
 *
 * Written in 2010-2022 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>

enum {
	LWS_SW_STDIN,
	LWS_SW_STDOUT,
	LWS_SW_D,
	LWS_SW_SELFTEST,
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_STDIN]	= { "--stdin",         "Enable --stdin feature" },
	[LWS_SW_STDOUT]	= { "--stdout",        "Enable --stdout feature" },
	[LWS_SW_D]	= { "-d",              "Debug logs (e.g. -d 15)" },
	[LWS_SW_SELFTEST] = { "--selftest",    "Decode built-in PNGs split up every way, and check them" },
	[LWS_SW_HELP]	= { "--help",		"Show this help information" },
};

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>

int fdin = 0, fdout = 1;

/*
 * --selftest: decode two small, valid PNGs with the input cut up every way
 * we can think of, and check every byte of every row.
 *
 * The decoder is documented as not being sensitive to how its input is
 * chunked, so the result must be identical however it is presented: one
 * buffer, fixed-size chunks down to 1 byte, and every two-way split plus
 * every three-way split with a 1- or 2-byte middle segment (which puts
 * boundaries everywhere, including either side of each byte of the zlib
 * header at the start of the first IDAT).
 *
 * Each segment lives in its own exactly-sized heap allocation, and whatever
 * the decoder leaves unconsumed is moved to a fresh allocation before the
 * next call.  So the decoder can't get away with remembering pointers into
 * a buffer after it returned, and under ASan, reading outside the one it
 * was given is caught.  We also check that what it hands back in *buf and
 * *size is always the tail of what we gave it.
 *
 * Where lws accounts its heap, the one-piece, fixed-size chunk and two-way
 * split decodes are also done with the decoder's window allocation failing
 * the first time, to check it recovers when retried as dlo does.
 *
 * The images were made with a normal PNG encoder, using zlib at level 9
 * and at level 0 (huffman-coded and stored deflate blocks), with a tEXt
 * chunk before the image data, the zlib stream spread over three IDATs and
 * the rows using each of the five PNG filter types in turn.  Byte j of
 * pixel x on row y is test_pix(x, y, j).
 */

static uint8_t
test_pix(unsigned int x, unsigned int y, unsigned int j)
{
	return (uint8_t)((x * 29 + y * 71 + j * 101 + ((x * y) >> 1)) & 0xff);
}

/* 23 x 11 RGB8, huffman-coded */
static const uint8_t png_rgb8_deflate[] = {
	0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d,
	0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x0b,
	0x08, 0x02, 0x00, 0x00, 0x00, 0x1b, 0x5c, 0x81, 0x17, 0x00, 0x00, 0x00,
	0x08, 0x74, 0x45, 0x58, 0x74, 0x6c, 0x77, 0x73, 0x00, 0x74, 0x65, 0x73,
	0x74, 0x26, 0x0c, 0x18, 0x02, 0x00, 0x00, 0x00, 0x03, 0x49, 0x44, 0x41,
	0x54, 0x78, 0xda, 0x63, 0x0c, 0x44, 0x6a, 0x3d, 0x00, 0x00, 0x00, 0x28,
	0x49, 0x44, 0x41, 0x54, 0x60, 0x48, 0x3d, 0x25, 0xdb, 0xf4, 0xdc, 0x6a,
	0x3e, 0x4b, 0xf8, 0x1e, 0xc5, 0x92, 0x9b, 0x76, 0x13, 0xbf, 0x45, 0xaf,
	0x13, 0xae, 0x38, 0x6d, 0x30, 0xf5, 0x85, 0xef, 0x26, 0xd6, 0xac, 0xf3,
	0x4a, 0xed, 0x6f, 0xec, 0x97, 0x70, 0xc6, 0x1c, 0x96, 0x2d, 0xd1, 0xd6,
	0x00, 0x00, 0x01, 0x8d, 0x49, 0x44, 0x41, 0x54, 0x54, 0xab, 0xbc, 0xe7,
	0x3c, 0xed, 0x77, 0xc2, 0x66, 0x89, 0xda, 0x0b, 0xa6, 0xb3, 0xde, 0x06,
	0x6d, 0xe7, 0xca, 0xbf, 0xa2, 0xde, 0xf3, 0xd1, 0x65, 0x25, 0x5f, 0xe2,
	0x31, 0xed, 0xba, 0xc7, 0x1e, 0x8c, 0xee, 0x6b, 0x04, 0x65, 0x65, 0x65,
	0xe5, 0xe4, 0xe4, 0x28, 0x21, 0x99, 0xdc, 0xdd, 0xdd, 0x3d, 0xc0, 0xc0,
	0x13, 0x0c, 0xbc, 0xc0, 0xc0, 0x1b, 0x0c, 0x7c, 0xc0, 0xc0, 0x17, 0x0c,
	0xfc, 0xc0, 0xc0, 0x1f, 0x0c, 0x02, 0xc0, 0x20, 0x10, 0x0c, 0x82, 0xc0,
	0x80, 0xb9, 0xef, 0x60, 0xb1, 0xb1, 0xb1, 0xb1, 0x89, 0x89, 0xc9, 0x66,
	0x30, 0x69, 0x62, 0xb2, 0xc5, 0xd4, 0xd4, 0x14, 0x48, 0x99, 0x6e, 0x05,
	0xd2, 0xa6, 0x66, 0x66, 0x66, 0x40, 0x7a, 0x1b, 0x90, 0x32, 0xdb, 0x66,
	0x6e, 0xbe, 0x1d, 0x48, 0x99, 0x6f, 0x07, 0xd2, 0xe6, 0x16, 0x16, 0x16,
	0xe6, 0xe6, 0xe6, 0x3b, 0x80, 0x94, 0xc5, 0x0e, 0x4b, 0xcb, 0x9d, 0x2c,
	0x40, 0xb7, 0xc8, 0xcb, 0xcb, 0x7b, 0xc8, 0x43, 0x80, 0x27, 0x94, 0xf6,
	0x86, 0xd2, 0x3e, 0x50, 0xda, 0x17, 0x4a, 0xfb, 0xcb, 0xc3, 0x41, 0x20,
	0x9c, 0x90, 0x97, 0x67, 0x48, 0x3e, 0xa1, 0xdb, 0xf4, 0xdc, 0x67, 0x11,
	0x7b, 0xce, 0x41, 0xb5, 0xee, 0x87, 0x6e, 0xab, 0x81, 0x81, 0xad, 0xd0,
	0xfa, 0x0a, 0x18, 0xa2, 0xf1, 0x47, 0x34, 0x81, 0xc1, 0x36, 0x8f, 0x39,
	0x63, 0xaf, 0x52, 0xfb, 0x5d, 0xa7, 0xe5, 0x7f, 0x12, 0x8f, 0xc9, 0x34,
	0x3e, 0xb3, 0x5e, 0xc0, 0x1a, 0x7d, 0x40, 0xb5, 0xea, 0xbe, 0xcb, 0xac,
	0xff, 0x29, 0x3b, 0xe5, 0x9a, 0x6f, 0xda, 0x2d, 0xfe, 0x11, 0x7b, 0x48,
	0xa2, 0xf6, 0x11, 0xe3, 0x2a, 0xfe, 0x12, 0x05, 0x8a, 0x01, 0x28, 0x74,
	0x29, 0x0f, 0x60, 0xe6, 0x03, 0x45, 0x4b, 0x4d, 0x41, 0x21, 0x09, 0x0e,
	0xcc, 0xad, 0xa6, 0x66, 0xe0, 0x90, 0x04, 0x05, 0x26, 0x30, 0x20, 0x41,
	0x21, 0x09, 0x06, 0xc0, 0xe0, 0x84, 0x84, 0x24, 0x18, 0x01, 0x83, 0xd3,
	0x12, 0x02, 0x76, 0x5a, 0x5a, 0x81, 0x01, 0x28, 0x74, 0x15, 0x15, 0x15,
	0x95, 0x94, 0x94, 0x14, 0x3d, 0xc0, 0x24, 0x98, 0xed, 0x05, 0x22, 0xbd,
	0xa1, 0xe2, 0x3e, 0x50, 0x71, 0x3f, 0xa8, 0xac, 0x3f, 0x54, 0x3c, 0x00,
	0x2a, 0x1e, 0xa4, 0xa4, 0xc4, 0x70, 0x4c, 0x7b, 0x02, 0x30, 0x99, 0x02,
	0xd3, 0xa2, 0xce, 0xc4, 0x6f, 0x7e, 0x9b, 0x25, 0x0a, 0xae, 0x5a, 0x4d,
	0xfa, 0x1e, 0xb3, 0x45, 0xb2, 0xee, 0x9a, 0xf5, 0x02, 0x60, 0xc8, 0x49,
	0xd5, 0x3f, 0xb1, 0x59, 0xc8, 0x16, 0x77, 0x58, 0xa3, 0xe1, 0xa9, 0x17,
	0x30, 0x06, 0x8e, 0x68, 0xf6, 0x3d, 0xf3, 0xde, 0xc0, 0x91, 0x7b, 0x49,
	0xab, 0xff, 0x8b, 0xcf, 0x46, 0xb1, 0xbc, 0xcb, 0x16, 0x13, 0xbe, 0x46,
	0x6d, 0x12, 0xaf, 0x01, 0x00, 0x9d, 0xa1, 0xe1, 0xfe, 0x48, 0x2f, 0x2c,
	0xde, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60,
	0x82,
};

/* 5 x 4 RGBA16, stored blocks */
static const uint8_t png_rgba16_stored[] = {
	0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d,
	0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x04,
	0x10, 0x06, 0x00, 0x00, 0x00, 0x16, 0xa3, 0x29, 0x03, 0x00, 0x00, 0x00,
	0x08, 0x74, 0x45, 0x58, 0x74, 0x6c, 0x77, 0x73, 0x00, 0x74, 0x65, 0x73,
	0x74, 0x26, 0x0c, 0x18, 0x02, 0x00, 0x00, 0x00, 0x02, 0x49, 0x44, 0x41,
	0x54, 0x78, 0x01, 0xec, 0x1a, 0x7e, 0xd2, 0x00, 0x00, 0x00, 0x39, 0x49,
	0x44, 0x41, 0x54, 0x01, 0xa4, 0x00, 0x5b, 0xff, 0x00, 0x00, 0x65, 0xca,
	0x2f, 0x94, 0xf9, 0x5e, 0xc3, 0x1d, 0x82, 0xe7, 0x4c, 0xb1, 0x16, 0x7b,
	0xe0, 0x3a, 0x9f, 0x04, 0x69, 0xce, 0x33, 0x98, 0xfd, 0x57, 0xbc, 0x21,
	0x86, 0xeb, 0x50, 0xb5, 0x1a, 0x74, 0xd9, 0x3e, 0xa3, 0x08, 0x6d, 0xd2,
	0x37, 0x01, 0x47, 0xac, 0x11, 0x76, 0xdb, 0x40, 0xa5, 0x0a, 0x1d, 0x1d,
	0xf2, 0xcd, 0x23, 0x37, 0x00, 0x00, 0x00, 0x74, 0x49, 0x44, 0x41, 0x54,
	0x1d, 0x1d, 0x1d, 0x1d, 0x1d, 0x1d, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e,
	0x1e, 0x1e, 0x1d, 0x1d, 0x1d, 0x1d, 0x1d, 0x1d, 0x1d, 0x1d, 0x1e, 0x1e,
	0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x1e, 0x02, 0x47, 0x47, 0x47, 0x47, 0x47,
	0x47, 0x47, 0x47, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48,
	0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x48, 0x49, 0x49, 0x49, 0x49, 0x49,
	0x49, 0x49, 0x49, 0x49, 0x49, 0x49, 0x49, 0x49, 0x49, 0x49, 0x49, 0x03,
	0x8e, 0xc1, 0x73, 0xa6, 0x58, 0x8b, 0xbd, 0x70, 0x33, 0x33, 0x33, 0xb3,
	0x33, 0x33, 0x33, 0x33, 0x34, 0x34, 0x34, 0xb4, 0x34, 0x34, 0x34, 0x34,
	0xb3, 0x33, 0x33, 0x33, 0x33, 0xb3, 0x33, 0x33, 0x34, 0x34, 0x34, 0x34,
	0x34, 0xb4, 0x34, 0x34, 0xad, 0xf3, 0x32, 0xf7, 0x71, 0xc3, 0x35, 0xcc,
	0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
};

static const struct {
	const char		*name;
	const uint8_t		*png;
	size_t			len;
	unsigned int		w, h, bypp;
} test_images[] = {
	{ "rgb8-deflate",  png_rgb8_deflate,  sizeof(png_rgb8_deflate),
								23, 11, 3 },
	{ "rgba16-stored", png_rgba16_stored, sizeof(png_rgba16_stored),
								 5,  4, 8 },
};

static uint8_t *
seg_dup(const uint8_t *p, size_t len)
{
	uint8_t *d = malloc(len ? len : 1);

	if (d && len)
		memcpy(d, p, len);

	return d;
}

/*
 * Decode test image ti presented as segments, each ending at the next of
 * cuts[], and the last one at the end of the image.  Returns 0 if every
 * row came out exactly right.
 *
 * If oom is set, the heap is limited so the decoder can't get its window
 * allocation the first time it tries.  It has to return LWS_SRET_YIELD
 * having told us what it consumed, and then carry on correctly when we
 * lift the limit and call again with what it left, the way dlo retries.
 */

static int
decode_cut(size_t ti, const size_t *cuts, size_t ncuts, int oom)
{
	unsigned int w = test_images[ti].w, h = test_images[ti].h,
		     bypp = test_images[ti].bypp, rows = 0, x, j;
	size_t len = test_images[ti].len, start = 0, l = 0, seg_len = 0,
	       n = 0, calls = 0;
	const uint8_t *png = test_images[ti].png, *p = NULL, *pix;
	uint8_t *seg = NULL, *moved;
	lws_stateful_ret_t r;
	lws_upng_t *u;
	int ret = 1, yields = 0;

	u = lws_upng_new();
	if (!u)
		return 1;

	/*
	 * Only possible where lws accounts its heap.  The decoder object is
	 * already allocated, the window it needs next is > 32KB
	 */

	if (oom && lws_get_allocated_heap())
		lws_heap_limit_set(lws_get_allocated_heap() + 4096);
	else
		oom = 0;

	while (rows < h) {

		/* the input is tiny, so this many calls means it's stuck */
		if (++calls > 4 * (len + h)) {
			lwsl_err("%s: no progress at row %u\n", __func__, rows);
			goto bail;
		}

		if (!seg) {
			/* present the next segment, in a buffer of its own */

			if (start == len) {
				lwsl_err("%s: out of input at row %u\n",
					 __func__, rows);
				goto bail;
			}
			seg_len = (n < ncuts ? cuts[n++] : len) - start;
			seg = seg_dup(png + start, seg_len);
			if (!seg)
				goto bail;
			start += seg_len;
			p = seg;
			l = seg_len;
		}

		pix = NULL;
		r = lws_upng_emit_next_line(u, &pix, &p, &l, 0);
		if (r & LWS_SRET_FATAL) {
			lwsl_err("%s: FATAL %d at row %u\n", __func__,
				 (int)(r & 0xff), rows);
			goto bail;
		}

		if (r & LWS_SRET_YIELD) {
			if (!oom || yields++) {
				lwsl_err("%s: unexpected YIELD\n", __func__);
				goto bail;
			}
			/* the heap is back: it can retry the allocation */
			lws_heap_limit_set(0);
		}

		/* what's left must be the tail of what we gave it */

		if (l > seg_len || p != seg + (seg_len - l)) {
			lwsl_err("%s: bad remaining input at row %u\n",
				 __func__, rows);
			goto bail;
		}

		if (pix) {
			if (lws_upng_get_width(u) != w ||
			    lws_upng_get_height(u) != h ||
			    lws_upng_get_pixelsize(u) != bypp * 8) {
				lwsl_err("%s: bad metadata\n", __func__);
				goto bail;
			}

			for (x = 0; x < w; x++)
				for (j = 0; j < bypp; j++)
					if (pix[x * bypp + j] !=
						       test_pix(x, rows, j)) {
						lwsl_err("%s: row %u px %u "
							 "byte %u wrong\n",
							 __func__, rows, x, j);
						goto bail;
					}
			rows++;
		} else
			if (r == LWS_SRET_OK) {
				lwsl_err("%s: ended after %u rows\n",
					 __func__, rows);
				goto bail;
			}

		if (!l) {
			free(seg);
			seg = NULL;
			continue;
		}

		/* move what it left of the segment somewhere else */

		moved = seg_dup(p, l);
		if (!moved)
			goto bail;
		free(seg);
		seg = moved;
		seg_len = l;
		p = seg;
	}

	if (oom && !yields) {
		lwsl_err("%s: the allocation never failed\n", __func__);
		goto bail;
	}

	ret = 0;

bail:
	if (oom)
		lws_heap_limit_set(0);
	free(seg);
	lws_upng_free(&u);

	return ret;
}

/*
 * A decoder that has failed stays failed: every later call gives the same
 * FATAL and takes none of the input it is offered.  Something that is not a
 * PNG at all fails on its first byte, and then even a real PNG offered to
 * the same decoder, over and over, gets that same answer.
 */

static int
selftest_sticky(void)
{
	static const uint8_t junk[] = "this is not a png";
	lws_stateful_ret_t r, r1;
	const uint8_t *p, *pix;
	lws_upng_t *u;
	size_t ps;
	int e = 0, n;

	u = lws_upng_new();
	if (!u)
		return 1;

	p = junk;
	ps = sizeof(junk);
	r = lws_upng_emit_next_line(u, &pix, &p, &ps, 0);
	if (!(r & LWS_SRET_FATAL)) {
		lwsl_err("%s: junk accepted: 0x%x\n", __func__, (unsigned int)r);
		e++;
		goto bail;
	}

	for (n = 0; n < 12; n++) {
		p = png_rgb8_deflate;
		ps = sizeof(png_rgb8_deflate);
		r1 = lws_upng_emit_next_line(u, &pix, &p, &ps, 0);
		if (r1 != r || pix || p != png_rgb8_deflate ||
		    ps != sizeof(png_rgb8_deflate)) {
			lwsl_err("%s: after FATAL 0x%x: 0x%x, took %u\n",
				 __func__, (unsigned int)r, (unsigned int)r1,
				 (unsigned int)(sizeof(png_rgb8_deflate) - ps));
			e++;
			break;
		}
	}

bail:
	lws_upng_free(&u);

	return e;
}

static int
selftest(void)
{
	static const size_t chunks[] = { 1, 2, 3, 4, 5, 7, 8, 13, 16, 31, 64,
					 256 };
	size_t ti, i, k, cuts[3];
	int fails = 0, runs = 0;

	for (ti = 0; ti < LWS_ARRAY_SIZE(test_images); ti++) {
		size_t len = test_images[ti].len;
		int f = fails;

		/* in one piece */

		runs++;
		fails += !!decode_cut(ti, NULL, 0, 0);
		runs++;
		fails += !!decode_cut(ti, NULL, 0, 1);

		/* in fixed-size chunks, however they fall */

		for (k = 0; k < LWS_ARRAY_SIZE(chunks); k++) {
			size_t *pc, nc = 0, o;

			pc = malloc(sizeof(size_t) * (len / chunks[k] + 1));
			if (!pc)
				return 1;
			for (o = chunks[k]; o < len; o += chunks[k])
				pc[nc++] = o;

			runs++;
			if (decode_cut(ti, pc, nc, 0)) {
				lwsl_err("%s: %s: %u-byte chunks failed\n",
					 __func__, test_images[ti].name,
					 (unsigned int)chunks[k]);
				fails++;
			}

			/* ...and with the window allocation failing once */

			runs++;
			if (decode_cut(ti, pc, nc, 1)) {
				lwsl_err("%s: %s: %u-byte chunks, OOM "
					 "failed\n", __func__,
					 test_images[ti].name,
					 (unsigned int)chunks[k]);
				fails++;
			}
			free(pc);
		}

		for (i = 1; i < len; i++) {

			/* split in two at every offset */

			cuts[0] = i;
			runs++;
			if (decode_cut(ti, cuts, 1, 0)) {
				lwsl_err("%s: %s: split at %u failed\n",
					 __func__, test_images[ti].name,
					 (unsigned int)i);
				fails++;
			}

			/* ...also with the window allocation failing once */

			runs++;
			if (decode_cut(ti, cuts, 1, 1)) {
				lwsl_err("%s: %s: split at %u, OOM failed\n",
					 __func__, test_images[ti].name,
					 (unsigned int)i);
				fails++;
			}

			/* ...and in three, with a 1 or 2 byte middle part */

			for (k = 1; k <= 2 && i + k < len; k++) {
				cuts[1] = i + k;
				runs++;
				if (decode_cut(ti, cuts, 2, 0)) {
					lwsl_err("%s: %s: split at %u + %u "
						 "failed\n", __func__,
						 test_images[ti].name,
						 (unsigned int)i,
						 (unsigned int)k);
					fails++;
				}
			}
		}

		lwsl_user("%s: %s: %d failed\n", __func__,
			  test_images[ti].name, fails - f);
	}

	lwsl_user("%s: %d / %d decodes correct\n", __func__, runs - fails,
		  runs);

	if (selftest_sticky()) {
		lwsl_user("%s: FATAL is not sticky\n", __func__);
		fails++;
	}

	return !!fails;
}

int
main(int argc, const char **argv)
{
	int result = 0;
	lws_stateful_ret_t r = LWS_SRET_WANT_INPUT;
	const char *p;
	lws_upng_t *u;
	(void)switches;

	if ((argc == 1) || lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches, LWS_ARRAY_SIZE(switches));
		return 0;
	}



	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_D].sw)))
		lws_set_log_level(atoi(p), NULL);
	else
		if (lws_cmdline_option(argc, argv,
				       switches[LWS_SW_SELFTEST].sw))
			/* the decoder's notice at every stall drowns it */
			lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN, NULL);

	lwsl_user("LWS UPNG test tool\n");

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_SELFTEST].sw)) {
		result = selftest();
		goto bail;
	}

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_STDIN].sw))) {
		fdin = open(p, LWS_O_RDONLY, 0);
		if (fdin < 0) {
			result = 1;
			lwsl_err("%s: unable to open stdin file\n", __func__);
			goto bail;
		}
	}

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_STDOUT].sw))) {
		fdout = open(p, LWS_O_WRONLY | LWS_O_CREAT | LWS_O_TRUNC, 0600);
		if (fdout < 0) {
			result = 1;
			lwsl_err("%s: unable to open stdout file\n", __func__);
			goto bail;
		}
	}

	if (!fdin) {
		struct timeval	timeout;
		fd_set	fds;

		FD_ZERO(&fds);
		FD_SET(0, &fds);

		timeout.tv_sec  = 0;
		timeout.tv_usec = 1000;

		if (select(fdin + 1, &fds, NULL, NULL, &timeout) < 0 ||
		    !FD_ISSET(0, &fds)) {
			result = 1;
			lwsl_err("%s: pass PNG "
				 "on stdin or use --stdin\n", __func__);
			goto bail;
		}
	}


	u = lws_upng_new();
	if (!u) {
		lwsl_err("%s: failed to allocate\n", __func__);
		goto bail;
	}

	do {
		const uint8_t *pix;
		uint8_t ib[256];
		const uint8_t *pib = (const uint8_t *)ib;
		ssize_t s, os;
		size_t ps;

		if (r == LWS_SRET_WANT_INPUT) {
			s = read(fdin, ib, sizeof(ib));

			if (s <= 0) {
				lwsl_err("%s: failed to read: %d\n", __func__, errno);
				goto bail1;
			}

			ps = (size_t)s;

			// lwsl_notice("%s: fetched %d\n", __func__, (int)s);
		}

		do {
			r = lws_upng_emit_next_line(u, &pix, &pib, &ps, 0);
			if (r == LWS_SRET_WANT_INPUT)
				break;

			if (r > LWS_SRET_FATAL) {
				lwsl_err("%s: emit returned FATAL %d\n", __func__, r &0xff);
				result = 1;
				goto bail1;
			}

			if (!pix)
				goto bail1;

			os = (ssize_t)(lws_upng_get_width(u) * (lws_upng_get_pixelsize(u) / 8));

			if (write(fdout, pix, 
#if defined(WIN32)
						(unsigned int)
#endif
						(size_t)os) < os) {
				lwsl_err("%s: write %d failed %d\n", __func__, (int)os, errno);
				goto bail1;
			}

			lwsl_notice("%s: wrote %d\n", __func__, (int)os);
		} while (ps);

	} while (1);

bail1:
	if (fdin)
		close(fdin);
	if (fdout != 1)
		close(fdout);

	lws_upng_free(&u);

bail:
	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
