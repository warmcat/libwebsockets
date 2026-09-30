/*
 * lws-api-test-jpeg
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Either decode a JPEG from --stdin (or stdin) to raw pixels on --stdout (or
 * stdout), or with --selftest, decode built-in images every way we can cut
 * them up and check what comes out.
 */

#include <libwebsockets.h>

enum {
	LWS_SW_STDIN,
	LWS_SW_STDOUT,
	LWS_SW_NO_OUTPUT,
	LWS_SW_SELFTEST,
	LWS_SW_D,
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_STDIN]	= { "--stdin",         "Enable --stdin feature" },
	[LWS_SW_STDOUT]	= { "--stdout",        "Enable --stdout feature" },
	[LWS_SW_NO_OUTPUT] = { "--no-output",  "Decode and check it completes, without writing the pixels" },
	[LWS_SW_SELFTEST] = { "--selftest",    "Decode built-in JPEGs split up every way, and check them" },
	[LWS_SW_D]	= { "-d",              "Debug logs (e.g. -d 15)" },
	[LWS_SW_HELP]	= { "--help",		"Show this help information" },
};

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>

#if defined(WIN32)
#define JPEG_O_BINARY _O_BINARY
#else
#define JPEG_O_BINARY 0
#endif

#include "images.h"

/*
 * --selftest: the images in images.h were made by a normal encoder from this
 * pattern.  Byte c of pixel (x, y) of a w x h image; a grayscale image uses
 * c = 2.
 */

static uint8_t
test_pix(unsigned int x, unsigned int y, unsigned int c, unsigned int w,
	 unsigned int h)
{
	switch (c) {
	case 0:
		return (uint8_t)((x * 255) / (w - 1));
	case 1:
		return (uint8_t)((y * 255) / (h - 1));
	}

	return (uint8_t)(((x + y) * 255) / (w + h - 2));
}

typedef struct {
	const char		*name;
	const uint8_t		*jpg;
	size_t			len;
	unsigned int		w, h, comps;
} test_img_t;

#define TI(_n, _w, _h, _c) { #_n, jpg_##_n, sizeof(jpg_##_n), _w, _h, _c }

static const test_img_t test_imgs[] = {
	TI(gray,		29, 19, 1),
	TI(rgb_h1v1,		37, 21, 3),
	TI(rgb_h2v1,		37, 21, 3),
	TI(rgb_h2v2,		37, 21, 3),
	TI(gray_dri,		29, 19, 1),
	TI(rgb_h1v1_dri,	37, 21, 3),
	TI(rgb_h2v2_dri,	45, 37, 3),
};

/*
 * Decode ti, presented as a first segment of split bytes (if nonzero), then
 * the rest in segments of chunk bytes.  Each segment lives in its own
 * exactly-sized heap allocation that is freed once the decoder has taken
 * all of it, so under ASan any read outside what it was given, or through a
 * pointer it kept after returning, is caught.
 *
 * The first h rows are copied into out.  Returns 0 if the decode completed
 * with at least h rows, and never handed back anything in *buf / *size
 * except the tail of what it was given.
 */

static int
decode_split(const test_img_t *ti, size_t split, size_t chunk, uint8_t *out)
{
	lws_stateful_ret_t r = LWS_SRET_WANT_INPUT;
	size_t pos = 0, row_len = ti->w * ti->comps;
	unsigned int rows = 0;
	lws_jpeg_t *j;
	int ret = 1;

	j = lws_jpeg_new();
	if (!j)
		return 1;

	while (pos < ti->len && r == LWS_SRET_WANT_INPUT) {
		size_t n = split && !pos ? split : chunk;
		const uint8_t *p;
		uint8_t *seg;
		size_t ps;

		if (n > ti->len - pos)
			n = ti->len - pos;

		seg = malloc(n);
		if (!seg)
			goto bail;
		memcpy(seg, ti->jpg + pos, n);
		pos += n;
		p = seg;
		ps = n;

		do {
			const uint8_t *pix = NULL;

			r = lws_jpeg_emit_next_line(j, &pix, &p, &ps, 0);
			if (r & LWS_SRET_FATAL) {
				lwsl_err("%s: %s: FATAL 0x%x at %u\n", __func__,
					 ti->name, (unsigned int)r,
					 (unsigned int)(pos - ps));
				free(seg);
				goto bail;
			}

			if (p < seg || ps > n || p + ps != seg + n) {
				lwsl_err("%s: %s: bad *buf / *size back\n",
					 __func__, ti->name);
				free(seg);
				goto bail;
			}

			if (r & LWS_SRET_WANT_OUTPUT) {
				if (!pix) {
					lwsl_err("%s: %s: WANT_OUTPUT, no row\n",
						 __func__, ti->name);
					free(seg);
					goto bail;
				}
				if (rows < ti->h)
					memcpy(out + rows * row_len, pix,
					       row_len);
				rows++;
			}

		} while (r != LWS_SRET_WANT_INPUT && r != LWS_SRET_OK);

		free(seg);
	}

	if (r != LWS_SRET_OK) {
		lwsl_err("%s: %s: incomplete (0x%x)\n", __func__, ti->name,
			 (unsigned int)r);
		goto bail;
	}

	if (lws_jpeg_get_width(j) != ti->w || lws_jpeg_get_height(j) != ti->h ||
	    lws_jpeg_get_components(j) != ti->comps) {
		lwsl_err("%s: %s: geometry %u x %u x %u\n", __func__, ti->name,
			 lws_jpeg_get_width(j), lws_jpeg_get_height(j),
			 lws_jpeg_get_components(j));
		goto bail;
	}

	if (rows < ti->h) {
		lwsl_err("%s: %s: only %u rows\n", __func__, ti->name, rows);
		goto bail;
	}

	ret = 0;

bail:
	lws_jpeg_free(&j);

	return ret;
}

static int
selftest_img(const test_img_t *ti)
{
	size_t sz = (size_t)ti->w * ti->h * ti->comps, n, sum = 0;
	uint8_t *ref, *out;
	unsigned int x, y, c;
	int e = 0;

	ref = malloc(sz);
	out = malloc(sz);
	if (!ref || !out) {
		e = 1;
		goto bail;
	}

	/* in one piece */

	if (decode_split(ti, 0, ti->len, ref)) {
		e = 1;
		goto bail;
	}

	/*
	 * It is lossy, so it can only be close to the pattern.  Something
	 * that has lost its place in the entropy-coded data is nowhere near.
	 */

	for (y = 0; y < ti->h; y++)
		for (x = 0; x < ti->w; x++)
			for (c = 0; c < ti->comps; c++) {
				int d = (int)ref[(y * ti->w + x) * ti->comps + c] -
					(int)test_pix(x, y, ti->comps == 1 ?
							2 : c, ti->w, ti->h);

				sum += (size_t)(d < 0 ? -d : d);
			}

	if (sum > sz * 8) {
		lwsl_err("%s: %s: mean error %u / 8 is too large\n", __func__,
			 ti->name, (unsigned int)(sum / sz));
		e++;
	}

	/*
	 * However it is cut up, the result must be identical: fixed-size
	 * pieces down to 1 byte, and every two-way split
	 */

	for (n = 1; n <= 64 && !e; n++)
		if (decode_split(ti, 0, n, out) || memcmp(ref, out, sz)) {
			lwsl_err("%s: %s: differs in %u-byte chunks\n",
				 __func__, ti->name, (unsigned int)n);
			e++;
		}

	for (n = 1; n < ti->len && !e; n++)
		if (decode_split(ti, n, ti->len, out) || memcmp(ref, out, sz)) {
			lwsl_err("%s: %s: differs split at %u\n",
				 __func__, ti->name, (unsigned int)n);
			e++;
		}

bail:
	free(ref);
	free(out);

	return e;
}

/*
 * A decoder that has failed stays failed: every later call gives the same
 * FATAL and takes none of the input it is offered.  Something that is not a
 * JPEG at all fails when the decoder gives up looking for the SOI.
 */

static int
selftest_sticky(void)
{
	lws_stateful_ret_t r, r1;
	const uint8_t *p, *pix;
	uint8_t junk[5000];
	lws_jpeg_t *j;
	size_t ps;
	int e = 0, n;

	memset(junk, 0, sizeof(junk));

	j = lws_jpeg_new();
	if (!j)
		return 1;

	p = junk;
	ps = sizeof(junk);
	r = lws_jpeg_emit_next_line(j, &pix, &p, &ps, 0);
	if (!(r & LWS_SRET_FATAL)) {
		lwsl_err("%s: junk accepted: 0x%x\n", __func__, (unsigned int)r);
		e++;
		goto bail;
	}

	for (n = 0; n < 3; n++) {
		/* even offered a real JPEG, it is over */
		p = jpg_gray;
		ps = sizeof(jpg_gray);
		r1 = lws_jpeg_emit_next_line(j, &pix, &p, &ps, 0);
		if (r1 != r || p != jpg_gray || ps != sizeof(jpg_gray)) {
			lwsl_err("%s: after FATAL 0x%x: 0x%x, took %u\n",
				 __func__, (unsigned int)r, (unsigned int)r1,
				 (unsigned int)(sizeof(jpg_gray) - ps));
			e++;
			break;
		}
	}

bail:
	lws_jpeg_free(&j);

	return e;
}

/*
 * Restart markers only change how the image is coded, not what it decodes
 * to: an image with a restart interval must give exactly the pixels of the
 * same image coded without one
 */

static int
selftest_same(const test_img_t *a, const test_img_t *b)
{
	size_t sz = (size_t)a->w * a->h * a->comps;
	uint8_t *pa = malloc(sz), *pb = malloc(sz);
	int e = 1;

	if (pa && pb && a->w == b->w && a->h == b->h && a->comps == b->comps &&
	    !decode_split(a, 0, a->len, pa) && !decode_split(b, 0, b->len, pb))
		e = !!memcmp(pa, pb, sz);

	if (e)
		lwsl_err("%s: %s and %s differ\n", __func__, a->name, b->name);

	free(pa);
	free(pb);

	return e;
}

static int
selftest(void)
{
	size_t n;
	int e = 0;

	for (n = 0; n < LWS_ARRAY_SIZE(test_imgs); n++) {
		int e1 = selftest_img(&test_imgs[n]);

		lwsl_user("%s: %s: %s\n", __func__, test_imgs[n].name,
			  e1 ? "FAIL" : "PASS");
		e += e1;
	}

	/* gray / gray_dri, rgb_h1v1 / rgb_h1v1_dri */
	e += selftest_same(&test_imgs[0], &test_imgs[4]);
	e += selftest_same(&test_imgs[1], &test_imgs[5]);

	if (selftest_sticky()) {
		lwsl_user("%s: FATAL is not sticky\n", __func__);
		e++;
	}

	return e;
}

/*
 * Decode what comes on fdin, writing the rows to fdout if it is not -1.  The
 * decode must complete, with at least as many rows as the image is high.
 */

static int
decode_fd(int fdin, int fdout, size_t *total)
{
	lws_stateful_ret_t r = LWS_SRET_WANT_INPUT;
	const uint8_t *pib = NULL;
	unsigned int rows = 0;
	uint8_t ib[128];
	size_t ps = 0;
	lws_jpeg_t *j;
	int result = 1;

	j = lws_jpeg_new();
	if (!j) {
		lwsl_err("%s: failed to allocate\n", __func__);
		return 1;
	}

	do {
		const uint8_t *pix = NULL;

		if (r == LWS_SRET_WANT_INPUT) {
			ssize_t s = read(fdin, ib, sizeof(ib));

			if (s < 0) {
				lwsl_err("%s: failed to read: %d\n", __func__,
					 errno);
				goto bail;
			}
			if (!s) {
				lwsl_err("%s: input ended before the image did\n",
					 __func__);
				goto bail;
			}

			pib = ib;
			ps = (size_t)s;
			*total += ps;
		}

		r = lws_jpeg_emit_next_line(j, &pix, &pib, &ps, 0);
		if (r & LWS_SRET_FATAL) {
			lwsl_notice("%s: emit returned FATAL 0x%x\n", __func__,
				    (unsigned int)r);
			goto bail;
		}

		if ((r & LWS_SRET_WANT_OUTPUT) && pix) {
			ssize_t os = (ssize_t)(lws_jpeg_get_width(j) *
					(lws_jpeg_get_pixelsize(j) / 8));

			rows++;

			if (fdout != -1 && write(fdout, pix,
#if defined(WIN32)
						(unsigned int)
#endif
						(size_t)os) < os) {
				lwsl_err("%s: write %d failed %d\n", __func__,
						(int)os, errno);
				goto bail;
			}
		}

	} while (r != LWS_SRET_OK);

	if (rows < lws_jpeg_get_height(j)) {
		lwsl_err("%s: %u rows of %u\n", __func__, rows,
			 lws_jpeg_get_height(j));
		goto bail;
	}

	lwsl_user("%s: %u x %u, %u rows\n", __func__, lws_jpeg_get_width(j),
		  lws_jpeg_get_height(j), rows);

	result = 0;

bail:
	lws_jpeg_free(&j);

	return result;
}

int
main(int argc, const char **argv)
{
	int result = 1, fdin = 0, fdout = 1;
	const char *p;
	size_t l = 0;

	if ((argc == 1) || lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches, LWS_ARRAY_SIZE(switches));
		return 0;
	}

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_D].sw)))
		lws_set_log_level(atoi(p), NULL);

	lwsl_user("LWS JPEG test tool\n");

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_SELFTEST].sw)) {
		result = selftest();
		lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

		return !!result;
	}

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_STDIN].sw))) {
		fdin = open(p, LWS_O_RDONLY | JPEG_O_BINARY, 0);
		if (fdin < 0) {
			lwsl_err("%s: unable to open stdin file\n", __func__);
			goto bail;
		}
	}

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_NO_OUTPUT].sw))
		fdout = -1;
	else
		if ((p = lws_cmdline_option(argc, argv,
					    switches[LWS_SW_STDOUT].sw))) {
			fdout = open(p, LWS_O_WRONLY | LWS_O_CREAT |
					LWS_O_TRUNC | JPEG_O_BINARY, 0600);
			if (fdout < 0) {
				lwsl_err("%s: unable to open stdout file\n",
					 __func__);
				goto bail1;
			}
		}

	if (!fdin) {
		struct timeval timeout;
		fd_set	fds;

		FD_ZERO(&fds);
		FD_SET(0, &fds);

		timeout.tv_sec  = 0;
		timeout.tv_usec = 1000;

		if (select(fdin + 1, &fds, NULL, NULL, &timeout) < 0 ||
		    !FD_ISSET(0, &fds)) {
			lwsl_err("%s: pass JPEG "
				 "on stdin or use --stdin\n", __func__);
			goto bail1;
		}
	}

	result = decode_fd(fdin, fdout, &l);

bail1:
	if (fdin)
		close(fdin);
	if (fdout != 1 && fdout != -1)
		close(fdout);

bail:
	lwsl_user("Completed: %s (read %u)\n", result ? "FAIL" : "PASS",
							(unsigned int)l);

	return result;
}
