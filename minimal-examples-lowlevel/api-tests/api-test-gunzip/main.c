/*
 * lws-api-test-gunzip
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * tests for LWS_WITH_GZINFLATE (inflator via upng)
 *
 * With --selftest, inflates gzip members held in memory and checks the
 * output and the outcome: assembled here from stored, fixed huffman and
 * zero-length blocks in different orders, made by the system gzip (see
 * gz-vectors.h), cut short, and with a damaged trailer.  Each is fed in
 * several chunk sizes, since the inflator is stateful across its input.
 *
 * Otherwise it gunzips --stdin (or stdin) to --stdout (or stdout).
 */

#include <libwebsockets.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>

#include "gz-vectors.h"

enum {
	LWS_SW_STDIN,
	LWS_SW_STDOUT,
	LWS_SW_SELFTEST,
	LWS_SW_D,
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_STDIN]		= { "--stdin",    "Read the gzip from this file" },
	[LWS_SW_STDOUT]		= { "--stdout",   "Write the output to this file" },
	[LWS_SW_SELFTEST]	= { "--selftest", "Run the built-in tests and exit" },
	[LWS_SW_D]		= { "-d",         "Debug logs (e.g. -d 15)" },
	[LWS_SW_HELP]		= { "--help",     "Show this help information" },
};

int fdin = 0, fdout = 1;

/*
 * Selftest
 */

#define PLAIN_LEN	70000 /* more than one stored block can carry */

typedef enum {
	RES_OK,		/* completed, trailer checked, output as expected */
	RES_INCOMPLETE,	/* ran out of input without completing */
	RES_FATAL,	/* the inflator said the stream is broken */
	RES_MISMATCH,	/* the output was not what went in */
} res_t;

static const char * const res_names[] = {
	"OK", "INCOMPLETE", "FATAL", "MISMATCH"
};

static uint8_t plain[PLAIN_LEN], gz[PLAIN_LEN + 1024], text[4096];
static size_t text_len;

static void
noise_fill(uint8_t *p, size_t len)
{
	uint32_t x = 0x12345678;

	while (len--) {
		/* the LCG is mod 2^32: drop what the multiply carries past it */
		x = (uint32_t)(((uint64_t)x * 1103515245u + 12345u) &
			       0xffffffffu);
		*p++ = (uint8_t)(x >> 16);
	}
}

static void
text_fill(void)
{
	int n;

	for (n = 0; n < 60; n++)
		text_len += (size_t)lws_snprintf((char *)text + text_len,
				sizeof(text) - text_len,
				"line %d of the lws gunzip selftest, "
				"mostly repeating\n", n);
}

/* a deflate bitstream writer, lsb-first as RFC1951 3.1.1 packs it */

typedef struct {
	uint8_t		*p;
	uint32_t	acc;
	int		nbits;
} bw_t;

static void
bw_put(bw_t *bw, uint32_t v, int n)
{
	bw->acc |= v << bw->nbits;
	bw->nbits += n;
	while (bw->nbits >= 8) {
		*bw->p++ = (uint8_t)bw->acc;
		bw->acc >>= 8;
		bw->nbits -= 8;
	}
}

static void
bw_put_huff(bw_t *bw, uint32_t code, int n) /* huffman codes are msb-first */
{
	while (n--)
		bw_put(bw, (code >> n) & 1, 1);
}

static void
bw_align(bw_t *bw)
{
	if (bw->nbits)
		bw_put(bw, 0, 8 - bw->nbits);
}

static void
bw_le(bw_t *bw, uint32_t v, int bytes)
{
	while (bytes--) {
		bw_put(bw, v & 0xff, 8);
		v >>= 8;
	}
}

static void
gz_start(bw_t *bw)
{
	static const uint8_t hdr[] = { 0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff };

	memset(bw, 0, sizeof(*bw));
	memcpy(gz, hdr, sizeof(hdr));
	bw->p = gz + sizeof(hdr);
}

static void
blk_stored(bw_t *bw, int final, size_t ofs, size_t len)
{
	bw_put(bw, (uint32_t)final, 1);
	bw_put(bw, 0, 2);
	bw_align(bw);
	bw_le(bw, (uint32_t)len, 2);
	bw_le(bw, (uint32_t)len ^ 0xffff, 2);
	memcpy(bw->p, plain + ofs, len);
	bw->p += len;
}

static void
blk_fixed(bw_t *bw, int final, size_t ofs, size_t len)
{
	const uint8_t *p = plain + ofs;

	bw_put(bw, (uint32_t)final, 1);
	bw_put(bw, 1, 2);
	while (len--) {
		if (*p < 144)
			bw_put_huff(bw, 0x30u + *p, 8);
		else
			bw_put_huff(bw, 0x190u + *p - 144u, 9);
		p++;
	}
	bw_put_huff(bw, 0, 7); /* end of block */
}

/* the trailer for plain[0 .. len), returns the gzip length */

static size_t
gz_end(bw_t *bw, size_t len)
{
	bw_align(bw);
	bw_le(bw, lws_crc32(0, plain, len), 4);
	bw_le(bw, (uint32_t)len, 4);

	return lws_ptr_diff_size_t(bw->p, gz);
}

static res_t
inflate_one(const uint8_t *in, size_t in_len, size_t chunk,
	    const uint8_t *expect, size_t expect_len)
{
	lws_stateful_ret_t r = LWS_SRET_WANT_INPUT;
	struct inflator_ctx *inf;
	size_t ringlen, *opl, *cl, fed = 0;
	const uint8_t *ring;
	res_t res = RES_FATAL;

	inf = lws_upng_inflator_create(&ring, &ringlen, &opl, &cl);
	if (!inf)
		return RES_FATAL;

	do {
		const uint8_t *p = NULL;
		size_t l = 0;

		if (r & LWS_SRET_WANT_INPUT) {
			if (fed == in_len) {
				res = RES_INCOMPLETE;
				break;
			}
			p = in + fed;
			l = in_len - fed < chunk ? in_len - fed : chunk;
			fed += l;
		}

		r = lws_upng_inflate_data(inf, p, l);

		/* take the output, the inflator can't overwrite it until we do */

		res = RES_MISMATCH;
		while (*cl < *opl) {
			if (*cl >= expect_len ||
			    ring[*cl % ringlen] != expect[*cl])
				goto bail;
			(*cl)++;
		}

		if (r & LWS_SRET_FATAL) {
			res = RES_FATAL;
			break;
		}

		if (r == LWS_SRET_OK) {
			res = *cl == expect_len ? RES_OK : RES_MISMATCH;
			break;
		}
	} while (1);

bail:
	lws_upng_inflator_destroy(&inf);

	return res;
}

static int
check(const char *name, const uint8_t *in, size_t in_len,
      const uint8_t *expect, size_t expect_len, res_t want)
{
	static const size_t chunks[] = { 1, 7, 4096, 1 << 30 };
	size_t n;
	res_t res;

	for (n = 0; n < LWS_ARRAY_SIZE(chunks); n++) {
		res = inflate_one(in, in_len, chunks[n], expect, expect_len);
		if (res != want) {
			lwsl_err("%s: %s, chunk %u: %s, expected %s\n", __func__,
				 name, (unsigned int)chunks[n], res_names[res],
				 res_names[want]);

			return 1;
		}
	}

	lwsl_user("%s: %s: %s\n", __func__, name, res_names[want]);

	return 0;
}

static int
selftest(void)
{
	size_t len, n;
	int fails = 0;
	bw_t bw;

	noise_fill(plain, sizeof(plain));
	text_fill();

	/* what the system gzip makes */

	fails += check("gzip of noise (stored, final)", gz_noise,
		       sizeof(gz_noise), plain, 700, RES_OK);
	fails += check("gzip of text (FNAME, dynamic)", gz_text,
		       sizeof(gz_text), text, text_len, RES_OK);

	/* a single stored block with BFINAL, then the trailer */

	gz_start(&bw);
	blk_stored(&bw, 1, 0, 1000);
	len = gz_end(&bw, 1000);
	fails += check("stored final", gz, len, plain, 1000, RES_OK);

	/* bytes after the member are not ours to read */

	gz[len] = 0xff;
	fails += check("stored final, trailing byte", gz, len + 1,
		       plain, 1000, RES_OK);

	/* the trailer must match what was inflated */

	gz[len - 8] ^= 1;
	fails += check("bad CRC32", gz, len, plain, 1000, RES_FATAL);
	gz[len - 8] ^= 1;
	gz[len - 4] ^= 1;
	fails += check("bad ISIZE", gz, len, plain, 1000, RES_FATAL);
	gz[len - 4] ^= 1;

	/* stored blocks are at most 65535 bytes, so big ones come in several */

	gz_start(&bw);
	blk_stored(&bw, 0, 0, 65535);
	blk_stored(&bw, 1, 65535, PLAIN_LEN - 65535);
	len = gz_end(&bw, PLAIN_LEN);
	fails += check("two stored", gz, len, plain, PLAIN_LEN, RES_OK);

	/* a final fixed block after a stored one, and the other way round */

	gz_start(&bw);
	blk_stored(&bw, 0, 0, 300);
	blk_fixed(&bw, 0, 300, 300);
	blk_stored(&bw, 0, 600, 0);
	blk_fixed(&bw, 1, 600, 400);
	len = gz_end(&bw, 1000);
	fails += check("stored, fixed, empty stored, fixed final", gz, len,
		       plain, 1000, RES_OK);

	gz_start(&bw);
	blk_fixed(&bw, 0, 0, 333);
	blk_stored(&bw, 1, 333, 667);
	len = gz_end(&bw, 1000);
	fails += check("fixed, stored final", gz, len, plain, 1000, RES_OK);

	/*
	 * Cut short anywhere, it must want more input, neither complete nor
	 * call it broken
	 */

	for (n = 0; n < len; n++)
		if (inflate_one(gz, n, 1 << 30, plain, 1000) !=
							RES_INCOMPLETE) {
			lwsl_err("%s: cut at %u of %u not INCOMPLETE\n",
				 __func__, (unsigned int)n, (unsigned int)len);
			fails++;
			break;
		}
	if (n == len)
		lwsl_user("%s: every truncation: INCOMPLETE\n", __func__);

	/* an empty member is one zero-length stored block with BFINAL */

	gz_start(&bw);
	blk_stored(&bw, 1, 0, 0);
	len = gz_end(&bw, 0);
	fails += check("empty stored final", gz, len, plain, 0, RES_OK);

	return fails;
}

int
main(int argc, const char **argv)
{
	int result = 0, more = 1;
	const char *p;
	lws_stateful_ret_t r = LWS_SRET_WANT_INPUT;
	struct inflator_ctx *gunz;
	const uint8_t *outring;
	size_t l = 0, old_op = 0, outringlen, *opl, *cl, pw = 0;

	if ((argc == 1) || lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches, LWS_ARRAY_SIZE(switches));
		return 0;
	}

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_D].sw)))
		lws_set_log_level(atoi(p), NULL);

	lwsl_user("LWS API selftest: gunzip\n");

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_SELFTEST].sw)) {
		result = selftest();
		lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

		return !!result;
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
		struct timeval timeout;
		fd_set	fds;

		FD_ZERO(&fds);
		FD_SET(0, &fds);

		timeout.tv_sec  = 0;
		timeout.tv_usec = 1000;

		if (select(fdin + 1, &fds, NULL, NULL, &timeout) < 0 ||
		    !FD_ISSET(0, &fds)) {
			result = 1;
			lwsl_err("%s: pass gzip "
				 "on stdin or use --stdin\n", __func__);
			goto bail;
		}
	}

	gunz = lws_upng_inflator_create(&outring, &outringlen, &opl, &cl);
	if (!gunz)
		goto bail;

	do {
		uint8_t ib[9];
		const uint8_t *pib = NULL;
		ssize_t s, os;
		size_t ps = 0, part;

		pib = NULL;
		if ((r & LWS_SRET_WANT_INPUT) && more) {
			s = read(fdin, ib, sizeof(ib));

			if (s <= 0) {
				lwsl_err("%s: failed to read: %d (after %lu)\n", __func__, errno, (unsigned long)l);
				more = 0;
			} else {

				pib = ib;
				ps = (size_t)s;
				l += ps;

				lwsl_info("%s: fetched %u (%u)\n", __func__,
						(unsigned int)s, (unsigned int)l);
			}
		}

		do {
			r = lws_upng_inflate_data(gunz, pib, ps);
			pib = NULL;
			ps = 0;

			if (r & LWS_SRET_FATAL) {
				lwsl_err("%s: emit returned FATAL %d\n", __func__, r &0xff);
				result = 1;
				goto bail1;
			}

			if (!more && *opl == *cl) {
				/*
				 * No more input possible, and no output came:
				 * a complete member would have returned OK
				 */
				lwsl_err("%s: gzip is truncated\n", __func__);
				result = 1;
				goto bail1;
			}

			os = (ssize_t)((*opl - (size_t)old_op) % outringlen);

			/* if we wrap around the ring, first do the part to the
			 * end of the ring */

			part = (size_t)os;
			if ((*opl % outringlen) < old_op)
				part = outringlen - old_op;

			if (write(fdout, outring + old_op,
#if defined(WIN32)
						(unsigned int)
#endif
						part) < (ssize_t)part) {
				lwsl_err("%s: write %d failed %d\n", __func__,
						(int)os, errno);
				goto bail1;
			}

			/* then do the remainder (if any) from the ring start */

			if ((*opl % outringlen) < old_op)
				if (write(fdout, outring,
	#if defined(WIN32)
							(unsigned int)
	#endif
							*opl % outringlen) < (ssize_t)(*opl % outringlen)) {
					lwsl_err("%s: write %d failed %d\n", __func__,
							(int)os, errno);
					goto bail1;
				}

			old_op = *opl % outringlen;
			*cl = *opl;
			pw = (size_t)(pw + (size_t)os);

			lwsl_debug("%s: wrote %d: r %u (left %u)\n", __func__,
					(int)os, r, (unsigned int)ps);

			if (r == LWS_SRET_OK) {
				lwsl_notice("%s: complete, %lu\n", __func__,
					    (unsigned long)pw);
				goto bail1;
			}

			if (r & LWS_SRET_WANT_INPUT)
				break;

		} while (ps); /* while any input left */
	} while (1);

bail1:

	lws_upng_inflator_destroy(&gunz);

bail:

	if (fdin >= 0)
		close(fdin);
	if (fdout >= 0 && fdout != 1)
		close(fdout);

	lwsl_user("Completed\n");

	return result;
}
