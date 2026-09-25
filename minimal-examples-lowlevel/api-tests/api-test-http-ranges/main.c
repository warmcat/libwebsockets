/*
 * lws-api-test-http-ranges
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * One process: a file mount serves three generated files, and the client
 * side asks for them back with every shape of Range: header RFC 7233
 * describes, over h1 and h2.
 *
 * Each response is checked as a whole: the status, the Content-Type, the
 * Content-Range, that the Content-Length promised is exactly the count of
 * body bytes that arrived, and that every payload byte is the byte the
 * file has at that offset.  The file content is a mixing function of the
 * offset, so a part that is short, doubled, misaligned or seeked to the
 * wrong place cannot pass by accident.
 *
 * A multipart/byteranges response is parsed the way a client has to parse
 * it: the boundary comes from the Content-Type parameter, and the body
 * must be the delimiters, part headers and payloads RFC 2046 lays out,
 * ending at the close delimiter with nothing after it.
 *
 * The generated files are a small one (everything fits one lws_write()),
 * a big one (every part spans many, so the producer's resumption and the
 * h2 frame and tx credit clamps are in play) and an empty one, which has
 * no satisfiable range at all.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

/* the served files */

enum {
	F_SMALL,
	F_BIG,
	F_EMPTY,

	F_COUNT
};

#define SMALL_LEN	1000
#define BIG_LEN		200000

static const char * const file_name[F_COUNT] = {
	"small.bin", "big.bin", "empty.bin"
};
static const size_t file_len[F_COUNT] = { SMALL_LEN, BIG_LEN, 0 };

/* what the mount gives an unknown extension */
static const char * const octet = "application/octet-stream";

#define MAX_RANGES	64

struct rng {
	unsigned long long	start;
	unsigned long long	end;		/* inclusive */
};

struct xcase {
	const char	*name;
	const char	*range;		/* the Range: value, NULL for none */
	const char	*if_range;	/* a literal If-Range: value */
	uint8_t		file;
	uint8_t		if_range_etag;	/* send If-Range: <the file's etag> */
	uint8_t		gen_n;		/* generate this many 1-byte ranges */
	uint8_t		h2;
	uint16_t	status;		/* expected */
	uint8_t		nexp;		/* expected parts; 0 means whole file */
	struct rng	exp[3];
};

/*
 * The whole-file cases expect 200 and no Content-Range; one expected range
 * is a plain 206; two or more is multipart/byteranges.
 */

static const struct xcase cases[] = {
	/*
	 * Case 0 has to come first: it is the plain GET whose ETag the
	 * If-Range cases below quote back.
	 */
	{ .name = "h1 no Range",
	  .file = F_SMALL, .status = 200 },

	/* the shapes of a single range */

	{ .name = "h1 first 100 bytes",
	  .file = F_SMALL, .range = "bytes=0-99", .status = 206,
	  .nexp = 1, .exp = { { 0, 99 } } },
	{ .name = "h1 a range in the middle",
	  .file = F_SMALL, .range = "bytes=400-499", .status = 206,
	  .nexp = 1, .exp = { { 400, 499 } } },
	{ .name = "h1 the last 10 bytes, explicitly",
	  .file = F_SMALL, .range = "bytes=990-999", .status = 206,
	  .nexp = 1, .exp = { { 990, 999 } } },
	{ .name = "h1 suffix range",
	  .file = F_SMALL, .range = "bytes=-10", .status = 206,
	  .nexp = 1, .exp = { { SMALL_LEN - 10, SMALL_LEN - 1 } } },
	{ .name = "h1 suffix longer than the file",
	  .file = F_SMALL, .range = "bytes=-2000", .status = 206,
	  .nexp = 1, .exp = { { 0, SMALL_LEN - 1 } } },
	{ .name = "h1 open-ended range",
	  .file = F_SMALL, .range = "bytes=500-", .status = 206,
	  .nexp = 1, .exp = { { 500, SMALL_LEN - 1 } } },
	{ .name = "h1 the whole file as a range",
	  .file = F_SMALL, .range = "bytes=0-", .status = 206,
	  .nexp = 1, .exp = { { 0, SMALL_LEN - 1 } } },
	{ .name = "h1 the first byte alone",
	  .file = F_SMALL, .range = "bytes=0-0", .status = 206,
	  .nexp = 1, .exp = { { 0, 0 } } },
	{ .name = "h1 the last byte alone",
	  .file = F_SMALL, .range = "bytes=999-999", .status = 206,
	  .nexp = 1, .exp = { { SMALL_LEN - 1, SMALL_LEN - 1 } } },
	{ .name = "h1 last-byte-pos past the end clamps",
	  .file = F_SMALL, .range = "bytes=900-100000", .status = 206,
	  .nexp = 1, .exp = { { 900, SMALL_LEN - 1 } } },
	{ .name = "h1 an unsatisfiable range among satisfiable ones",
	  .file = F_SMALL, .range = "bytes=0-9,5000-6000", .status = 206,
	  .nexp = 1, .exp = { { 0, 9 } } },

	/* a Range: we have to ignore leaves an ordinary 200 */

	{ .name = "h1 unparseable Range is ignored",
	  .file = F_SMALL, .range = "bytes=abc", .status = 200 },
	{ .name = "h1 empty Range is ignored",
	  .file = F_SMALL, .range = "bytes=", .status = 200 },
	{ .name = "h1 a unit that is not bytes is ignored",
	  .file = F_SMALL, .range = "items=0-9", .status = 200 },

	/* nothing satisfiable: 416 */

	{ .name = "h1 first-byte-pos at the end",
	  .file = F_SMALL, .range = "bytes=1000-", .status = 416 },
	{ .name = "h1 a range wholly past the end",
	  .file = F_SMALL, .range = "bytes=2000-3000", .status = 416 },
	{ .name = "h1 zero-length suffix",
	  .file = F_SMALL, .range = "bytes=-0", .status = 416 },
	{ .name = "h1 last-byte-pos before first-byte-pos",
	  .file = F_SMALL, .range = "bytes=500-400", .status = 416 },
	{ .name = "h1 ranges that aggregate past the file",
	  .file = F_SMALL, .range = "bytes=0-999,0-999", .status = 416 },
	{ .name = "h1 more ranges than we will compose",
	  .file = F_SMALL, .gen_n = 17, .status = 416 },
	{ .name = "h1 a Range longer than the parser will hold",
	  .file = F_SMALL, .gen_n = 80, .status = 416 },

	/* multipart/byteranges */

	{ .name = "h1 two ranges",
	  .file = F_SMALL, .range = "bytes=0-99,200-299", .status = 206,
	  .nexp = 2, .exp = { { 0, 99 }, { 200, 299 } } },
	{ .name = "h1 three ranges",
	  .file = F_SMALL, .range = "bytes=0-9,20-29,40-49", .status = 206,
	  .nexp = 3, .exp = { { 0, 9 }, { 20, 29 }, { 40, 49 } } },
	{ .name = "h1 the first and last bytes (RFC 7233 2.1)",
	  .file = F_SMALL, .range = "bytes=0-0,-1", .status = 206,
	  .nexp = 2, .exp = { { 0, 0 }, { SMALL_LEN - 1, SMALL_LEN - 1 } } },
	{ .name = "h1 adjacent ranges",
	  .file = F_SMALL, .range = "bytes=0-499,500-999", .status = 206,
	  .nexp = 2, .exp = { { 0, 499 }, { 500, SMALL_LEN - 1 } } },
	{ .name = "h1 overlapping ranges within the file",
	  .file = F_SMALL, .range = "bytes=0-399,300-699", .status = 206,
	  .nexp = 2, .exp = { { 0, 399 }, { 300, 699 } } },
	{ .name = "h1 ranges out of order",
	  .file = F_SMALL, .range = "bytes=800-899,100-199", .status = 206,
	  .nexp = 2, .exp = { { 800, 899 }, { 100, 199 } } },
	{ .name = "h1 ten one-byte ranges",
	  .file = F_SMALL, .gen_n = 10, .status = 206 },
	{ .name = "h1 as many ranges as we will compose",
	  .file = F_SMALL, .gen_n = 16, .status = 206 },

	/* the same, on a file far larger than one lws_write() */

	{ .name = "h1 big file, no Range",
	  .file = F_BIG, .status = 200 },
	{ .name = "h1 big file, a range spanning many writes",
	  .file = F_BIG, .range = "bytes=1000-150000", .status = 206,
	  .nexp = 1, .exp = { { 1000, 150000 } } },
	{ .name = "h1 big file, suffix range",
	  .file = F_BIG, .range = "bytes=-100000", .status = 206,
	  .nexp = 1, .exp = { { BIG_LEN - 100000, BIG_LEN - 1 } } },
	{ .name = "h1 big file, a range ending at the last byte",
	  .file = F_BIG, .range = "bytes=199000-199999", .status = 206,
	  .nexp = 1, .exp = { { 199000, BIG_LEN - 1 } } },
	{ .name = "h1 big file, three parts each spanning many writes",
	  .file = F_BIG, .range = "bytes=0-49999,60000-109999,150000-199999",
	  .status = 206, .nexp = 3,
	  .exp = { { 0, 49999 }, { 60000, 109999 }, { 150000, BIG_LEN - 1 } } },
	{ .name = "h1 big file, a one-byte part beside a huge one",
	  .file = F_BIG, .range = "bytes=0-0,1000-190000", .status = 206,
	  .nexp = 2, .exp = { { 0, 0 }, { 1000, 190000 } } },

	/* an empty representation has no satisfiable byte-range at all */

	{ .name = "h1 empty file, no Range",
	  .file = F_EMPTY, .status = 200 },
	{ .name = "h1 empty file, first byte",
	  .file = F_EMPTY, .range = "bytes=0-0", .status = 416 },
	{ .name = "h1 empty file, suffix",
	  .file = F_EMPTY, .range = "bytes=-1", .status = 416 },

	/* If-Range decides whether the Range applies at all */

	{ .name = "h1 If-Range matching the etag keeps the range",
	  .file = F_SMALL, .range = "bytes=0-99", .if_range_etag = 1,
	  .status = 206, .nexp = 1, .exp = { { 0, 99 } } },
	{ .name = "h1 If-Range not matching defeats the range",
	  .file = F_SMALL, .range = "bytes=0-99",
	  .if_range = "0000000000000000", .status = 200 },

#if defined(LWS_WITH_HTTP2)
	/* h2 frames the same responses, and clamps what the producer may
	 * make by its max frame size and the stream's tx credit */

	{ .name = "h2 no Range",
	  .file = F_SMALL, .h2 = 1, .status = 200 },
	{ .name = "h2 first 100 bytes",
	  .file = F_SMALL, .h2 = 1, .range = "bytes=0-99", .status = 206,
	  .nexp = 1, .exp = { { 0, 99 } } },
	{ .name = "h2 suffix range",
	  .file = F_SMALL, .h2 = 1, .range = "bytes=-10", .status = 206,
	  .nexp = 1, .exp = { { SMALL_LEN - 10, SMALL_LEN - 1 } } },
	{ .name = "h2 open-ended range",
	  .file = F_SMALL, .h2 = 1, .range = "bytes=500-", .status = 206,
	  .nexp = 1, .exp = { { 500, SMALL_LEN - 1 } } },
	{ .name = "h2 three ranges",
	  .file = F_SMALL, .h2 = 1, .range = "bytes=0-9,20-29,40-49",
	  .status = 206, .nexp = 3,
	  .exp = { { 0, 9 }, { 20, 29 }, { 40, 49 } } },
	{ .name = "h2 nothing satisfiable",
	  .file = F_SMALL, .h2 = 1, .range = "bytes=2000-3000", .status = 416 },
	{ .name = "h2 big file, no Range",
	  .file = F_BIG, .h2 = 1, .status = 200 },
	{ .name = "h2 big file, a range spanning many writes",
	  .file = F_BIG, .h2 = 1, .range = "bytes=1000-150000", .status = 206,
	  .nexp = 1, .exp = { { 1000, 150000 } } },
	{ .name = "h2 big file, three parts each spanning many writes",
	  .file = F_BIG, .h2 = 1,
	  .range = "bytes=0-49999,60000-109999,150000-199999",
	  .status = 206, .nexp = 3,
	  .exp = { { 0, 49999 }, { 60000, 109999 }, { 150000, BIG_LEN - 1 } } },
#endif
};

struct conn {
	uint8_t		*body;
	size_t		body_len, body_max;
	long long	cl;
	int		status;
	char		ct[128];
	char		cr[128];
	char		ar[32];
	char		cl_valid;
	char		completed;
	char		failed;
};

static struct lws_context *context;
static struct lws_vhost *vh_cli;
static lws_sorted_usec_list_t sul_next, sul_watchdog;
static struct conn conn;
static char tmpdir[256], path[384], etag[64], gen_range[1024];
static const char *tmpbase = ".";
static const char *server_addr = "127.0.0.1";
static int cur = -1, failures, only_case = -1, interrupted,
	   port_h1 = 7681, port_h2 = 7682;
static unsigned int serv_buf_size;

static void
next_case(lws_sorted_usec_list_t *sul);

/*
 * The byte a file has at a given offset: a mixing function of the offset, so
 * that a payload which is misaligned by one byte, or which repeats or skips
 * a lump, cannot match what was asked for.
 */

static uint8_t
pat(size_t i)
{
	uint32_t x = (uint32_t)i + 0x9e3779b9u;

	x ^= x << 13;
	x ^= x >> 17;
	x ^= x << 5;

	return (uint8_t)(x ^ (x >> 8) ^ (x >> 16));
}

static int
generate_files(void)
{
	uint8_t buf[4096];
	size_t n, m;
	FILE *f;

	lws_snprintf(tmpdir, sizeof(tmpdir), "%s/lws-http-ranges-XXXXXX",
		     tmpbase);
	if (!mkdtemp(tmpdir)) {
		lwsl_err("%s: mkdtemp %s failed\n", __func__, tmpdir);
		tmpdir[0] = '\0';

		return 1;
	}

	for (n = 0; n < F_COUNT; n++) {
		size_t done = 0;

		lws_snprintf(path, sizeof(path), "%s/%s", tmpdir,
			     file_name[n]);
		f = fopen(path, "wb");
		if (!f) {
			lwsl_err("%s: cannot create %s\n", __func__, path);

			return 1;
		}

		while (done < file_len[n]) {
			size_t l = file_len[n] - done;

			if (l > sizeof(buf))
				l = sizeof(buf);
			for (m = 0; m < l; m++)
				buf[m] = pat(done + m);
			if (fwrite(buf, 1, l, f) != l) {
				lwsl_err("%s: write failed\n", __func__);
				fclose(f);

				return 1;
			}
			done += l;
		}
		fclose(f);
	}

	lwsl_user("%s: %s\n", __func__, tmpdir);

	return 0;
}

static void
cleanup_files(void)
{
	size_t n;

	if (!tmpdir[0])
		return;

	for (n = 0; n < F_COUNT; n++) {
		lws_snprintf(path, sizeof(path), "%s/%s", tmpdir,
			     file_name[n]);
		unlink(path);
	}

	rmdir(tmpdir);
}

/*
 * The ranges the case expects back, in the order they must arrive.  A case
 * with gen_n asks for that many one-byte ranges at stride 2, which is also
 * how many parts it must get.
 */

static int
case_expect(const struct xcase *c, struct rng *out, int max)
{
	int n;

	if (!c->gen_n) {
		for (n = 0; n < (int)c->nexp && n < max; n++)
			out[n] = c->exp[n];

		return n;
	}

	for (n = 0; n < (int)c->gen_n && n < max; n++) {
		out[n].start = (unsigned long long)n * 2;
		out[n].end = out[n].start;
	}

	return n;
}

/* the Range: value the case sends */

static const char *
case_range(const struct xcase *c)
{
	size_t pos;
	int n;

	if (!c->gen_n)
		return c->range;

	pos = (size_t)lws_snprintf(gen_range, sizeof(gen_range), "bytes=");
	for (n = 0; n < (int)c->gen_n; n++)
		pos += (size_t)lws_snprintf(gen_range + pos,
					    sizeof(gen_range) - pos, "%s%d-%d",
					    n ? "," : "", n * 2, n * 2);

	return gen_range;
}

/*
 * Checks len bytes at p are the file's bytes from start on.  Returns the
 * offset within them of the first byte that is not, or -1 if all are.
 */

static long long
cmp_pat(const uint8_t *p, size_t len, unsigned long long start)
{
	size_t n;

	for (n = 0; n < len; n++)
		if (p[n] != pat((size_t)start + n))
			return (long long)n;

	return -1;
}

/*
 * The multipart/byteranges body, parsed the way a client must parse it: the
 * boundary is whatever the Content-Type parameter said, and the body is
 *
 *   ["\r\n"] "--" boundary "\r\n" part-headers "\r\n" payload "\r\n"
 *   ... "--" boundary "--" ["\r\n"]
 *
 * Returns 0 if the body is exactly that, for exactly the expected ranges.
 */

static int
check_multipart(const char *ct, const uint8_t *body, size_t len,
		const struct rng *exp, int nexp, unsigned long long extent)
{
	char boundary[80], dash[84], want[128];
	const uint8_t *p = body, *end = body + len;
	const char *b;
	size_t bl, dl;
	int n;

	if (strncmp(ct, "multipart/byteranges", 20)) {
		lwsl_err("%s: content-type '%s' is not multipart/byteranges\n",
			 __func__, ct);

		return 1;
	}

	b = strstr(ct, "boundary=");
	if (!b) {
		lwsl_err("%s: content-type '%s' declares no boundary\n",
			 __func__, ct);

		return 1;
	}

	b += 9;
	if (*b == '"')
		b++;
	bl = strcspn(b, "\";");
	if (!bl || bl >= sizeof(boundary)) {
		lwsl_err("%s: boundary in '%s' is unusable\n", __func__, ct);

		return 1;
	}
	lws_strnncpy(boundary, b, bl, sizeof(boundary));

	dl = (size_t)lws_snprintf(dash, sizeof(dash), "--%s", boundary);

	/* the first delimiter may or may not be preceded by a CRLF */

	if ((size_t)(end - p) >= 2 && p[0] == '\r' && p[1] == '\n')
		p += 2;

	for (n = 0; n < nexp; n++) {
		unsigned long long amount = exp[n].end - exp[n].start + 1;
		int seen_ct = 0, seen_cr = 0;
		long long bad;

		/* the part's delimiter */

		if ((size_t)(end - p) < dl + 2 || memcmp(p, dash, dl) ||
		    p[dl] != '\r' || p[dl + 1] != '\n') {
			lwsl_err("%s: part %d: no '%s' delimiter at +%u\n",
				 __func__, n, dash,
				 (unsigned int)(p - body));

			return 1;
		}
		p += dl + 2;

		/* its headers, to the empty line */

		while (1) {
			const uint8_t *eol = p;

			while (eol + 1 < end && (eol[0] != '\r' ||
						 eol[1] != '\n'))
				eol++;
			if (eol + 1 >= end) {
				lwsl_err("%s: part %d: headers unterminated\n",
					 __func__, n);

				return 1;
			}

			if (eol == p) { /* the empty line ends them */
				p += 2;
				break;
			}

			lws_snprintf(want, sizeof(want), "Content-Type: %s",
				     octet);
			if ((size_t)(eol - p) == strlen(want) &&
			    !strncasecmp((const char *)p, want, strlen(want)))
				seen_ct = 1;

			lws_snprintf(want, sizeof(want),
				     "Content-Range: bytes %llu-%llu/%llu",
				     exp[n].start, exp[n].end, extent);
			if ((size_t)(eol - p) == strlen(want) &&
			    !strncasecmp((const char *)p, want, strlen(want)))
				seen_cr = 1;

			p = eol + 2;
		}

		if (!seen_ct) {
			lwsl_err("%s: part %d: no 'Content-Type: %s'\n",
				 __func__, n, octet);

			return 1;
		}
		if (!seen_cr) {
			lwsl_err("%s: part %d: no 'Content-Range: bytes "
				 "%llu-%llu/%llu'\n", __func__, n,
				 exp[n].start, exp[n].end, extent);

			return 1;
		}

		/* its payload */

		if ((unsigned long long)(end - p) < amount) {
			lwsl_err("%s: part %d: %u payload bytes left, "
				 "%llu needed\n", __func__, n,
				 (unsigned int)(end - p), amount);

			return 1;
		}

		bad = cmp_pat(p, (size_t)amount, exp[n].start);
		if (bad >= 0) {
			lwsl_err("%s: part %d: payload differs at +%lld "
				 "(file offset %llu)\n", __func__, n, bad,
				 exp[n].start + (unsigned long long)bad);

			return 1;
		}
		p += amount;

		/* the CRLF that belongs to the next delimiter */

		if ((size_t)(end - p) < 2 || p[0] != '\r' || p[1] != '\n') {
			lwsl_err("%s: part %d: payload not followed by CRLF\n",
				 __func__, n);

			return 1;
		}
		p += 2;
	}

	/* the close delimiter, and nothing of substance after it */

	if ((size_t)(end - p) < dl + 2 || memcmp(p, dash, dl) ||
	    p[dl] != '-' || p[dl + 1] != '-') {
		lwsl_err("%s: no '%s--' close delimiter at +%u\n", __func__,
			 dash, (unsigned int)(p - body));

		return 1;
	}
	p += dl + 2;

	if ((size_t)(end - p) >= 2 && p[0] == '\r' && p[1] == '\n')
		p += 2;

	if (p != end) {
		lwsl_err("%s: %u bytes after the close delimiter\n", __func__,
			 (unsigned int)(end - p));

		return 1;
	}

	return 0;
}

static int
verify(const struct xcase *c, struct conn *cn)
{
	unsigned long long extent = (unsigned long long)file_len[c->file];
	struct rng exp[MAX_RANGES];
	char want[128];
	int nexp, ok = 1;
	long long bad;

	nexp = case_expect(c, exp, (int)LWS_ARRAY_SIZE(exp));

	if (cn->status != (int)c->status) {
		lwsl_err("%s: status %d, expected %d\n", __func__, cn->status,
			 c->status);

		return 0;
	}

	if (c->status == 416) {
		/*
		 * RFC 7233 4.4: a 416 says what length the ranges were
		 * unsatisfiable against
		 */

		lws_snprintf(want, sizeof(want), "bytes */%llu", extent);
		if (strcmp(cn->cr, want)) {
			lwsl_err("%s: 416 content-range '%s', expected '%s'\n",
				 __func__, cn->cr, want);
			ok = 0;
		}

		return ok;
	}

	if (c->status != 200 && c->status != 206)
		/* an error response's own body is not our business */
		return 1;

	/*
	 * Whatever the shape, a Content-Length we gave has to be the count
	 * of body bytes that actually arrived
	 */

	if (!cn->cl_valid) {
		/*
		 * h1 is framed by the Content-Length, so it must be there;
		 * a mux stream is framed by its own end, and lws does not
		 * send a Content-Length on one
		 */
		if (!c->h2) {
			lwsl_err("%s: no content-length\n", __func__);
			ok = 0;
		}
	} else
		if ((unsigned long long)cn->cl !=
					(unsigned long long)cn->body_len) {
			lwsl_err("%s: content-length %lld, but %u body bytes "
				 "arrived\n", __func__, cn->cl,
				 (unsigned int)cn->body_len);
			ok = 0;
		}

	if (strcmp(cn->ar, "bytes")) {
		lwsl_err("%s: accept-ranges '%s', expected 'bytes'\n",
			 __func__, cn->ar);
		ok = 0;
	}

	if (c->status == 200) {
		/* the whole file, and no Content-Range at all */

		if (cn->cr[0]) {
			lwsl_err("%s: 200 carries content-range '%s'\n",
				 __func__, cn->cr);
			ok = 0;
		}
		if (strcmp(cn->ct, octet)) {
			lwsl_err("%s: content-type '%s', expected '%s'\n",
				 __func__, cn->ct, octet);
			ok = 0;
		}
		if (cn->body_len != file_len[c->file]) {
			lwsl_err("%s: %u body bytes, expected %u\n", __func__,
				 (unsigned int)cn->body_len,
				 (unsigned int)file_len[c->file]);

			return 0;
		}
		bad = cmp_pat(cn->body, cn->body_len, 0);
		if (bad >= 0) {
			lwsl_err("%s: body differs at +%lld\n", __func__, bad);
			ok = 0;
		}

		return ok;
	}

	if (nexp == 1) {
		unsigned long long amount = exp[0].end - exp[0].start + 1;

		lws_snprintf(want, sizeof(want), "bytes %llu-%llu/%llu",
			     exp[0].start, exp[0].end, extent);
		if (strcmp(cn->cr, want)) {
			lwsl_err("%s: content-range '%s', expected '%s'\n",
				 __func__, cn->cr, want);
			ok = 0;
		}
		if (strcmp(cn->ct, octet)) {
			lwsl_err("%s: content-type '%s', expected '%s'\n",
				 __func__, cn->ct, octet);
			ok = 0;
		}
		if ((unsigned long long)cn->body_len != amount) {
			lwsl_err("%s: %u body bytes, expected %llu\n",
				 __func__, (unsigned int)cn->body_len, amount);

			return 0;
		}
		bad = cmp_pat(cn->body, cn->body_len, exp[0].start);
		if (bad >= 0) {
			lwsl_err("%s: body differs at +%lld (file offset "
				 "%llu)\n", __func__, bad,
				 exp[0].start + (unsigned long long)bad);
			ok = 0;
		}

		return ok;
	}

	/* multipart: a whole-response Content-Range would be wrong */

	if (cn->cr[0]) {
		lwsl_err("%s: multipart carries content-range '%s'\n",
			 __func__, cn->cr);
		ok = 0;
	}

	if (check_multipart(cn->ct, cn->body, cn->body_len, exp, nexp, extent))
		ok = 0;

	return ok;
}

static void
conn_finish(struct conn *cn, const struct xcase *c, int completed)
{
	int ok;

	if (cn->completed)
		return;
	cn->completed = 1;

	if (!completed) {
		lwsl_err("%s: connection closed before completion (%u body "
			 "bytes of a promised %lld)\n", __func__,
			 (unsigned int)cn->body_len,
			 cn->cl_valid ? cn->cl : -1);
		ok = 0;
	} else
		ok = verify(c, cn) && !cn->failed;

	lwsl_user("%s: case %d: %s: %s\n", __func__, cur, c->name,
		  ok ? "PASS" : "FAIL");

	if (!ok)
		failures++;

	lws_sul_schedule(context, 0, &sul_next, next_case, LWS_US_PER_MS);
}

static int
conn_rx(struct conn *cn, const uint8_t *in, size_t len)
{
	if (cn->body_len + len > cn->body_max) {
		size_t ns = (cn->body_len + len) * 2;
		uint8_t *nb = realloc(cn->body, ns);

		if (!nb)
			return 1;

		cn->body = nb;
		cn->body_max = ns;
	}

	memcpy(cn->body + cn->body_len, in, len);
	cn->body_len += len;

	return 0;
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	struct conn *cn = (struct conn *)lws_get_opaque_user_data(wsi);
	const struct xcase *c = cur >= 0 ? &cases[cur] : NULL;
	char buf[1024];
	char *px = buf;
	int lenx = sizeof(buf);

	switch (reason) {
	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER: {
		unsigned char **p = (unsigned char **)in, *end = (*p) + len;
		const char *r;

		if (!c)
			break;

		r = case_range(c);
		if (r && lws_add_http_header_by_token(wsi,
					WSI_TOKEN_HTTP_RANGE,
					(unsigned char *)r, (int)strlen(r),
					p, end))
			return -1;

		if (c->if_range_etag)
			r = etag;
		else
			r = c->if_range;

		if (r && r[0] && lws_add_http_header_by_token(wsi,
					WSI_TOKEN_HTTP_IF_RANGE,
					(unsigned char *)r, (int)strlen(r),
					p, end))
			return -1;
		break;
	}

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: connection error: %s\n", __func__,
			 in ? (const char *)in : "(null)");
		if (cn && c) {
			cn->failed = 1;
			conn_finish(cn, c, 0);
		}
		break;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		if (!cn || !c)
			break;

		cn->status = (int)lws_http_client_http_response(wsi);
		lws_hdr_copy(wsi, cn->ct, sizeof(cn->ct),
			     WSI_TOKEN_HTTP_CONTENT_TYPE);
		lws_hdr_copy(wsi, cn->cr, sizeof(cn->cr),
			     WSI_TOKEN_HTTP_CONTENT_RANGE);
		lws_hdr_copy(wsi, cn->ar, sizeof(cn->ar),
			     WSI_TOKEN_HTTP_ACCEPT_RANGES);

		if (lws_hdr_copy(wsi, buf, sizeof(buf),
				 WSI_TOKEN_HTTP_CONTENT_LENGTH) > 0) {
			cn->cl = atoll(buf);
			cn->cl_valid = 1;
		}

		/*
		 * The first case is the plain GET whose etag the If-Range
		 * cases quote back
		 */
		if (!etag[0])
			lws_hdr_copy(wsi, etag, sizeof(etag),
				     WSI_TOKEN_HTTP_ETAG);

		lwsl_info("%s: status %d, ct '%s', cr '%s', cl %lld\n",
			  __func__, cn->status, cn->ct, cn->cr,
			  cn->cl_valid ? cn->cl : -1);
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		if (!cn || cn->completed)
			break;
		if (conn_rx(cn, (const uint8_t *)in, len)) {
			cn->failed = 1;

			return -1;
		}
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;
		break;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		if (cn && c)
			conn_finish(cn, c, 1);
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		if (cn && c)
			/*
			 * An error response's body has no framing of its own
			 * to end on, so for those the close is the completion
			 */
			conn_finish(cn, c, c->status != 200 &&
					   c->status != 206);
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static void
next_case(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;
	const struct xcase *c;
	char upath[96];

	if (only_case >= 0 && cur >= 0)
		cur = (int)LWS_ARRAY_SIZE(cases) - 1;
	cur++;
	if (only_case >= 0 && cur < (int)LWS_ARRAY_SIZE(cases))
		cur = only_case;

	if (cur >= (int)LWS_ARRAY_SIZE(cases)) {
		interrupted = 1;
		lws_cancel_service(context);

		return;
	}
	c = &cases[cur];

	lwsl_user("--- case %d: %s ---\n", cur, c->name);

	free(conn.body);
	memset(&conn, 0, sizeof(conn));

	lws_snprintf(upath, sizeof(upath), "/%s", file_name[c->file]);

	memset(&i, 0, sizeof(i));
	i.context = context;
	i.vhost = vh_cli;
	i.address = server_addr;
	i.host = server_addr;
	i.origin = server_addr;
	i.port = c->h2 ? port_h2 : port_h1;
#if defined(LWS_WITH_HTTP2)
	if (c->h2)
		i.ssl_connection = LCCSCF_H2_PRIOR_KNOWLEDGE;
#endif
	i.path = upath;
	i.method = "GET";
	i.protocol = "http-ranges";
	i.opaque_user_data = &conn;

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("%s: connect failed\n", __func__);
		conn.completed = 1;
		failures++;
		lws_sul_schedule(context, 0, &sul_next, next_case,
				 LWS_US_PER_MS);
	}
}

static void
watchdog(lws_sorted_usec_list_t *sul)
{
	lwsl_err("%s: test timed out in case %d\n", __func__, cur);
	failures++;
	interrupted = 1;
	lws_cancel_service(context);
}

static void
sigint_handler(int sig)
{
	interrupted = 1;
}

static const struct lws_protocols protocols_srv[] = {
	{ "http", lws_callback_http_dummy, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_cli[] = {
	{ "http-ranges", callback_cli, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static struct lws_http_mount mount = {
	.mountpoint		= "/",
	.origin_protocol	= LWSMPRO_FILE,
	.mountpoint_len		= 1,
};

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	int logs = LLL_USER | LLL_ERR | LLL_WARN;
	struct lws_vhost *vh;
	const char *p;
	int result = 1;

	signal(SIGINT, sigint_handler);

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);
	lws_set_log_level(logs, NULL);

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port_h1 = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--h2-port")))
		port_h2 = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--tmpdir")))
		tmpbase = p;
	if ((p = lws_cmdline_option(argc, argv, "--case")))
		only_case = atoi(p);
	/*
	 * The producer composes the part header, the payload and the close
	 * delimiter into the pt serv_buf, so how big it is decides how much
	 * of a part one write carries.  A small one puts the framing right
	 * up against the end of the buffer on every write.
	 */
	if ((p = lws_cmdline_option(argc, argv, "--serv-buf")))
		serv_buf_size = (unsigned int)atoi(p);

	lwsl_user("LWS API selftest: http file ranges\n");

	if (generate_files())
		goto bail_files;

	mount.origin = tmpdir;

	lws_context_info_defaults(&info, NULL);
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
	/*
	 * The default fd budget is sized for a lone client; we have the
	 * listen sockets of two server vhosts, v4 and v6, as well
	 */
	info.fd_limit_per_thread = 0;
	info.pt_serv_buf_size = serv_buf_size;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		goto bail_files;
	}

	info.port = port_h1;
	info.vhost_name = "srv-h1";
	info.protocols = protocols_srv;
	info.mounts = &mount;
	vh = lws_create_vhost(context, &info);
	if (!vh) {
		lwsl_err("Failed to create h1 server vhost\n");
		goto bail;
	}

#if defined(LWS_WITH_HTTP2)
	info.port = port_h2;
	info.vhost_name = "srv-h2";
	info.options |= LWS_SERVER_OPTION_H2_PRIOR_KNOWLEDGE;
	vh = lws_create_vhost(context, &info);
	if (!vh) {
		lwsl_err("Failed to create h2 server vhost\n");
		goto bail;
	}
	info.options &= ~(uint64_t)LWS_SERVER_OPTION_H2_PRIOR_KNOWLEDGE;
#endif

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.vhost_name = "cli";
	info.protocols = protocols_cli;
	info.mounts = NULL;
	vh_cli = lws_create_vhost(context, &info);
	if (!vh_cli) {
		lwsl_err("Failed to create client vhost\n");
		goto bail;
	}

	lws_sul_schedule(context, 0, &sul_watchdog, watchdog,
			 300 * LWS_US_PER_SEC);
	lws_sul_schedule(context, 0, &sul_next, next_case, LWS_US_PER_MS);

	while (!interrupted && lws_service(context, 0) >= 0)
		;

	result = failures ? 1 : 0;

	lwsl_user("Completed: %s (%d cases, %d failures)\n",
		  result ? "FAIL" : "PASS", (int)LWS_ARRAY_SIZE(cases),
		  failures);

bail:
	lws_sul_cancel(&sul_watchdog);
	lws_sul_cancel(&sul_next);
	lws_context_destroy(context);
	free(conn.body);
bail_files:
	cleanup_files();

	return result;
}
