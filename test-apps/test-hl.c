/*
 * lws-hl test app
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Exercises the streaming syntax highlighter:
 *
 *  - golden token streams for tricky C constructs
 *  - fragmentation invariance: identical token streams whatever the input
 *    fragment sizes (including 0 and 1)
 *  - byte conservation: every input byte classified into exactly one token
 *  - token sink flow control: deferring pieces at arbitrary points then
 *    resuming produces the same stream
 *  - html emitter escaping and span balance
 */

#include <libwebsockets.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_STREAM			  65536

struct capture {
	char		buf[MAX_STREAM];
	size_t		len;
	lws_hl_class_t last;
	/* flow-control budget: defer pieces once used up */
	size_t		budget;
	int		defer_enabled;
};

static char cls_char(lws_hl_class_t cls)
{
	switch (cls) {
	case LHL_CLS_PLAIN:	return 'P';
	case LHL_CLS_IDENT:	return 'I';
	case LHL_CLS_KEYWORD:	return 'K';
	case LHL_CLS_TYPE:	return 'T';
	case LHL_CLS_NUMBER:	return 'N';
	case LHL_CLS_STRING:	return 'S';
	case LHL_CLS_CHARLIT:	return 'C';
	case LHL_CLS_COMMENT:	return 'M';
	case LHL_CLS_PREPROC:	return 'X';
	case LHL_CLS_DIFF_ADD:	return 'a';
	case LHL_CLS_DIFF_REM:	return 'r';
	case LHL_CLS_DIFF_HUNK:	return 'h';
	case LHL_CLS_DIFF_META:	return 'm';
	default:		return '?';
	}
}

static lws_stateful_ret_t
capture_cb(void *user, lws_hl_class_t cls, const uint8_t *tok, size_t len)
{
	struct capture *cap = (struct capture *)user;

	if (cap->defer_enabled && !cap->budget)
		return LWS_SRET_WANT_OUTPUT;

	if (cap->defer_enabled)
		cap->budget--;

	if (cap->len + len + 8 >= sizeof(cap->buf))
		return LWS_SRET_FATAL;

	if (cls != cap->last) {
		cap->buf[cap->len++] = cls_char(cls);
		cap->buf[cap->len++] = ':';
		cap->last = cls;
	}

	memcpy(cap->buf + cap->len, tok, len);
	cap->len += len;
	cap->buf[cap->len] = '\0';

	return LWS_SRET_OK;
}

static void
capture_reset(struct capture *cap)
{
	cap->len = 0;
	cap->last = LHL_CLS_COUNT;
	cap->budget = 0;
	cap->defer_enabled = 0;
}

static int
run_whole(const lws_hl_ops_t *ops, const uint8_t *in, size_t in_len,
	  struct capture *cap)
{
	lws_hl_ctx_t ctx;

	capture_reset(cap);

	if (lws_hl_construct(&ctx, ops, capture_cb, cap))
		return 1;

	while (in_len) {
		size_t was = in_len;

		if (lws_hl_parse(&ctx, &in, &in_len))
			return 2;
		if (in_len == was)
			break;	/* held decision byte... finish resolves */
	}

	if (lws_hl_finish(&ctx))
		return 3;

	return 0;
}

static uint32_t
xs32(uint32_t *seed)
{
	*seed ^= *seed << 13;
	*seed ^= *seed >> 17;
	*seed ^= *seed << 5;

	return *seed;
}

/*
 * Feed the same input in randomly-sized fragments (0..4 bytes) including
 * zero-length fragments; the merged token stream must be identical.
 */

static int
run_fragmented(const lws_hl_ops_t *ops, const uint8_t *in, size_t in_len,
	       uint32_t seed, struct capture *cap)
{
	lws_hl_ctx_t ctx;
	size_t done = 0, minl = 1;

	capture_reset(cap);

	if (lws_hl_construct(&ctx, ops, capture_cb, cap))
		return 1;

	while (done < in_len) {
		const uint8_t *p;
		size_t l;
		uint32_t r = xs32(&seed);
		size_t before = done;

		/* sometimes poke it with a zero-length fragment */
		if (r & 1) {
			p = in + done;
			l = 0;
			if (lws_hl_parse(&ctx, &p, &l))
				return 2;
		}

		l = minl + (r >> 1) % 4;
		if (l > in_len - done)
			l = in_len - done;

		p = in + done;
		while (l) {
			size_t was2 = l;

			if (lws_hl_parse(&ctx, &p, &l))
				return 3;
			done += was2 - l;
			if (l == was2)
				break;	/* held byte... more input decides */
		}
		if (done == before) {
			/* no progress at all... only legal for a final held
			 * byte, otherwise force a bigger fragment past it */
			if (in_len - done <= 1)
				break;
			minl = 2;
		} else
			minl = 1;
	}

	if (lws_hl_finish(&ctx))
		return 4;

	return 0;
}

/*
 * Run with a token sink that defers after a budget, then resumes; the merged
 * stream must match the unconstrained one.  This exercises restartable
 * pieces, held decision bytes and scratch retention.
 */

static int
run_deferred(const lws_hl_ops_t *ops, const uint8_t *in, size_t in_len,
	     size_t budget, struct capture *cap)
{
	lws_hl_ctx_t ctx;
	const uint8_t *p = in;
	size_t l = in_len;
	int n = 0;

	capture_reset(cap);
	cap->defer_enabled = 1;
	cap->budget = budget;

	if (lws_hl_construct(&ctx, ops, capture_cb, cap))
		return 1;

	while (l) {
		size_t was = l;
		lws_stateful_ret_t ret = lws_hl_parse(&ctx, &p, &l);

		if (ret == LWS_SRET_WANT_OUTPUT) {
			if (++n > 100000)
				return 2;
			cap->budget = 1 + (size_t)(n & 7); /* sink recovers */
			continue;
		}
		if (ret)
			return 2;
		if (l == was)
			break;	/* held decision byte... finish resolves */
	}

	n = 0;
	while (lws_hl_finish(&ctx) == LWS_SRET_WANT_OUTPUT) {
		if (++n > 100000)
			return 3;
		cap->budget = 1 + (size_t)(n & 7); /* sink recovers */
	}

	cap->defer_enabled = 0;

	return 0;
}

struct golden {
	const char	*name;
	const char	*in;
	const char	*expect;
};

/*
 * Expected streams are in the merged capture format: "X:" then the token
 * bytes for each class change, consecutive same-class pieces merged with no
 * separator.
 */

static const struct golden goldens[] = {

	{ "simple-decl",
	  "int main(void) { return 0; }\n",
	  "T:intP: I:mainP:(T:voidP:) { K:returnP: N:0P:; }\n" },

	{ "include-angle",
	  "#include <stdio.h>\n",
	  "X:#includeP: X:<stdio.h>P:\n" },

	{ "include-quote",
	  "#  include \"../x.h\"\n",
	  "X:#  includeP: S:\"../x.h\"P:\n" },

	{ "define",
	  "#define FOO(x) ((x) + 1)",
	  "X:#defineP: I:FOOP:(I:xP:) ((I:xP:) + N:1P:)" },

	{ "string-charlit",
	  "printf(\"hi\\n\", 'a');",
	  "I:printfP:(S:\"hi\\n\"P:, C:'a'P:);" },

	{ "comments",
	  "a /* c */ b // x\ny",
	  "I:aP: M:/* c */P: I:bP: M:// xP:\nI:y" },

	{ "comment-after-newline-hash",
	  "/* c\n*/ #define X 1\n",
	  "M:/* c\n*/P: X:#defineP: I:XP: N:1P:\n" },

	{ "hash-not-at-bol",
	  "x = a # b\n",
	  "I:xP: = I:aP: # I:bP:\n" },

	{ "division-not-comment",
	  "a / b / c",
	  "I:aP: / I:bP: / I:c" },

	{ "pp-number-munch",
	  "0x1e+2-x 1.5f .5 1'000",
	  "N:0x1e+2P:-I:xP: N:1.5fP: N:.5P: N:1'000" },

	{ "stray-dots",
	  "a..b .\n",
	  "I:aP:..I:bP: .\n" },

	{ "unterminated-string",
	  "\"abc\nx",
	  "S:\"abcP:\nI:x" },

	{ "unterminated-block-comment",
	  "x /* rest\nof it",
	  "I:xP: M:/* rest\nof it" },

	{ "line-splice-pp",
	  "#define A 1 \\\n 2\n",
	  "X:#defineP: I:AP: N:1P: \\\n N:2P:\n" },

	{ "line-splice-comment",
	  "// split \\\n still comment\n",
	  "M:// split \\\n still commentP:\n" },

	{ "string-splice",
	  "\"a\\\nb\" c",
	  "S:\"a\\\nb\"P: I:c" },

	{ "escaped-quote",
	  "'\\'' \"a\\\"b\"",
	  "C:'\\''P: S:\"a\\\"b\"" },

	{ "null-directive",
	  "#\nint a;\n",
	  "X:#P:\nT:intP: I:aP:;\n" },

	{ "null-directive-ws",
	  "#  \nx\n",
	  "X:#  P:\nI:xP:\n" },

	{ "pp-if",
	  "#if defined(A) && B > 3\n#endif\n",
	  "X:#ifP: I:definedP:(I:AP:) && I:BP: > N:3P:\nX:#endifP:\n" },

	{ "splices-are-not-directives",
	  "x = 1 \\\n+ 2 # not a directive\n",
	  "I:xP: = N:1P: \\\n+ N:2P: # I:notP: I:aP: I:directiveP:\n" },

	{ "trailing-slash",
	  "a /",
	  "I:aP: /" },

	{ "long-ident",
	  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;",
	  "I:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaP:;" },

	{ "long-string",
	  "\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\" x",
	  "S:\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"P: I:x" },

	{ "keywords-c23",
	  "constexpr bool b = nullptr;",
	  "K:constexprP: T:boolP: I:bP: = K:nullptrP:;" },

	{ "utf8-ident",
	  "caf\xc3\xa9_1 = 2;",
	  "I:caf\xc3\xa9_1P: = N:2P:;" },

	{ "control-bytes",
	  "a\x01" "\x02" "b",
	  "I:aP:\x01\x02I:b" },

	{ "mismatched-quotes",
	  "\"it's\" 'x\"y'",
	  "S:\"it's\"P: C:'x\"y'" },
};

#if defined(LWS_WITH_HL_LANG_DIFF)

/* diff goldens... same merged capture format, with a/r/h/m classes */

static const struct golden diff_goldens[] = {

	{ "diff-basic",
	  "diff --git a/x.c b/x.c\n"
	  "index 1234567..89abcde 100644\n"
	  "--- a/x.c\n"
	  "+++ b/x.c\n"
	  "@@ -10,7 +10,8 @@ fn(void)\n"
	  " context line\n"
	  "-removed line\n"
	  "+added line\n"
	  "+another added\n"
	  " more context\n",
	  "m:diff --git a/x.c b/x.c\n"
	  "index 1234567..89abcde 100644\n"
	  "--- a/x.c\n"
	  "+++ b/x.c\n"
	  "h:@@ -10,7 +10,8 @@ fn(void)\n"
	  "P: context line\n"
	  "r:-removed line\n"
	  "a:+added line\n+another added\n"
	  "P: more context\n" },

	{ "diff-marker-prefixes",
	  "++plus-start\n---minus-start\n+++ b/f\n",
	  "a:++plus-start\nr:---minus-start\nm:+++ b/f\n" },

	{ "diff-bound-eos",
	  "+++",
	  "m:+++" },

	{ "diff-at-holds",
	  "@x\n@",
	  "P:@x\n@" },

	{ "diff-hunk-eos",
	  "@@",
	  "h:@@" },

	{ "diff-no-newline",
	  "\\ No newline at end of file\n",
	  "m:\\ No newline at end of file\n" },

	{ "diff-word-nomatch",
	  "hello world\ndifferential\n",
	  "P:hello world\ndifferential\n" },

	{ "diff-word-eos",
	  "diff",
	  "m:diff" },

	{ "diff-word-overflow",
	  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
	  "P:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n" },

	{ "diff-empty-lines",
	  "\n\n",
	  "P:\n\n" },

	{ "diff-garbage-plain",
	  "1234\n!bang\n",
	  "P:1234\n!bang\n" },

	{ "diff-long-add",
	  "+" "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
	  "a:+aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n" },
};

#endif

static int
run_goldens(const struct golden *gtab, size_t gcount,
	    const lws_hl_ops_t *ops, const char *lang, struct capture *cap)
{
	size_t n;
	int bad = 0;

	for (n = 0; n < gcount; n++) {
		const struct golden *g = &gtab[n];
		uint32_t seed = 0x12345678u + (uint32_t)n;
		int ret, m;

		ret = run_whole(ops, (const uint8_t *)g->in, strlen(g->in), cap);
		if (ret) {
			fprintf(stderr, "FAIL(%s): run_whole %d\n", g->name, ret);
			bad++;
			continue;
		}
		if (strcmp(cap->buf, g->expect)) {
			fprintf(stderr, "FAIL(%s): golden mismatch\n"
					"  got:  %s\n  want: %s\n",
				g->name, cap->buf, g->expect);
			bad++;
			continue;
		}

		/*
		 * fragmentation invariance... arbitrary splits including
		 * zero-length pokes must produce the identical stream
		 */

		for (m = 0; m < 40; m++) {
			ret = run_fragmented(ops, (const uint8_t *)g->in,
					     strlen(g->in),
					     seed + (uint32_t)m * 17u, cap);
			if (ret) {
				fprintf(stderr, "FAIL(%s): fragmented %d\n",
					g->name, ret);
				bad++;
				break;
			}
			if (strcmp(cap->buf, g->expect)) {
				fprintf(stderr, "FAIL(%s): fragmented stream "
					"differs (round %d)\n  got:  %s\n"
					"  want: %s\n",
					g->name, m, cap->buf, g->expect);
				bad++;
				break;
			}
		}
		if (m != 40)
			continue;

		/*
		 * flow control... deferring at arbitrary piece boundaries
		 * and resuming must also produce the identical stream
		 */

		for (m = 0; m < 8; m++) {
			size_t budget = 1u << m;

			ret = run_deferred(ops, (const uint8_t *)g->in,
					   strlen(g->in), budget, cap);
			if (ret) {
				fprintf(stderr, "FAIL(%s): deferred %d\n",
					g->name, ret);
				bad++;
				break;
			}
			if (strcmp(cap->buf, g->expect)) {
				fprintf(stderr, "FAIL(%s): deferred stream "
					"differs (budget %zu)\n  got:  %s\n"
					"  want: %s\n",
					g->name, budget, cap->buf, g->expect);
				bad++;
				break;
			}
		}
	}

	if (!bad)
		fprintf(stderr, "test-hl: %zu %s goldens + fragmentation + "
			"flow control: PASS\n", gcount, lang);

	return bad;
}

static int
test_goldens(struct capture *cap)
{
	int bad = run_goldens(goldens, LWS_ARRAY_SIZE(goldens),
			      lws_hl_lang_c(), "c", cap);
#if defined(LWS_WITH_HL_LANG_DIFF)
	bad += run_goldens(diff_goldens, LWS_ARRAY_SIZE(diff_goldens),
			   lws_hl_lang_diff(), "diff", cap);
#endif

	return bad;
}

struct counter {
	size_t		bytes;
	size_t		tokens;
};

static lws_stateful_ret_t
count_cb(void *user, lws_hl_class_t cls, const uint8_t *tok, size_t len)
{
	struct counter *ct = (struct counter *)user;

	(void)cls; (void)tok;

	ct->bytes += len;
	ct->tokens++;

	return LWS_SRET_OK;
}

/*
 * Byte conservation on a real source file: every input byte must be
 * classified into exactly one token piece, whatever the fragmentation.
 */

static int
test_selffeed(void)
{
	const char *paths[] = { __FILE__, "test-apps/test-hl.c",
				"../test-apps/test-hl.c" };
	uint8_t *buf = malloc(1024 * 1024);
	size_t total = 0;
	FILE *f = NULL;
	size_t n, bad = 0;

	if (!buf)
		return 1;

	for (n = 0; n < LWS_ARRAY_SIZE(paths); n++) {
		f = fopen(paths[n], "rb");
		if (f)
			break;
	}
	if (!f) {
		free(buf);
		return 2;
	}

	total = fread(buf, 1, 1024 * 1024, f);
	fclose(f);

	for (n = 0; n < 16; n++) {
		lws_hl_ctx_t ctx;
		struct counter ct = { 0, 0 };
		const uint8_t *p = buf;
		size_t l = total, seed = 0xdeadbeefu + n, minl = 1;

		if (lws_hl_construct(&ctx, lws_hl_lang_c(), count_cb, &ct)) {
			bad++;
			break;
		}

		while (l) {
			const uint8_t *pp;
			size_t wl;
			const uint8_t *p_was = p;

			seed = seed * 1103515245 + 12345;
			wl = minl + (seed >> 16) % 136;
			if (wl > l)
				wl = l;

			pp = p;
			while (wl) {
				size_t was2 = wl;

				if (lws_hl_parse(&ctx, &pp, &wl)) {
					bad++;
					break;
				}
				p += was2 - wl;
				if (wl == was2)
					break; /* held byte... re-feed with more */
			}
			if (bad)
				break;

			if (p == p_was) {
				/* no progress: only legal for a final held
				 * byte, otherwise force a bigger fragment */
				if (l <= 1)
					break;
				minl = 2;
			} else
				minl = 1;

			l = (size_t)(buf + total - p);
		}

		if (!bad && lws_hl_finish(&ctx))
			bad++;

		if (!bad && (ct.bytes != total || ct.tokens < 500)) {
			fprintf(stderr, "test-hl: selffeed round %zu: "
				"%zu bytes in, %zu bytes classified in "
				"%zu pieces\n", n, total, ct.bytes,
				ct.tokens);
			bad++;
		}
		if (bad)
			break;
	}

	free(buf);

	if (!bad)
		fprintf(stderr, "test-hl: selffeed (%zu bytes, 16 fragmentations)"
			": PASS\n", total);

	return (int)bad;
}

struct htmlcap {
	char		buf[MAX_STREAM];
	size_t		len;
};

static lws_stateful_ret_t
html_write(void *user, const uint8_t *buf, size_t len)
{
	struct htmlcap *h = (struct htmlcap *)user;

	if (h->len + len >= sizeof(h->buf))
		return LWS_SRET_FATAL;

	memcpy(h->buf + h->len, buf, len);
	h->len += len;

	return LWS_SRET_OK;
}

/*
 * The output must only contain markup we issued: outside of our span tags,
 * there can be no raw '<', '>' or unescaped '&'.
 */

static int
html_check(const char *name, const char *html)
{
	const char *p = html;
	int open_spans = 0, bad = 0;

	while (*p) {
		if (!strncmp(p, "<span class=\"", 13)) {
			open_spans++;
			p = strchr(p + 13, '>');
			if (!p) {
				bad++;
				break;
			}
			p++;
			continue;
		}
		if (!strncmp(p, "</span>", 7)) {
			if (!open_spans) {
				bad++;
				break;
			}
			open_spans--;
			p += 7;
			continue;
		}
		if (*p == '<' || *p == '>') {
			bad++;
			break;
		}
		if (*p == '&') {
			if (strncmp(p, "&lt;", 4) && strncmp(p, "&gt;", 4) &&
			    strncmp(p, "&amp;", 5) &&
			    strncmp(p, "&#65533;", 8)) {
				bad++;
				break;
			}
			p += (p[1] == 'l' || p[1] == 'g') ? 4 :
			     (p[1] == 'a') ? 5 : 8;
			continue;
		}
		p++;
	}

	if (bad || open_spans) {
		fprintf(stderr, "FAIL(html:%s): unbalanced or unsafe markup\n"
				"  %s\n", name, html);
		return 1;
	}

	return 0;
}

static int
test_html(void)
{
	/* explicit lengths, so embedded NULs are included */
	static const uint8_t in0[] = "char *s = \"a<b&c\";\n";
	static const uint8_t in1[] = "#include <stdio.h>\nint x = a & b;\n";
	static const uint8_t in2[] = "/* a < b && c > d */\n";
	static const uint8_t in3[] = "\"unterminated\x00 \x01str\" x";
#if defined(LWS_WITH_HL_LANG_DIFF)
	static const uint8_t in4[] = "@@ -1 +1 @@\n-old & <x>\n+new & <y>\n";
#endif
	const struct {
		const uint8_t			*data;
		size_t				len;
		const lws_hl_ops_t		*(*ops)(void);
	} inputs[] = {
		{ in0, sizeof(in0) - 1, lws_hl_lang_c },
		{ in1, sizeof(in1) - 1, lws_hl_lang_c },
		{ in2, sizeof(in2) - 1, lws_hl_lang_c },
		{ in3, sizeof(in3) - 1, lws_hl_lang_c },
#if defined(LWS_WITH_HL_LANG_DIFF)
		{ in4, sizeof(in4) - 1, lws_hl_lang_diff },
#endif
	};
	struct htmlcap h;
	size_t n;
	int bad = 0, saw_replacement = 0;

	for (n = 0; n < LWS_ARRAY_SIZE(inputs); n++) {
		lws_hl_ctx_t ctx;
		lws_hl_html_t html;
		const uint8_t *p = inputs[n].data;
		size_t l = inputs[n].len;

		h.len = 0;
		h.buf[0] = '\0';

		if (lws_hl_html_construct(&html, html_write, &h, NULL) ||
		    lws_hl_construct(&ctx, inputs[n].ops(),
				     lws_hl_html_token, &html)) {
			bad++;
			continue;
		}

		while (l) {
			size_t was = l;

			if (lws_hl_parse(&ctx, &p, &l)) {
				bad++;
				break;
			}
			if (l == was)
				break;	/* held decision byte... finish */
		}
		if (!bad && (lws_hl_finish(&ctx) ||
			     lws_hl_html_close(&html)))
			bad++;

		h.buf[h.len] = '\0';
		if (strstr(h.buf, "&#65533;"))
			saw_replacement = 1;
		if (html_check("input", h.buf))
			bad++;
#if defined(LWS_WITH_HL_LANG_DIFF)
		if (inputs[n].ops == lws_hl_lang_diff &&
		    (!strstr(h.buf, "hl-dh") || !strstr(h.buf, "hl-dr") ||
		     !strstr(h.buf, "hl-da") ||
		     strstr(h.buf, "<x>"))) {
			fprintf(stderr, "FAIL(html): diff spans missing\n"
					"  %s\n", h.buf);
			bad++;
		}
#endif
	}

	if (!saw_replacement) {
		/* the NUL and \x01 in the last input must be replaced */
		fprintf(stderr, "FAIL(html): control bytes not replaced\n");
		bad++;
	}

	if (!bad)
		fprintf(stderr, "test-hl: html emitter: PASS\n");

	return bad;
}

static int
test_escape(void)
{
	struct htmlcap h;
	static const char in[] = "a<b>c&d\x00";
	char expect[128];
	lws_stateful_ret_t r;
	int bad = 0;

	h.len = 0;
	r = lws_html_escape(html_write, &h, (const uint8_t *)in,
			    sizeof(in) - 1);
	h.buf[h.len] = '\0';

	(void)lws_snprintf(expect, sizeof(expect),
			  "a&lt;b&gt;c&amp;d&#65533;");

	if (r || strcmp(h.buf, expect)) {
		fprintf(stderr, "FAIL(escape): got %s want %s\n", h.buf, expect);
		bad++;
	}

	if (!bad)
		fprintf(stderr, "test-hl: escaper: PASS\n");

	return bad;
}

/*
 * Hostile input: pseudo-random garbage (biased to syntax bytes) must
 * tokenize without losing or duplicating a byte, and identically under any
 * fragmentation or deferral pattern.
 */

static int
test_hostile(struct capture *cap)
{
	static const uint8_t syntax[] = "\"'\\/?#<>._+-eEpP0189abcxyzZ_\n\t\r ";
	static uint8_t buf[3072];
	const lws_hl_ops_t *langs[] = {
		lws_hl_lang_c(),
#if defined(LWS_WITH_HL_LANG_DIFF)
		lws_hl_lang_diff(),
#endif
	};
	size_t nl, bad = 0;

	for (nl = 0; nl < LWS_ARRAY_SIZE(langs); nl++) {
	  uint32_t seed = 0xcafebabeu;
	  char whole[MAX_STREAM];
	  size_t round;

	  for (round = 0; round < 24; round++) {
		size_t n, len = 512 + xs32(&seed) % (sizeof(buf) - 512);
		lws_hl_ctx_t ctx;
		struct counter ct = { 0, 0 };
		const uint8_t *p = buf;
		int m, ret;

		for (n = 0; n < len; n++)
			buf[n] = (xs32(&seed) & 3) ?
				syntax[xs32(&seed) % (sizeof(syntax) - 1)] :
				(uint8_t)xs32(&seed);

		/* byte conservation on the whole input */

		if (lws_hl_construct(&ctx, langs[nl], count_cb, &ct)) {
			bad++;
			break;
		}
		while (p - buf < (ptrdiff_t)len) {
			const uint8_t *pp = p;
			size_t l = (size_t)(buf + len - p), was = l;

			while (l) {
				size_t was2 = l;

				if (lws_hl_parse(&ctx, &pp, &l)) {
					bad++;
					break;
				}
				p += was2 - l;
				if (l == was2)
					break;
			}
			if (bad || l == was)
				break;
		}
		if (!bad && lws_hl_finish(&ctx))
			bad++;
		if (!bad && ct.bytes != len) {
			fprintf(stderr, "test-hl: hostile %s round %zu: %zu "
				"of %zu bytes classified\n",
				langs[nl]->name, round, ct.bytes, len);
			bad++;
		}
		if (bad)
			break;

		/* identical stream under any feeding pattern */

		ret = run_whole(langs[nl], buf, len, cap);
		if (ret) {
			fprintf(stderr, "FAIL(hostile %s %zu): whole %d\n",
				langs[nl]->name, round, ret);
			bad++;
			break;
		}
		lws_strncpy(whole, cap->buf, sizeof(whole));

		for (m = 0; m < 8 && !bad; m++) {
			ret = run_fragmented(langs[nl], buf, len,
					      seed + (uint32_t)m * 31u,
					      cap);
			if (ret || strcmp(cap->buf, whole)) {
				fprintf(stderr, "FAIL(hostile %s %zu): "
					"fragmented differs (%d)\n",
					langs[nl]->name, round, ret);
				bad++;
			}
		}
		for (m = 0; m < 3 && !bad; m++) {
			ret = run_deferred(langs[nl], buf, len,
					   (size_t)1 << m, cap);
			if (ret || strcmp(cap->buf, whole)) {
				fprintf(stderr, "FAIL(hostile %s %zu): "
					"deferred differs (%d)\n",
					langs[nl]->name, round, ret);
				bad++;
			}
		}
		if (bad)
			break;
	  }
	  if (bad)
		  break;
	}

	if (!bad)
		fprintf(stderr, "test-hl: hostile garbage rounds: PASS\n");

	return (int)bad;
}

int
main(int argc, char *argv[])
{
	struct capture cap;
	int bad = 0;

	(void)argc; (void)argv;

	bad += test_goldens(&cap);
	bad += test_selffeed();
	bad += test_hostile(&cap);
	bad += test_html();
	bad += test_escape();

	if (bad) {
		fprintf(stderr, "test-hl: %d failures\n", bad);
		return 1;
	}

	fprintf(stderr, "test-hl: ALL PASS\n");

	return 0;
}
