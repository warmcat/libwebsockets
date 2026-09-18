/*
 * lws-md test app
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Exercises the streaming markdown renderer:
 *
 *  - golden html for the markdown subset, including hostile constructs
 *  - fragmentation invariance: identical html whatever the input fragment
 *    sizes (including 0 and 1)
 *  - event sink flow control: deferring events at arbitrary points then
 *    resuming produces the same html
 *  - structural validation: balanced tags, no raw markup from the input
 *  - hostile garbage rounds through the stock html sink
 *  - the lws-hl bridge for fenced code with a known info string
 */

#include <libwebsockets.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_STREAM			  262144

struct htmlcap {
	char		buf[MAX_STREAM];
	size_t		len;
	/* flow-control budget: defer writes once used up */
	size_t		budget;
	int		defer_enabled;
};

static lws_stateful_ret_t
html_write(void *user, const uint8_t *buf, size_t len)
{
	struct htmlcap *h = (struct htmlcap *)user;

	if (h->defer_enabled && !h->budget)
		return LWS_SRET_WANT_OUTPUT;

	if (h->defer_enabled)
		h->budget--;

	if (h->len + len >= sizeof(h->buf))
		return LWS_SRET_FATAL;

	memcpy(h->buf + h->len, buf, len);
	h->len += len;
	h->buf[h->len] = '\0';

	return LWS_SRET_OK;
}

static void
capture_reset(struct htmlcap *h)
{
	h->len = 0;
	h->buf[0] = '\0';
	h->budget = 0;
	h->defer_enabled = 0;
}

/*
 * Run the stock html sink over the input and finish.  A context pair is
 * big; keep them static.
 */

static lws_md_ctx_t ctx_static;
static lws_md_html_t html_static;
static struct htmlcap cap_static;

/* when set, the sink gets this repo-relative url resolver */

static lws_md_resolve_cb test_resolve;

static int
run_md(const uint8_t *in, size_t in_len, struct htmlcap *h, int deferred,
       size_t budget)
{
	const uint8_t *p = in;
	size_t l = in_len;
	int n = 0;

	capture_reset(h);

	if (lws_md_html_construct(&html_static, html_write, h,
				      test_resolve, NULL) ||
	    lws_md_construct(&ctx_static, lws_md_html_event, &html_static))
		return 1;

	if (deferred) {
		h->defer_enabled = 1;
		h->budget = budget;
	}

	while (l) {
		size_t was = l;
		lws_stateful_ret_t ret = lws_md_parse(&ctx_static, &p, &l);

		if (ret == LWS_SRET_WANT_OUTPUT) {
			if (++n > 1000000)
				return 2;
			h->budget = 1 + (size_t)(n & 15); /* sink recovers */
			continue;
		}
		if (ret)
			return 2;
		if (l == was) {
			/* nothing consumed: only legal for a held CR at the
			 * very end of input, which finish strips anyway */

			p++;
			l--;
		}
	}

	n = 0;
	while (lws_md_finish(&ctx_static) == LWS_SRET_WANT_OUTPUT) {
		if (++n > 1000000)
			return 3;
		h->budget = 1 + (size_t)(n & 15);
	}

	n = 0;
	while (lws_md_html_close(&html_static) == LWS_SRET_WANT_OUTPUT) {
		if (++n > 1000000)
			return 4;
		h->budget = 1 + (size_t)(n & 15);
	}

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

/* feed the same input in randomly-sized fragments including zero-length */

static int
run_fragmented(const uint8_t *in, size_t in_len, uint32_t seed,
	       struct htmlcap *h)
{
	size_t done = 0, stuck = 0;

	capture_reset(h);

	if (lws_md_html_construct(&html_static, html_write, h,
				      test_resolve, NULL) ||
	    lws_md_construct(&ctx_static, lws_md_html_event, &html_static))
		return 1;

	while (done < in_len) {
		const uint8_t *pp;
		size_t l, before = done;
		uint32_t r = xs32(&seed);

		/* sometimes poke it with a zero-length fragment */

		if (r & 1) {
			pp = in + done;
			l = 0;
			if (lws_md_parse(&ctx_static, &pp, &l))
				return 2;
		}

		l = 1 + (r >> 1) % 5;
		if (l > in_len - done)
			l = in_len - done;

		pp = in + done;
		while (l) {
			size_t was = l;

			if (lws_md_parse(&ctx_static, &pp, &l))
				return 3;
			done = (size_t)(pp - in);
			if (l == was)
				break;	/* held byte joins the next fragment */
		}

		if (done == before) {
			/*
			 * No progress at all: only legal when everything
			 * left is a final held byte; finish decides it.
			 */
			if (++stuck > 2 || in_len - done > 1)
				return 5;
			done = in_len;
		} else
			stuck = 0;
	}

	if (lws_md_finish(&ctx_static))
		return 4;

	if (lws_md_html_close(&html_static))
		return 5;

	return 0;
}

/*
 * Structural validation: tags from the closed set must balance, void
 * elements aside, and outside of tags there can be no raw '<' or '>' and
 * '&' only as our entities.
 */

static int
html_check(const char *name, const char *html)
{
	static const char * const known[] = {
		"p", "h1", "h2", "h3", "h4", "h5", "h6", "blockquote",
		"ul", "ol", "li", "table", "tr", "th", "td", "pre", "code",
		"em", "strong", "a", "span",
	};
	static const char * const voids[] = { "hr", "img" };
	const char *p = html;
	int stack[128];
	int depth = 0, bad = 0;
	char tag[16];

	while (*p) {
		if (*p == '<') {
			const char *e = strchr(p, '>');
			size_t tl;
			int is_close = 0, m, idx = -1, is_void = 0;

			if (!e) {
				bad++;
				break;
			}

			{
				const char *ts = p + 1 + (p[1] == '/');

				is_close = (p[1] == '/');

				/* just the element name, not the attributes */

				while (ts < e && *ts != ' ' && *ts != '\t')
					ts++;
				tl = (size_t)(ts - (p + 1 + is_close));
				if (tl > sizeof(tag) - 1)
					tl = sizeof(tag) - 1;
				memcpy(tag, p + 1 + is_close, tl);
				tag[tl] = '\0';
			}

			for (m = 0; m < (int)LWS_ARRAY_SIZE(voids); m++)
				if (!strcmp(tag, voids[m]))
					is_void = 1;

			for (m = 0; m < (int)LWS_ARRAY_SIZE(known); m++)
				if (!strcmp(tag, known[m]))
					idx = m;

			if (is_void) {
				if (is_close)
					bad++;	/* void elements never close */
			} else if (idx < 0)
				bad++;	/* markup from outside the sink */
			else if (is_close) {
				if (!depth || stack[depth - 1] != idx)
					bad++;
				else
					depth--;
			} else {
				if (depth == (int)LWS_ARRAY_SIZE(stack))
					bad++;
				else
					stack[depth++] = idx;
			}

			if (bad)
				break;
			p = e + 1;
			continue;
		}
		if (*p == '>') {
			bad++;
			break;
		}
		if (*p == '&') {
			if (strncmp(p, "&lt;", 4) && strncmp(p, "&gt;", 4) &&
			    strncmp(p, "&amp;", 5) &&
			    strncmp(p, "&quot;", 6) &&
			    strncmp(p, "&#65533;", 8)) {
				bad++;
				break;
			}
			p += (p[1] == 'l' || p[1] == 'g') ? 4 :
			     (p[1] == 'a') ? 5 :
			     (p[1] == 'q') ? 6 :
			     (p[1] == '#') ? 8 : 1;
			continue;
		}
		p++;
	}

	if (bad || depth) {
		fprintf(stderr, "FAIL(html:%s): unbalanced or unsafe markup\n"
				"  %.120s\n", name, html);
		return 1;
	}

	return 0;
}

struct golden {
	const char	*name;
	const char	*in;
	const char	*expect;
};

static const struct golden goldens[] = {

	{ "simple",
	  "# Title\n\nsome *text* here\n",
	  "<h1>Title</h1><p>some <em>text</em> here</p>" },

	{ "heading-level-trailing",
	  "### h ###\n#### x\n",
	  "<h3>h</h3><h4>x</h4>" },

	{ "para-join",
	  "one\ntwo\n\nthree\n",
	  "<p>one\ntwo</p><p>three</p>" },

	{ "emphasis",
	  "**b *i* b** and *em*\n",
	  "<p><strong>b <em>i</em> b</strong> and <em>em</em></p>" },

	{ "escaped-marker",
	  "a \\*b\\* c\n",
	  "<p>a *b* c</p>" },

	{ "codespan",
	  "a `x < y` b\n",
	  "<p>a <code>x &lt; y</code> b</p>" },

	{ "links-images-autolink",
	  "[a](https://x.y) ![i](/im.png) http://z.z & <b>\n",
	  "<p><a href=\"https://x.y\">a</a> "
	  "<img src=\"/im.png\" alt=\"i\"> "
	  "<a href=\"http://z.z\">http://z.z</a> &amp; &lt;b&gt;</p>" },

	{ "hostile-urls",
	  "[x](javascript:alert(1)) [y](JaVaScRiPt:q) [z](data:text/html,x) "
	  "[w](mailto:a@b) [v](#frag) [u](/abs/path)\n",
	  "<p><a href=\"#\">x</a> <a href=\"#\">y</a> <a href=\"#\">z</a> "
	  "<a href=\"mailto:a@b\">w</a> <a href=\"#frag\">v</a> "
	  "<a href=\"/abs/path\">u</a></p>" },

	{ "raw-html-stays-escaped",
	  "<script>alert(1)</script>\n",
	  "<p>&lt;script&gt;alert(1)&lt;/script&gt;</p>" },

	{ "entities-stay-escaped",
	  "&lt;b&gt; &amp; &#65;\n",
	  "<p>&amp;lt;b&amp;gt; &amp;amp; &amp;#65;</p>" },

	{ "fence-plain",
	  "```\nint x = 1;\n```\n",
	  "<pre><code>int x = 1;\n</code></pre>" },

	{ "fence-tilde-unterminated",
	  "~~~\nbody\n",
	  "<pre><code>body\n</code></pre>" },

	{ "fence-inner-backticks",
	  "````\na ``` b\n````\n",
	  "<pre><code>a ``` b\n</code></pre>" },

	{ "indented-code-with-blank",
	  "    code a\n\n    code b\ntext\n",
	  "<pre><code>code a\n\ncode b\n</code></pre><p>text</p>" },

	{ "blockquote-nested",
	  "> a\n> > b\n< c\n",
	  "<blockquote><p>a</p><blockquote><p>b</p></blockquote>"
	  "</blockquote><p>&lt; c</p>" },

	{ "list-basics",
	  "- a\n  cont\n- b\n\n1. x\n",
	  "<ul><li>a\ncont</li><li>b</li></ul><ol><li>x</li></ol>" },

	{ "list-type-switch",
	  "1. a\n- b\n",
	  "<ol><li>a</li></ol><ul><li>b</li></ul>" },

	{ "table",
	  "| a | b |\n| --- | --- |\n| 1 | 2 |\n",
	  "<table><tr><th>a</th><th>b</th></tr>"
	  "<tr><td>1</td><td>2</td></tr></table>" },

	{ "table-midrow-empty-cell",
	  "| a || b |\n| --- | --- | --- |\n| 1 | 2 |\n",
	  "<table><tr><th>a</th><th></th><th>b</th></tr>"
	  "<tr><td>1</td><td>2</td></tr></table>" },

	{ "linked-image",
	  "[![CI status](https://x/y.svg)](https://x/y)\n",
	  "<p><a href=\"https://x/y\">"
	  "<img src=\"https://x/y.svg\" alt=\"CI status\"></a></p>" },

	{ "no-nested-links",
	  "[a [b](/u)](/v)\n",
	  "<p><a href=\"/v\">a [b](/u)</a></p>" },

	{ "table-hold-gives-up",
	  "| a |\nnot sep\n| - | - |\n",
	  "<p>| a |\nnot sep\n| - | - |</p>" },

	{ "table-eof-no-follower",
	  "| a | b |\n",
	  "<p>| a | b |</p>" },

	{ "hr",
	  "---\n***\ntext\n",
	  "<hr><hr><p>text</p>" },

	{ "crlf",
	  "# h\r\n\r\ntext\r\n",
	  "<h1>h</h1><p>text</p>" },

	{ "control-bytes",
	  "a\x01" "\x02" "<b\n",
	  "<p>a&#65533;&#65533;&lt;b</p>" },

	{ "unterminated-linkish",
	  "[[[[ ((((( ]] )) x\n",
	  "<p>[[[[ ((((( ]] )) x</p>" },

	{ "empty-link-and-image",
	  "a []() b ![](x) c\n",
	  "<p>a <a href=\"#\"></a> b <img src=\"x\" alt=\"\"> c</p>" },
};

static int
test_goldens(void)
{
	size_t n;
	int bad = 0;

	for (n = 0; n < LWS_ARRAY_SIZE(goldens); n++) {
		const struct golden *g = &goldens[n];
		uint32_t seed = 0x87654321u + (uint32_t)n;
		int ret, m;

		ret = run_md((const uint8_t *)g->in, strlen(g->in),
			     &cap_static, 0, 0);
		if (ret) {
			fprintf(stderr, "FAIL(%s): run_md %d\n", g->name, ret);
			bad++;
			continue;
		}
		if (strcmp(cap_static.buf, g->expect)) {
			fprintf(stderr, "FAIL(%s): golden mismatch\n"
					"  got:  %s\n  want: %s\n",
				g->name, cap_static.buf, g->expect);
			bad++;
			continue;
		}

		for (m = 0; m < 40; m++) {
			ret = run_fragmented((const uint8_t *)g->in,
					     strlen(g->in),
					     seed + (uint32_t)m * 13u,
					     &cap_static);
			if (ret || strcmp(cap_static.buf, g->expect)) {
				fprintf(stderr, "FAIL(%s): fragmented differs "
						"(%d, round %d)\n  got:  %s\n",
					g->name, ret, m, cap_static.buf);
				bad++;
				break;
			}
		}
		if (m != 40)
			continue;

		for (m = 0; m < 8; m++) {
			ret = run_md((const uint8_t *)g->in, strlen(g->in),
				     &cap_static, 1, (size_t)1 << m);
			if (ret || strcmp(cap_static.buf, g->expect)) {
				fprintf(stderr, "FAIL(%s): deferred differs "
						"(%d, budget %d)\n  got:  %s\n",
					g->name, ret, m, cap_static.buf);
				bad++;
				break;
			}
		}
	}

	if (!bad)
		fprintf(stderr, "test-md: %zu goldens + fragmentation + "
			"flow control: PASS\n", LWS_ARRAY_SIZE(goldens));

	return bad;
}

/* deep quote nesting: capped, no recursion, content preserved */

static int
test_deep_quotes(void)
{
	static char in[64 * 1024];
	size_t n, off = 0, qn = 30;
	char expect[64 * 1024];
	size_t e = 0;
	int bad = 0, m;

	for (n = 0; n < qn; n++)
		in[off++] = '>';
	in[off++] = 'x';
	in[off++] = '\n';

	for (n = 0; n < LMD_NEST_MAX; n++)
		e += (size_t)lws_snprintf(expect + e, sizeof(expect) - e,
					  "<blockquote>");
	e += (size_t)lws_snprintf(expect + e, sizeof(expect) - e, "<p>");
	for (n = 0; n < qn - LMD_NEST_MAX; n++)
		e += (size_t)lws_snprintf(expect + e, sizeof(expect) - e,
					  "&gt;");
	e += (size_t)lws_snprintf(expect + e, sizeof(expect) - e,
				  "x</p>");
	for (n = 0; n < LMD_NEST_MAX; n++)
		e += (size_t)lws_snprintf(expect + e, sizeof(expect) - e,
					  "</blockquote>");

	if (run_md((const uint8_t *)in, off, &cap_static, 0, 0) ||
	    strcmp(cap_static.buf, expect)) {
		fprintf(stderr, "FAIL(deep-quotes): got  %.120s\n", cap_static.buf);
		bad++;
	}

	for (m = 0; m < 8 && !bad; m++) {
		if (run_md((const uint8_t *)in, off, &cap_static, 1,
			   (size_t)1 << m) ||
		    strcmp(cap_static.buf, expect)) {
			fprintf(stderr, "FAIL(deep-quotes): deferred %d\n", m);
			bad++;
		}
	}

	if (!bad)
		fprintf(stderr, "test-md: deep quote nesting: PASS\n");

	return bad;
}

/*
 * An over-cap line: structure is given up but every byte survives as
 * escaped paragraph text.
 */

static int
test_overlong(void)
{
	static char in[LMD_LINE_MAX + 2048];
	static char expect[LMD_LINE_MAX + 4096];
	size_t n, len = 0, e = 0;
	int bad = 0;

	for (n = 0; n < LMD_LINE_MAX + 1024; n++)
		in[len++] = 'a';
	in[len++] = '\n';
	in[len++] = 'a';
	in[len++] = 'f';
	in[len++] = 't';
	in[len++] = 'e';
	in[len++] = 'r';
	in[len++] = '\n';

	e += (size_t)lws_snprintf(expect + e, sizeof(expect) - e, "<p>");
	for (n = 0; n < LMD_LINE_MAX + 1024; n++)
		expect[e++] = 'a';
	e += (size_t)lws_snprintf(expect + e, sizeof(expect) - e,
				  "\nafter</p>");

	if (run_md((const uint8_t *)in, len, &cap_static, 0, 0) ||
	    strcmp(cap_static.buf, expect)) {
		fprintf(stderr, "FAIL(overlong): got  %.80s... "
			"(%zu bytes)\n", cap_static.buf, cap_static.len);
		bad++;
	}

	if (run_fragmented((const uint8_t *)in, len, 0x42434445u,
			   &cap_static) ||
	    strcmp(cap_static.buf, expect)) {
		fprintf(stderr, "FAIL(overlong): fragmented differs\n");
		bad++;
	}

	if (run_md((const uint8_t *)in, len, &cap_static, 1, 3) ||
	    strcmp(cap_static.buf, expect)) {
		fprintf(stderr, "FAIL(overlong): deferred differs\n");
		bad++;
	}

	if (!bad)
		fprintf(stderr, "test-md: overlong line degradation: PASS\n");

	return bad;
}

/*
 * The resolver path: absolute urls must pass through untouched (they
 * carry an allowed scheme), only scheme-less relatives rewrite.
 */

static size_t
resolver_cb(void *user, int is_image, const char *url, size_t len,
	    char *dest, size_t dest_len)
{
	(void)user;

	return (size_t)lws_snprintf(dest, dest_len, "%s/%.*s",
				    is_image ? "/plain" : "/tree",
				    (int)len, url);
}

static int
test_resolver(void)
{
	static const char in[] =
		"[x](https://libwebsockets.org/sai/) [y](dir/f.md) "
		"![i](img.png) [z](/abs) [w](#frag)\n";
	static const char expect[] =
		"<p><a href=\"https://libwebsockets.org/sai/\">x</a> "
		"<a href=\"/tree/dir/f.md\">y</a> "
		"<img src=\"/plain/img.png\" alt=\"i\"> "
		"<a href=\"/abs\">z</a> <a href=\"#frag\">w</a></p>";
	int bad = 0, m;

	test_resolve = resolver_cb;

	if (run_md((const uint8_t *)in, sizeof(in) - 1, &cap_static, 0, 0) ||
	    strcmp(cap_static.buf, expect)) {
		fprintf(stderr, "FAIL(resolver): got  %s\n", cap_static.buf);
		bad++;
	}
	for (m = 0; m < 8 && !bad; m++) {
		if (run_md((const uint8_t *)in, sizeof(in) - 1, &cap_static, 1,
			   (size_t)1 << m) ||
		    strcmp(cap_static.buf, expect)) {
			fprintf(stderr, "FAIL(resolver): deferred %d\n", m);
			bad++;
		}
	}

	test_resolve = NULL;

	if (!bad)
		fprintf(stderr, "test-md: url resolver: PASS\n");

	return bad;
}

/* fenced code with a known info string goes through lws-hl */

static int
test_hl_bridge(void)
{
#if defined(LWS_WITH_HL) && defined(LWS_WITH_HL_LANG_C)
	static const char in[] = "```c\nint x = 1; /* c */\n```\n";
	static const char expect[] =
		"<pre><code><span class=\"hl-t\">int</span> x = "
		"<span class=\"hl-n\">1</span>; "
		"<span class=\"hl-cm\">/* c */</span>\n</code></pre>";
	int bad = 0;

	if (run_md((const uint8_t *)in, sizeof(in) - 1, &cap_static, 0, 0) ||
	    strcmp(cap_static.buf, expect)) {
		fprintf(stderr, "FAIL(hl-bridge): got  %s\n", cap_static.buf);
		bad++;
	}
	if (run_fragmented((const uint8_t *)in, sizeof(in) - 1, 0x51525354u,
			   &cap_static) || strcmp(cap_static.buf, expect)) {
		fprintf(stderr, "FAIL(hl-bridge): fragmented differs\n");
		bad++;
	}
	if (run_md((const uint8_t *)in, sizeof(in) - 1, &cap_static, 1, 2) ||
	    strcmp(cap_static.buf, expect)) {
		fprintf(stderr, "FAIL(hl-bridge): deferred differs\n");
		bad++;
	}

	if (!bad)
		fprintf(stderr, "test-md: lws-hl fence bridge: PASS\n");

	return bad;
#else
	fprintf(stderr, "test-md: lws-hl fence bridge: SKIP\n");

	return 0;
#endif
}

/*
 * Hostile input: pseudo-random garbage biased to markdown syntax bytes must
 * render to structurally valid, escaped html, identically under any
 * fragmentation or deferral pattern.
 */

static int
test_hostile(void)
{
	static const uint8_t syntax[] =
		"`~>#*-+_[]()!|\\\n \t&<>:/;.'\"=abcxyz0189";
	static uint8_t buf[3072];
	size_t round, bad = 0;
	uint32_t seed = 0xfeedfaceu;

	for (round = 0; round < 48; round++) {
		size_t n, len = 512 + xs32(&seed) % (sizeof(buf) - 512);
		static char whole[MAX_STREAM];
		int m, ret;

		for (n = 0; n < len; n++)
			buf[n] = (xs32(&seed) & 3) ?
				syntax[xs32(&seed) % (sizeof(syntax) - 1)] :
				(uint8_t)xs32(&seed);

		ret = run_md(buf, len, &cap_static, 0, 0);
		if (ret) {
			fprintf(stderr, "FAIL(hostile %zu): run %d\n", round, ret);
			bad++;
			break;
		}
		if (html_check("hostile", cap_static.buf)) {
			bad++;
			break;
		}
		lws_strncpy(whole, cap_static.buf, sizeof(whole));

		for (m = 0; m < 8 && !bad; m++) {
			ret = run_fragmented(buf, len,
					     seed + (uint32_t)m * 29u,
					     &cap_static);
			if (ret || strcmp(cap_static.buf, whole)) {
				fprintf(stderr, "FAIL(hostile %zu): fragmented "
						"differs (%d)\n", round, ret);
				bad++;
			}
		}
		for (m = 0; m < 3 && !bad; m++) {
			ret = run_md(buf, len, &cap_static, 1, (size_t)1 << m);
			if (ret || strcmp(cap_static.buf, whole)) {
				fprintf(stderr, "FAIL(hostile %zu): deferred "
						"differs (%d)\n", round, ret);
				bad++;
			}
		}
		if (bad)
			break;
	}

	if (!bad)
		fprintf(stderr, "test-md: hostile garbage rounds: PASS\n");

	return (int)bad;
}

/*
 * Self-feed: render this file's own source through the renderer; the
 * result must be structurally valid and contain the fence from this
 * file's own test as highlighted code.
 */

static int
test_selffeed(void)
{
	const char *paths[] = { __FILE__, "test-apps/test-md.c",
				"../test-apps/test-md.c" };
	uint8_t *buf = malloc(1024 * 1024);
	size_t total, n;
	FILE *f = NULL;
	int bad = 0;

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

	if (run_md(buf, total, &cap_static, 0, 0))
		bad++;
	else
		bad += html_check("selffeed", cap_static.buf);

	free(buf);

	if (!bad)
		fprintf(stderr, "test-md: selffeed (%zu bytes): PASS\n", total);

	return bad;
}

int
main(int argc, char *argv[])
{
	int bad = 0;

	(void)argc; (void)argv;

	bad += test_goldens();
	bad += test_resolver();
	bad += test_deep_quotes();
	bad += test_overlong();
	bad += test_hl_bridge();
	bad += test_hostile();
	bad += test_selffeed();

	if (bad) {
		fprintf(stderr, "test-md: %d failures\n", bad);
		return 1;
	}

	fprintf(stderr, "test-md: ALL PASS\n");

	return 0;
}
