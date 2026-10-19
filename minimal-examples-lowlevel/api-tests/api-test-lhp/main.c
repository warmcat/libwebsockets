/*
 * lws-api-test-lhp
 *
 * Written in 2010-2022 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * sanity tests for lhp
 */

#include <libwebsockets.h>

enum {
	LWS_SW_D,
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_D]	= { "-d",              "Debug logs (e.g. -d 15)" },
	[LWS_SW_HELP]	= { "--help",		"Show this help information" },
};

#include <stdio.h>

static const char * const cb_reasons[] = {
		"LHPCB_CONSTRUCTED",
		"LHPCB_DESTRUCTED",
		"LHPCB_COMPLETE",
		"LHPCB_FAILED",
		"LHPCB_ELEMENT_START",	/* reported at end of <> */
		"LHPCB_ELEMENT_END",
		"LHPCB_CONTENT",
		"LHPCB_COMMENT",
};

static const char * const html_tests[] = {
	/* POC test */
	"<style>span.note{color:#123;}</style><span class>x</span>",
	/* test 1 */
	"hello",
	/* test 2 */
	"<!doctype html>",
	/* test 3 */
	"<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.0//EN\">",
	/* test 4 */
	"<!doctype html><html><head></head><body>hello</body></html>",
	/* test 5 */
	"<!doctype html>\n"
	 "<html>\n"
	 "<head>\n"
	 "<title>An HTML standard template</title>\n"
	 "<meta charset=\"utf-8\"  />\n"
	 "</head>\n"
	 "<body>\n"
	 "<h1>heading</h1>\n"
	 "<b>bold</b>, normal<br>\n"
	 "</body>\n"
	 "</html>\n",
	"<>",
	"<thing></thing>",
	"<thing a></thing>",
	"<thing a b=c></thing>",
	"<thing a b='d'></thing>",
	"<thing a b=\"e\"></thing>",
	"<thing ></thing>",
	"<thing a ></thing>",
	"<thing a b=c ></thing>",
	"<thing a b='d' ></thing>",
	"<thing a b=\"e\" ></thing>",
	"<br/>",
	"<br />",
	"<br something/>",
	"<br something />",
	"<!--comment-->",
	"<!doctype html>\n"
	 "<html>\n"
	 "<head>\n"
	 "<title>Test html</title>\n"
	 "<meta charset=\"utf-8\" />\n"
	 "</head>\n"
	 "<style>"
		"h1 { font-size: 32px },"
		"b { font-weight: bold }"
	 "</style>"
	 "<body>\n"
	 "<h1>libwebsockets.org</h1>\n"
	 "A bunch of normal text, long enough that it is going to want to wrap<br>"
	 "<b>bold</b>, normal<br>\n"
	 "<img src=\"something.png\">"
	 "</body>\n"
	 "</html>\n",
	 "&#x20ac;&#x1f44d;",
	 "<html><head><title>the title</title></head><body><style>"
		 "<!-- css comment-->"
		 "/* another css comment */"
		 "body { font-size: 16px; font-family: default }"
		 "div { font-size: 16px; display: inline-block }"
		 "h1 { font-size: 32px; font-family: \"term\" }"
		 "b { font-weight: bold; color: #f00 }"
		 ".wordy { position: absolute; width: 280px; left: 10px; right: 10px; font-size: 16px; color: #7a7b7c }"
		 ".cat { display: list-item; }"
	 "</style>"
	 "<h1>Heading</h1>\n"
	 "<div class=\"wordy cat\">"
	 "A bunch of normal <b> and bold</b>text in a div"
	 "</div>"
        "hello</body></html>",

        "<style> a { width: 0em }</style><a><body>",

	/* standalone parse with no lws_context and an <img> with an absolute
	 * url: must leave the element empty rather than deref the (absent)
	 * context or assert on the (empty) base url */

	"<html><head></head><body><img src=\"file://x\"></body></html>",

	/* named entities from the HTML 4.01 Latin-1, symbol and special
	 * sets in body text, mixed with numeric ones */

	("<html><body>Dr Alp&ouml;ge &euro;5 &ldquo;x&rdquo; &Omega;&amp;&#233;"
	 "&nbsp;&iexcl;&yuml;&bogus;</body></html>")
};

/* the last test's body text, once the entities are expanded to utf-8 */

#define ENTITY_TEST_IDX (LWS_ARRAY_SIZE(html_tests) - 1)
static const char * const entity_expect =
	"Dr Alp\xc3\xb6ge \xe2\x82\xac" "5 \xe2\x80\x9cx\xe2\x80\x9d "
	"\xce\xa9&\xc3\xa9\xc2\xa0\xc2\xa1\xc3\xbf&bogus;";

/* the content arrives in pieces, one per entity: collect it */

static char content_acc[128];
static size_t content_len;

static unsigned int m, step;

static int
dump_atr(lws_dll2_t *d, void *user)
{
	lhp_atr_t *atr = lws_container_of(d, lhp_atr_t, list);
	const char *p = (const char *)&atr[1];

	printf("{ \"%.*s\", \"%.*s\" }, ",
		    (int)atr->name_len, p, (int)atr->value_len, p + atr->name_len + 1);

	return 0;
}

#if 0
static int
dump_css_atr(lws_dll2_t *d, void *user)
{
	lcsp_atr_ptr_t *pa = lws_container_of(d, lcsp_atr_ptr_t, list);
	lcsp_atr_t *a = pa->atr;

	if (a->unit == LCSP_UNIT_RGBA)
		lwsl_notice("css attr: color 0x%08x\n", a->u.rgba);
	else
		lwsl_notice("css attr: %d %u.%u %u\n", a->propval, a->u.i.whole, a->u.i.frac, a->unit);

	return 0;
}
#endif

static lws_stateful_ret_t
test_cb(lhp_ctx_t *ctx, char reason)
{
	lhp_pstack_t *ps = lws_container_of(lws_dll2_get_tail(&ctx->stack), lhp_pstack_t, list);
	const lcsp_atr_t *a;

	printf("{ %s, %u, \"%.*s\", %u, { ", cb_reasons[(unsigned int)reason], ctx->npos, ctx->npos, ctx->buf, lws_dll2_count(
		&ps->atr));

	if (m == ENTITY_TEST_IDX && reason == LHPCB_CONTENT &&
	    content_len + (size_t)ctx->npos < sizeof(content_acc)) {
		memcpy(content_acc + content_len, ctx->buf, (size_t)ctx->npos);
		content_len += (size_t)ctx->npos;
	}

	if (reason == LHPCB_ELEMENT_START || reason == LHPCB_ELEMENT_END) {
		lws_dll2_foreach_safe(&ps->atr, NULL, dump_atr);

		a = lws_css_cascade_get_prop_atr(ctx, LCSP_PROP_DISPLAY);
		if (a)
			lwsl_notice("display: %d\n", a->propval);

		a = lws_css_cascade_get_prop_atr(ctx, LCSP_PROP_COLOR);
		if (a)
			lwsl_notice("color: %d 0x%08X\n", a->propval, a->u.rgba);
		//lwsl_notice("color: active_stz %d, atr %d\n", ctx->active_stanzas.count, ctx->active_atr.count);
		//lws_dll2_foreach_safe(&ctx->active_atr, NULL, dump_css_atr);

		a = ps->css_position;
		if (a)
			lwsl_notice("position: %d\n", a->propval);

		a = ps->css_width;
		if (a)
			lwsl_notice("width: %d.%u\n", a->u.i.whole, a->u.i.frac);

		a = ps->css_height;
		if (a)
			lwsl_notice("height: %d.%u\n", a->u.i.whole, a->u.i.frac);

		a = ps->css_pos[CCPAS_TOP];
		if (a)
			lwsl_notice("top: %d.%u\n", a->u.i.whole, a->u.i.frac);
		a = ps->css_pos[CCPAS_RIGHT];
		if (a)
			lwsl_notice("right: %d.%u\n", a->u.i.whole, a->u.i.frac);
		a = ps->css_pos[CCPAS_BOTTOM];
		if (a)
			lwsl_notice("bottom: %d.%u\n", a->u.i.whole, a->u.i.frac);
		a = ps->css_pos[CCPAS_LEFT];
		if (a)
			lwsl_notice("left: %d.%u\n", a->u.i.whole, a->u.i.frac);

		a = ps->css_margin[CCPAS_TOP];
		if (a)
			lwsl_notice("margin top: %d.%u\n", a->u.i.whole, a->u.i.frac);
		a = ps->css_margin[CCPAS_RIGHT];
		if (a)
			lwsl_notice("margin right: %d.%u\n", a->u.i.whole, a->u.i.frac);
		a = ps->css_margin[CCPAS_BOTTOM];
		if (a)
			lwsl_notice("margin bottom: %d.%u\n", a->u.i.whole, a->u.i.frac);
		a = ps->css_margin[CCPAS_LEFT];
		if (a)
			lwsl_notice("margin left: %d.%u\n", a->u.i.whole, a->u.i.frac);

		a = ps->css_padding[CCPAS_TOP];
		if (a)
			lwsl_notice("padding top: %d.%u\n", a->u.i.whole, a->u.i.frac);
		a = ps->css_padding[CCPAS_RIGHT];
		if (a)
			lwsl_notice("padding right: %d.%u\n", a->u.i.whole, a->u.i.frac);
		a = ps->css_padding[CCPAS_BOTTOM];
		if (a)
			lwsl_notice("padding bottom: %d.%u\n", a->u.i.whole, a->u.i.frac);
		a = ps->css_padding[CCPAS_LEFT];
		if (a)
			lwsl_notice("padding left: %d.%u\n", a->u.i.whole, a->u.i.frac);

		a = lws_css_cascade_get_prop_atr(ctx, LCSP_PROP_FONT_SIZE);
		if (a)
			lwsl_notice("font-size: %d.%u\n", a->u.i.whole, a->u.i.frac);

		a = lws_css_cascade_get_prop_atr(ctx, LCSP_PROP_FONT_FAMILY);
		if (a)
			lwsl_notice("font-family: %s\n", (const char *)&a[1]);
	}

	printf(" },\n");

#if 0
	if (m < LWS_ARRAY_SIZE(rpkg)) {
		if (step < rpkg[m].len) {
			// lwsl_notice("test %d, step %d\n", m, step);
			if (reason != rpkg[m].r[step].reason) {
				lwsl_err("%s: reason mismatch %d vs %d\n", __func__, reason, rpkg[m].r[step].reason);
				return -1;
			}
			if (ctx->ipos != rpkg[m].r[step].ipos) {
				lwsl_err("%s: ipos mismatch %d vs %d\n", __func__, ctx->ipos, rpkg[m].r[step].ipos);
				return -1;
			}
			if (ctx->ipos && memcmp(ctx->i, rpkg[m].r[step].indexes, ctx->ipos)) {
				lwsl_err("%s: indexes mismatch\n", __func__);
				lwsl_hexdump_err(ctx->i, ctx->ipos);
				lwsl_hexdump_err(rpkg[m].r[step].indexes, ctx->ipos);
				return -1;
			}
			if (ctx->path_match != rpkg[m].r[step].path_match) {
				lwsl_err("%s: path_match mismatch %d vs %d\n", __func__, ctx->path_match, rpkg[m].r[step].path_match);
				return -1;
			}
			if (strcmp(ctx->path, rpkg[m].r[step].path)) {
				lwsl_err("%s: path mismatch '%s' vs '%s'\n", __func__, ctx->path, rpkg[m].r[step].path);
				return -1;
			}
			if (strcmp(ctx->buf, rpkg[m].r[step].buf)) {
				lwsl_err("%s: buf mismatch '%s' vs '%s'\n", __func__, ctx->buf, rpkg[m].r[step].buf);
				return -1;
			}
		} else {
			lwsl_err("%s: extra steps\n", __func__);
			return -1;
		}

		step++;
	}
#endif
	return 0;
}

/*
 * lws_http_rel_to_url(): every branch, and every branch refusing a result
 * that does not fit (a truncated url would name some other resource)
 */

static const struct {
	const char	*base, *rel, *expect;	/* expect NULL: must fail */
	size_t		len;
} rel_tests[] = {
	{ "https://x.com/y/z.html", "a.html", "https://x.com/y/a.html", 64 },
	{ "https://x.com/y/z.html", "/c.html", "https://x.com/c.html", 64 },
	{ "https://x.com/y/z.html", "https://y.com/a.html",
					"https://y.com/a.html", 64 },
	{ "https://x.com/y/z.html", "//y.com/a.html",
					"https://y.com/a.html", 64 },
	{ "file:///d/e/f.html", "g.css", "file:///d/e/g.css", 64 },
	{ "file:///d/e/f.html", "/g.css", "file:///d/e/g.css", 64 },

	/* exactly fits, including the NUL */
	{ "https://x.com/y/z.html", "a.html", "https://x.com/y/a.html", 23 },
	{ "https://x.com/y/z.html", "/c.html", "https://x.com/c.html", 21 },
	{ "https://x.com/y/z.html", "//y.com/a.html",
					"https://y.com/a.html", 21 },
	{ "file:///d/e/f.html", "g.css", "file:///d/e/g.css", 18 },
	{ "https://x.com/y/z.html", "https://y.com/a.html",
					"https://y.com/a.html", 21 },

	/* one short */
	{ "https://x.com/y/z.html", "a.html", NULL, 22 },
	{ "https://x.com/y/z.html", "/c.html", NULL, 20 },
	{ "https://x.com/y/z.html", "https://y.com/a.html", NULL, 20 },
	{ "https://x.com/y/z.html", "//y.com/a.html", NULL, 20 },
	{ "file:///d/e/f.html", "g.css", NULL, 17 },
	{ "x", "a.html", NULL, 2 },
};

static int
test_rel_to_url(void)
{
	char dest[64];
	size_t n;

	for (n = 0; n < LWS_ARRAY_SIZE(rel_tests); n++) {
		int r = lws_http_rel_to_url(dest, rel_tests[n].len,
					    rel_tests[n].base, rel_tests[n].rel);

		if (!rel_tests[n].expect) {
			if (!r)
				goto fail;
			continue;
		}
		if (r || strcmp(dest, rel_tests[n].expect))
			goto fail;
		continue;
fail:
		lwsl_err("%s: case %d: %s + %s (len %d): r %d, %s\n", __func__,
			 (int)n, rel_tests[n].base, rel_tests[n].rel,
			 (int)rel_tests[n].len, r, r ? "-" : dest);

		return 1;
	}

	return 0;
}

static const lws_surface_info_t ic = {
	.wh_px = { { 600,0 },       { 448,0 } },
	.wh_mm = { { 114,5000000 }, {  82,5000000 } },
};

static lws_displaylist_t displaylist;

/*
 * Selector matching work must be bounded per element, however the selectors
 * nest.  Each :is() below can only match after its first alternative has
 * backtracked over the remembered siblings looking for a <b> that isn't
 * there, and the descendant chain around them backtracks over the ancestors
 * the same way, so a matcher that renews its step budget inside :is() pays
 * the whole inner budget for every outer step, ~1e7 steps per element.  The
 * elements also repeat a class token that keys more of the same.
 *
 * And :not() of an argument that ran out of budget must not turn into a
 * match: unbudgeted, the argument below simply fails to match (there's no
 * <b>), so :not() matches the elements with few enough earlier siblings to
 * decide that, but not the ones where the search runs out.
 */

#define LHPT_BUDGET_NEST	20
#define LHPT_BUDGET_SIBS	8
#define LHPT_BUDGET_COPIES	128
#define LHPT_BUDGET_CLASSES	500
#define LHPT_BUDGET_DEADLINE_US	(10 * LWS_US_PER_SEC)

#define LHPT_SIB8		"b~a~a~a~a~a~a~a~a"
#define LHPT_IS			":is(" LHPT_SIB8 ",a)"

static lws_usec_t budget_start;
static int budget_a, budget_late, budget_not_matched;

static lws_stateful_ret_t
budget_cb(lhp_ctx_t *ctx, char reason)
{
	lhp_pstack_t *ps = lws_container_of(lws_dll2_get_tail(&ctx->stack),
					    lhp_pstack_t, list);
	const lhp_atr_t *ta;

	if (reason != LHPCB_ELEMENT_START || lws_dll2_is_empty(&ps->atr))
		return 0;

	/* fail at the first element that finishes late, don't wait for all */

	if (lws_now_usecs() - budget_start > LHPT_BUDGET_DEADLINE_US) {
		budget_late = 1;
		return LWS_SRET_FATAL;
	}

	ta = lws_container_of(lws_dll2_get_head(&ps->atr), lhp_atr_t, list);
	if (ta->name_len != 1 || *(const char *)&ta[1] != 'a')
		return 0;

	budget_a++;

	/* only the :not() rule sets a width, which isn't inherited */

	if (ps->css_width && ps->css_width->u.i.whole == 7)
		budget_not_matched++;

	return 0;
}

static int
test_selector_budget(int copies, int classes)
{
	size_t alloc = 512 * 1024, n, len;
	lws_stateful_ret_t r;
	const uint8_t *data;
	lws_dl_rend_t drt;
	lhp_ctx_t *ctx;
	char *doc, *p;
	int e = 1, i, j;

	doc = malloc(alloc);
	ctx = malloc(sizeof(*ctx));
	if (!doc || !ctx)
		goto bail;
	memset(ctx, 0, sizeof(*ctx));
	budget_a = budget_late = budget_not_matched = 0;

	p = doc;
	p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
			  "<html><head><style>"
			  "a:not(" LHPT_SIB8 "){width:7px}\n");
	for (i = 0; i < copies; i++)
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  "b " LHPT_IS " " LHPT_IS " " LHPT_IS
				  "{margin:%dpx}\n"
				  "b " LHPT_IS " " LHPT_IS " " LHPT_IS
				  ".x{padding:%dpx}\n", i, i);
	p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
			  "</style></head><body>");
	for (i = 0; i < LHPT_BUDGET_NEST; i++) {
		/* closed earlier siblings for '~' to search */
		for (j = 0; j < LHPT_BUDGET_SIBS; j++)
			p += lws_snprintf(p, alloc -
					  lws_ptr_diff_size_t(p, doc),
					  "<a></a>");
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  "<a class=\"");
		for (n = 0; n < (size_t)classes; n++)
			p += lws_snprintf(p, alloc -
					  lws_ptr_diff_size_t(p, doc), "x ");
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  "\">");
	}
	for (i = 0; i < LHPT_BUDGET_NEST; i++)
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  "</a>");
	p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
			  "</body></html>");
	len = lws_ptr_diff_size_t(p, doc);
	if (len >= alloc - 1) {
		lwsl_err("%s: document doesn't fit\n", __func__);
		goto bail;
	}

	memset(&drt, 0, sizeof(drt));
	drt.dl = &displaylist;
	drt.w = ic.wh_px[0].whole;
	drt.h = ic.wh_px[1].whole;

	if (lws_lhp_construct(ctx, budget_cb, &drt, &ic))
		goto bail;
	ctx->flags = LHP_FLAG_DOCUMENT_END;
	ctx->base_url = strdup("");

	budget_start = lws_now_usecs();
	data = (const uint8_t *)doc;
	r = lws_lhp_parse(ctx, &data, &len);
	lws_lhp_destruct(ctx);

	lwsl_user("%s: copies %d: %d <a> in %dms, r 0x%x, :not() matched %d\n",
		  __func__, copies, budget_a,
		  (int)((lws_now_usecs() - budget_start) / LWS_US_PER_MS),
		  (unsigned int)r, budget_not_matched);

	if (budget_late) {
		lwsl_err("%s: selector matching took too long\n", __func__);
		goto bail;
	}
	if (r & LWS_SRET_FATAL ||
	    budget_a != LHPT_BUDGET_NEST * (LHPT_BUDGET_SIBS + 1)) {
		lwsl_err("%s: parse failed\n", __func__);
		goto bail;
	}

	/*
	 * Elements with few earlier siblings decide the :not() argument
	 * within the budget, the rest run out.  With the hostile selectors
	 * present, those may use up an element's budget before the :not() rule
	 * is tried at all, so only the first run checks the count.
	 */
	if (!copies && (!budget_not_matched || budget_not_matched >= budget_a)) {
		lwsl_err("%s: :not() matched %d of %d\n", __func__,
			 budget_not_matched, budget_a);
		goto bail;
	}

	e = 0;

bail:
	free(ctx);
	free(doc);

	return e;
}

/*
 * calc() work must be bounded per resolve however var() expands: here each of
 * four levels names the next calc() custom property LHPT_CALC_BREADTH times,
 * so evaluating the top one expands to LHPT_CALC_BREADTH^4 var() lookups.
 * It must resolve promptly, to the 0 a calc() that runs out of budget is
 * worth, while an ordinary calc() through var() still resolves to its value.
 */

#define LHPT_CALC_BREADTH	100
#define LHPT_CALC_DEADLINE_US	(2 * LWS_US_PER_SEC)

static int calc_t_seen, calc_u_seen, calc_late;
static lws_fx_t calc_t, calc_u;

static lws_stateful_ret_t
calc_cb(lhp_ctx_t *ctx, char reason)
{
	lhp_pstack_t *ps = lws_container_of(lws_dll2_get_tail(&ctx->stack),
					    lhp_pstack_t, list);
	const char *id;
	lws_usec_t t;
	lws_fx_t v;

	if (reason != LHPCB_ELEMENT_START || lws_dll2_is_empty(&ps->atr) ||
	    !ps->css_width)
		return 0;

	id = lws_html_get_atr(ps, "id", 2);
	if (!id)
		return 0;

	t = lws_now_usecs();
	v = *lws_csp_px(ps->css_width, ps);
	t = lws_now_usecs() - t;

	lwsl_user("%s: #%s width %d.%u in %dms\n", __func__, id,
		  (int)v.whole, (unsigned int)v.frac, (int)(t / LWS_US_PER_MS));

	if (t > LHPT_CALC_DEADLINE_US)
		calc_late = 1;

	if (!strcmp(id, "t")) {
		calc_t = v;
		calc_t_seen = 1;
	}
	if (!strcmp(id, "u")) {
		calc_u = v;
		calc_u_seen = 1;
	}

	return 0;
}

static int
calc_breadth(char *p, size_t len, const char *name, const char *next)
{
	char *s = p;
	int i;

	s += lws_snprintf(s, len, "%s:calc(", name);
	for (i = 0; i < LHPT_CALC_BREADTH; i++)
		s += lws_snprintf(s, len - lws_ptr_diff_size_t(s, p),
				  "%svar(%s)", i ? "+" : "", next);
	s += lws_snprintf(s, len - lws_ptr_diff_size_t(s, p), ");");

	return lws_ptr_diff(s, p);
}

static int
test_calc_budget(void)
{
	size_t alloc = 16 * 1024, len;
	lws_stateful_ret_t r;
	const uint8_t *data;
	lws_dl_rend_t drt;
	lhp_ctx_t *ctx;
	char *doc, *p;
	int e = 1;

	doc = malloc(alloc);
	ctx = malloc(sizeof(*ctx));
	if (!doc || !ctx)
		goto bail;
	memset(ctx, 0, sizeof(*ctx));

	p = doc;
	p += lws_snprintf(p, alloc, "<html><head><style>#t{--d:1px;");
	p += calc_breadth(p, alloc - lws_ptr_diff_size_t(p, doc), "--c", "--d");
	p += calc_breadth(p, alloc - lws_ptr_diff_size_t(p, doc), "--b", "--c");
	p += calc_breadth(p, alloc - lws_ptr_diff_size_t(p, doc), "--a", "--b");
	p += calc_breadth(p, alloc - lws_ptr_diff_size_t(p, doc), "width",
			  "--a");
	p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
			  "}\n#u{--u:10px;width:calc(var(--u) * 3 + 5px)}"
			  "</style></head><body>"
			  "<div id=\"t\">x</div><div id=\"u\">y</div>"
			  "</body></html>");
	len = lws_ptr_diff_size_t(p, doc);
	if (len >= alloc - 1) {
		lwsl_err("%s: document doesn't fit\n", __func__);
		goto bail;
	}

	memset(&drt, 0, sizeof(drt));
	drt.dl = &displaylist;
	drt.w = ic.wh_px[0].whole;
	drt.h = ic.wh_px[1].whole;

	if (lws_lhp_construct(ctx, calc_cb, &drt, &ic))
		goto bail;
	ctx->flags = LHP_FLAG_DOCUMENT_END;
	ctx->base_url = strdup("");

	data = (const uint8_t *)doc;
	r = lws_lhp_parse(ctx, &data, &len);
	lws_lhp_destruct(ctx);

	if (r & LWS_SRET_FATAL || !calc_t_seen || !calc_u_seen) {
		lwsl_err("%s: parse failed\n", __func__);
		goto bail;
	}
	if (calc_late) {
		lwsl_err("%s: calc() took too long\n", __func__);
		goto bail;
	}
	if (calc_t.whole || calc_t.frac) {
		lwsl_err("%s: exhausted calc() was not 0\n", __func__);
		goto bail;
	}
	if (calc_u.whole != 35 || calc_u.frac) {
		lwsl_err("%s: ordinary calc() resolved wrongly\n", __func__);
		goto bail;
	}

	e = 0;

bail:
	free(ctx);
	free(doc);

	return e;
}

/*
 * A class-keyed cosmetic filter rule must apply to an element with that
 * class however many other classes, distinct or repeated, come before it.
 * Only the element with id "ad" has the filtered class.
 */

#define LHPT_FILTER_CLASSES	100

static int filter_ad_seen, filter_ad_hidden, filter_other_hidden;

static lws_stateful_ret_t
filter_cb(lhp_ctx_t *ctx, char reason)
{
	lhp_pstack_t *ps = lws_container_of(lws_dll2_get_tail(&ctx->stack),
					    lhp_pstack_t, list);
	const char *id;
	int hit;

	if (reason != LHPCB_ELEMENT_START || lws_dll2_is_empty(&ps->atr))
		return 0;

	id = lws_html_get_atr(ps, "id", 2);
	if (!id)
		return 0;

	/* the filter rule sets a width, which isn't inherited */

	hit = ps->css_width && ps->css_width->u.i.whole == 7;

	if (!strcmp(id, "ad")) {
		filter_ad_seen = 1;
		filter_ad_hidden = hit;
	} else if (hit)
		filter_other_hidden = 1;

	return 0;
}

static int
test_filter_classes(int classes)
{
	static const lws_lhp_filter_t filter = {
		.cosmetic_css = ".junk{width:7px}"
	};
	size_t alloc = 8 * 1024, len;
	lws_stateful_ret_t r;
	const uint8_t *data;
	lws_dl_rend_t drt;
	lhp_ctx_t *ctx;
	char *doc, *p;
	int e = 1, i;

	doc = malloc(alloc);
	ctx = malloc(sizeof(*ctx));
	if (!doc || !ctx)
		goto bail;
	memset(ctx, 0, sizeof(*ctx));
	filter_ad_seen = filter_ad_hidden = filter_other_hidden = 0;

	/*
	 * Distinct leading classes, each also repeated, then the filtered one,
	 * then more junk after it.  The second div has the same junk without
	 * the filtered class and must not be styled.
	 */

	p = doc;
	p += lws_snprintf(p, alloc, "<html><body><div id=\"ad\" class=\"");
	for (i = 0; i < classes; i++)
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  "c%d c%d ", i, i);
	p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
			  "junk c0 junk\">x</div><div id=\"ok\" class=\"");
	for (i = 0; i < classes; i++)
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  "c%d ", i);
	p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
			  "junkx\">y</div></body></html>");
	len = lws_ptr_diff_size_t(p, doc);
	if (len >= alloc - 1) {
		lwsl_err("%s: document doesn't fit\n", __func__);
		goto bail;
	}

	memset(&drt, 0, sizeof(drt));
	drt.dl = &displaylist;
	drt.w = ic.wh_px[0].whole;
	drt.h = ic.wh_px[1].whole;

	if (lws_lhp_construct(ctx, filter_cb, &drt, &ic))
		goto bail;
	if (lws_lhp_set_filter(ctx, &filter)) {
		lws_lhp_destruct(ctx);
		goto bail;
	}
	ctx->flags = LHP_FLAG_DOCUMENT_END;
	ctx->base_url = strdup("");

	data = (const uint8_t *)doc;
	r = lws_lhp_parse(ctx, &data, &len);
	lws_lhp_destruct(ctx);

	lwsl_user("%s: %d leading classes: filtered %d, other %d\n", __func__,
		  classes, filter_ad_hidden, filter_other_hidden);

	if (r & LWS_SRET_FATAL || !filter_ad_seen) {
		lwsl_err("%s: parse failed\n", __func__);
		goto bail;
	}
	if (!filter_ad_hidden || filter_other_hidden) {
		lwsl_err("%s: filter rule applied wrongly\n", __func__);
		goto bail;
	}

	e = 0;

bail:
	free(ctx);
	free(doc);

	return e;
}

/*
 * An element lhp can't hold as a browser sees it fails closed against a
 * cosmetic filter (G-172): a class or id too long to keep, or a NUL (raw or a
 * character reference to 0) in an attribute value, gets the element hidden
 * rather than filtered on a truncated or missing class.  An overlong value of
 * any other attribute (eg, a data: URI) is just discarded, as before.
 *
 * The elements are told apart by data-t, "ad" must be hidden and "ok" not.
 */

#define LHPT_SUSP_PAD		2100

static int susp_ad_seen, susp_ad_hidden, susp_ok_seen, susp_ok_hidden;

static lws_stateful_ret_t
susp_cb(lhp_ctx_t *ctx, char reason)
{
	lhp_pstack_t *ps = lws_container_of(lws_dll2_get_tail(&ctx->stack),
					    lhp_pstack_t, list);
	const char *t;

	if (reason != LHPCB_ELEMENT_START || lws_dll2_is_empty(&ps->atr))
		return 0;

	t = lws_html_get_atr(ps, "data-t", 6);
	if (!t)
		return 0;

	if (!strcmp(t, "ad")) {
		susp_ad_seen = 1;
		susp_ad_hidden = ps->hidden;
	}
	if (!strcmp(t, "ok")) {
		susp_ok_seen = 1;
		susp_ok_hidden = ps->hidden;
	}

	return 0;
}

enum {
	LHPT_SUSP_PLAIN,	/* class="x junk": the filter rule itself */
	LHPT_SUSP_NUL_DEC,	/* class="x&#0; junk" */
	LHPT_SUSP_NUL_HEX,	/* class="x&#x0; junk" */
	LHPT_SUSP_NUL_RAW,	/* class="x<0x00> junk" */
	LHPT_SUSP_NUL_OTHER,	/* title="a<0x00>b" class="y" */
	LHPT_SUSP_LONG_CLASS,	/* class="junk <pad>" */
	LHPT_SUSP_LONG_ID,	/* id="<pad>" */
	LHPT_SUSP_LONG_ENT,	/* class="junk <pad>&#65;" */
	LHPT_SUSP_LONG_OTHER,	/* title="<pad>" class="y": not suspicious */

	LHPT_SUSP_COUNT
};

static int
test_filter_suspicious(int c, int with_filter)
{
	static const lws_lhp_filter_t filter = {
		.cosmetic_css = ".junk{display:none}"
	};
	size_t alloc = 8 * 1024, len;
	lws_stateful_ret_t r;
	const uint8_t *data;
	lws_dl_rend_t drt;
	int e = 1, expect;
	lhp_ctx_t *ctx;
	char *doc, *p;

	doc = malloc(alloc);
	ctx = malloc(sizeof(*ctx));
	if (!doc || !ctx)
		goto bail;
	memset(ctx, 0, sizeof(*ctx));
	susp_ad_seen = susp_ad_hidden = susp_ok_seen = susp_ok_hidden = 0;

	p = doc;
	p += lws_snprintf(p, alloc, "<html><body><div data-t=\"ad\" ");

	switch (c) {
	case LHPT_SUSP_PLAIN:
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  "class=\"x junk\"");
		break;
	case LHPT_SUSP_NUL_DEC:
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  "class=\"x&#0; junk\"");
		break;
	case LHPT_SUSP_NUL_HEX:
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  "class=\"x&#x0; junk\"");
		break;
	case LHPT_SUSP_NUL_RAW:
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  "class=\"x");
		*p++ = '\0';
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  " junk\"");
		break;
	case LHPT_SUSP_NUL_OTHER:
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  "title=\"a");
		*p++ = '\0';
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  "b\" class=\"y\"");
		break;
	case LHPT_SUSP_LONG_CLASS:
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  "class=\"junk ");
		memset(p, ' ', LHPT_SUSP_PAD);
		p += LHPT_SUSP_PAD;
		*p++ = '\"';
		break;
	case LHPT_SUSP_LONG_ID:
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  "id=\"");
		memset(p, 'i', LHPT_SUSP_PAD);
		p += LHPT_SUSP_PAD;
		*p++ = '\"';
		break;
	case LHPT_SUSP_LONG_ENT:
		/*
		 * The value collected so far, from "class=", is
		 * LHP_STRING_CHUNK - 5 long at the '&': it is the character
		 * reference's expansion that finds the value doesn't fit
		 */
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  "class=\"junk ");
		memset(p, 'c', LHP_STRING_CHUNK - 16);
		p += LHP_STRING_CHUNK - 16;
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  "&#65;\"");
		break;
	case LHPT_SUSP_LONG_OTHER:
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  "title=\"");
		memset(p, 't', LHPT_SUSP_PAD);
		p += LHPT_SUSP_PAD;
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  "\" class=\"y\"");
		break;
	}

	p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
			  ">x</div><div data-t=\"ok\" class=\"y\">y</div>"
			  "</body></html>");
	len = lws_ptr_diff_size_t(p, doc);
	if (len >= alloc - 1) {
		lwsl_err("%s: document doesn't fit\n", __func__);
		goto bail;
	}

	memset(&drt, 0, sizeof(drt));
	drt.dl = &displaylist;
	drt.w = ic.wh_px[0].whole;
	drt.h = ic.wh_px[1].whole;

	if (lws_lhp_construct(ctx, susp_cb, &drt, &ic))
		goto bail;
	if (with_filter && lws_lhp_set_filter(ctx, &filter)) {
		lws_lhp_destruct(ctx);
		goto bail;
	}
	ctx->flags = LHP_FLAG_DOCUMENT_END;
	ctx->base_url = strdup("");

	data = (const uint8_t *)doc;
	r = lws_lhp_parse(ctx, &data, &len);
	lws_lhp_destruct(ctx);

	/* without a filter nothing is hidden; with it, all but the last */
	expect = with_filter && c != LHPT_SUSP_LONG_OTHER;

	lwsl_user("%s: case %d, filter %d: ad hidden %d (expect %d), "
		  "ok hidden %d\n", __func__, c, with_filter, susp_ad_hidden,
		  expect, susp_ok_hidden);

	if (r & LWS_SRET_FATAL || !susp_ad_seen || !susp_ok_seen) {
		lwsl_err("%s: parse failed\n", __func__);
		goto bail;
	}
	if (susp_ad_hidden != expect || susp_ok_hidden) {
		lwsl_err("%s: case %d hidden wrongly\n", __func__, c);
		goto bail;
	}

	e = 0;

bail:
	free(ctx);
	free(doc);

	return e;
}

int
main(int argc, const char **argv)
{
	int e = 0, sc;
	lws_stateful_ret_t n;
	lws_dl_rend_t drt;
	lhp_ctx_t ctx;
	(void)switches;

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches, LWS_ARRAY_SIZE(switches));
		return 0;
	}



	memset(&ctx, 0, sizeof(ctx));


	lwsl_user("LWS API selftest: lhp HTML5 parser\n");

	for (m = 0; m < (int)LWS_ARRAY_SIZE(html_tests); m++) {
		const uint8_t *data;
		size_t size;

		lwsl_user("%s: ++++++++++++++++ test %d\n", __func__, m + 1);
		step = 0;

		drt.dl = &displaylist;
		drt.w = ic.wh_px[0].whole;
		drt.h = ic.wh_px[1].whole;

		if (lws_lhp_construct(&ctx, test_cb, &drt, &ic)) {
			e++;
			continue;
		}
		ctx.flags = LHP_FLAG_DOCUMENT_END;
		ctx.base_url = strdup("");

		data = (uint8_t *)html_tests[m];
		size = strlen(html_tests[m]);

		lwsl_hexdump_info(data, size);
		n = lws_lhp_parse(&ctx, &data, &size);

		lwsl_notice("n = %d\n", (int)n);
		if (n & LWS_SRET_FATAL)
			e = 1;

		lws_lhp_destruct(&ctx);
	}

	if (e)
		goto bail;

	if (test_rel_to_url())
		goto bail;

	if (test_selector_budget(0, 0) ||
	    test_selector_budget(LHPT_BUDGET_COPIES, LHPT_BUDGET_CLASSES))
		goto bail;

	if (test_calc_budget())
		goto bail;

	if (test_filter_classes(0) ||
	    test_filter_classes(LHPT_FILTER_CLASSES))
		goto bail;

	for (sc = 0; sc < LHPT_SUSP_COUNT; sc++)
		if (test_filter_suspicious(sc, 0) ||
		    test_filter_suspicious(sc, 1))
			goto bail;

	if (content_len != strlen(entity_expect) ||
	    memcmp(content_acc, entity_expect, content_len)) {
		lwsl_err("%s: entity expansion mismatch\n", __func__);
		lwsl_hexdump_err(content_acc, content_len);
		lwsl_hexdump_err(entity_expect, strlen(entity_expect));
		goto bail;
	}

	lwsl_user("Completed: PASS\n");

	return 0;

bail:
	lwsl_user("Completed: FAIL\n");

	return 1;
}
