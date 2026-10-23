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
	 "&nbsp;&iexcl;&yuml;&bogus; &#65 &#x42;&#x43!&#;&#xg&#a1&#00000068i"
	 "</body></html>")
};

/* the last test's body text, once the entities are expanded to utf-8 */

#define ENTITY_TEST_IDX (LWS_ARRAY_SIZE(html_tests) - 1)
static const char * const entity_expect =
	"Dr Alp\xc3\xb6ge \xe2\x82\xac" "5 \xe2\x80\x9cx\xe2\x80\x9d "
	"\xce\xa9&\xc3\xa9\xc2\xa0\xc2\xa1\xc3\xbf&bogus; "
	/*
	 * as in html, a numeric reference's ';' is optional, and one
	 * without digits is just text
	 */
	"A BC!&#;&#xg&#a1Di";

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
 * Selector matching is budgeted in steps, and a step must stand for a bounded
 * amount of work, or the budget bounds nothing.  ctx->sel_work counts that
 * work where it is done (attribute names compared, value bytes scanned,
 * simple selectors and ancestors visited), apart from the steps charged for
 * it, so these tests bound the work itself, not only the steps the library
 * counts (G-529, G-530).
 *
 * A step is at most a compound's first or one further simple selector, with
 * its attribute lookups (a binary search each), and up to a couple of
 * LHP_SEL_SCAN_BYTES of value scanned beyond what is charged for
 */
#define LHPT_WORK_STEP		320
/*
 * The steps cascading one element may take: the document's selectors share
 * one LHP_SEL_CASCADE_BUDGET, the user-agent css's are a few hundred, and the
 * selector that runs out may finish the value it is scanning
 */
#define LHPT_SEL_STEPS_ELEM	(32768 + 4096)
#define LHPT_SEL_WORK_ELEM	((uint64_t)LHPT_SEL_STEPS_ELEM * LHPT_WORK_STEP)

/*
 * Selector matching work must be bounded per element, however the selectors
 * nest.  Each :is() below can only match after its first alternative has
 * backtracked over the remembered siblings looking for a <b> that isn't
 * there, and the descendant chain around them backtracks over the ancestors
 * the same way, so a matcher that renews its step budget inside :is() pays
 * the whole inner budget for every outer step, ~1e7 steps per element.  The
 * elements also repeat a class token that keys more of the same.  The work
 * matching really does for each element is bounded, not the time it takes
 * or the steps counted for it.  These selectors scan no attribute values, so
 * a step is at most a compound or simple selector visited with its attribute
 * lookup, a binary search: a matcher renewing its budget inside :is() does
 * ~60 times the work this allows.
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
#define LHPT_BUDGET_WORK_STEP	16
#define LHPT_BUDGET_WORK_ELEM	((uint64_t)LHPT_SEL_STEPS_ELEM * \
				 LHPT_BUDGET_WORK_STEP)

#define LHPT_SIB8		"b~a~a~a~a~a~a~a~a"
#define LHPT_IS			":is(" LHPT_SIB8 ",a)"

static int budget_elems, budget_a, budget_over, budget_not_matched;

static lws_stateful_ret_t
budget_cb(lhp_ctx_t *ctx, char reason)
{
	lhp_pstack_t *ps = lws_container_of(lws_dll2_get_tail(&ctx->stack),
					    lhp_pstack_t, list);
	const lhp_atr_t *ta;

	if (reason != LHPCB_ELEMENT_START || lws_dll2_is_empty(&ps->atr))
		return 0;

	/* fail at the first element that is over, don't wait for all */

	if (ctx->sel_work > (uint64_t)(budget_elems + 1) *
						LHPT_BUDGET_WORK_ELEM) {
		budget_over = 1;
		return LWS_SRET_FATAL;
	}
	budget_elems++;

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
	budget_elems = budget_a = budget_over = budget_not_matched = 0;

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

	data = (const uint8_t *)doc;
	r = lws_lhp_parse(ctx, &data, &len);

	lwsl_user("%s: copies %d: %d <a>, %llu work, r 0x%x, :not() matched "
		  "%d\n", __func__, copies, budget_a,
		  (unsigned long long)ctx->sel_work, (unsigned int)r,
		  budget_not_matched);

	lws_lhp_destruct(ctx);

	if (budget_over) {
		lwsl_err("%s: over %llu work per element at element %d\n",
			 __func__, (unsigned long long)LHPT_BUDGET_WORK_ELEM,
			 budget_elems + 1);
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
 * The cascade's work per element must be bounded however much css a page
 * has, measured in steps (ctx->cascade_ops), not time.  A sheet of more
 * selectors matching every element than a document may have (most of them
 * an empty *{}), declaring more custom properties than it may have, is
 * applied to a document nested nearly as deep as lhp allows with leaf
 * elements under it.  Unbounded, each element walked every stanza hit so far for every
 * selector it tried (quadratic in the selectors), and every inherited
 * property and var() lookup walked every declaration of every matched stanza
 * at every ancestor level.
 *
 * The leaves must still get the values the cascade gives them: a var()
 * declared on <html> and looked up from the leaves through every level, and
 * one declared on every element twice, where the later wins.  And the
 * document must have been held to its limits on selectors and custom
 * properties.  (The custom properties are declared on <html>, not on every
 * element: thousands of them on every element of 120 levels are more than
 * the document's open elements may hold for their css, LHP_MAX_CSS_LEVEL_HEAP,
 * see test_cascade_level_heap.)
 */

#define LHPT_CW_DECLS		(LHP_MAX_CSS_VARS + 100)
#define LHPT_CW_EMPTY		40000
#define LHPT_CW_NEST		120
#define LHPT_CW_LEAVES		40
/* steps of cascade work allowed per element */
#define LHPT_CW_OPS_PER_ELEM	(3 * LHP_MAX_CSS_SELECTORS)
/* the most steps each byte of css may cost to parse and index */
#define LHPT_OPS_CSS_BYTE	4

static int cw_elems, cw_leaves, cw_leaves_ok, cw_over;
static size_t cw_css_len;

static lws_stateful_ret_t
cw_cb(lhp_ctx_t *ctx, char reason)
{
	lhp_pstack_t *ps = lws_container_of(lws_dll2_get_tail(&ctx->stack),
					    lhp_pstack_t, list);
	const lhp_atr_t *ta;

	if (reason != LHPCB_ELEMENT_START || lws_dll2_is_empty(&ps->atr))
		return 0;

	cw_elems++;

	/* fail at the first element that is over, don't wait for all */

	if (ctx->cascade_ops > (uint64_t)cw_elems * LHPT_CW_OPS_PER_ELEM +
			       (uint64_t)cw_css_len * LHPT_OPS_CSS_BYTE) {
		cw_over = 1;
		return LWS_SRET_FATAL;
	}

	ta = lws_container_of(lws_dll2_get_head(&ps->atr), lhp_atr_t, list);
	if (ta->name_len != 1 || *(const char *)&ta[1] != 'p')
		return 0;

	cw_leaves++;
	if (ps->css_width && ps->css_width->u.i.whole == 7 &&
	    ps->css_height && ps->css_height->u.i.whole == 2)
		cw_leaves_ok++;

	return 0;
}

static int
test_cascade_work(void)
{
	size_t alloc = 512 * 1024, len;
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
	cw_elems = cw_leaves = cw_leaves_ok = cw_over = 0;

	p = doc;
	p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
			  "<html><head><style>*{--vdup:1px}\n*{--vdup:2px}\n"
			  "p{width:var(--v7)}\np{height:var(--vdup)}\n");
	for (i = 0; i < LHPT_CW_DECLS; i++)
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  "html{--v%d:%dpx}\n*{margin-left:1px}\n",
				  i, i);
	for (i = 0; i < LHPT_CW_EMPTY; i++)
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  "*{}");
	/* the css counts too, as it is parsed and indexed */
	cw_css_len = lws_ptr_diff_size_t(p, doc);
	p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
			  "</style></head><body>");
	for (i = 0; i < LHPT_CW_NEST; i++)
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  "<div>");
	for (i = 0; i < LHPT_CW_LEAVES; i++)
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  "<p>x</p>");
	for (i = 0; i < LHPT_CW_NEST; i++)
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  "</div>");
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

	if (lws_lhp_construct(ctx, cw_cb, &drt, &ic))
		goto bail;
	ctx->flags = LHP_FLAG_DOCUMENT_END;
	ctx->base_url = strdup("");

	data = (const uint8_t *)doc;
	r = lws_lhp_parse(ctx, &data, &len);

	lwsl_user("%s: %d elements, %llu cascade steps (%llu per element), "
		  "%u selectors, %u custom properties kept, r 0x%x\n",
		  __func__, cw_elems, (unsigned long long)ctx->cascade_ops,
		  (unsigned long long)(cw_elems ?
				ctx->cascade_ops / (unsigned int)cw_elems : 0),
		  (unsigned int)ctx->css_doc_selectors,
		  (unsigned int)ctx->css_doc_vars, (unsigned int)r);

	if (cw_over) {
		lwsl_err("%s: cascade took over %d steps per element\n",
			 __func__, LHPT_CW_OPS_PER_ELEM);
		goto bail_destruct;
	}
	if (r & LWS_SRET_FATAL || cw_leaves != LHPT_CW_LEAVES) {
		lwsl_err("%s: parse failed, %d leaves\n", __func__, cw_leaves);
		goto bail_destruct;
	}
	if (ctx->css_doc_selectors != LHP_MAX_CSS_SELECTORS) {
		lwsl_err("%s: %u selectors kept, expected the limit %d\n",
			 __func__, (unsigned int)ctx->css_doc_selectors,
			 LHP_MAX_CSS_SELECTORS);
		goto bail_destruct;
	}
	if (ctx->css_doc_vars != LHP_MAX_CSS_VARS) {
		lwsl_err("%s: %u custom properties kept, expected the limit "
			 "%d\n", __func__, (unsigned int)ctx->css_doc_vars,
			 LHP_MAX_CSS_VARS);
		goto bail_destruct;
	}
	if (cw_leaves_ok != LHPT_CW_LEAVES) {
		lwsl_err("%s: only %d of %d leaves got their css\n", __func__,
			 cw_leaves_ok, LHPT_CW_LEAVES);
		goto bail_destruct;
	}

	e = 0;

bail_destruct:
	lws_lhp_destruct(ctx);
bail:
	free(ctx);
	free(doc);

	return e;
}

/*
 * The cascade's work per document must be bounded too, not only per element.
 * A sheet of as many selectors as a document may have, every one a
 * non-empty *{} so that each matches every element, made each element cost
 * matching all of them and sorting all of them and their declarations: a
 * ~600KB page of it with a couple of thousand cheap elements held the event
 * loop for most of a minute, linear in the elements.  The document's
 * cascade work is now limited to LHP_MAX_CSS_CASCADE_OPS steps; after that,
 * its own css is ignored with a warning and elements get only the user-agent
 * (and any filter) css.
 *
 * So whatever the element count, the document's cascade steps stay within
 * the limit, plus what one element can cost with the document's css, plus
 * what each element costs with only the user-agent css.  The early elements
 * get the document's css, the later ones still parse and get the
 * user-agent's.
 */

#define LHPT_DB_ELEMS		3000
/* most steps one element can cost with the document's css */
#define LHPT_DB_OPS_ELEM	(8 * LHP_MAX_CSS_SELECTORS)
/* ... and with only the user-agent's */
#define LHPT_DB_OPS_UA		2048
#define LHPT_DB_OPS_MAX(_e)	((uint64_t)LHP_MAX_CSS_CASCADE_OPS + \
				 LHPT_DB_OPS_ELEM + \
				 (uint64_t)(_e) * LHPT_DB_OPS_UA)

static int db_elems, db_styled, db_unstyled, db_over;

static lws_stateful_ret_t
db_cb(lhp_ctx_t *ctx, char reason)
{
	lhp_pstack_t *ps = lws_container_of(lws_dll2_get_tail(&ctx->stack),
					    lhp_pstack_t, list);
	const lcsp_atr_t *ml;
	const lhp_atr_t *ta;

	if (reason != LHPCB_ELEMENT_START || lws_dll2_is_empty(&ps->atr))
		return 0;

	/* fail at the first element that is over, don't wait for all */

	if (ctx->cascade_ops > LHPT_DB_OPS_MAX(db_elems + 1)) {
		db_over = 1;
		return LWS_SRET_FATAL;
	}

	ta = lws_container_of(lws_dll2_get_head(&ps->atr), lhp_atr_t, list);
	if (ta->name_len != 1 || *(const char *)&ta[1] != 'p')
		return 0;

	db_elems++;
	ml = lws_css_cascade_get_prop_atr(ctx, LCSP_PROP_MARGIN_LEFT);
	if (ml && ml->unit == LCSP_UNIT_LENGTH_PX && ml->u.i.whole == 1)
		db_styled++;
	else
		db_unstyled++;

	return 0;
}

static int
test_cascade_doc_budget(void)
{
	size_t alloc = (size_t)LHP_MAX_CSS_SELECTORS * 20 +
		       LHPT_DB_ELEMS * 8 + 256, len;
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
	db_elems = db_styled = db_unstyled = db_over = 0;

	p = doc;
	p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
			  "<html><head><style>");
	for (i = 0; i < LHP_MAX_CSS_SELECTORS; i++)
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  "*{margin-left:1px}");
	p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
			  "</style></head><body>");
	for (i = 0; i < LHPT_DB_ELEMS; i++)
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  "<p>x</p>");
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

	if (lws_lhp_construct(ctx, db_cb, &drt, &ic))
		goto bail;
	ctx->flags = LHP_FLAG_DOCUMENT_END;
	ctx->base_url = strdup("");

	data = (const uint8_t *)doc;
	r = lws_lhp_parse(ctx, &data, &len);

	lwsl_user("%s: %d elements (%d with the document's css), %llu cascade "
		  "steps, r 0x%x\n", __func__, db_elems, db_styled,
		  (unsigned long long)ctx->cascade_ops, (unsigned int)r);

	if (db_over) {
		lwsl_err("%s: the document's cascade took over %llu steps\n",
			 __func__,
			 (unsigned long long)LHPT_DB_OPS_MAX(db_elems + 1));
		goto bail_destruct;
	}
	if (r & LWS_SRET_FATAL || db_elems != LHPT_DB_ELEMS) {
		lwsl_err("%s: parse failed, %d elements\n", __func__,
			 db_elems);
		goto bail_destruct;
	}
	if (!db_styled || !db_unstyled) {
		lwsl_err("%s: expected the document's css on the first "
			 "elements and not on the last\n", __func__);
		goto bail_destruct;
	}

	e = 0;

bail_destruct:
	lws_lhp_destruct(ctx);
bail:
	free(ctx);
	free(doc);

	return e;
}

/*
 * The heap the cascade holds for the open elements must be bounded per
 * document, not only per element.  Each open level kept every stanza it
 * matched and an index of the declarations that win for it, so css whose
 * selectors all match every element, under deep nesting, cost that again at
 * every level: 32768 *{} (590KB) under 127 nested <div> held 80MB.  Now a
 * level keeps only its declaration index once it is cascaded, and when the
 * open levels hold LHP_MAX_CSS_LEVEL_HEAP, the document's css is ignored for
 * the rest of it, as when its css work budget is spent.
 *
 * So with a sheet at the selector limit that matches every element and
 * declares as many custom properties as a document may have, under nesting
 * as deep as lhp allows, what the open levels hold must stay within the
 * limit plus what one element can hold, counted by lhp, summed from the
 * levels, and measured as lws heap; the first levels must get the document's
 * css and the deepest must still parse, without it.
 */

#define LHPT_LH_NEST		(LHP_MAX_ELEMS_NEST - 4)
/* lhp.c's lhp_decl_t, a pointer and a uint32_t, at least */
#define LHPT_LH_DECL_MIN	(sizeof(void *) + sizeof(uint32_t))
#define LHPT_LH_DECL_MAX	(2 * sizeof(void *))
/* the most one element can hold: its matched stanzas and declarations */
#define LHPT_LH_ELEM		(0xffffu * sizeof(lcsp_match_t) + \
				 (LHP_MAX_CSS_VARS + LCSP_PROP__COUNT) * \
						 LHPT_LH_DECL_MAX)
#define LHPT_LH_MAX		(LHP_MAX_CSS_LEVEL_HEAP + LHPT_LH_ELEM)
/* lws heap of a level besides its css: the level, its attributes... */
#define LHPT_LH_LEVEL		1024

static size_t lh_peak_lhp, lh_peak_sum, lh_peak_heap, lh_heap_base;
static int lh_elems, lh_styled, lh_unstyled, lh_over;

static lws_stateful_ret_t
lh_cb(lhp_ctx_t *ctx, char reason)
{
	lhp_pstack_t *ps = lws_container_of(lws_dll2_get_tail(&ctx->stack),
					    lhp_pstack_t, list);
	const lcsp_atr_t *ml;
	const lhp_atr_t *ta;
	size_t sum = 0, heap;

	if (reason != LHPCB_ELEMENT_START || lws_dll2_is_empty(&ps->atr))
		return 0;

	ta = lws_container_of(lws_dll2_get_head(&ps->atr), lhp_atr_t, list);
	if (ta->name_len == 4 && !strncmp((const char *)&ta[1], "body", 4)) {
		/* the stylesheet and anything kept for the whole document
		 * are allocated by now: count from here */
		lh_heap_base = lws_get_allocated_heap();
		return 0;
	}
	if (ta->name_len != 3 || strncmp((const char *)&ta[1], "div", 3))
		return 0;

	lh_elems++;

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&ctx->stack)) {
		const lhp_pstack_t *l = lws_container_of(d, lhp_pstack_t,
							 list);

		sum += l->nmatched * sizeof(lcsp_match_t) +
		       l->ndecl * LHPT_LH_DECL_MIN;
	} lws_end_foreach_dll(d);

	heap = lws_get_allocated_heap();
	heap = heap > lh_heap_base ? heap - lh_heap_base : 0;

	if (ctx->css_level_heap > lh_peak_lhp)
		lh_peak_lhp = ctx->css_level_heap;
	if (sum > lh_peak_sum)
		lh_peak_sum = sum;
	if (heap > lh_peak_heap)
		lh_peak_heap = heap;

	/* fail at the first element that is over, don't wait for all */

	if (ctx->css_level_heap > LHPT_LH_MAX || sum > LHPT_LH_MAX ||
	    heap > LHPT_LH_MAX + (size_t)lh_elems * LHPT_LH_LEVEL) {
		lh_over = 1;
		return LWS_SRET_FATAL;
	}

	ml = lws_css_cascade_get_prop_atr(ctx, LCSP_PROP_MARGIN_LEFT);
	if (ml && ml->unit == LCSP_UNIT_LENGTH_PX && ml->u.i.whole == 1)
		lh_styled++;
	else
		lh_unstyled++;

	return 0;
}

static int
test_cascade_level_heap(void)
{
	size_t alloc = (size_t)LHP_MAX_CSS_SELECTORS * 32 +
		       LHPT_LH_NEST * 16 + 256, len;
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
	lh_peak_lhp = lh_peak_sum = lh_peak_heap = lh_heap_base = 0;
	lh_elems = lh_styled = lh_unstyled = lh_over = 0;

	p = doc;
	p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
			  "<html><head><style>");
	for (i = 0; i < LHP_MAX_CSS_SELECTORS; i++)
		if (i < LHP_MAX_CSS_VARS)
			p += lws_snprintf(p, alloc -
					  lws_ptr_diff_size_t(p, doc),
					  "*{--v%d:1px;margin-left:1px}", i);
		else
			p += lws_snprintf(p, alloc -
					  lws_ptr_diff_size_t(p, doc),
					  "*{margin-left:1px}");
	p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
			  "</style></head><body>");
	for (i = 0; i < LHPT_LH_NEST; i++)
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  "<div>");
	p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc), "x");
	for (i = 0; i < LHPT_LH_NEST; i++)
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  "</div>");
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

	if (lws_lhp_construct(ctx, lh_cb, &drt, &ic))
		goto bail;
	ctx->flags = LHP_FLAG_DOCUMENT_END;
	ctx->base_url = strdup("");

	data = (const uint8_t *)doc;
	r = lws_lhp_parse(ctx, &data, &len);

	lwsl_user("%s: %d levels (%d with the document's css), held at most "
		  "%llu (lhp) %llu (levels) %llu (lws heap), r 0x%x\n",
		  __func__, lh_elems, lh_styled,
		  (unsigned long long)lh_peak_lhp,
		  (unsigned long long)lh_peak_sum,
		  (unsigned long long)lh_peak_heap, (unsigned int)r);

	if (lh_over) {
		lwsl_err("%s: the open levels held over %llu at level %d\n",
			 __func__, (unsigned long long)LHPT_LH_MAX, lh_elems);
		goto bail_destruct;
	}
	if (r & LWS_SRET_FATAL || lh_elems != LHPT_LH_NEST) {
		lwsl_err("%s: parse failed, %d levels\n", __func__, lh_elems);
		goto bail_destruct;
	}
	if (!lh_styled || !lh_unstyled) {
		lwsl_err("%s: expected the document's css on the first levels "
			 "and not on the deepest\n", __func__);
		goto bail_destruct;
	}
	if (ctx->css_level_heap) {
		lwsl_err("%s: %llu still counted with every level closed\n",
			 __func__, (unsigned long long)ctx->css_level_heap);
		goto bail_destruct;
	}

	e = 0;

bail_destruct:
	lws_lhp_destruct(ctx);
bail:
	free(ctx);
	free(doc);

	return e;
}

/*
 * <html> is cascaded again each time a <body> starts directly under it, so
 * that the stylesheets in the head apply to it.  Each of those cascades used
 * to parse its style="" attribute again into its styleac, which only grows
 * while <html> is open, ie for the whole document, and wasn't counted in any
 * budget: a 2KB style="" of custom properties on <html> and 2000
 * <head></head><body></body> (28KB) held 74MB (G-666).
 *
 * So the heap <html> holds for its style="" must be the same at the last
 * <body> as at the first, it must be counted in the open levels' heap, and
 * the style must still apply at each <body>.
 */

#define LHPT_SR_BODIES		2000

static size_t sr_first, sr_peak;
static int sr_bodies, sr_styled, sr_uncounted, sr_over;

static lws_stateful_ret_t
sr_cb(lhp_ctx_t *ctx, char reason)
{
	lhp_pstack_t *ps = lws_container_of(lws_dll2_get_tail(&ctx->stack),
					    lhp_pstack_t, list), *html = NULL;
	const lcsp_atr_t *col;
	const lhp_atr_t *ta;
	size_t sa;

	if (reason != LHPCB_ELEMENT_START || lws_dll2_is_empty(&ps->atr))
		return 0;

	ta = lws_container_of(lws_dll2_get_head(&ps->atr), lhp_atr_t, list);
	if (ta->name_len != 4 || strncmp((const char *)&ta[1], "body", 4))
		return 0;

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&ctx->stack)) {
		lhp_pstack_t *l = lws_container_of(d, lhp_pstack_t, list);

		if (!lws_dll2_is_empty(&l->atr)) {
			ta = lws_container_of(lws_dll2_get_head(&l->atr),
					      lhp_atr_t, list);
			if (ta->name_len == 4 &&
			    !strncmp((const char *)&ta[1], "html", 4))
				html = l;
		}
	} lws_end_foreach_dll(d);

	if (!html)
		return LWS_SRET_FATAL;

	sr_bodies++;
	sa = lwsac_total_alloc(html->styleac);
	if (!sr_first)
		sr_first = sa;
	if (sa > sr_peak)
		sr_peak = sa;
	if (ctx->css_level_heap < sa)
		sr_uncounted = 1;

	/* fail at the first body that is over, don't wait for all */

	if (!sr_first || sa > sr_first) {
		sr_over = 1;
		return LWS_SRET_FATAL;
	}

	col = lws_css_cascade_get_prop_atr(ctx, LCSP_PROP_COLOR);
	if (col && col->unit == LCSP_UNIT_RGBA &&
	    col->u.rgba == LWSDC_RGBA(0x12, 0x34, 0x56, 0xff))
		sr_styled++;

	return 0;
}

static int
test_style_recascade(void)
{
	size_t alloc = LHP_STRING_CHUNK + LHPT_SR_BODIES * 32 + 256, len;
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
	sr_first = sr_peak = 0;
	sr_bodies = sr_styled = sr_uncounted = sr_over = 0;

	p = doc;
	p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
			  "<html style=\"");
	for (i = 0; lws_ptr_diff_size_t(p, doc) < LHP_STRING_CHUNK - 64; i++)
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  "--v%d:1px;", i);
	p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
			  "color:#123456\">");
	for (i = 0; i < LHPT_SR_BODIES; i++)
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  "<head></head><body></body>");
	p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc), "</html>");
	len = lws_ptr_diff_size_t(p, doc);
	if (len >= alloc - 1) {
		lwsl_err("%s: document doesn't fit\n", __func__);
		goto bail;
	}

	memset(&drt, 0, sizeof(drt));
	drt.dl = &displaylist;
	drt.w = ic.wh_px[0].whole;
	drt.h = ic.wh_px[1].whole;

	if (lws_lhp_construct(ctx, sr_cb, &drt, &ic))
		goto bail;
	ctx->flags = LHP_FLAG_DOCUMENT_END;
	ctx->base_url = strdup("");

	data = (const uint8_t *)doc;
	r = lws_lhp_parse(ctx, &data, &len);

	lwsl_user("%s: %d bodies (%d styled), <html> styleac %llu at the "
		  "first, at most %llu, r 0x%x\n", __func__, sr_bodies,
		  sr_styled, (unsigned long long)sr_first,
		  (unsigned long long)sr_peak, (unsigned int)r);

	if (sr_over) {
		lwsl_err("%s: <html>'s styleac grew to %llu by body %d\n",
			 __func__, (unsigned long long)sr_peak, sr_bodies);
		goto bail_destruct;
	}
	if (r & LWS_SRET_FATAL || sr_bodies != LHPT_SR_BODIES) {
		lwsl_err("%s: parse failed, %d bodies\n", __func__, sr_bodies);
		goto bail_destruct;
	}
	if (sr_uncounted) {
		lwsl_err("%s: <html>'s styleac isn't counted in the open "
			 "levels' heap\n", __func__);
		goto bail_destruct;
	}
	if (sr_styled != LHPT_SR_BODIES) {
		lwsl_err("%s: <html>'s style applied at %d of %d bodies\n",
			 __func__, sr_styled, LHPT_SR_BODIES);
		goto bail_destruct;
	}

	e = 0;

bail_destruct:
	lws_lhp_destruct(ctx);
bail:
	free(ctx);
	free(doc);

	return e;
}

/*
 * The bytes of a style="" attribute are the document's css as much as a
 * stylesheet's, and count in its css work budget the same way (G-666).  So a
 * page whose one element has a long style="" must cost at least its bytes
 * more than the same page without it.  The style is one declaration repeated,
 * so the declaration index adds little: the difference is in the bytes.
 */

static lws_stateful_ret_t
noop_cb(lhp_ctx_t *ctx, char reason)
{
	(void)ctx;
	(void)reason;

	return 0;
}

static int
style_attr_ops(const char *style, uint64_t *ops)
{
	char doc[LHP_STRING_CHUNK + 128];
	lws_stateful_ret_t r;
	const uint8_t *data;
	lws_dl_rend_t drt;
	lhp_ctx_t *ctx;
	size_t len;

	ctx = malloc(sizeof(*ctx));
	if (!ctx)
		return 1;
	memset(ctx, 0, sizeof(*ctx));

	len = (size_t)lws_snprintf(doc, sizeof(doc), "<html><body><p%s%s%s>"
				   "x</p></body></html>", *style ? " style=\"" :
				   "", style, *style ? "\"" : "");

	memset(&drt, 0, sizeof(drt));
	drt.dl = &displaylist;
	drt.w = ic.wh_px[0].whole;
	drt.h = ic.wh_px[1].whole;

	if (lws_lhp_construct(ctx, noop_cb, &drt, &ic)) {
		free(ctx);
		return 1;
	}
	ctx->flags = LHP_FLAG_DOCUMENT_END;
	ctx->base_url = strdup("");

	data = (const uint8_t *)doc;
	r = lws_lhp_parse(ctx, &data, &len);
	*ops = ctx->cascade_ops;

	lws_lhp_destruct(ctx);
	free(ctx);

	return !!(r & LWS_SRET_FATAL);
}

static int
test_style_attr_budget(void)
{
	char style[LHP_STRING_CHUNK - 64];
	uint64_t with, without;
	size_t n = 0;

	while (n + 16 < sizeof(style))
		n += (size_t)lws_snprintf(style + n, sizeof(style) - n,
					  "margin-left:1px;");

	if (style_attr_ops("", &without) || style_attr_ops(style, &with)) {
		lwsl_err("%s: parse failed\n", __func__);
		return 1;
	}

	lwsl_user("%s: %llu steps with a %d byte style=\"\", %llu without\n",
		  __func__, (unsigned long long)with, (int)n,
		  (unsigned long long)without);

	if (with < without + n) {
		lwsl_err("%s: the style=\"\" bytes aren't counted\n", __func__);
		return 1;
	}

	return 0;
}

/*
 * The document's css work must be bounded however its <style> blocks are
 * interleaved with its elements.  The selector index used to be made again
 * from every stanza whenever an element found the stanza count changed, and
 * that work wasn't counted against the document's budget, so a page
 * alternating an element with a tiny <style> block was quadratic: 64000 of
 * them (830KB) took 21s.  Each stanza is now indexed once, the indexing and
 * the css parsing count against the budget, and stanzas that can't style
 * anything aren't kept at all: a nameless one, one with no declarations, or
 * one past the selector limit.
 *
 * So a document of elements each followed by such a <style> block must cost
 * at most what its elements cost with only the user-agent css, plus a few
 * steps per byte of its css, it must keep only the stanzas with selectors
 * and declarations, and a rule must still apply to the elements after it,
 * until the selector limit is reached.
 */

#define LHPT_IS_REPS		(LHP_MAX_CSS_SELECTORS / 2 + 4000)
#define LHPT_IS_REP		"<p>x</p><style>.q{}{}.r{margin-left:1px}</style>"
#define LHPT_IS_EARLY		"<style>p.a{margin-left:2px}</style>"
#define LHPT_IS_MID		"<style>p.b{margin-left:3px}</style>"
#define LHPT_IS_LATE		"<style>p.c{margin-left:4px}</style>"
#define LHPT_IS_OPS_MAX(_e)	((uint64_t)(_e) * (LHPT_DB_OPS_UA + \
				 LHPT_OPS_CSS_BYTE * sizeof(LHPT_IS_REP)) + \
				 4 * LHP_MAX_CSS_SELECTORS)

static int is_elems, is_over, is_a, is_b, is_c, is_ua_stz;

static lws_stateful_ret_t
is_cb(lhp_ctx_t *ctx, char reason)
{
	lhp_pstack_t *ps = lws_container_of(lws_dll2_get_tail(&ctx->stack),
					    lhp_pstack_t, list);
	const lcsp_atr_t *ml;
	const lhp_atr_t *ta;
	const char *cls;

	if (reason != LHPCB_ELEMENT_START || lws_dll2_is_empty(&ps->atr))
		return 0;

	if (!is_ua_stz)
		/* the first element: only the user-agent css is listed */
		is_ua_stz = (int)ctx->css.count + 1;

	ta = lws_container_of(lws_dll2_get_head(&ps->atr), lhp_atr_t, list);
	if (ta->name_len != 1 || *(const char *)&ta[1] != 'p')
		return 0;

	/* fail at the first element that is over, don't wait for all */

	if (ctx->cascade_ops > LHPT_IS_OPS_MAX(is_elems + 1)) {
		is_over = 1;
		return LWS_SRET_FATAL;
	}

	is_elems++;
	cls = lws_html_get_atr(ps, "class", 5);
	if (!cls)
		return 0;

	ml = lws_css_cascade_get_prop_atr(ctx, LCSP_PROP_MARGIN_LEFT);
	if (!ml || ml->unit != LCSP_UNIT_LENGTH_PX)
		return 0;

	switch (*cls) {
	case 'a':
		is_a = ml->u.i.whole == 2;
		break;
	case 'b':
		is_b = ml->u.i.whole == 3;
		break;
	case 'c':
		is_c = ml->u.i.whole == 4;
		break;
	}

	return 0;
}

static int
test_interleaved_style(void)
{
	size_t alloc = (size_t)LHPT_IS_REPS * sizeof(LHPT_IS_REP) + 1024, len;
	lws_stateful_ret_t r;
	const uint8_t *data;
	unsigned int kept;
	lws_dl_rend_t drt;
	lhp_ctx_t *ctx;
	char *doc, *p;
	int e = 1, i;

	doc = malloc(alloc);
	ctx = malloc(sizeof(*ctx));
	if (!doc || !ctx)
		goto bail;
	memset(ctx, 0, sizeof(*ctx));
	is_elems = is_over = is_a = is_b = is_c = is_ua_stz = 0;

	p = doc;
	p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
			  "<html><body>" LHPT_IS_EARLY);
	for (i = 0; i < LHPT_IS_REPS; i++) {
		if (i == LHP_MAX_CSS_SELECTORS / 4)
			p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
					  LHPT_IS_MID);
		if (i == LHPT_IS_REPS - 1)
			/* past the selector limit by now */
			p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
					  LHPT_IS_LATE);
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  LHPT_IS_REP);
	}
	p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
			  "<p class=a>x</p><p class=b>x</p><p class=c>x</p>"
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

	if (lws_lhp_construct(ctx, is_cb, &drt, &ic))
		goto bail;
	ctx->flags = LHP_FLAG_DOCUMENT_END;
	ctx->base_url = strdup("");

	data = (const uint8_t *)doc;
	r = lws_lhp_parse(ctx, &data, &len);

	kept = (unsigned int)ctx->css.count - (unsigned int)(is_ua_stz - 1);
	lwsl_user("%s: %d elements, %llu cascade steps, %u selectors, %u "
		  "stanzas kept, r 0x%x\n", __func__, is_elems,
		  (unsigned long long)ctx->cascade_ops,
		  (unsigned int)ctx->css_doc_selectors, kept, (unsigned int)r);

	if (is_over) {
		lwsl_err("%s: the document's css took over %llu steps at "
			 "element %d\n", __func__,
			 (unsigned long long)LHPT_IS_OPS_MAX(is_elems + 1),
			 is_elems + 1);
		goto bail_destruct;
	}
	if (r & LWS_SRET_FATAL || is_elems != LHPT_IS_REPS + 3) {
		lwsl_err("%s: parse failed, %d elements\n", __func__,
			 is_elems);
		goto bail_destruct;
	}
	/* each .r{} with a declaration is kept, each .q{} and {} isn't */
	if (kept > ctx->css_doc_selectors / 2 + 2) {
		lwsl_err("%s: %u stanzas kept for %u selectors\n", __func__,
			 kept, (unsigned int)ctx->css_doc_selectors);
		goto bail_destruct;
	}
	if (!is_a || !is_b || is_c) {
		lwsl_err("%s: rules applied: early %d, mid %d, past the "
			 "limit %d\n", __func__, is_a, is_b, is_c);
		goto bail_destruct;
	}

	e = 0;

bail_destruct:
	lws_lhp_destruct(ctx);
bail:
	free(ctx);
	free(doc);

	return e;
}

/*
 * Selector matching steps must be bounded amounts of work too.  A compound
 * like [x*="aaa...ab"] compares up to the attribute value's length times the
 * pattern's, thousands of bytes, but counted as one step of the element's
 * selector budget and none of the document's: 1000 such selectors over 1000
 * elements with a long x="aaa..." (1.6MB) took 210s under ASan.  A compound
 * now costs a step per 64 bytes it may compare as well, and every selector
 * step counts in ctx->cascade_ops.
 *
 * So with selectors like that matching every element, the bytes each
 * element's matching really compares (ctx->sel_work) must stay within what
 * its selector budget stands for, and a short value must still match.
 * Bounding the steps alone proves nothing here: with the scans not charged,
 * the steps counted stay small while the work is back (G-530).
 */

#define LHPT_SS_SELS		1000
#define LHPT_SS_PAT		100
#define LHPT_SS_ELEMS		300
#define LHPT_SS_VAL		2000

static int ss_elems, ss_short_ok, ss_over;

static lws_stateful_ret_t
ss_cb(lhp_ctx_t *ctx, char reason)
{
	lhp_pstack_t *ps = lws_container_of(lws_dll2_get_tail(&ctx->stack),
					    lhp_pstack_t, list);
	const lcsp_atr_t *ml;
	const lhp_atr_t *ta;
	const char *x;

	if (reason != LHPCB_ELEMENT_START || lws_dll2_is_empty(&ps->atr))
		return 0;

	ta = lws_container_of(lws_dll2_get_head(&ps->atr), lhp_atr_t, list);
	if (ta->name_len != 1 || *(const char *)&ta[1] != 'p')
		return 0;

	/* fail at the first element that is over, don't wait for all */

	if (ctx->sel_work > (uint64_t)(ss_elems + 1) * LHPT_SEL_WORK_ELEM) {
		ss_over = 1;
		return LWS_SRET_FATAL;
	}
	ss_elems++;

	x = lws_html_get_atr(ps, "x", 1);
	ml = lws_css_cascade_get_prop_atr(ctx, LCSP_PROP_MARGIN_LEFT);
	if (x && !strcmp(x, "zzq") && ml && ml->unit == LCSP_UNIT_LENGTH_PX &&
	    ml->u.i.whole == 2)
		ss_short_ok = 1;

	return 0;
}

static int
test_selector_scan(void)
{
	size_t alloc = (size_t)LHPT_SS_SELS * (LHPT_SS_PAT + 48) +
		       (size_t)LHPT_SS_ELEMS * (LHPT_SS_VAL + 16) + 512, len;
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
	ss_elems = ss_short_ok = ss_over = 0;

	p = doc;
	p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
			  "<html><head><style>p[x*=\"q\"]{margin-left:2px}");
	for (i = 0; i < LHPT_SS_SELS; i++) {
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  "*[x*=\"");
		memset(p, 'a', LHPT_SS_PAT);
		p += LHPT_SS_PAT;
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  "b%d\"]{margin-left:1px}", i);
	}
	p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
			  "</style></head><body><p x=\"zzq\">x</p>");
	for (i = 0; i < LHPT_SS_ELEMS; i++) {
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  "<p x=\"");
		memset(p, 'a', LHPT_SS_VAL);
		p += LHPT_SS_VAL;
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  "\">x</p>");
	}
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

	if (lws_lhp_construct(ctx, ss_cb, &drt, &ic))
		goto bail;
	ctx->flags = LHP_FLAG_DOCUMENT_END;
	ctx->base_url = strdup("");

	data = (const uint8_t *)doc;
	r = lws_lhp_parse(ctx, &data, &len);

	lwsl_user("%s: %d elements, %llu cascade steps, %llu work, r 0x%x\n",
		  __func__, ss_elems, (unsigned long long)ctx->cascade_ops,
		  (unsigned long long)ctx->sel_work, (unsigned int)r);

	if (ss_over) {
		lwsl_err("%s: over %llu work per element at element %d\n",
			 __func__, (unsigned long long)LHPT_SEL_WORK_ELEM,
			 ss_elems + 1);
		goto bail_destruct;
	}
	if (r & LWS_SRET_FATAL || ss_elems != LHPT_SS_ELEMS + 1) {
		lwsl_err("%s: parse failed, %d elements\n", __func__,
			 ss_elems);
		goto bail_destruct;
	}
	if (!ss_short_ok) {
		lwsl_err("%s: the short value didn't match\n", __func__);
		goto bail_destruct;
	}

	e = 0;

bail_destruct:
	lws_lhp_destruct(ctx);
bail:
	free(ctx);
	free(doc);

	return e;
}

/*
 * A budget step must be a bounded amount of work however long the compound
 * selector it is for and however many attributes the element has.  Each
 * simple selector of a compound, [z] or .a, walked the element's attributes
 * (up to 64) and maybe scanned the class, while the whole compound cost one
 * step: 256 selectors of forty [z] over 120 nested <div y=1 (x62) z=1> took
 * 195s (release) before the document's css budget ended them.  Each simple
 * selector now costs a step, and finds its attribute by a binary search of
 * the element's attribute index.
 *
 * So with compounds of many simple selectors that only fail on their last,
 * tried against every ancestor of every element, the work selector matching
 * does for an element must stay within what its steps stand for.  And the
 * index must find attributes as the walk did: by name ignoring case, and the
 * first of a repeated name.
 *
 * These steps scan no values to speak of (test_selector_values fences
 * that), so the allowance is near what one really costs, not LHPT_WORK_STEP:
 * a simple selector with its index probes and one short name compared,
 * ~8 units of work.  The work is also charged, a step per LHP_SEL_STEP_WORK
 * units, so taking away the step for every other simple selector only
 * raises the work per step ~1.5x, not 2x: the allowance is ~1.25x what it
 * costs, so that is red as well as taking the step away altogether (~3x).
 * An allowance of 96, or one sized for compounds that scan long class
 * values, left a step per two simple selectors green (G-541).
 */

#define LHPT_SC_SELS		128	/* of each kind */
#define LHPT_SC_ATRS		40	/* [z] in a compound */
#define LHPT_SC_CLASSES		58	/* .a in a compound */
#define LHPT_SC_NEST		60
#define LHPT_SC_JUNK		2	/* class bytes before the a */
#define LHPT_SC_WORK_STEP	10
#define LHPT_SC_WORK_ELEM	((uint64_t)LHPT_SEL_STEPS_ELEM * \
				 LHPT_SC_WORK_STEP)

static int sc_elems, sc_ok, sc_over;

static lws_stateful_ret_t
sc_cb(lhp_ctx_t *ctx, char reason)
{
	lhp_pstack_t *ps = lws_container_of(lws_dll2_get_tail(&ctx->stack),
					    lhp_pstack_t, list);
	const lcsp_atr_t *ml;
	const char *x;

	if (reason != LHPCB_ELEMENT_START || lws_dll2_is_empty(&ps->atr))
		return 0;

	/* fail at the first element that is over, don't wait for all */

	if (ctx->sel_work > (uint64_t)(sc_elems + 1) * LHPT_SC_WORK_ELEM) {
		sc_over = 1;
		return LWS_SRET_FATAL;
	}
	sc_elems++;

	x = lws_html_get_atr(ps, "x", 1);
	ml = lws_css_cascade_get_prop_atr(ctx, LCSP_PROP_MARGIN_LEFT);
	if (x && !strcmp(x, "ok") && ml && ml->unit == LCSP_UNIT_LENGTH_PX &&
	    ml->u.i.whole == 2)
		sc_ok = 1;

	return 0;
}

static int
test_selector_compound(void)
{
	size_t alloc = (size_t)LHPT_SC_SELS * 2 *
			(LHPT_SC_ATRS * 3 + LHPT_SC_CLASSES * 2 + 48) +
		       (size_t)LHPT_SC_NEST * (64 * 4 + LHPT_SC_JUNK + 32) +
		       1024, len;
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
	sc_elems = sc_ok = sc_over = 0;

	/*
	 * The rule that matches: attribute names ignore case, and the first
	 * of a repeated attribute is the one that counts
	 */
	p = doc;
	p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
			  "<html><head><style>"
			  "p[Y=\"2\"][z][class~=b].a.b{margin-left:2px}\n");
	for (i = 0; i < LHPT_SC_SELS; i++) {
		for (j = 0; j < LHPT_SC_ATRS; j++)
			p += lws_snprintf(p, alloc -
					  lws_ptr_diff_size_t(p, doc), "[z]");
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  "[q] *{margin-left:1px}\n");
		for (j = 0; j < LHPT_SC_CLASSES; j++)
			p += lws_snprintf(p, alloc -
					  lws_ptr_diff_size_t(p, doc), ".a");
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  ".q *{margin-left:1px}\n");
	}
	p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
			  "</style></head><body>"
			  "<p z=1 y=2 Y=3 class=\"b a\" x=ok>x</p>");
	for (i = 0; i < LHPT_SC_NEST; i++) {
		/* the tag and 64 attributes, the most an element keeps */
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  "<div");
		for (j = 0; j < 61; j++)
			p += lws_snprintf(p, alloc -
					  lws_ptr_diff_size_t(p, doc), " y=1");
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  " z=1 class=\"");
		memset(p, 'j', LHPT_SC_JUNK);
		p += LHPT_SC_JUNK;
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  " a\">");
	}
	for (i = 0; i < LHPT_SC_NEST; i++)
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  "</div>");
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

	if (lws_lhp_construct(ctx, sc_cb, &drt, &ic))
		goto bail;
	ctx->flags = LHP_FLAG_DOCUMENT_END;
	ctx->base_url = strdup("");

	data = (const uint8_t *)doc;
	r = lws_lhp_parse(ctx, &data, &len);

	lwsl_user("%s: %d elements, %llu cascade steps, %llu work, r 0x%x\n",
		  __func__, sc_elems, (unsigned long long)ctx->cascade_ops,
		  (unsigned long long)ctx->sel_work, (unsigned int)r);

	if (sc_over) {
		lwsl_err("%s: over %llu work per element at element %d\n",
			 __func__, (unsigned long long)LHPT_SC_WORK_ELEM,
			 sc_elems + 1);
		goto bail_destruct;
	}
	/* html, head, style, body, p, the divs */
	if (r & LWS_SRET_FATAL || sc_elems != LHPT_SC_NEST + 5) {
		lwsl_err("%s: parse failed, %d elements\n", __func__,
			 sc_elems);
		goto bail_destruct;
	}
	/* the deep elements really did spend their budget */
	if (ctx->cascade_ops < (uint64_t)LHPT_SC_NEST / 2 * 32768) {
		lwsl_err("%s: only %llu steps\n", __func__,
			 (unsigned long long)ctx->cascade_ops);
		goto bail_destruct;
	}
	if (!sc_ok) {
		lwsl_err("%s: the attribute rule didn't match\n", __func__);
		goto bail_destruct;
	}

	e = 0;

bail_destruct:
	lws_lhp_destruct(ctx);
bail:
	free(ctx);
	free(doc);

	return e;
}

/*
 * A step must also be bounded in bytes, however long the selector text and
 * the attribute names.  The matcher rescanned the selector text for the
 * rightmost compound (<= 127 chars) for every ancestor it tried, parsed each
 * simple selector's text again, and compared up to six attribute names of
 * ~120 chars in each lookup, ~1000 bytes for a step: 256 '[a{120}zz] *'
 * over 30 nested <div> with 15 attributes a{120}00.. (110KB) took 16.6s
 * (release) before the document's css budget ended it.  Selectors are now
 * compiled once, and the attribute index is ordered by a hash of the name,
 * so a lookup compares hashes, and a name only when the hash matches.
 *
 * So with long selectors and names that share all but their last chars, the
 * work matching does must stay within what a step that compares no names at
 * all stands for, a compound or simple selector visited and its index
 * probes, for every step counted so far.  These pages don't spend an
 * element's whole budget, so this bounds the work by the steps really
 * counted (ctx->cascade_ops, which also counts some other css work), not by
 * the most an element may take.
 *
 * Names can be chosen to share a hash, so different names of the same length
 * and hash are compared in turn, and each one compared after the first costs
 * a step.  The second page has 62 attributes with a name sharing the hash of
 * the one the selectors look for (and found by searching for a pair), so
 * every lookup walks past all of them: there a step may compare one name.
 */

#define LHPT_SN_SELS		128
#define LHPT_SN_NEST		40
#define LHPT_SN_LEAVES		40
#define LHPT_SN_ATRS		15	/* long names on each div */
#define LHPT_SN_COLL		62	/* colliding names on each div */
/* a step with its index probes, but no name compared */
#define LHPT_SN_WORK_STEP	16
/* a step that may compare one name of < 128 bytes */
#define LHPT_SN_WORK_STEP_COLL	160

/* lhp_name_hash() of these two 120-char names is the same */
#define LHPT_SN_A10		"aaaaaaaaaa"
#define LHPT_SN_PFX		LHPT_SN_A10 LHPT_SN_A10 LHPT_SN_A10 \
				LHPT_SN_A10 LHPT_SN_A10 LHPT_SN_A10 \
				LHPT_SN_A10 LHPT_SN_A10 LHPT_SN_A10 \
				LHPT_SN_A10 LHPT_SN_A10
#define LHPT_SN_COLL_HAS	LHPT_SN_PFX "puehwejmjh"
#define LHPT_SN_COLL_FIND	LHPT_SN_PFX "quwvmxrkeg"

static uint64_t sn_work_step;
static int sn_elems, sn_ok, sn_over, sn_leaf_hit;

static lws_stateful_ret_t
sn_cb(lhp_ctx_t *ctx, char reason)
{
	lhp_pstack_t *ps = lws_container_of(lws_dll2_get_tail(&ctx->stack),
					    lhp_pstack_t, list);
	const lcsp_atr_t *ml;
	const lhp_atr_t *ta;
	const char *x;

	if (reason != LHPCB_ELEMENT_START || lws_dll2_is_empty(&ps->atr))
		return 0;

	/* fail at the first element that is over, don't wait for all */

	if (ctx->sel_work > sn_work_step * ctx->cascade_ops) {
		sn_over = 1;
		return LWS_SRET_FATAL;
	}
	sn_elems++;

	ml = lws_css_cascade_get_prop_atr(ctx, LCSP_PROP_MARGIN_LEFT);
	x = lws_html_get_atr(ps, "x", 1);
	if (x && !strcmp(x, "ok") && ml && ml->unit == LCSP_UNIT_LENGTH_PX &&
	    ml->u.i.whole == 2)
		sn_ok = 1;

	/* nothing has the attribute the hostile selectors look for */
	ta = lws_container_of(lws_dll2_get_head(&ps->atr), lhp_atr_t, list);
	if (ta->name_len == 1 && *(const char *)&ta[1] == 'i' && ml &&
	    ml->unit == LCSP_UNIT_LENGTH_PX && ml->u.i.whole == 1)
		sn_leaf_hit = 1;

	return 0;
}

static int
test_selector_names(int collide)
{
	size_t alloc = (size_t)LHPT_SN_SELS * 160 +
		       (size_t)LHPT_SN_NEST * (LHPT_SN_COLL * 126 + 16) +
		       (size_t)LHPT_SN_LEAVES * 16 + 1024, len;
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
	sn_elems = sn_ok = sn_over = sn_leaf_hit = 0;
	sn_work_step = collide ? LHPT_SN_WORK_STEP_COLL : LHPT_SN_WORK_STEP;

	/*
	 * The rule that matches: attribute names ignore case, and a name is
	 * found past others sharing its hash
	 */
	p = doc;
	if (collide)
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  "<html><head><style>p[" LHPT_SN_COLL_FIND
				  "]{margin-left:2px}\n");
	else
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  "<html><head><style>[A" LHPT_SN_PFX
				  "aaaaaaa07]{margin-left:2px}\n");
	for (i = 0; i < LHPT_SN_SELS; i++)
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  "[%s] *{margin-left:1px}\n", collide ?
				  LHPT_SN_COLL_FIND :
				  LHPT_SN_PFX "aaaaaaaazz");
	if (collide)
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  "</style></head><body><p "
				  LHPT_SN_COLL_HAS "=1 " LHPT_SN_COLL_FIND
				  "=2 x=ok>x</p>");
	else
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  "</style></head><body><p " LHPT_SN_PFX
				  "aaaaaaaa07=1 x=ok>x</p>");
	for (i = 0; i < LHPT_SN_NEST; i++) {
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  "<div");
		for (j = 0; j < (collide ? LHPT_SN_COLL : LHPT_SN_ATRS); j++)
			p += lws_snprintf(p, alloc -
					  lws_ptr_diff_size_t(p, doc),
					  collide ? " " LHPT_SN_COLL_HAS "=1" :
					  " " LHPT_SN_PFX "aaaaaaaa%02d=1", j);
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  ">");
		if (!i)
			/* a leaf decided well within its budget */
			p += lws_snprintf(p, alloc -
					  lws_ptr_diff_size_t(p, doc),
					  "<i>x</i>");
	}
	for (i = 0; i < LHPT_SN_LEAVES; i++)
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  "<b>x</b>");
	for (i = 0; i < LHPT_SN_NEST; i++)
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  "</div>");
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

	if (lws_lhp_construct(ctx, sn_cb, &drt, &ic))
		goto bail;
	ctx->flags = LHP_FLAG_DOCUMENT_END;
	ctx->base_url = strdup("");

	data = (const uint8_t *)doc;
	r = lws_lhp_parse(ctx, &data, &len);

	lwsl_user("%s: collide %d: %d elements, %llu cascade steps, %llu "
		  "work, r 0x%x\n", __func__, collide, sn_elems,
		  (unsigned long long)ctx->cascade_ops,
		  (unsigned long long)ctx->sel_work, (unsigned int)r);

	if (sn_over) {
		lwsl_err("%s: over %llu work per step at element %d\n",
			 __func__, (unsigned long long)sn_work_step,
			 sn_elems + 1);
		goto bail_destruct;
	}
	/* html, head, style, body, p, the divs, the leaves */
	if (r & LWS_SRET_FATAL ||
	    sn_elems != LHPT_SN_NEST + LHPT_SN_LEAVES + 6) {
		lwsl_err("%s: parse failed, %d elements\n", __func__,
			 sn_elems);
		goto bail_destruct;
	}
	/* the colliding names really are compared, and charged for */
	if (collide &&
	    ctx->cascade_ops < (uint64_t)LHPT_SN_NEST / 2 * 32768) {
		lwsl_err("%s: only %llu steps\n", __func__,
			 (unsigned long long)ctx->cascade_ops);
		goto bail_destruct;
	}
	if (!sn_ok || sn_leaf_hit) {
		lwsl_err("%s: the attribute rule matched %d, a leaf %d\n",
			 __func__, sn_ok, sn_leaf_hit);
		goto bail_destruct;
	}

	e = 0;

bail_destruct:
	lws_lhp_destruct(ctx);
bail:
	free(ctx);
	free(doc);

	return e;
}

/*
 * A step must be a bounded amount of work for short values too.  A scan was
 * charged a step per 64 bytes rounded down, so a value under 64 bytes was
 * scanned for free; '~=' ran lws_tokenize() once per word, ~30x a byte
 * compare each; '*=' ran a memcmp() per position, and the first attribute
 * name a lookup compared was free.  256 '[b~=q] *' over 40 nested
 * <div b="x x x ..."> (63 bytes, 24KB) took 15s (release) inside the
 * document's css budget.  Now the work is counted in units, a byte of a
 * name or value or an index probe each, and every LHP_SEL_STEP_WORK (32) of
 * them, carried from one simple selector to the next, costs a step.
 *
 * So with selectors that scan a value or compare a long name at every
 * ancestor of every element, the work matching does must stay within what
 * the steps really counted stand for (as test_selector_names), and the rule
 * using each kind of compare must still match.  Each page's allowance is
 * near what its steps really cost (~1.25x): with any one of the charges for
 * its kind of work taken out, or the work charged a step per 32 units
 * rounded down in each call instead of carried, it goes over.
 */

#define LHPT_SV_SELS		256
#define LHPT_SV_NEST		40
#define LHPT_SV_LEAVES		40

#define LHPT_SV_N10		"aaaaaaaaaa"
/* a 118-char attribute name */
#define LHPT_SV_LONG		LHPT_SV_N10 LHPT_SV_N10 LHPT_SV_N10 \
				LHPT_SV_N10 LHPT_SV_N10 LHPT_SV_N10 \
				LHPT_SV_N10 LHPT_SV_N10 LHPT_SV_N10 \
				LHPT_SV_N10 LHPT_SV_N10 "aaaaaaaa"
#define LHPT_SV_W10		"x x x x x "
/* 31 bytes, 16 words: a scan shorter than LHP_SEL_STEP_WORK */
#define LHPT_SV_WORDS		LHPT_SV_W10 LHPT_SV_W10 LHPT_SV_W10 "x"
#define LHPT_SV_X10		"xxxxxxxxxx"
/* 63 bytes, one word */
#define LHPT_SV_X63		LHPT_SV_X10 LHPT_SV_X10 LHPT_SV_X10 \
				LHPT_SV_X10 LHPT_SV_X10 LHPT_SV_X10 "xxx"

static const struct {
	const char	*name;
	const char	*sel;	/* each of the expensive selectors */
	const char	*atr;	/* the attribute of the nested divs */
	const char	*rule;	/* the rule that must match the <p> */
	const char	*p;	/* attributes of the <p> */
	int		work_step; /* work allowed per step counted */
} sv_pages[] = {
	{ "~=", "[b~=q]", "b=\"" LHPT_SV_WORDS "\"",
	  "p[b~=ok]", "b=\"x\tok y\"", 20 },
	{ ".class", ".q", "class=\"" LHPT_SV_WORDS "\"",
	  "p.ok", "class=\"x ok y\"", 20 },
	{ "*=", "[b*=q]", "b=\"" LHPT_SV_X63 "\"",
	  "p[b*=ok]", "b=\"xxokxx\"", 30 },
	{ "long name", "[" LHPT_SV_LONG "=q]",
	  LHPT_SV_LONG "=\"" LHPT_SV_X63 "\"",
	  "p[" LHPT_SV_LONG "=ok]", LHPT_SV_LONG "=\"ok\"", 30 },
};

static int sv_page;
static int sv_elems, sv_ok, sv_over, sv_leaf_hit;

static lws_stateful_ret_t
sv_cb(lhp_ctx_t *ctx, char reason)
{
	lhp_pstack_t *ps = lws_container_of(lws_dll2_get_tail(&ctx->stack),
					    lhp_pstack_t, list);
	const lcsp_atr_t *ml;
	const lhp_atr_t *ta;
	const char *x;

	if (reason != LHPCB_ELEMENT_START || lws_dll2_is_empty(&ps->atr))
		return 0;

	/* fail at the first element that is over, don't wait for all */

	if (ctx->sel_work > (uint64_t)sv_pages[sv_page].work_step *
						ctx->cascade_ops) {
		sv_over = 1;
		return LWS_SRET_FATAL;
	}
	sv_elems++;

	ml = lws_css_cascade_get_prop_atr(ctx, LCSP_PROP_MARGIN_LEFT);
	x = lws_html_get_atr(ps, "x", 1);
	if (x && !strcmp(x, "ok") && ml && ml->unit == LCSP_UNIT_LENGTH_PX &&
	    ml->u.i.whole == 2)
		sv_ok = 1;

	/* nothing has the value the expensive selectors look for */
	ta = lws_container_of(lws_dll2_get_head(&ps->atr), lhp_atr_t, list);
	if (ta->name_len == 1 && *(const char *)&ta[1] == 'i' && ml &&
	    ml->unit == LCSP_UNIT_LENGTH_PX && ml->u.i.whole == 1)
		sv_leaf_hit = 1;

	return 0;
}

static int
test_selector_values(int page)
{
	size_t alloc = (size_t)LHPT_SV_SELS * 160 +
		       (size_t)LHPT_SV_NEST * 200 +
		       (size_t)LHPT_SV_LEAVES * 16 + 1024, len;
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
	sv_elems = sv_ok = sv_over = sv_leaf_hit = 0;
	sv_page = page;

	p = doc;
	p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
			  "<html><head><style>%s{margin-left:2px}\n",
			  sv_pages[page].rule);
	for (i = 0; i < LHPT_SV_SELS; i++)
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  "%s *{margin-left:1px}\n", sv_pages[page].sel);
	p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
			  "</style></head><body><p %s x=ok>x</p>",
			  sv_pages[page].p);
	for (i = 0; i < LHPT_SV_NEST; i++)
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  "<div %s>", sv_pages[page].atr);
	for (i = 0; i < LHPT_SV_LEAVES; i++)
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  "<i>x</i>");
	for (i = 0; i < LHPT_SV_NEST; i++)
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  "</div>");
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

	if (lws_lhp_construct(ctx, sv_cb, &drt, &ic))
		goto bail;
	ctx->flags = LHP_FLAG_DOCUMENT_END;
	ctx->base_url = strdup("");

	data = (const uint8_t *)doc;
	r = lws_lhp_parse(ctx, &data, &len);

	lwsl_user("%s: %s: %d elements, %llu cascade steps, %llu work, "
		  "r 0x%x\n", __func__, sv_pages[page].name, sv_elems,
		  (unsigned long long)ctx->cascade_ops,
		  (unsigned long long)ctx->sel_work, (unsigned int)r);

	if (sv_over) {
		lwsl_err("%s: %s: over %d work per step at element %d\n",
			 __func__, sv_pages[page].name,
			 sv_pages[page].work_step, sv_elems + 1);
		goto bail_destruct;
	}
	/* html, head, style, body, p, the divs, the leaves */
	if (r & LWS_SRET_FATAL ||
	    sv_elems != LHPT_SV_NEST + LHPT_SV_LEAVES + 5) {
		lwsl_err("%s: %s: parse failed, %d elements\n", __func__,
			 sv_pages[page].name, sv_elems);
		goto bail_destruct;
	}
	if (!sv_ok || sv_leaf_hit) {
		lwsl_err("%s: %s: the rule matched %d, a leaf %d\n", __func__,
			 sv_pages[page].name, sv_ok, sv_leaf_hit);
		goto bail_destruct;
	}

	e = 0;

bail_destruct:
	lws_lhp_destruct(ctx);
bail:
	free(ctx);
	free(doc);

	return e;
}

/*
 * Property lookups must cost a bounded amount however long the declarations
 * they find.  Every lookup listed all the values of the winning declaration
 * in ctx->active_atr, which had no limit, and an inherited property is
 * looked up from every element, from the ancestor whose declaration wins,
 * however long ago its css was spent: body{color: red x 50000} over 2000
 * <p> took 31s under ASan.  A declaration now keeps at most
 * LHP_MAX_CSS_DECL_VALUES values, and the copies count in ctx->cascade_ops,
 * as do the walks of a ::before / ::after stanza's declarations when its box
 * is laid out.
 *
 * So each <p> under that <body> must cost at most what it costs with only
 * the user-agent css plus the values it may list, while a shorthand of a few
 * values still works.  And with a ::before stanza of 20000 declarations on
 * every <p>, laid out for real, the document's css must be cut off by its
 * budget, so the later <p> get no pseudo box.
 */

#define LHPT_DV_VALUES		50000
#define LHPT_DV_ELEMS		2000
/* lookups that list values, per element: generous */
#define LHPT_DV_OPS_ELEM	(LHPT_DB_OPS_UA + 64 * LHP_MAX_CSS_DECL_VALUES)
#define LHPT_DV_PS_DECLS	20000
#define LHPT_DV_PS_ELEMS	3000

static int dv_elems, dv_over, dv_margin_ok, dv_values_ok, dv_pseudo,
	   dv_no_pseudo;
static size_t dv_css_len;

static lws_stateful_ret_t
dv_cb(lhp_ctx_t *ctx, char reason)
{
	lhp_pstack_t *ps = lws_container_of(lws_dll2_get_tail(&ctx->stack),
					    lhp_pstack_t, list);
	const lcsp_atr_t *a;
	const lhp_atr_t *ta;

	if (reason != LHPCB_ELEMENT_START || lws_dll2_is_empty(&ps->atr))
		return 0;

	ta = lws_container_of(lws_dll2_get_head(&ps->atr), lhp_atr_t, list);
	if (ta->name_len != 1 || *(const char *)&ta[1] != 'p')
		return 0;

	/* fail at the first element that is over, don't wait for all */

	if (ctx->cascade_ops > (uint64_t)(dv_elems + 1) * LHPT_DV_OPS_ELEM +
			       (uint64_t)dv_css_len * LHPT_OPS_CSS_BYTE) {
		dv_over = 1;
		return LWS_SRET_FATAL;
	}
	dv_elems++;

	a = ps->css_margin[CCPAS_LEFT];
	if (a && a->unit == LCSP_UNIT_LENGTH_PX && a->u.i.whole == 4)
		dv_margin_ok++;

	/* inherited from <body> */
	if (lws_css_cascade_get_prop_atr(ctx, LCSP_PROP_COLOR) &&
	    ctx->active_atr.count == LHP_MAX_CSS_DECL_VALUES)
		dv_values_ok++;

	return 0;
}

static lws_stateful_ret_t
dv_ps_cb(lhp_ctx_t *ctx, char reason)
{
	lhp_pstack_t *ps = lws_container_of(lws_dll2_get_tail(&ctx->stack),
					    lhp_pstack_t, list);
	const lhp_atr_t *ta;

	if (reason == LHPCB_ELEMENT_START && !lws_dll2_is_empty(&ps->atr)) {
		ta = lws_container_of(lws_dll2_get_head(&ps->atr), lhp_atr_t,
				      list);
		if (ta->name_len == 1 && *(const char *)&ta[1] == 'p') {
			if (ps->pseudo_before)
				dv_pseudo++;
			else
				dv_no_pseudo++;
		}
	}

	/* and lay it out for real */

	return lhp_displaylist_layout(ctx, reason);
}

static int
test_decl_values(void)
{
	size_t alloc = (size_t)LHPT_DV_VALUES * 4 +
		       (size_t)LHPT_DV_PS_DECLS * 12 +
		       (size_t)LHPT_DV_PS_ELEMS * 8 + 1024, len;
	struct lws_context_creation_info info;
	struct lws_context *cx = NULL;
	lws_stateful_ret_t r;
	const uint8_t *data;
	lws_displaylist_t dl;
	lws_dl_rend_t drt;
	lhp_ctx_t *ctx;
	char *doc, *p;
	int e = 1, i;

	doc = malloc(alloc);
	ctx = malloc(sizeof(*ctx));
	if (!doc || !ctx)
		goto bail;
	memset(ctx, 0, sizeof(*ctx));
	dv_elems = dv_over = dv_margin_ok = dv_values_ok = 0;
	dv_pseudo = dv_no_pseudo = 0;

	/* the long inherited declaration */

	p = doc;
	p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
			  "<html><head><style>p{margin:1px 2px 3px 4px}"
			  "body{color:");
	for (i = 0; i < LHPT_DV_VALUES; i++)
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  " red");
	p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc), "}");
	dv_css_len = lws_ptr_diff_size_t(p, doc);
	p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
			  "</style></head><body>");
	for (i = 0; i < LHPT_DV_ELEMS; i++)
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  "<p>x</p>");
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

	if (lws_lhp_construct(ctx, dv_cb, &drt, &ic))
		goto bail;
	ctx->flags = LHP_FLAG_DOCUMENT_END;
	ctx->base_url = strdup("");

	data = (const uint8_t *)doc;
	r = lws_lhp_parse(ctx, &data, &len);

	lwsl_user("%s: %d elements, %llu cascade steps, r 0x%x\n", __func__,
		  dv_elems, (unsigned long long)ctx->cascade_ops,
		  (unsigned int)r);
	lws_lhp_destruct(ctx);

	if (dv_over) {
		lwsl_err("%s: over %d steps per element at element %d\n",
			 __func__, LHPT_DV_OPS_ELEM, dv_elems + 1);
		goto bail;
	}
	if (r & LWS_SRET_FATAL || dv_elems != LHPT_DV_ELEMS ||
	    dv_margin_ok != LHPT_DV_ELEMS || dv_values_ok != LHPT_DV_ELEMS) {
		lwsl_err("%s: %d elements, margin ok %d, values ok %d\n",
			 __func__, dv_elems, dv_margin_ok, dv_values_ok);
		goto bail;
	}

	/* the long ::before stanza, laid out for real */

	memset(ctx, 0, sizeof(*ctx));
	p = doc;
	p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
			  "<html><head><style>p::before{content:\"\";");
	for (i = 0; i < LHPT_DV_PS_DECLS; i++)
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  "color:red;");
	p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
			  "}</style></head><body>");
	for (i = 0; i < LHPT_DV_PS_ELEMS; i++)
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  "<p></p>");
	p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
			  "</body></html>");
	len = lws_ptr_diff_size_t(p, doc);
	if (len >= alloc - 1) {
		lwsl_err("%s: document doesn't fit\n", __func__);
		goto bail;
	}

	/* the layout chooses fonts from a context, this one has none */
	lws_context_info_defaults(&info, NULL);
	info.port = CONTEXT_PORT_NO_LISTEN;
	cx = lws_create_context(&info);
	if (!cx)
		goto bail;

	lws_display_dl_init(&dl, NULL);
	memset(&drt, 0, sizeof(drt));
	drt.dl = &dl;
	drt.w = ic.wh_px[0].whole;
	drt.h = ic.wh_px[1].whole;

	if (lws_lhp_construct(ctx, dv_ps_cb, &drt, &ic))
		goto bail;
	ctx->user1 = cx;
	ctx->flags = LHP_FLAG_DOCUMENT_END;
	ctx->base_url = strdup("");

	data = (const uint8_t *)doc;
	r = lws_lhp_parse(ctx, &data, &len);

	lwsl_user("%s: ::before on %d elements, not on %d, %llu cascade "
		  "steps, r 0x%x\n", __func__, dv_pseudo, dv_no_pseudo,
		  (unsigned long long)ctx->cascade_ops, (unsigned int)r);

	if (r & LWS_SRET_FATAL ||
	    dv_pseudo + dv_no_pseudo != LHPT_DV_PS_ELEMS)
		lwsl_err("%s: parse failed\n", __func__);
	else if (!dv_pseudo || !dv_no_pseudo)
		lwsl_err("%s: expected ::before on the first elements and "
			 "not on the last\n", __func__);
	else
		e = 0;

	lws_lhp_destruct(ctx);
	lws_display_list_destroy(cx, &dl);

bail:
	if (cx)
		lws_context_destroy(cx);
	free(ctx);
	free(doc);

	return e;
}

/*
 * Table layout work must be linear in the cells, however they are arranged:
 * one row of very many cells used to find each cell's column by walking the
 * column list from its head, when the cell opened and again at table close,
 * so a row of N cells cost N^2 steps.  The cells are laid out for real, by
 * lhp_displaylist_layout(), counting steps in ctx->layout_ops, followed by
 * a second, short row.
 */

#define LHPT_TW_CELLS		16000
/* steps of table layout work allowed per cell */
#define LHPT_TW_OPS_PER_CELL	8

static int
test_table_wide(void)
{
	size_t alloc = 256 * 1024, len;
	struct lws_context_creation_info info;
	struct lws_context *cx = NULL;
	lws_displaylist_t dl;
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

	/* the layout chooses fonts from a context, this one has none */
	lws_context_info_defaults(&info, NULL);
	info.port = CONTEXT_PORT_NO_LISTEN;
	cx = lws_create_context(&info);
	if (!cx)
		goto bail;

	p = doc;
	p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
			  "<html><body><table><tr>");
	for (i = 0; i < LHPT_TW_CELLS; i++)
		p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
				  "<td></td>");
	p += lws_snprintf(p, alloc - lws_ptr_diff_size_t(p, doc),
			  "</tr><tr><td></td><td></td></tr></table>"
			  "</body></html>");
	len = lws_ptr_diff_size_t(p, doc);
	if (len >= alloc - 1) {
		lwsl_err("%s: document doesn't fit\n", __func__);
		goto bail;
	}

	lws_display_dl_init(&dl, NULL);
	memset(&drt, 0, sizeof(drt));
	drt.dl = &dl;
	drt.w = ic.wh_px[0].whole;
	drt.h = ic.wh_px[1].whole;

	if (lws_lhp_construct(ctx, lhp_displaylist_layout, &drt, &ic))
		goto bail;
	ctx->user1 = cx;
	ctx->flags = LHP_FLAG_DOCUMENT_END;
	ctx->base_url = strdup("");

	data = (const uint8_t *)doc;
	r = lws_lhp_parse(ctx, &data, &len);

	lwsl_user("%s: %d cells in a row: %llu layout steps, r 0x%x\n",
		  __func__, LHPT_TW_CELLS,
		  (unsigned long long)ctx->layout_ops, (unsigned int)r);

	if (r & LWS_SRET_FATAL)
		lwsl_err("%s: parse failed\n", __func__);
	else if (ctx->layout_ops >
			(uint64_t)LHPT_TW_CELLS * LHPT_TW_OPS_PER_CELL)
		lwsl_err("%s: table layout took over %d steps per cell\n",
			 __func__, LHPT_TW_OPS_PER_CELL);
	else
		e = 0;

	lws_lhp_destruct(ctx);
	lws_display_list_destroy(cx, &dl);

bail:
	if (cx)
		lws_context_destroy(cx);
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

/*
 * Where the html tokenizer reads more of a class value out of an attribute
 * than a naive one, lhp must read it too, or a class-keyed cosmetic filter
 * rule misses an element a browser would apply it to (G-235).  Each of these
 * gives the element the class "junk" in a browser, so with the filter
 * ".junk{display:none}" it must be hidden, whether the document arrives at
 * once or a byte at a time.
 */

static const char * const tok_classes[] = {
	/* a numeric reference's ';' is optional */
	"class=\"x&#0 junk\"",
	"class=\"x&#65 junk\"",
	"class=\"x&#x0 junk\"",
	"class=\"x&#x41 junk\"",
	"class=\"x&#9junk\"",
	"class=x&#x20junk",
	/* ... and its digits are not limited in number */
	"class=\"x&#000000000000000000000000000000000000000032;junk\"",
	"class=\"x&#x0000000000020;junk\"",
	/* whitespace around '=' */
	"class =\"x junk\"",
	"class= \"x junk\"",
	"class \t=\n 'x junk'",
	"class = junk",
	/* the named references to whitespace */
	"class=\"x&Tab;junk\"",
	"class=\"x&NewLine;junk\"",
	/* an '&#' with no digits is text, not the start of a reference */
	"class=\"&#; junk\"",
	"class=\"&#xg junk\"",
};

static int
test_filter_tokenizer(const char *cls, int bytewise)
{
	static const lws_lhp_filter_t filter = {
		.cosmetic_css = ".junk{display:none}"
	};
	lws_stateful_ret_t r = 0;
	const uint8_t *data;
	lws_dl_rend_t drt;
	char doc[512];
	size_t len, one;
	lhp_ctx_t *ctx;
	int e = 1;

	ctx = malloc(sizeof(*ctx));
	if (!ctx)
		return 1;
	memset(ctx, 0, sizeof(*ctx));
	susp_ad_seen = susp_ad_hidden = susp_ok_seen = susp_ok_hidden = 0;

	len = (size_t)lws_snprintf(doc, sizeof(doc),
			"<html><body><div data-t=\"ad\" %s>x</div>"
			"<div data-t=\"ok\" class=\"y\">y</div>"
			"</body></html>", cls);

	memset(&drt, 0, sizeof(drt));
	drt.dl = &displaylist;
	drt.w = ic.wh_px[0].whole;
	drt.h = ic.wh_px[1].whole;

	if (lws_lhp_construct(ctx, susp_cb, &drt, &ic))
		goto bail;
	if (lws_lhp_set_filter(ctx, &filter)) {
		lws_lhp_destruct(ctx);
		goto bail;
	}
	ctx->base_url = strdup("");

	data = (const uint8_t *)doc;
	if (!bytewise) {
		ctx->flags = LHP_FLAG_DOCUMENT_END;
		r = lws_lhp_parse(ctx, &data, &len);
	} else
		while (len && !(r & LWS_SRET_FATAL)) {
			if (len == 1)
				ctx->flags = LHP_FLAG_DOCUMENT_END;
			one = 1;
			r = lws_lhp_parse(ctx, &data, &one);
			if (one) {
				lwsl_err("%s: byte not taken\n", __func__);
				r = LWS_SRET_FATAL;
				break;
			}
			len--;
		}
	lws_lhp_destruct(ctx);

	if (r & LWS_SRET_FATAL || !susp_ad_seen || !susp_ok_seen) {
		lwsl_err("%s: '%s' (bytewise %d): parse failed\n", __func__,
			 cls, bytewise);
		goto bail;
	}
	if (!susp_ad_hidden || susp_ok_hidden) {
		lwsl_err("%s: '%s' (bytewise %d): ad hidden %d, ok hidden %d\n",
			 __func__, cls, bytewise, susp_ad_hidden,
			 susp_ok_hidden);
		goto bail;
	}

	e = 0;

bail:
	free(ctx);

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

	if (test_cascade_work())
		goto bail;

	if (test_cascade_doc_budget())
		goto bail;

	if (test_interleaved_style())
		goto bail;

	if (test_cascade_level_heap())
		goto bail;

	if (test_style_recascade() || test_style_attr_budget())
		goto bail;

	if (test_selector_scan())
		goto bail;

	if (test_selector_compound())
		goto bail;

	if (test_selector_names(0) || test_selector_names(1))
		goto bail;

	for (sc = 0; sc < (int)LWS_ARRAY_SIZE(sv_pages); sc++)
		if (test_selector_values(sc))
			goto bail;

	if (test_decl_values())
		goto bail;

	if (test_table_wide())
		goto bail;

	if (test_filter_classes(0) ||
	    test_filter_classes(LHPT_FILTER_CLASSES))
		goto bail;

	for (sc = 0; sc < LHPT_SUSP_COUNT; sc++)
		if (test_filter_suspicious(sc, 0) ||
		    test_filter_suspicious(sc, 1))
			goto bail;

	for (sc = 0; sc < (int)LWS_ARRAY_SIZE(tok_classes); sc++)
		if (test_filter_tokenizer(tok_classes[sc], 0) ||
		    test_filter_tokenizer(tok_classes[sc], 1))
			e++;
	if (e)
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
