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
	 "hello</body></html>"
};

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
	lhp_pstack_t *ps = lws_container_of(ctx->stack.tail, lhp_pstack_t, list);
	const lcsp_atr_t *a;

	printf("{ %s, %u, \"%.*s\", %u, { ", cb_reasons[(unsigned int)reason], ctx->npos, ctx->npos, ctx->buf, ps->atr.count);

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

static const lws_surface_info_t ic = {
	.wh_px = { { 600,0 },       { 448,0 } },
	.wh_mm = { { 114,5000000 }, {  82,5000000 } },
};

static lws_displaylist_t displaylist;

int
main(int argc, const char **argv)
{
	int e = 0, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	lws_stateful_ret_t n;
	lws_dl_rend_t drt;
	lhp_ctx_t ctx;
	const char *p;


	memset(&ctx, 0, sizeof(ctx));

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
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

	lwsl_user("Completed: PASS\n");

	return 0;

bail:
	lwsl_user("Completed: FAIL\n");

	return 1;
}
