/*
 * lws fuzz target: lhp HTML5 + CSS parser driving the dlo layout
 *
 * Written in 2010 - 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * fuzz-lhp only parses: its element callback is a stub, so nothing it finds
 * reaches the layout.  This one lays the document out with the stock layout
 * callback, lhp_displaylist_layout(), as a renderer does: that needs a
 * context with fonts registered.  base_url is NULL so no assets are fetched,
 * the elements wanting one are laid out without it.  The document's dlos and
 * the parser context are then destroyed, so heap errors and leaks in the
 * layout or the teardown are caught too.
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdlib.h>

static const uint8_t fira_c_r_12[] = {
#include "../contrib/mcufont/fonts/FiraSansCondensed-Regular12.mcufont.h"
};
static const uint8_t fira_c_r_16[] = {
#include "../contrib/mcufont/fonts/FiraSansCondensed-Regular16.mcufont.h"
};
static const uint8_t fira_c_b_12[] = {
#include "../contrib/mcufont/fonts/FiraSansCondensed-Bold12.mcufont.h"
};
static const uint8_t fira_c_b_16[] = {
#include "../contrib/mcufont/fonts/FiraSansCondensed-Bold16.mcufont.h"
};

static const lws_surface_info_t ic = {
	.wh_px = { { 600, 0 },       { 448, 0 } },
	.wh_mm = { { 114, 5000000 }, {  82, 5000000 } },
};

static struct lws_context *cx;
static lws_displaylist_t displaylist;

/*
 * Fuzzing means constantly feeding the parser garbage, so its rejection
 * logs are expected noise that dominates the runtime.  Set LWS_FUZZ_VERBOSE=1
 * to get them back (eg, when replaying a crash artifact).
 */

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	struct lws_context_creation_info info;

	(void)argc;
	(void)argv;

	if (!getenv("LWS_FUZZ_VERBOSE"))
		lws_set_log_level(0, NULL);

	memset(&info, 0, sizeof(info));
	info.port = CONTEXT_PORT_NO_LISTEN;

	cx = lws_create_context(&info);
	if (!cx)
		abort();

	if (lws_font_register(cx, fira_c_r_12, sizeof(fira_c_r_12)) ||
	    lws_font_register(cx, fira_c_r_16, sizeof(fira_c_r_16)) ||
	    lws_font_register(cx, fira_c_b_12, sizeof(fira_c_b_12)) ||
	    lws_font_register(cx, fira_c_b_16, sizeof(fira_c_b_16)))
		abort();

	return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	lhp_ctx_t ctx;
	lws_dl_rend_t drt;
	size_t left = size;
	const uint8_t *p = data;
	int n = 0;

	memset(&drt, 0, sizeof(drt));
	drt.dl  = &displaylist;
	drt.w   = ic.wh_px[0].whole;
	drt.h   = ic.wh_px[1].whole;

	if (lws_lhp_construct(&ctx, lhp_displaylist_layout, &drt, &ic))
		return 0;

	ctx.flags = LHP_FLAG_DOCUMENT_END;
	ctx.user1 = cx;

	/* it can return before consuming all input; keep going until done */

	while (left && n++ < 4096) {
		const uint8_t *before = p;

		if (lws_lhp_parse(&ctx, &p, &left) & LWS_SRET_FATAL)
			break;
		if (p == before)
			break;
	}

	lws_lhp_destruct(&ctx);
	lws_display_list_destroy(cx, &displaylist);

	return 0;
}
