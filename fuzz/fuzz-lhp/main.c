/*
 * lws fuzz target: lhp HTML5 + CSS parser producing display list objects
 *
 * Written in 2010 - 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Parses the input as a complete document into a display list, then
 * destroys the document's dlos and the parser context, so heap errors and
 * leaks in the parse or the teardown are caught.
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdlib.h>

/*
 * Fuzzing means constantly feeding the parser garbage, so its rejection
 * logs are expected noise that dominates the runtime.  Set LWS_FUZZ_VERBOSE=1
 * to get them back (eg, when replaying a crash artifact).
 */

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;

	if (!getenv("LWS_FUZZ_VERBOSE"))
		lws_set_log_level(0, NULL);

	return 0;
}

static lws_stateful_ret_t
cb(lhp_ctx_t *ctx, char reason)
{
	return 0;
}

static const lws_surface_info_t ic = {
	.wh_px = { { 600, 0 },       { 448, 0 } },
	.wh_mm = { { 114, 5000000 }, {  82, 5000000 } },
};

static lws_displaylist_t displaylist;

static int
destroy_one(lws_dll2_t *d, void *user)
{
	lws_dlo_t *dlo = lws_container_of(d, lws_dlo_t, list);

	lws_display_dlo_destroy(&dlo);

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
	drt.w   = 600;
	drt.h   = 448;

	if (lws_lhp_construct(&ctx, cb, &drt, &ic))
		return 0;

	ctx.flags = LHP_FLAG_DOCUMENT_END;
	ctx.base_url = strdup("");

	/* it can return before consuming all input; keep going until done */

	while (left && n++ < 4096) {
		const uint8_t *before = p;

		if (lws_lhp_parse(&ctx, &p, &left) & LWS_SRET_FATAL)
			break;
		if (p == before)
			break;
	}

	/* lws_lhp_destruct() frees base_url */

	lws_lhp_destruct(&ctx);

	/* the document's dlos belong to the display list; destroy them all */

	lws_dll2_foreach_safe(&displaylist.dl, NULL, destroy_one);

	return 0;
}
