/*
 * lws fuzz target: svg scene parser and linewise rasterizer
 *
 * Written for the libwebsockets project in 2026
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Parses the input as an SVG document into a retained vector scene, then
 * renders every line of it into a span-counting sink, so heap errors,
 * leaks and arithmetic misbehaviour in the parse, the scene retention,
 * the rasterization and the teardown are all caught.
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

static int
span_cb(void *user, int x0, int x1, uint32_t rgba)
{
	(void)user;
	(void)x0;
	(void)x1;
	(void)rgba;

	return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	lws_svg_render_t ri;
	lws_svg_t *svg;
	int y, n = 0;

	if (!size)
		return 0;

	svg = lws_svg_new();
	if (!svg)
		return 0;

	/*
	 * The first byte steers the harness rather than the parser, so the
	 * mutations explore the state machine's chunk boundary handling
	 * and both raster paths as well as the document bytes themselves:
	 *
	 *   bit 0:   hold at the root tag metadata first
	 *   bits1-3: base-2 log of the chunk stride input is fed in
	 *   bit 6:   antialiased line rendering
	 *   bit 7:   16px raster instead of 64px
	 */

	if (data[0] & 1) {
		const uint8_t *hp = data + 1;
		size_t hl = size - 1;

		/* hold returns as soon as the root tag has parsed */

		(void)lws_svg_parse(svg, &hp, &hl, 1);
		(void)lws_svg_get_width(svg);
		(void)lws_svg_get_height(svg);
	}

	{
		const uint8_t *p = data + 1;
		size_t left = size - 1;
		size_t stride = 1u << ((data[0] >> 1) & 7);

		while (n++ < 4096) {
			const uint8_t *cp = p;
			size_t cl = left < stride ? left : stride;
			lws_stateful_ret_t r = lws_svg_parse(svg, &cp, &cl, 0);

			left -= (size_t)(cp - p);
			p = cp;

			if (r & (LWS_SRET_FATAL | LWS_SRET_OK) || !left)
				break;
		}
	}

	memset(&ri, 0, sizeof(ri));
	ri.w = ri.h = (data[0] & 0x80) ? 16 : 64;
	ri.aa = !!(data[0] & 0x40);

	for (y = 0; y < ri.h; y++)
		if (lws_svg_render_line(svg, &ri, y, span_cb, NULL) &
								LWS_SRET_FATAL)
			break;

	lws_svg_free(&svg);

	return 0;
}
