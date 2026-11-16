/*
 * lhp grey levels page
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * See greys-ui.h
 */

#include "greys-ui.h"
#include <string.h>

static int
has_palette(const lws_surface_info_t *ic)
{
	return ic->palette && ic->palette_depth;
}

int
lhp_greys_usable(const lws_surface_info_t *ic)
{
	if (!has_palette(ic))
		return 1;

	return ic->greyscale && ic->palette_depth >= 2 &&
	       ic->palette_depth <= LHP_GREYS_MAX;
}

/*
 * The grey, 0 - 255, to write in the html for palette entry want.  It's
 * gamma-corrected, then the palette's nearest entry is chosen and the error
 * left over is spread to the pixels around it, see
 * lws_display_palettize_grey(): so the grey wanted is the one that leaves no
 * error, or the bar is dithered.  If no grey is exactly the entry's, eg, its
 * level isn't one the gamma correction can give, the one leaving the least
 * error is used, and it's said.
 */

static int
grey_for_entry(const lws_surface_info_t *ic, size_t want)
{
	int c, best = -1, best_err = 256, e;
	lws_greyscale_error_t err;

	for (c = 0; c < 256; c++) {
		err.rgb[0] = 0;
		if (lws_display_palettize_grey(ic, ic->palette,
				ic->palette_depth,
				LWSDC_RGBA(c, c, c, 255), &err) != want)
			continue;

		e = err.rgb[0] < 0 ? -err.rgb[0] : err.rgb[0];
		if (e < best_err) {
			best = c;
			best_err = e;
		}
	}

	if (best_err)
		lwsl_warn("%s: palette entry %d (%d) is only approximated, "
			  "so it will be dithered\n", __func__, (int)want,
			  (int)LWSDC_R(ic->palette[want]));

	return best;
}

/*
 * The greys of the levels, from black to white.  The palette's entries may be
 * in any order, so they're put in order of how light they are.
 */

static int
levels(const lws_surface_info_t *ic, uint8_t *grey)
{
	uint8_t order[LHP_GREYS_MAX];
	int n, m, c;

	if (!has_palette(ic)) {
		for (n = 0; n < LHP_GREYS_DEFAULT; n++)
			grey[n] = (uint8_t)((n * 255) / (LHP_GREYS_DEFAULT - 1));

		return LHP_GREYS_DEFAULT;
	}

	if (!lhp_greys_usable(ic))
		return -1;

	for (n = 0; n < (int)ic->palette_depth; n++) {
		/* insert it among those already in order */
		for (m = n; m && LWSDC_R(ic->palette[order[m - 1]]) >
				 LWSDC_R(ic->palette[n]); m--)
			order[m] = order[m - 1];
		order[m] = (uint8_t)n;
	}

	for (n = 0; n < (int)ic->palette_depth; n++) {
		c = grey_for_entry(ic, order[n]);
		if (c < 0)
			/* the palette never chooses it */
			return -1;
		grey[n] = (uint8_t)c;
	}

	return (int)ic->palette_depth;
}

int
lhp_greys_html(char *buf, size_t len, const lws_surface_info_t *ic)
{
	int w = ic->wh_px[0].whole, h = ic->wh_px[1].whole, nl, n, row, x0, x1;
	uint8_t grey[LHP_GREYS_MAX];
	lws_html_w_t hw;

	nl = levels(ic, grey);
	if (nl < 2)
		return -1;

	lws_html_w_init(&hw, buf, len);

	lws_html_w_printf(&hw, "<!doctype html><html><head>"
		"<meta charset=\"utf-8\"><style>"
		"* { margin: 0; padding: 0 }"
		"body { background-color: #fff }"
		"div { position: absolute }");

	/*
	 * The bars tile what can be seen exactly, the rows splitting its
	 * height and the bars its width, with no gaps or overlaps between
	 * them: a boundary between bars is the same in both rows
	 */

	for (row = 0; row < 2; row++)
		for (n = 0; n < nl; n++) {
			x0 = (n * w) / nl;
			x1 = ((n + 1) * w) / nl;
			lws_html_w_printf(&hw, "#%c%d { left: %dpx; top: %dpx;"
				" width: %dpx; height: %dpx;"
				" background-color: #%02x%02x%02x }",
				row ? 'b' : 't', n, x0, row ? h / 2 : 0,
				x1 - x0, row ? h - h / 2 : h / 2,
				/* the bottom row goes from white to black */
				grey[row ? nl - 1 - n : n],
				grey[row ? nl - 1 - n : n],
				grey[row ? nl - 1 - n : n]);
		}

	lws_html_w_printf(&hw, "</style></head><body>");

	for (row = 0; row < 2; row++)
		for (n = 0; n < nl; n++)
			lws_html_w_printf(&hw, "<div id=\"%c%d\"></div>",
					  row ? 'b' : 't', n);

	lws_html_w_printf(&hw, "</body></html>");

	return lws_html_w_len(&hw, buf);
}
