/*
 * lws-api-test-lhp-dlo
 *
 * Written in 2010-2022 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>

enum {
	LWS_SW_BMP,
	LWS_SW_DUMP,
		LWS_SW_W,
		LWS_SW_H,
		LWS_SW_FDLIMIT,
		LWS_SW_CSS_FILTER,
		LWS_SW_BLOCK_LIST,
		LWS_SW_ASSET_CACHE,
		LWS_SW_PRESEED,
		LWS_SW_FONTS,
		LWS_SW_FONT_MANIFEST,
		LWS_SW_SERVE_FONTS,
		LWS_SW_HEAP_LIMIT,
		LWS_SW_RECLAIM_LINES,
		LWS_SW_RECLAIM_ELEMS,
		LWS_SW_STARVE_MS,
		LWS_SW_FONTS_LOCAL,
		LWS_SW_KERN_CHECK,
		LWS_SW_RETAINED,
		LWS_SW_SVG_LIVE_MAX,
		LWS_SW_LAYOUT_H,
		LWS_SW_PAN,
		LWS_SW_PAN_HEAP_MAX,
		LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_BMP]	= { "--bmp",           "Render to the given .bmp file" },
	[LWS_SW_DUMP]	= { "--dump",          "Write layout DLO tree as text to the given file (no render)" },
	[LWS_SW_W]	= { "--w",             "Surface width in px (default 600)" },
	[LWS_SW_H]	= { "--h",             "Surface height in px (default 448)" },
	[LWS_SW_FDLIMIT]= { "--fd-limit",     "Context fd limit, to try layouts against small targets" },
	[LWS_SW_CSS_FILTER]= { "--css-filter", "Filter css from file hides junk elements, eg .ad { display: none !important; }" },
	[LWS_SW_BLOCK_LIST]= { "--block-list", "URL block rules from file: ||host.tld or substring per line" },
	[LWS_SW_ASSET_CACHE]= { "--asset-cache", "Directory for the document asset cache, enables it" },
	[LWS_SW_PRESEED]	= { "--preseed",    "Preseed the asset cache with url=file" },
	[LWS_SW_FONTS]	= { "--fonts",         "Register the .mcufont files in this directory as file-backed faces, instead of the built-in ones" },
	[LWS_SW_FONT_MANIFEST] = { "--font-manifest", "Use the faces this font manifest url lists, fetched when needed, with only one built-in face as the fallback" },
	[LWS_SW_SERVE_FONTS] = { "--serve-fonts", "Serve this directory over http on a localhost port, and use the font manifest in it as --font-manifest does" },
	[LWS_SW_HEAP_LIMIT] = { "--heap-limit", "Simulate a heap of this many bytes above what is in use at the start, so fonts and images get reclaimed" },
	[LWS_SW_RECLAIM_LINES] = { "--reclaim-lines", "Evict every reclaimable heap occupant after each N rendered lines, so they all get renewed mid-render on any allocator" },
	[LWS_SW_RECLAIM_ELEMS] = { "--reclaim-elems", "Evict every reclaimable heap occupant as every N-th element of the layout opens, so they all get renewed mid-layout on any allocator" },
	[LWS_SW_STARVE_MS] = { "--starve-ms", "With --reclaim-lines, at the first such line also refuse every heap allocation for this many ms, so the faces evicted there can't be fetched again at first" },
	[LWS_SW_FONTS_LOCAL] = { "--fonts-local", "Lay the page out in the built-in faces only" },
	[LWS_SW_KERN_CHECK] = { "--kern-check", "Check how the registered 14px regular face kerns pairs of glyphs, instead of laying out a page" },
	[LWS_SW_RETAINED] = { "--retained",    "Render the display list retained, as for a touch panel, keeping its DLOs as the raster passes them" },
	[LWS_SW_SVG_LIVE_MAX] = { "--svg-live-max", "Fail if more than this many svg images were held at once" },
	[LWS_SW_LAYOUT_H] = { "--layout-h",    "Lay the page out this tall in px, taller than --h, so it can be panned down (rs.layout_h)" },
	[LWS_SW_PAN]	= { "--pan",           "x,y[:x,y...]: render the display list panned to x,y with lws_display_render_pan(), kept to what is laid out.  With --retained, more are rendered one after the other from the same display list, as a touch display redraws a page dragged around, and the last goes in the bmp" },
	[LWS_SW_PAN_HEAP_MAX] = { "--pan-heap-max", "With --retained and more than one --pan, fail if the heap in use after the last pan is more than this many bytes over what it was after the first" },
	[LWS_SW_HELP]	= { "--help",          "Show this help information" },
};

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <signal.h>

//#define SEVENCOL

struct lws_context *cx;

#if defined(LWS_WITH_SERVER)
/* builds without ipv4 can only use ipv6 loopback */
#if defined(LWS_WITH_IPV4)
#define LOOPBACK		"127.0.0.1"
#define LOOPBACK_URL		"127.0.0.1"
#else
#define LOOPBACK		"::1"
#define LOOPBACK_URL		"[::1]"
#endif

/*
 * With --serve-fonts, the faces come from our own http server on localhost:
 * the built-in policy's __default streamtype insists on tls, so it gets one
 * that doesn't
 */
static const char * const serve_fonts_policy =
	"{"
		"\"release\":\"1\","
		"\"product\":\"lhp-dlo-serve-fonts\","
		"\"schema-version\":1,"
		"\"retry\":[{\"default\":{"
			"\"backoff\":[100,200],"
			"\"conceal\":2,"
			"\"jitterpc\":0,"
			"\"svalidping\":30,"
			"\"svalidhup\":35"
		"}}],"
		"\"s\":[{\"__default\":{"
			"\"endpoint\":\"${endpoint}\","
			"\"port\":80,"
			"\"protocol\":\"h1\","
			"\"http_method\":\"GET\","
			"\"http_url\":\"\","
			"\"metadata\":[{"
				"\"endpoint\":\"\","
				"\"acc\":\"accept\","
				"\"ua\":\"user-agent\""
			"}],"
			"\"retry\":\"default\","
			"\"timeout_ms\":10000"
		"}}]"
	"}";
#endif

LWS_SS_USER_TYPEDEF
	lws_flow_t			flow;
	lhp_ctx_t			lhp; /* html ss owns html parser */
	lws_dl_rend_t			drt;
	lws_sorted_usec_list_t		sul;
	lws_display_render_state_t	*rs;
} htmlss_t;

static lws_display_render_state_t drs;

static const uint8_t fira_c_r_10[] = {
#include "../contrib/mcufont/fonts/FiraSansCondensed-Regular10.mcufont.h"
};
static const uint8_t fira_c_r_12[] = {
#include "../contrib/mcufont/fonts/FiraSansCondensed-Regular12.mcufont.h"
};
static const uint8_t fira_c_r_14[] = {
#include "../contrib/mcufont/fonts/FiraSansCondensed-Regular14.mcufont.h"
};
static const uint8_t fira_c_r_16[] = {
#include "../contrib/mcufont/fonts/FiraSansCondensed-Regular16.mcufont.h"
};
static const uint8_t fira_c_r_20[] = {
#include "../contrib/mcufont/fonts/FiraSansCondensed-Regular20.mcufont.h"
};
static const uint8_t fira_c_r_24[] = {
#include "../contrib/mcufont/fonts/FiraSansCondensed-Regular24.mcufont.h"
};
static const uint8_t fira_c_r_32[] = {
#include "../contrib/mcufont/fonts/FiraSansCondensed-Regular32.mcufont.h"
};

static const uint8_t fira_c_b_10[] = {
#include "../contrib/mcufont/fonts/FiraSansCondensed-Bold10.mcufont.h"
};
static const uint8_t fira_c_b_12[] = {
#include "../contrib/mcufont/fonts/FiraSansCondensed-Bold12.mcufont.h"
};
static const uint8_t fira_c_b_14[] = {
#include "../contrib/mcufont/fonts/FiraSansCondensed-Bold14.mcufont.h"
};
static const uint8_t fira_c_b_16[] = {
#include "../contrib/mcufont/fonts/FiraSansCondensed-Bold16.mcufont.h"
};
static const uint8_t fira_c_b_20[] = {
#include "../contrib/mcufont/fonts/FiraSansCondensed-Bold20.mcufont.h"
};
static const uint8_t fira_c_b_24[] = {
#include "../contrib/mcufont/fonts/FiraSansCondensed-Bold24.mcufont.h"
};
static const uint8_t fira_c_b_32[] = {
#include "../contrib/mcufont/fonts/FiraSansCondensed-Bold32.mcufont.h"
};

#if defined(SEVENCOL)
static const lws_display_colour_t palette[] = {
        LWSDC_RGBA(0, 0, 0, 255),               /* black */
        LWSDC_RGBA(255, 255, 255, 255),         /* white */
        LWSDC_RGBA(0, 255, 0, 255),             /* green */
        LWSDC_RGBA(0, 0, 255, 255),             /* blue */
        LWSDC_RGBA(255, 0, 0, 255),             /* red */
        LWSDC_RGBA(255, 255, 0, 255),           /* yellow */
        LWSDC_RGBA(255, 127, 0, 255),           /* orange */
};
#endif

/* the 5.65" 600x448 ACEP epd the test page was written for */
static lws_surface_info_t ic = {
	.wh_px = { { 600,0 },        { 448,0 } },
	.wh_mm = { { 114,5000000 }, {  82,5000000 } },
#if defined(SEVENCOL)
        .palette                = palette,
        .palette_depth          = LWS_ARRAY_SIZE(palette),
	.type			= LWSSURF_PALETTE,
#else
	.type			= LWSSURF_TRUECOLOR32,
#endif
	.greyscale		= 0
};

int fdin = 0, fdout = 1, result = 0;
static const char *dump_path;
#define PAN_MAX		8
static struct {
	int x, y;
} pans[PAN_MAX];
static int pan_count, pan_step, pan_heap_max = -1;
/* the heap in use after the first --pan was rendered */
static size_t pan_heap_first;
static int reclaim_lines, reclaimed_line = -1, svg_live_max = -1, starve_ms;
static size_t heap_limit;
static lws_sorted_usec_list_t sul_starve;
/* what the page was browsed with, to browse it again for a relayout */
static const char *page_url;
static lws_lhp_filter_t page_filter;
static char page_filtered;
static lws_sorted_usec_list_t sul_relayout;
static int relayout_tries;

/*
 * How often, and how many times, we try to browse the page again for a
 * relayout: the heap may still be short just after the render gave up
 */
#define RELAYOUT_RETRY_US	(250 * LWS_US_PER_MS)
#define RELAYOUT_TRIES		40

/*
 * --kern-check: glyphs are kerned in from the shapes of their ink, never
 * apart, by at most a quarter of the narrower advance, and not across a
 * space; and the width a run is laid out at is the width it measures
 */

static int
kern_width(lws_dlo_text_t *t, const char *s, size_t len)
{
	lws_fx_t total, word;

	lws_display_dlo_text_measure(t, s, len, &total, &word);

	return total.whole;
}

static int
kern_check(struct lws_context *cx)
{
	static const char run[] = "LYING ABOUT LT-YACHTS, I lied";
	lws_font_choice_t hints = { .family_name = "Fira Sans Condensed",
				    .weight = 400, .fixed_height = 17 };
	const lws_display_font_t *f = lws_font_choose(cx, &hints);
	int a, b, ab, ca, cb, kerned = 0, fails = 0;
	lws_displaylist_t dl;
	lws_dlo_text_t *t;
	char pair[3];
	lws_box_t box;

	if (!f) {
		lwsl_err("%s: no face\n", __func__);
		return 1;
	}

	lws_display_dl_init(&dl, NULL);
	memset(&box, 0, sizeof(box));
	box.w.whole = 2000;
	box.h.whole = 100;

	t = lws_display_dlo_text_new(&dl, NULL, &box, f);
	if (!t)
		return 1;

	pair[2] = '\0';
	for (ca = '!'; ca <= '~'; ca++)
		for (cb = '!'; cb <= '~'; cb++) {
			pair[0] = (char)ca;
			pair[1] = (char)cb;
			a = kern_width(t, pair, 1);
			b = kern_width(t, pair + 1, 1);
			ab = kern_width(t, pair, 2);

			if (ab > a + b || ab < a + b - (a < b ? a : b) / 4) {
				lwsl_err("%s: '%s' %d, from %d + %d\n",
					 __func__, pair, ab, a, b);
				fails++;
			}
			if (ab < a + b)
				kerned++;
		}

	lwsl_notice("%s: %d of %d pairs kerned\n", __func__, kerned, 94 * 94);
	if (!kerned) {
		lwsl_err("%s: no pairs kerned\n", __func__);
		fails++;
	}

	/*
	 * In this face, LT and YA leave more room between their ink than the
	 * face's usual gap, and come together; nn is already at it, and stays
	 */

	if (kern_width(t, "LT", 2) >= kern_width(t, "L", 1) + kern_width(t, "T", 1) ||
	    kern_width(t, "YA", 2) >= kern_width(t, "Y", 1) + kern_width(t, "A", 1) ||
	    kern_width(t, "nn", 2) != 2 * kern_width(t, "n", 1)) {
		lwsl_err("%s: LT, YA or nn kerned wrongly\n", __func__);
		fails++;
	}

	/* a space stops it */

	if (kern_width(t, "T o", 3) != kern_width(t, "T", 1) +
				      kern_width(t, " ", 1) + kern_width(t, "o", 1)) {
		lwsl_err("%s: kerned across a space\n", __func__);
		fails++;
	}

	/* laying the run out gives it the width it measures */

	for (ab = 0, a = 0; run[a]; a++)
		ab += kern_width(t, &run[a], 1);

	if (lws_display_dlo_text_update(t, 0, box.x, run, sizeof(run) - 1) ||
	    t->bounding_box.w.whole != kern_width(t, run, sizeof(run) - 1) ||
	    t->bounding_box.w.whole >= ab) {
		lwsl_err("%s: run laid out at %d\n", __func__,
			 t->bounding_box.w.whole);
		fails++;
	}

	lws_display_list_destroy(cx, &dl);

	return !!fails;
}

/*
 * Write the DLO tree as deterministic text (no pointers), so the layout
 * result for a given html can be compared against a golden file by ctest.
 */

typedef struct {
	int		fd;
	char		err;	/* any write failed or line would truncate */
} dump_t;

static void
dump_raw(dump_t *d, const char *p, size_t len)
{
	while (len && !d->err) {
		ssize_t n = write(d->fd, p, LWS_POSIX_LENGTH_CAST(len));

		if (n <= 0) {
			d->err = 1;
			return;
		}
		p += n;
		len -= (size_t)n;
	}
}

static void
dump_printf(dump_t *d, const char *fmt, ...) LWS_FORMAT(2);

static void
dump_printf(dump_t *d, const char *fmt, ...)
{
	char buf[256];
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	/* a truncated line would just be a confusing golden mismatch */
	if (n < 0 || (size_t)n >= sizeof(buf)) {
		d->err = 1;
		return;
	}

	dump_raw(d, buf, (size_t)n);
}

static void
dump_dlo(dump_t *f, lws_dlo_t *dlo, int depth)
{
	char b[4][22];
	int i;

	while (dlo) {
		lws_fx_string(&dlo->box.x, b[0], sizeof(b[0]));
		lws_fx_string(&dlo->box.y, b[1], sizeof(b[1]));
		lws_fx_string(&dlo->box.w, b[2], sizeof(b[2]));
		lws_fx_string(&dlo->box.h, b[3], sizeof(b[3]));

		for (i = 0; i < depth; i++)
			dump_raw(f, " ", 1);

		if (dlo->_destroy == lws_display_dlo_text_destroy) {
			lws_dlo_text_t *t = lws_container_of(dlo,
							lws_dlo_text_t, dlo);

			dump_printf(f, "text (%s,%s) [%s x %s] rgba=%08X f=%u/%u \"",
				b[0], b[1], b[2], b[3], (unsigned int)dlo->dc,
				(unsigned int)t->font->choice.fixed_height,
				(unsigned int)t->font->choice.weight);
			if (t->text)
				dump_raw(f, t->text, t->text_len);
			dump_raw(f, "\"", 1);
		} else
		if (dlo->render == lws_display_render_hit) {
			lws_dlo_hit_t *h = lws_container_of(dlo,
							lws_dlo_hit_t, dlo);

			static const char * const cur[] = {
				"default", "pointer", "text", "crosshair",
				"move", "wait", "help", "not-allowed", "none"
			};

			dump_printf(f, "hit (%s,%s) [%s x %s]%s %s \"",
				b[0], b[1], b[2], b[3], h->fill ? " fill" : "",
				h->cursor < LWS_ARRAY_SIZE(cur) ?
					cur[h->cursor] : "?");
			if (h->url)
				dump_raw(f, h->url, strlen(h->url));
			dump_raw(f, "\"", 1);
		} else
#if defined(LWS_WITH_UPNG)
		if (dlo->_destroy == lws_display_dlo_png_destroy)
			dump_printf(f, "png (%s,%s) [%s x %s]",
				b[0], b[1], b[2], b[3]);
		else
#endif
#if defined(LWS_WITH_JPEG)
		if (dlo->_destroy == lws_display_dlo_jpeg_destroy)
			dump_printf(f, "jpeg (%s,%s) [%s x %s]",
				b[0], b[1], b[2], b[3]);
		else
#endif
#if defined(LWS_WITH_SVG)
		if (dlo->_destroy == lws_display_dlo_svg_destroy)
			dump_printf(f, "svg (%s,%s) [%s x %s]",
				b[0], b[1], b[2], b[3]);
		else
#endif
#if defined(LWS_WITH_GIF)
		if (dlo->_destroy == lws_display_dlo_gif_destroy)
			dump_printf(f, "gif (%s,%s) [%s x %s]",
				b[0], b[1], b[2], b[3]);
		else
#endif
		{
			lws_dlo_rect_t *r = lws_container_of(dlo,
							lws_dlo_rect_t, dlo);
			int n, rad = 0;

			for (n = 0; n < 4; n++)
				rad |= r->c[n].r.whole || r->c[n].r.frac;

			dump_printf(f, "rect (%s,%s) [%s x %s] rgba=%08X",
				b[0], b[1], b[2], b[3], (unsigned int)dlo->dc);
			if (rad) {
				dump_raw(f, " radii=", 7);
				for (n = 0; n < 4; n++) {
					lws_fx_string(&r->c[n].r, b[0],
						      sizeof(b[0]));
					dump_printf(f, "%s%s", n ? "," : "", b[0]);
				}
			}
		}

		/* what the dlo and its children are composed with */
		if (dlo->opacity_inv)
			dump_printf(f, " alpha=%u", 255u - dlo->opacity_inv);
		if (dlo->flag_clip)
			dump_raw(f, " clip", 5);
		dump_raw(f, "\n", 1);

		if (lws_dll2_get_head(&dlo->children))
			dump_dlo(f, lws_container_of(
					lws_dll2_get_head(&dlo->children),
					lws_dlo_t, list), depth + 1);

		if (!lws_dll2_get_next(&dlo->list))
			break;

		dlo = lws_container_of(lws_dll2_get_next(&dlo->list),
				       lws_dlo_t, list);
	}
}

static int
dump_displaylist(const char *path, lws_displaylist_t *dl)
{
	dump_t f;
	lws_dll2_t *d;

	memset(&f, 0, sizeof(f));
	f.fd = lws_open(path, LWS_O_WRONLY | LWS_O_CREAT | LWS_O_TRUNC, 0644);
	if (f.fd < 0) {
		lwsl_err("%s: unable to open %s\n", __func__, path);
		return 1;
	}

	d = lws_dll2_get_head(&dl->dl);
	if (d)
		dump_dlo(&f, lws_container_of(d, lws_dlo_t, list), 0);

	close(f.fd);

	if (f.err)
		lwsl_err("%s: unable to write all of %s\n", __func__, path);

	return f.err;
}

static void
write_bmp_header(int fd, int w, int h)
{
	uint8_t head[54];
	int filesize = 54 + (w * h * 3);

	memset(head, 0, sizeof(head));

	head[0] = 'B';
	head[1] = 'M';
	head[2] = (uint8_t)(filesize & 0xff);
	head[3] = (uint8_t)((filesize >> 8) & 0xff);
	head[4] = (uint8_t)((filesize >> 16) & 0xff);
	head[5] = (uint8_t)((filesize >> 24) & 0xff);
	head[10] = 54;

	head[14] = 40;
	head[18] = (uint8_t)(w & 0xff);
	head[19] = (uint8_t)((w >> 8) & 0xff);
	head[20] = (uint8_t)((w >> 16) & 0xff);
	head[21] = (uint8_t)((w >> 24) & 0xff);

	h = -h; /* top-down */
	head[22] = (uint8_t)(h & 0xff);
	head[23] = (uint8_t)((h >> 8) & 0xff);
	head[24] = (uint8_t)((h >> 16) & 0xff);
	head[25] = (uint8_t)((h >> 24) & 0xff);

	head[26] = 1;
	head[28] = 24;

	if (write(fd, head, 54) < 54)
		lwsl_err("%s: write failed\n", __func__);
}

#if defined(SEVENCOL)
static void
expand(uint8_t nyb, uint8_t *rgba)
{
	*rgba++ = LWSDC_R(palette[nyb]);
	*rgba++ = LWSDC_G(palette[nyb]);
	*rgba++ = LWSDC_B(palette[nyb]);
	*rgba++ = 255;
}
#endif

/* --starve-ms is over: the heap is as it was before */

static void
starve_end(lws_sorted_usec_list_t *sul)
{
	lws_heap_limit_set(heap_limit);
}

static void
render(lws_sorted_usec_list_t *sul);

static void
relayout_browse(lws_sorted_usec_list_t *sul)
{
	if (!lws_lhp_ss_browse_filter(cx, &drs, page_url, render,
				      page_filtered ? &page_filter : NULL))
		return;

	if (++relayout_tries < RELAYOUT_TRIES) {
		lws_sul_schedule(cx, 0, &sul_relayout, relayout_browse,
				 RELAYOUT_RETRY_US);
		return;
	}

	lwsl_err("%s: unable to lay the page out again\n", __func__);
	result = 1;
	lws_default_loop_exit(cx);
}

/*
 * The render couldn't have a face from the server some text was laid out
 * in: throw the display list and what was rendered of it away, and lay the
 * page out again keeping the faces from the server it uses until the display
 * list is destroyed, so the render can't lose them.  The bmp is written again
 * from its start
 */

static void
relayout(lws_display_render_state_t *rs)
{
	lwsl_user("%s: laying the page out again in faces it can keep\n",
		  __func__);

	lws_lhp_ss_cancel(rs);

	free(rs->line);
	rs->line = NULL;

	lws_display_list_destroy(cx, &rs->displaylist);
	lws_display_render_free_ids(rs);
	memset(&rs->displaylist, 0, sizeof(rs->displaylist));

	memset(rs->st, 0, sizeof(rs->st));
	rs->sp = 0;
	rs->curr = 0;
	rs->lowest_id_y = 0;

	/* the redone layout can't need doing again */
	rs->fonts_hold = 1;
	rs->relayout_ok = 0;

	if (lseek(fdout, 0, SEEK_SET)) {
		lwsl_err("%s: unable to rewind the bmp\n", __func__);
		result = 1;
		lws_default_loop_exit(cx);
		return;
	}

	relayout_browse(&sul_relayout);
}

static void
render(lws_sorted_usec_list_t *sul)
{
	lws_display_render_state_t *rs = lws_container_of(sul,
					lws_display_render_state_t, sul);
	size_t lbuflen = (size_t)rs->ic->wh_px[0].whole *
					(rs->ic->greyscale ? 1 : 3);
	lws_stateful_ret_t r;

	lwsl_notice("%s: line %d\n", __func__, rs->curr);

	if (rs->html == 1)
		return;

	if (rs->layout_failed) {
		/*
		 * Out of memory with nothing left to reclaim, or unparseable:
		 * the display list is only what was laid out before that,
		 * and comparing it against anything would just mislead
		 */
		lwsl_err("%s: layout failed\n", __func__);
		result = 1;
		lws_display_list_destroy(cx, &rs->displaylist);
		lws_default_loop_exit(cx);
		return;
	}

	if (dump_path) {
		if (dump_displaylist(dump_path, &rs->displaylist))
			result = 1;
		lws_display_list_destroy(cx, &rs->displaylist);
		lws_default_loop_exit(cx);
		return;
	}

	if (!rs->line) {

		lws_display_get_ids_boxes(rs);

		if (pan_step < pan_count) {
			lws_display_render_pan(rs, pans[pan_step].x - rs->pan_x,
					       pans[pan_step].y - rs->pan_y);
			pan_step++;
			lwsl_user("%s: panned to %d, %d\n", __func__,
				  (int)rs->pan_x, (int)rs->pan_y);
		}
		//lws_display_dl_dump(&rs->displaylist);

		/* allocate one line of RGB output pixels to render into */

		rs->line = malloc(lbuflen);
		if (!rs->line) {
			lwsl_err("%s: OOM\n", __func__);
			/* !!! cleanup */
			return;
		}

		/*
		 * Start from white paper: areas of the surface no DLO covers
		 * show the page background, not stale buffer contents
		 */

		memset(rs->line, 0xff, lbuflen);
		rs->curr = 0;

		if (fdout != 1)
			write_bmp_header(fdout, rs->ic->wh_px[0].whole,
					 rs->ic->wh_px[1].whole);
	}

	/*
	 * Render every line of the surface, not only down to the lowest DLO:
	 * the bmp header promises --h rows, and the canvas below any content
	 * is the page background
	 */

	while (rs->curr != rs->ic->wh_px[1].whole) {

		/*
		 * --reclaim-lines: sound the bat signal ourselves every few
		 * lines, so every tenant (fonts, images) is evicted and has
		 * to renew itself mid-render, independent of the allocator.
		 * Only once per such line: the render may come back to the
		 * same line after waiting for a tenant to be fetched again,
		 * and evicting it again then would never let the line finish
		 */
		if (reclaim_lines && !(rs->curr % reclaim_lines) &&
		    rs->curr != reclaimed_line) {
			lws_reclaim((size_t)-1);
			reclaimed_line = rs->curr;
			if (starve_ms) {
				/*
				 * --starve-ms: as on a device whose heap is
				 * all in use for a while, the faces can't be
				 * fetched again until it is given back
				 */
				lws_heap_limit_set(lws_get_allocated_heap());
				lws_sul_schedule(cx, 0, &sul_starve,
						 starve_end,
						 (lws_usec_t)starve_ms *
							LWS_US_PER_MS);
				starve_ms = 0;
			}
		}

		r = lws_display_list_render_line(rs);

		if ((r & LWS_SRET_FATAL) && rs->relayout) {
			relayout(rs);
			return;
		}

		if (r) {
			/*
			 * eg, waiting for more jpg or whatever.  A yield
			 * (a decoder couldn't get memory this time round)
			 * has nothing else to wake us: come back shortly
			 */
			lwsl_notice("%s: leaving 0x%x\n", __func__, (unsigned int)r);
			if (r & LWS_SRET_YIELD)
				lws_sul_schedule(cx, 0, &rs->sul, render,
						 20 * LWS_US_PER_MS);
			return;
		}

#if defined(SEVENCOL)
		/* convert from paletteized result to RGBA for dump purposes */
		{
			uint8_t dump[2048 * 4];
			int n;

			for (n = 0; n < rs->box.w.whole; n += 2) {
				expand(rs->line[(n >> 1)] >> 4, dump + (4 * n));
				expand(rs->line[(n >> 1)] & 0xf, dump + (4 * (n + 1)));
			}

			if (write(fdout, dump, (size_t)rs->box.w.whole * 4) < (ssize_t)((size_t)rs->box.w.whole * 4))
				lwsl_err("%s: write failed\n", __func__);
		}
#else
		{
			/* swap RGB -> BGR */
			uint8_t *p = (uint8_t *)rs->line;
			size_t n;

			for (n = 0; n < lbuflen; n += 3) {
				uint8_t t = p[0];
				p[0] = p[2];
				p[2] = t;
				p += 3;
			}
		}

#if defined(WIN32)
		if (write(fdout, rs->line, (unsigned int)lbuflen) < 0) {
#else
		if (write(fdout, rs->line, lbuflen) < 0) {
#endif
#endif
			lwsl_err("%s: unable to write\n", __func__);
		}

		rs->curr++;

		/* the next line starts from white paper again */

		memset(rs->line, 0xff, lbuflen);
	}

	free(rs->line);
	rs->line = NULL;

	if (pan_count) {
		/*
		 * Panning over more of the page mustn't hold more heap: what
		 * is kept for what was drawn is only for what can be seen
		 */
		size_t hu = lws_get_allocated_heap();

		lwsl_user("%s: pan %d: heap %u\n", __func__, pan_step,
			  (unsigned int)hu);
		if (pan_step == 1)
			pan_heap_first = hu;
		if (pan_step == pan_count && pan_heap_max >= 0 &&
		    hu > pan_heap_first + (size_t)pan_heap_max) {
			lwsl_err("%s: heap grew by %u over the pans, max %d\n",
				 __func__, (unsigned int)(hu - pan_heap_first),
				 pan_heap_max);
			result = 1;
		}
	}

	if (pan_step < pan_count) {
		/* --pan: render the display list again from the top, panned */
		memset(rs->st, 0, sizeof(rs->st));
		rs->sp = 0;
		if (fdout != 1 && lseek(fdout, 0, SEEK_SET)) {
			lwsl_err("%s: unable to rewind the bmp\n", __func__);
			result = 1;
			lws_default_loop_exit(cx);
			return;
		}
		lws_sul_schedule(cx, 0, &rs->sul, render, 1);
		return;
	}

#if defined(LWS_WITH_SVG)
	/*
	 * --svg-live-max: svg images are only held while something needs
	 * them, eg, a page of local icons stacked vertically holds one at a
	 * time, from the raster reaching it to the raster leaving it
	 */
	if (svg_live_max >= 0 &&
	    lws_svg_get_live_peak() > (unsigned int)svg_live_max) {
		lwsl_err("%s: %u svg images were held at once, max %d\n",
			 __func__, lws_svg_get_live_peak(), svg_live_max);
		result = 1;
	}
#endif

	lwsl_warn("%s: render has reached end and destroys displaylist\n", __func__);
	lws_display_list_destroy(cx, &rs->displaylist);

	lws_default_loop_exit(cx);
}

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(cx);
}

/*
 * Read a whole file into a NUL-terminated heap buffer, or return NULL.  The
 * caller frees it with free().
 */
#if defined(LWS_WITH_CACHE_BLOB)
static uint8_t *
read_raw_file(const char *path, size_t *len)
{
	uint8_t *buf = NULL;
	struct stat s;
	size_t done = 0;
	ssize_t n;
	int fd;

	fd = open(path, LWS_O_RDONLY);
	if (fd < 0)
		return NULL;

	if (fstat(fd, &s)) {
		close(fd);

		return NULL;
	}

	buf = malloc((size_t)s.st_size);
	if (!buf) {
		close(fd);

		return NULL;
	}

	while (done < (size_t)s.st_size) {
		n = read(fd, buf + done, (size_t)s.st_size - done);
		if (n <= 0)
			break;
		done += (size_t)n;
	}
	close(fd);

	if (done != (size_t)s.st_size) {
		free(buf);

		return NULL;
	}

	*len = done;

	return buf;
}
#endif

static char *
read_file(const char *path)
{
	char *buf = NULL, *t;
	size_t len = 0;
	ssize_t n;
	int fd;

	fd = open(path, LWS_O_RDONLY);
	if (fd < 0)
		return NULL;

	for (;;) {
		t = realloc(buf, len + 1025);
		if (!t)
			goto bail;
		buf = t;

		n = read(fd, buf + len, 1024);
		if (n < 0)
			goto bail;
		if (!n)
			break;
		len += (size_t)n;
	}

	buf[len] = '\0';
	close(fd);

	return buf;

bail:
	free(buf);
	close(fd);

	return NULL;
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p;
	(void)switches;

	if ((argc == 1) || lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches, LWS_ARRAY_SIZE(switches));
		return 0;
	}


	signal(SIGINT, sigint_handler);

	lws_context_info_defaults(&info, NULL);lws_cmdline_option_handle_builtin(argc, argv, &info);

	lwsl_user("LWS LHP DLO test tool - %s https://site.com [--bmp file.bmp]\n", argv[0]);

	dump_path = lws_cmdline_option(argc, argv, switches[LWS_SW_DUMP].sw);

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_W].sw)))
		ic.wh_px[0].whole = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_H].sw)))
		ic.wh_px[1].whole = atoi(p);

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_FDLIMIT].sw)))
		info.fd_limit_per_thread = (unsigned int)atoi(p);

#if defined(LWS_WITH_CACHE_BLOB)
	if ((p = lws_cmdline_option(argc, argv,
				     switches[LWS_SW_ASSET_CACHE].sw)))
		info.dlo_asset_cache_dir = p;
#endif

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_BMP].sw))) {
		fdout = open(p, LWS_O_WRONLY | LWS_O_CREAT | LWS_O_TRUNC, 0600);
		if (fdout < 0) {
			result = 1;
			lwsl_err("%s: unable to open bmp file\n", __func__);
			goto bail;
		}
	}

	info.port = CONTEXT_PORT_NO_LISTEN;
#if defined(LWS_WITH_SERVER)
	if (lws_cmdline_option(argc, argv, switches[LWS_SW_SERVE_FONTS].sw))
		info.pss_policies_json = serve_fonts_policy;
#endif
	info.options |= LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
			LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT |
			LWS_SERVER_OPTION_H2_JUST_FIX_WINDOW_UPDATE_OVERFLOW;

	/*
	 * Real sites can return a large block of response headers in one go,
	 * eg a burst of set-cookie on a login redirect; the lws default of
	 * 4096 is too small to survive some sites that otherwise work
	 */

	if (!info.max_http_header_data)
		info.max_http_header_data = 16384;

	cx = lws_create_context(&info);
	if (!cx)
		goto bail;

	/* register the available fonts */

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_FONTS].sw))) {
		/*
		 * The same faces from files: the layout must come out
		 * identical, with the dictionaries and glyphs coming and
		 * going from the heap as the reclaim registry asks
		 */
		int n = lws_fonts_register_dir(cx, p);

		if (n <= 0) {
			lwsl_err("%s: no fonts found in %s\n", __func__, p);
			goto bail;
		}
		lwsl_notice("%s: %d file-backed fonts from %s\n", __func__,
			    n, p);
#if defined(LWS_WITH_SERVER)
	} else if ((p = lws_cmdline_option(argc, argv,
					  switches[LWS_SW_SERVE_FONTS].sw))) {
		/*
		 * The same, but from an http server serving the directory
		 * here, on a port of its own: a page it doesn't have is
		 * refused with a 404, as a server still making it would
		 */
		static const struct lws_protocol_vhost_options mcufont_mime = {
			NULL, NULL, ".mcufont", "application/octet-stream"
		};
		static struct lws_http_mount mount;
		struct lws_context_creation_info vi;
		struct lws_vhost *vh;
		char url[64];

		memset(&mount, 0, sizeof(mount));
		mount.mountpoint = "/";
		mount.mountpoint_len = 1;
		mount.origin = p;
		mount.origin_protocol = LWSMPRO_FILE;
		/* lws only serves files of types it knows */
		mount.extra_mimetypes = &mcufont_mime;

		memset(&vi, 0, sizeof(vi));
		vi.vhost_name = "fonts";
		vi.iface = LOOPBACK;
		vi.port = 0; /* any free port */
		vi.mounts = &mount;

		vh = lws_create_vhost(cx, &vi);
		if (!vh) {
			lwsl_err("%s: can't serve %s\n", __func__, p);
			goto bail;
		}

		lws_snprintf(url, sizeof(url),
			     "http://" LOOPBACK_URL ":%d/fonts.json",
			     lws_get_vhost_listen_port(vh));

		lws_font_register(cx, fira_c_r_14, sizeof(fira_c_r_14));
		if (lws_fonts_register_manifest(cx, url)) {
			lwsl_err("%s: can't use font manifest %s\n", __func__,
				 url);
			goto bail;
		}
#endif
	} else if ((p = lws_cmdline_option(argc, argv,
					  switches[LWS_SW_FONT_MANIFEST].sw))) {
		/*
		 * Fonts as a system attribute: one face kept here, so text
		 * can always be shown, and the rest learned from a manifest
		 * on a server and fetched into the heap a page at a time, as
		 * they are needed
		 */
		lws_font_register(cx, fira_c_r_14, sizeof(fira_c_r_14));
		if (lws_fonts_register_manifest(cx, p)) {
			lwsl_err("%s: can't use font manifest %s\n", __func__, p);
			goto bail;
		}
	} else {
	lws_font_register(cx, fira_c_r_10, sizeof(fira_c_r_10));
	lws_font_register(cx, fira_c_r_12, sizeof(fira_c_r_12));
	lws_font_register(cx, fira_c_r_14, sizeof(fira_c_r_14));
	lws_font_register(cx, fira_c_r_16, sizeof(fira_c_r_16));
	lws_font_register(cx, fira_c_r_20, sizeof(fira_c_r_20));
	lws_font_register(cx, fira_c_r_24, sizeof(fira_c_r_24));
	lws_font_register(cx, fira_c_r_32, sizeof(fira_c_r_32));
	lws_font_register(cx, fira_c_b_10, sizeof(fira_c_b_10));
	lws_font_register(cx, fira_c_b_12, sizeof(fira_c_b_12));
	lws_font_register(cx, fira_c_b_14, sizeof(fira_c_b_14));
	lws_font_register(cx, fira_c_b_16, sizeof(fira_c_b_16));
	lws_font_register(cx, fira_c_b_20, sizeof(fira_c_b_20));
	lws_font_register(cx, fira_c_b_24, sizeof(fira_c_b_24));
	lws_font_register(cx, fira_c_b_32, sizeof(fira_c_b_32));
	}

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_HEAP_LIMIT].sw))) {
		heap_limit = lws_get_allocated_heap() + (size_t)atoi(p);
		lws_heap_limit_set(heap_limit);
	}

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_STARVE_MS].sw)))
		starve_ms = atoi(p);

	if ((p = lws_cmdline_option(argc, argv,
				    switches[LWS_SW_RECLAIM_LINES].sw)))
		reclaim_lines = atoi(p);

	if ((p = lws_cmdline_option(argc, argv,
				    switches[LWS_SW_RECLAIM_ELEMS].sw)))
		drs.reclaim_elems = (uint16_t)atoi(p);

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_RETAINED].sw))
		drs.retained = 1;

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_FONTS_LOCAL].sw))
		drs.fonts_local = 1;

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_LAYOUT_H].sw)))
		drs.layout_h = atoi(p);

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_PAN].sw))) {
		while (*p) {
			const char *c = strchr(p, ','), *n;

			if (!c || pan_count == PAN_MAX) {
				lwsl_err("--pan takes up to %d x,y separated "
					 "by :\n", PAN_MAX);
				return 1;
			}
			pans[pan_count].x = atoi(p);
			pans[pan_count++].y = atoi(c + 1);
			n = strchr(c, ':');
			if (!n)
				break;
			p = n + 1;
		}
		if (pan_count > 1 && !drs.retained) {
			lwsl_err("--pan with more than one x,y needs "
				 "--retained\n");
			return 1;
		}
	}

	if ((p = lws_cmdline_option(argc, argv,
				    switches[LWS_SW_PAN_HEAP_MAX].sw)))
		pan_heap_max = atoi(p);

	/*
	 * If the render can't have a face from the server some text was laid
	 * out in, we can lay the page out again keeping the faces, as long as
	 * the bmp can be written again from its start
	 */
	drs.relayout_ok = fdout != 1;

	if ((p = lws_cmdline_option(argc, argv,
				    switches[LWS_SW_SVG_LIVE_MAX].sw)))
		svg_live_max = atoi(p);

	drs.ic = &ic;

#if defined(LWS_WITH_CACHE_BLOB)
	/*
	 * Optionally preseed the asset cache with a file payload under an
	 * arbitrary url (--preseed url=file), so cache hits can be tested
	 * without any network
	 */

	if (info.dlo_asset_cache_dir) {
		struct lws_cache_ttl_lru *cache = lws_dlo_asset_cache(cx);
		const char *ps = lws_cmdline_option(argc, argv,
						switches[LWS_SW_PRESEED].sw);

		if (ps && cache) {
			char url[300], *file;
			uint8_t *buf;
			size_t len;

			lws_strncpy(url, ps, sizeof(url));
			file = strchr(url, '=');
			if (file)
				*file++ = '\0';

			buf = file ? read_raw_file(file, &len) : NULL;
			if (buf) {
				if (lws_cache_write_through(cache, url, buf,
						len,
						lws_now_usecs() +
							3600 * LWS_US_PER_SEC,
						NULL))
					lwsl_err("%s: preseed failed\n",
						 __func__);
				else
					lwsl_notice("%s: preseeded %u bytes "
						    "as %s\n", __func__,
						    (unsigned int)len, url);
				free(buf);
			} else
				lwsl_err("%s: unable to preseed from %s\n",
					 __func__, ps);
		}
	}
#endif

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_KERN_CHECK].sw)) {
		result = kern_check(cx);
		lws_context_destroy(cx);
		goto bail;
	}

	/* create the SS to the html using the URL on argv[1] */

	if (argv[1] == NULL) {
		lwsl_err("Give a url like https://warmcat.com on the commandline\n");
		result = 1;
		goto bail;
	}

	{
		const char *cssf = lws_cmdline_option(argc, argv,
					switches[LWS_SW_CSS_FILTER].sw);
		const char *bl = lws_cmdline_option(argc, argv,
					switches[LWS_SW_BLOCK_LIST].sw);
		lws_lhp_filter_t *lf = &page_filter;
		int r;

		if (cssf) {
			lf->cosmetic_css = read_file(cssf);
			if (!lf->cosmetic_css) {
				lwsl_err("%s: unable to read %s\n", __func__, cssf);
				result = 1;
				goto bail;
			}
		}
		if (bl) {
			lf->block_rules = read_file(bl);
			if (!lf->block_rules) {
				lwsl_err("%s: unable to read %s\n", __func__, bl);
				result = 1;
				goto bail;
			}
		}

		page_url = argv[1];
		page_filtered = cssf || bl;

		r = lws_lhp_ss_browse_filter(cx, &drs, page_url, render,
					     page_filtered ? lf : NULL);
		if (r) {
			lws_context_destroy(cx);
			goto bail;
		}
	}

	lws_context_default_loop_run_destroy(cx);

	if (fdout != 1)
		close(fdout);

bail:
	/* the browse copies the filter, but a relayout browses again */
	free((void *)page_filter.cosmetic_css);
	free((void *)page_filter.block_rules);

	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
