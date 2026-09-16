/*
 * lws-lhp-browser
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * Made available under the Creative Commons CC0 1.0 Universal Public Domain
 * Dedication.
 *
 * A "degenerate browser" dev tool around lws lhp: browse a URL, lay it
 * out with the real css engine, and either render the whole document to a
 * bmp, or present it in a native resizable window (see plat/) that you can
 * scroll around and click on.  Resizing the window re-layouts the document
 * at the new size; with the asset cache enabled, the images for each
 * relayout mostly come from the cache instead of the network.
 *
 * This is also the development bench for the interactive side of lhp
 * (viewport scrolling, hit zones, damage regions): the window core here
 * mimics those layers until they exist in the library for real.
 */

#include <libwebsockets.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <signal.h>

#include "plat/private-lhp-browser.h"

enum {
	LWS_SW_BMP,
		LWS_SW_W,
		LWS_SW_H,
		LWS_SW_DOC_H,
		LWS_SW_GUI,
		LWS_SW_SHOT,
		LWS_SW_CSS_FILTER,
		LWS_SW_BLOCK_LIST,
		LWS_SW_ASSET_CACHE,
		LWS_SW_PRESEED,
		LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_BMP]	= { "--bmp",           "Render the whole document to the given .bmp file" },
	[LWS_SW_W]	= { "--w",             "Surface width in px (default 600)" },
	[LWS_SW_H]	= { "--h",             "Surface height in px (default 448)" },
	[LWS_SW_DOC_H]	= { "--doc-h",         "Lay out the document this tall in px (default --h); with --gui, taller docs scroll" },
	[LWS_SW_GUI]	= { "--gui",           "Show the render in a native window: scroll with wheel / keys, click reports the element under the pointer, resizing re-layouts" },
	[LWS_SW_SHOT]	= { "--shot",          "With --gui: after the first render, dump the window framebuffer to this .bmp and exit" },
	[LWS_SW_CSS_FILTER]= { "--css-filter", "Filter css from file hides junk elements, eg .ad { display: none !important; }" },
	[LWS_SW_BLOCK_LIST]= { "--block-list", "URL block rules from file: ||host.tld or substring per line" },
	[LWS_SW_ASSET_CACHE]= { "--asset-cache", "Directory for the document asset cache, enables it" },
	[LWS_SW_PRESEED]	= { "--preseed",    "Preseed the asset cache with url=file" },
	[LWS_SW_HELP]	= { "--help",          "Show this help information" },
};

struct lws_context *cx;
lws_display_render_state_t drs;

int fdout = 1, result = 0;

/* the app core state, shared with the plat window backend */

struct lhp_browser win;

/* the document surface: a 600x448-class truecolor window on the world */

lws_surface_info_t ic = {
	.wh_px = { { 600,0 },        { 448,0 } },
	.wh_mm = { { 114,5000000 }, {  82,5000000 } },
	.type = LWSSURF_TRUECOLOR32,
	.greyscale = 0
};

static void render(lws_sorted_usec_list_t *sul);

static const char *shot_path;
static const char *browse_url;
static char nav_url[256]; /* browse_url when a link was followed */

/*
 * While the window edge is dragged, relayouts run adaptively: a short
 * interval after the first resize event, one at a time, each laying out
 * and re-rendering at whatever size the window has reached by then.
 * Further resize events while one is pending or rendering only update
 * the target size; the next is scheduled as each render completes.
 */

#define RESIZE_RELAYOUT_DELAY_US	(120 * LWS_US_PER_MS)

/*
 * In --gui mode the document is laid out at the window width and its own
 * natural height (up to this ceiling), and the DLO is kept.  The window
 * is presented exactly as an EPD would be: the renderer fills a single
 * line buffer, which goes straight to the display, and there is no
 * framebuffer.  Scrolling re-scans the retained DLO from the new offset
 * from scratch; image decode state cannot go backwards, so scanned
 * images are renewed from the document asset cache first.
 */

#define WIN_LAYOUT_H_MAX		16384

/* how many viewport heights to offer the layout, so percentage-height
 * elements have something to resolve against without filling the whole
 * 16k ceiling with blank filler */

#define WIN_LAYOUT_H_MULT		8

/* viewport lines rendered per scan pass, to stay responsive */

#define WIN_SCAN_BUDGET			96

static void win_scan_start(void);
static void win_scan_cb(lws_sorted_usec_list_t *sul);
static void win_shot_cb(lws_sorted_usec_list_t *sul);
static void win_relayout(void);

/*
 * The height offered to the layout: --doc-h pins it, else a few viewports
 * to start with, grown when a document turns out to be taller than that
 * (the layout drops content below the surface it is given)
 */

static int
win_layout_h(void)
{
	int h;

	if (win.pin_h)
		return win.pin_h;

	h = win.vh * WIN_LAYOUT_H_MULT;
	if (h < win.layout_h)
		h = win.layout_h;
	if (h > WIN_LAYOUT_H_MAX)
		h = WIN_LAYOUT_H_MAX;

	return h;
}

static int relayout_scheduled;

/*
 * Window geometry persistence: the last window size is kept in the user
 * config area ($XDG_CONFIG_HOME or ~/.config)/lhp-browser/geometry and
 * used as the initial size of the next --gui window.  Explicit --w / --h
 * override it for that run.
 */

static char conf_path[384];

/* the document asset cache lives in the user cache area by default:
 * (XDG_CACHE_HOME or ~/.cache)/lhp-browser/assets */

static int
win_cache_path(char *dest, size_t len)
{
	const char *xdg = getenv("XDG_CACHE_HOME");
	const char *home = getenv("HOME");
	char dir[352];
	size_t n;

	if (xdg && *xdg)
		lws_snprintf(dir, sizeof(dir), "%s/lhp-browser", xdg);
	else {
		if (!home || !*home)
			return 1;
		n = (size_t)lws_snprintf(dir, sizeof(dir), "%s/.cache", home);
		(void)mkdir(dir, 0700); /* may already exist */
		lws_snprintf(dir + n, sizeof(dir) - n, "/lhp-browser");
	}

	(void)mkdir(dir, 0700); /* may already exist */
	lws_snprintf(dest, len, "%s/assets", dir);

	return 0;
}

static int
win_conf_path(char *dest, size_t len)
{
	const char *xdg = getenv("XDG_CONFIG_HOME");
	const char *home = getenv("HOME");
	char dir[352];
	size_t n;

	if (xdg && *xdg)
		lws_snprintf(dir, sizeof(dir), "%s/lhp-browser", xdg);
	else {
		if (!home || !*home)
			return 1;
		n = (size_t)lws_snprintf(dir, sizeof(dir), "%s/.config", home);
		(void)mkdir(dir, 0700); /* may already exist */
		lws_snprintf(dir + n, sizeof(dir) - n, "/lhp-browser");
	}

	(void)mkdir(dir, 0700); /* may already exist */
	lws_snprintf(dest, len, "%s/geometry", dir);

	return 0;
}

/* read back "w <n>\nh <n>\n"; anything unexpected means no geometry */

static int
win_geometry_load(int *w, int *h)
{
	char buf[128], num[16], name = 0;
	int vals[2] = { 0, 0 };
	lws_tokenize_t ts;
	ssize_t rd;
	int e, fd;

	fd = open(conf_path, LWS_O_RDONLY);
	if (fd < 0)
		return 1;

	rd = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (rd <= 0)
		return 1;
	buf[rd] = '\0';

	memset(&ts, 0, sizeof(ts));
	ts.start = buf;
	ts.len = (size_t)rd;

	do {
		e = lws_tokenize(&ts);
		switch (e) {
		case LWS_TOKZE_TOKEN:
			name = ts.token_len == 1 &&
			       (*ts.token == 'w' || *ts.token == 'h')
					? *ts.token : 0;
			break;
		case LWS_TOKZE_INTEGER:
			if (name) {
				size_t cl = (size_t)ts.token_len;

				if (cl > sizeof(num) - 1)
					cl = sizeof(num) - 1;
				memcpy(num, ts.token, cl);
				num[cl] = '\0';

				vals[name == 'w' ? 0 : 1] = atoi(num);
				name = 0;
			}
			break;
		default:
			break;
		}
	} while (e > 0);

	/* only sane geometry is usable */

	if (vals[0] < 64 || vals[0] > 8192 ||
	    vals[1] < 64 || vals[1] > 8192)
		return 1;

	*w = vals[0];
	*h = vals[1];

	return 0;
}

static void
win_geometry_save(int w, int h)
{
	char buf[64];
	int fd, n;

	fd = open(conf_path, LWS_O_WRONLY | LWS_O_CREAT | LWS_O_TRUNC, 0600);
	if (fd < 0)
		return;

	n = lws_snprintf(buf, sizeof(buf), "w %d\nh %d\n", w, h);

	if (write(fd, buf, (size_t)n) < n)
		lwsl_err("%s: write failed\n", __func__);

	close(fd);
}

/* kept for the process lifetime so window relayouts can re-apply them */

static char *css_filter_text;
static char *block_list_text;

static const uint8_t fira_c_r_10[] = {
#include "../../contrib/mcufont/fonts/FiraSansCondensed-Regular10.mcufont.h"
};
static const uint8_t fira_c_r_12[] = {
#include "../../contrib/mcufont/fonts/FiraSansCondensed-Regular12.mcufont.h"
};
static const uint8_t fira_c_r_14[] = {
#include "../../contrib/mcufont/fonts/FiraSansCondensed-Regular14.mcufont.h"
};
static const uint8_t fira_c_r_16[] = {
#include "../../contrib/mcufont/fonts/FiraSansCondensed-Regular16.mcufont.h"
};
static const uint8_t fira_c_r_20[] = {
#include "../../contrib/mcufont/fonts/FiraSansCondensed-Regular20.mcufont.h"
};
static const uint8_t fira_c_r_24[] = {
#include "../../contrib/mcufont/fonts/FiraSansCondensed-Regular24.mcufont.h"
};
static const uint8_t fira_c_r_32[] = {
#include "../../contrib/mcufont/fonts/FiraSansCondensed-Regular32.mcufont.h"
};

static const uint8_t fira_c_b_10[] = {
#include "../../contrib/mcufont/fonts/FiraSansCondensed-Bold10.mcufont.h"
};
static const uint8_t fira_c_b_12[] = {
#include "../../contrib/mcufont/fonts/FiraSansCondensed-Bold12.mcufont.h"
};
static const uint8_t fira_c_b_14[] = {
#include "../../contrib/mcufont/fonts/FiraSansCondensed-Bold14.mcufont.h"
};
static const uint8_t fira_c_b_16[] = {
#include "../../contrib/mcufont/fonts/FiraSansCondensed-Bold16.mcufont.h"
};
static const uint8_t fira_c_b_20[] = {
#include "../../contrib/mcufont/fonts/FiraSansCondensed-Bold20.mcufont.h"
};
static const uint8_t fira_c_b_24[] = {
#include "../../contrib/mcufont/fonts/FiraSansCondensed-Bold24.mcufont.h"
};
static const uint8_t fira_c_b_32[] = {
#include "../../contrib/mcufont/fonts/FiraSansCondensed-Bold32.mcufont.h"
};

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

static void
sigint_handler(int sig)
{
	win.quitting = 1;
	lws_default_loop_exit(cx);
	(void)sig;
}

/*
 * Read a whole file into a heap buffer, or return NULL.  The caller frees
 * it with free().
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
	if (fd < 0 || fstat(fd, &s))
		return NULL;

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

/*
 * Read a whole file into a NUL-terminated heap buffer, or return NULL.  The
 * caller frees it with free().
 */
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

/* move the viewport to an absolute doc y: the old viewport content is
 * gone (there is no framebuffer), so the retained DLO is re-scanned from
 * the new offset from scratch */

static void
win_scroll_set(int y)
{
	int max = win.doc_h - win.vh;

	if (max < 0)
		max = 0;

	if (y < 0)
		y = 0;
	if (y > max)
		y = max;

	if (y == win.scroll_y)
		return;

	win.scroll_y = y;

	lwsl_user("scroll: viewport y -> %d (document %d tall)\n",
		  win.scroll_y, win.doc_h);

	win_scan_start();
}

/* move the viewport down the document by delta px (negative = up) */

void
lhp_browser_scroll(int delta)
{
	static char once;

	if (!win.doc_h)
		return; /* still laying out */

	if (win.doc_h <= win.vh) {
		if (!once) {
			once = 1;
			lwsl_user("scroll: document is only %d tall in a "
				  "%d tall window, nothing below the "
				  "fold\n", win.doc_h, win.vh);
		}

		return;
	}

	win_scroll_set(win.scroll_y + delta);
}

/*
 * A click arrived at window coords: resolve it to the id'd element whose
 * final layout box contains the corresponding document point, if any.
 * This is the embryo of real hit-testing against the retained element
 * boxes.
 */

void
lhp_browser_click(int x, int y)
{
	int dy = y + win.scroll_y;
	lws_display_id_t *hit = NULL;
	lws_dlo_hit_t *h;
	lws_box_t hb;

	/*
	 * The layout leaves a non-printing hit region on every link's text
	 * runs, images and boxes: find the topmost one under the click,
	 * resolve its href against the document url and go there
	 */

	h = lws_display_dl_hit_test(&drs.displaylist, x, dy, &hb);
	if (h) {
		char url[256];

		if (lws_http_rel_to_url(url, sizeof(url), browse_url, h->url))
			lws_strncpy(url, h->url, sizeof(url));

		lwsl_user("click at %d,%d: link '%s' -> %s (doc box %d,%d "
			  "%dx%d)\n", x, y, h->url, url, (int)hb.x.whole,
			  (int)hb.y.whole, (int)hb.w.whole, (int)hb.h.whole);

		if (win.active && strcmp(url, browse_url)) {
			lws_strncpy(nav_url, url, sizeof(nav_url));
			browse_url = nav_url;
			/* a fresh document: lay it out from the top */
			win.scan_done = 0;
			win_relayout();
		}

		return;
	}

	lws_start_foreach_dll(lws_dll2_t *, d, lws_dll2_get_head(&drs.ids)) {
		lws_display_id_t *id = lws_container_of(d, lws_display_id_t, list);

		if (x >= id->box.x.whole &&
		    x <  id->box.x.whole + id->box.w.whole &&
		    dy >= id->box.y.whole &&
		    dy <  id->box.y.whole + id->box.h.whole) {
			hit = id;
			break;
		}
	} lws_end_foreach_dll(d);

	if (hit)
		lwsl_user("click at %d,%d: id '%s' (doc box %d,%d %dx%d)\n",
			  x, y, hit->id,
			  (int)hit->box.x.whole, (int)hit->box.y.whole,
			  (int)hit->box.w.whole, (int)hit->box.h.whole);
	else
		lwsl_user("click at %d,%d: no id'd element there\n", x, y);
}

void
lhp_browser_key(lhp_browser_key_t k)
{
	int max;

	if (k == LHPBK_QUIT) {
		win.quitting = 1;

		return;
	}

	if (!win.doc_h)
		return;

	max = win.doc_h - win.vh;
	if (max < 0)
		max = 0;

	switch (k) {
	case LHPBK_UP:		win_scroll_set(win.scroll_y - 40);	break;
	case LHPBK_DOWN:		win_scroll_set(win.scroll_y + 40);	break;
	case LHPBK_PAGE_UP:		win_scroll_set(win.scroll_y - win.vh);	break;
	case LHPBK_PAGE_DOWN:	win_scroll_set(win.scroll_y + win.vh);	break;
	case LHPBK_HOME:		win_scroll_set(0);			break;
	case LHPBK_END:		win_scroll_set(max);			break;
	default:
		return;
	}
}

/* window content was lost: re-scan the current viewport from the DLO */

void
lhp_browser_repaint(void)
{
	if (!win.active || !win.doc_h || !win.scan_done)
		return;

	win_scan_start();
}

static void
win_relayout(void);

static void
win_relayout_cb(lws_sorted_usec_list_t *sul);

/*
 * The window changed size: stop presenting the old document (it is the
 * wrong size now, and would show as repeated or stretched content), and
 * start an adaptive relayout cycle if one is not already running
 */

void
lhp_browser_resize(int w, int h)
{
	if (w == win.vw && h == win.vh)
		return;

	win.vw = w;
	win.vh = h;

	/* the current render no longer matches the window: present blank
	 * until the relayout's scan renders the new lines */

	lhp_browser_plat_clear(0, win.vh);

	if (!relayout_scheduled) {
		relayout_scheduled = 1;
		lws_sul_schedule(cx, 0, &win.sul_relayout, win_relayout_cb,
				 RESIZE_RELAYOUT_DELAY_US);
	}
}

/* throw the current document away and lay it out again at the window size */

static void
win_relayout(void)
{
	int w = win.vw;

	if (win.scan_done && w == drs.ic->wh_px[0].whole)
		return;

	lwsl_notice("%s: relayout at %d wide\n", __func__, w);

	/*
	 * Stop the previous document completely first: its parse, its
	 * render, and any assets still fetching.  Without this, tearing
	 * down an image dlo whose asset is in flight resumes the old
	 * document's parse against the display list we are about to pull
	 * down, and the two documents interleave on the render state.
	 */

	lws_lhp_ss_cancel(&drs);

	/* a render of the old document may have been mid-flight */

	if (drs.line) {
		free(drs.line);
		drs.line = NULL;
	}

	lws_sul_cancel(&win.sul_scan);

	lws_display_list_destroy(cx, &drs.displaylist);
	lws_display_render_free_ids(&drs);
	memset(&drs.displaylist, 0, sizeof(drs.displaylist));

	memset(drs.st, 0, sizeof(drs.st));
	drs.sp = 0;
	drs.curr = 0;
	drs.lowest_id_y = 0;

	/* lay out at the window width, to the document's natural height */

	ic.wh_px[0].whole = w;
	ic.wh_px[1].whole = win_layout_h();

	win.scroll_y = 0;
	win.doc_h = 0;
	win.scan_done = 0;

	if (css_filter_text || block_list_text) {
		lws_lhp_filter_t lf;

		memset(&lf, 0, sizeof(lf));
		lf.cosmetic_css = css_filter_text;
		lf.block_rules = block_list_text;

		if (lws_lhp_ss_browse_filter(cx, &drs, browse_url, render,
					     &lf)) {
			lwsl_err("%s: rebrowse failed\n", __func__);
			win.quitting = 1;
		}

		return;
	}

	if (lws_lhp_ss_browse(cx, &drs, browse_url, render)) {
		lwsl_err("%s: rebrowse failed\n", __func__);
		win.quitting = 1;
	}
}

static void
win_relayout_cb(lws_sorted_usec_list_t *sul)
{
	(void)sul;

	relayout_scheduled = 0;

	/* cancel makes tearing down mid-render safe, so relayout at the
	 * latest size immediately */

	win_relayout();
}

/*
 * --shot: the lines the window presented are journaled as they are
 * scanned, so the shot is exactly what the (framebufferless) window
 * showed for the viewport
 */

static uint8_t *shot_journal;

static void
win_scan_cb(lws_sorted_usec_list_t *sul)
{
	size_t lw = (size_t)drs.ic->wh_px[0].whole * 3;

	(void)sul;
	int last = win.scroll_y + win.vh;
	int budget = WIN_SCAN_BUDGET;

	if (last > win.doc_h)
		last = win.doc_h;

	while ((int)drs.curr < last) {
		lws_stateful_ret_t r;
		int wy;

		if (!budget--) {
			lws_sul_schedule(cx, 0, &win.sul_scan, win_scan_cb, 1);

			return;
		}

		r = lws_display_list_render_line(&drs);
		if (r) {
			/* eg, waiting for more jpg or whatever */

			lws_sul_schedule(cx, 0, &win.sul_scan, win_scan_cb,
					 20 * LWS_US_PER_MS);

			return;
		}

		wy = (int)drs.curr - win.scroll_y;
		lhp_browser_plat_line(wy, drs.line, (int)(lw / 3));

		if (shot_journal)
			memcpy(&shot_journal[(size_t)wy * lw],
			       drs.line, lw);

		drs.curr++;

		/* the next line starts from white paper again */

		memset(drs.line, 0xff, lw);
	}

	/* the viewport scan completed */

	win.scan_done = 1;

	lwsl_notice("%s: viewport at y=%d scanned (%d lines)\n", __func__,
		    win.scroll_y, (int)drs.curr - win.scroll_y);

	/* show the new frame in one step: a partially scanned viewport
	 * must never be sampled mid-update */

	lhp_browser_plat_present();

	if (shot_path) {
		static int shot_delay_us = -1;

		if (shot_delay_us == -1) {
			const char *e = getenv("LHP_SHOT_DELAY_MS");

			/* let scripted tests resize / scroll first */

			shot_delay_us = e ? atoi(e) * 1000 :
						750 * LWS_US_PER_MS;
		}

		lws_sul_schedule(cx, 0, &win.sul_shot, win_shot_cb,
				 shot_delay_us);
	}
}

/*
 * Start a scan of the viewport at the current scroll position: renew the
 * scanned images from the asset cache (their decode state cannot go
 * backwards), blank the window, and render the visible lines one at a
 * time into the single line buffer, presenting each as it completes,
 * exactly as a line-rendered EPD update
 */

static void
win_scan_start(void)
{
	size_t lw = (size_t)drs.ic->wh_px[0].whole * 3;

	win.scan_done = 0;

	lws_dlo_ss_renew_images(cx);

	/* the old viewport content is gone: blank while the scan runs */

	lhp_browser_plat_clear(0, win.vh);

	/* the scan restarts the DLO walk at the viewport top */

	memset(drs.st, 0, sizeof(drs.st));
	drs.sp = 0;
	drs.curr = (lws_display_scalar)win.scroll_y;

	if (!drs.line) {
		drs.line = malloc(lw);
		if (!drs.line) {
			lwsl_err("%s: OOM\n", __func__);
			win.quitting = 1;

			return;
		}
	}

	memset(drs.line, 0xff, lw);

	if (shot_path) {
		/* the journal is the presented viewport, for --shot */

		free(shot_journal);
		shot_journal = malloc(lw * (size_t)win.vh);

		if (!shot_journal) {
			lwsl_err("%s: OOM\n", __func__);
			win.quitting = 1;

			return;
		}

		memset(shot_journal, 0xff, lw * (size_t)win.vh);
	}

	lws_sul_schedule(cx, 0, &win.sul_scan, win_scan_cb, 1);
}

static void
win_shot_cb(lws_sorted_usec_list_t *sul)
{
	size_t lw = (size_t)drs.ic->wh_px[0].whole * 3;
	(void)sul;

	if (!win.scan_done || relayout_scheduled) {
		/*
		 * Any resize-driven relayout is given time to complete, so
		 * the shot shows the settled document
		 */
		lws_sul_schedule(cx, 0, &win.sul_shot, win_shot_cb,
				 200 * LWS_US_PER_MS);

		return;
	}

	{
		int fd = open(shot_path, LWS_O_WRONLY | LWS_O_CREAT | LWS_O_TRUNC,
			      0600);
		size_t n;

		if (fd < 0) {
			lwsl_err("%s: unable to open %s\n", __func__, shot_path);
			result = 1;
			goto done;
		}

		write_bmp_header(fd, (int)(lw / 3), win.vh);

		for (n = 0; n < (size_t)win.vh; n++) {
			uint8_t *p = &shot_journal[n * lw], *e = p;
			size_t i;

			/* swap RGB -> BGR into the bmp layout */

			for (i = 0; i < lw; i += 3) {
				uint8_t t = p[0];
				p[0] = p[2];
				p[2] = t;
				p += 3;
			}

			if (write(fd, e, lw) < (ssize_t)lw)
				lwsl_err("%s: write failed\n", __func__);
		}

		close(fd);
		lwsl_user("wrote window shot %s\n", shot_path);
	}

done:
	win.quitting = 1;
}

static void
render(lws_sorted_usec_list_t *sul)
{
	lws_display_render_state_t *rs = lws_container_of(sul,
					lws_display_render_state_t, sul);
	size_t lbuflen = (size_t)rs->ic->wh_px[0].whole *
					(rs->ic->greyscale ? 1 : 3);
	lws_stateful_ret_t r;

	if (rs->html == 1)
		return;

	if (win.active) {
		/*
		 * Window mode: the DLO is the artifact, laid out at the
		 * window width to the document's natural height.  Work out
		 * that height and start the first viewport scan; late asset
		 * completions can grow the document and re-scan it.
		 */

		int nd = 0;

		lws_display_get_ids_boxes(rs);

		/*
		 * The real content height: the root dlo is the body
		 * background, which stretches to whatever surface height we
		 * offered the layout, so look at its children instead
		 */

		{
			lws_dll2_t *d = lws_dll2_get_head(&rs->displaylist.dl);

			if (d) {
				lws_dlo_t *root = lws_container_of(d,
						lws_dlo_t, list);
				lws_fx_t t;

				lws_start_foreach_dll(lws_dll2_t *, c,
						lws_dll2_get_head(&root->children)) {
					lws_dlo_t *cd = lws_container_of(c,
							lws_dlo_t, list);

					lws_fx_add(&t, &cd->box.y,
						   &cd->box.h);
					lws_fx_add(&t, &t, &root->box.y);
					if (t.whole > nd)
						nd = t.whole;

				} lws_end_foreach_dll(c);
			}
		}

		if (nd < win.vh)
			nd = win.vh;
		if (nd > rs->ic->wh_px[1].whole)
			nd = rs->ic->wh_px[1].whole;

		/*
		 * The layout drops content that lands below the surface it
		 * was offered.  If the completed document was cut short
		 * that way, lay it out again with more room, up to the
		 * ceiling, so the whole page can be scrolled to
		 */

		if (rs->html == 2 && rs->layout_clipped && !win.pin_h &&
		    rs->ic->wh_px[1].whole < WIN_LAYOUT_H_MAX) {
			win.layout_h = rs->ic->wh_px[1].whole * 2;
			if (win.layout_h > WIN_LAYOUT_H_MAX)
				win.layout_h = WIN_LAYOUT_H_MAX;

			lwsl_notice("%s: document clipped at %d: relayout "
				    "at %d tall\n", __func__,
				    rs->ic->wh_px[1].whole, win.layout_h);

			win.scan_done = 0;
			relayout_scheduled = 1;
			lws_sul_schedule(cx, 0, &win.sul_relayout,
					 win_relayout_cb, 1);

			return;
		}

		if (nd == win.doc_h && win.scan_done)
			return;

		win.doc_h = nd;

		lwsl_notice("%s: document is %d tall (window %dx%d)\n", __func__, nd, win.vw, win.vh);

		win_scan_start();

		return;
	}

	if (!rs->line) {

		lws_display_get_ids_boxes(rs);

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

		r = lws_display_list_render_line(rs);

		if (r) {
			/* eg, waiting for more jpg or whatever */
			lwsl_notice("%s: leaving 0x%x\n", __func__, (unsigned int)r);
			return;
		}

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

#if defined(WIN32)
			if (write(fdout, rs->line, (unsigned int)lbuflen) < 0) {
#else
			if (write(fdout, rs->line, lbuflen) < 0) {
#endif
				lwsl_err("%s: unable to write\n", __func__);
			}
		}

		rs->curr++;

		/* the next line starts from white paper again */

		memset(rs->line, 0xff, lbuflen);
	}

	free(rs->line);
	rs->line = NULL;

	lwsl_notice("%s: render has reached end and destroys displaylist\n",
		    __func__);
	lws_display_list_destroy(cx, &rs->displaylist);

	lws_default_loop_exit(cx);
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p;
	int had_w = 0, had_h = 0;
	(void)switches;

	if ((argc == 1) || lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches, LWS_ARRAY_SIZE(switches));
		return 0;
	}

	signal(SIGINT, sigint_handler);

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	lwsl_user("LWS LHP browser - %s <url> [--gui]\n", argv[0]);

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_W].sw))) {
		ic.wh_px[0].whole = atoi(p);
		had_w = 1;
	}
	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_H].sw))) {
		ic.wh_px[1].whole = atoi(p);
		had_h = 1;
	}

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_GUI].sw))
		win.active = 1;

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_DOC_H].sw))) {
		win.pin_h = atoi(p);
		ic.wh_px[1].whole = win.pin_h;
		had_h = 1;
	}

	shot_path = lws_cmdline_option(argc, argv, switches[LWS_SW_SHOT].sw);
	if (shot_path && !win.active) {
		lwsl_err("%s: --shot needs --gui\n", __func__);
		return 1;
	}

#if defined(LWS_WITH_CACHE_BLOB)
	if ((p = lws_cmdline_option(argc, argv,
				     switches[LWS_SW_ASSET_CACHE].sw)))
		info.dlo_asset_cache_dir = p;
	else {
		/*
		 * The document asset cache is on by default: fetched
		 * documents and their assets stay in the user cache area,
		 * so repeat visits and relayouts mostly come from the cache
		 * instead of the network.  --asset-cache points it somewhere
		 * else.
		 */

		static char cache_dir[384];

		if (!win_cache_path(cache_dir, sizeof(cache_dir)))
			info.dlo_asset_cache_dir = cache_dir;
	}
#endif

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_BMP].sw))) {
		fdout = open(p, LWS_O_WRONLY | LWS_O_CREAT | LWS_O_TRUNC, 0600);
		if (fdout < 0) {
			lwsl_err("%s: unable to open bmp file\n", __func__);
			return 1;
		}
	}

	info.port = CONTEXT_PORT_NO_LISTEN;
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
		return 1;

	/* register the available fonts */

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

	/* the URL to browse is argv[1] */

	if (argv[1] == NULL) {
		lwsl_err("Give a url like https://warmcat.com on the commandline\n");
		result = 1;
		goto bail;
	}

	browse_url = argv[1];

	if (win.active) {
		int gw = ic.wh_px[0].whole, gh = had_h ? ic.wh_px[1].whole : 480;
		int have_conf = 0;

		/*
		 * The remembered window size from the user config area is
		 * the default; explicit --w / --h override it for this run.
		 * The window is only a viewport: the document lays out at
		 * the window width and its own natural height, and the DLO
		 * is retained for re-scanning as the viewport moves
		 */

		if (!win_conf_path(conf_path, sizeof(conf_path))) {
			int lw = gw, lh = gh;

			if (!win_geometry_load(&lw, &lh)) {
				have_conf = 1;

				/* explicit --w / --h beat the remembered
				 * geometry, per side */

				if (!had_w)
					gw = lw;
				if (!had_h)
					gh = lh;
			}
		}

		if (!had_w)
			ic.wh_px[0].whole = gw;

		if (have_conf) {
			/* the remembered geometry fit the screen last time */

			win.vw = ic.wh_px[0].whole;
			win.vh = gh;
		} else {
			win.vw = ic.wh_px[0].whole > 900 ? 900
						       : ic.wh_px[0].whole;
			win.vh = gh > 480 ? 480 : gh;
		}

		/* with the window size known, offer the layout room for the
		 * document's natural height */

		ic.wh_px[1].whole = win_layout_h();

		drs.retained = 1;

		if (lhp_browser_plat_init(win.vw, win.vh)) {
			lwsl_err("%s: --gui needs the app built with a "
				 "window backend (plat/unix.c, X11)\n",
				 __func__);
			result = 1;
			lws_context_destroy(cx);
			goto bail;
		}
	}

	{
		const char *cssf = lws_cmdline_option(argc, argv,
						switches[LWS_SW_CSS_FILTER].sw);
		const char *bl = lws_cmdline_option(argc, argv,
						switches[LWS_SW_BLOCK_LIST].sw);
		lws_lhp_filter_t lf;
		int r;

		memset(&lf, 0, sizeof(lf));

		if (cssf) {
			lf.cosmetic_css = read_file(cssf);
			if (!lf.cosmetic_css) {
				lwsl_err("%s: unable to read %s\n", __func__, cssf);
				result = 1;
				goto bail;
			}
		}
		if (bl) {
			lf.block_rules = read_file(bl);
			if (!lf.block_rules) {
				lwsl_err("%s: unable to read %s\n", __func__, bl);
				result = 1;
				goto bail;
			}
		}

		/*
		 * The filter contents were copied by the browse call, but
		 * window relayouts browse again: keep them for the process
		 * lifetime
		 */

		css_filter_text = (char *)lf.cosmetic_css;
		block_list_text = (char *)lf.block_rules;

		r = lws_lhp_ss_browse_filter(cx, &drs, argv[1], render,
					      (cssf || bl) ? &lf : NULL);

		if (r) {
			lws_context_destroy(cx);
			goto bail;
		}
	}

	if (win.active) {
		/*
		 * Our own loop: lws is serviced non-blockingly (a negative
		 * timeout means zero wait), and then we sleep in the backend
		 * until window input can arrive or a short interval passed.
		 * lws parks in a days-long poll when it is idle and the
		 * window fd is not in its wait set, so the backend owns the
		 * bounded wait.
		 */

		while (!lhp_browser_plat_pump()) {
			if (lws_service(cx, -1) < 0)
				break;
			lhp_browser_plat_wait(5);
		}

		lws_sul_cancel(&win.sul_relayout);
		lws_sul_cancel(&win.sul_scan);
		lws_sul_cancel(&win.sul_shot);
		lhp_browser_plat_destroy();

		/*
		 * Remember the window size for next time; scripted --shot
		 * runs must not clobber it
		 */

		if (!shot_path && conf_path[0])
			win_geometry_save(win.vw, win.vh);

		if (drs.line) {
			free(drs.line);
			drs.line = NULL;
		}

		if (shot_journal) {
			free(shot_journal);
			shot_journal = NULL;
		}

		lws_context_destroy(cx);
	} else
		lws_context_default_loop_run_destroy(cx);

	if (fdout != 1)
		close(fdout);

bail:
	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
