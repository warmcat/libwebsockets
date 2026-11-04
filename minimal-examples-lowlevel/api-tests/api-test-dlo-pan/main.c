/*
 * lws-api-test-dlo-pan
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Pans around a page laid out taller and wider than the display it is shown
 * on, without laying it out again, with lws_display_render_pan().  The page
 * is bands of colour 100px tall, the first one wider than the display, with
 * a png 160px tall, red over blue, between them.  It's laid out to
 * .layout_h, taller than the display, and rendered on a pretend 240 x 240
 * display that keeps what is sent to it in a framebuffer, first a round one,
 * like the Waveshare ESP32-S3-Touch-LCD-1.28's, then a rectangular one.  It
 * checks
 *
 *  - the page wasn't cut short by the layout, though it's longer than the
 *    display
 *
 *  - panning down shows what is further down the page
 *
 *  - panning back up a little shows the top of the png again, though the
 *    previous render stopped partway down it
 *
 *  - the view can't go further than the end of the page; on the round
 *    display, only as much further as it takes to bring the corners of the
 *    page to the first pixel of the circle that can be seen there
 *
 *  - what the view shows beyond the page is white
 *
 *  - the view can go across to the right edge of the wider band, but not
 *    further
 *
 *  - a page shorter than the display stays where it was laid out, unless
 *    it's moved.  It is as wide as the display: on the round display it can
 *    be moved right to bring its right corners into the circle, and up and
 *    left for its top left corner, but not down, since the bottom of what is
 *    in it is in the circle already
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>

#define W		240
#define H		240
#define LAYOUT_H	1024

/* the page: bands 100px tall, the png's box 160px tall, the first band wider */
#define PAGE_W		400
#define PAGE_H		660
#define PNG_Y		300	/* the png is 32 x 160, at the left */

/*
 * On a round display, the view can go as far as bringing a corner of the page
 * to the first pixel of the circle at 45 degrees from the middle: that's
 * 120 - sqrt(120^2 / 2) = 36 pixels in from each side
 */
#define AFF		36

#define C_GREEN		0x00ff00
#define C_YELLOW	0xffff00
#define C_CYAN		0x00ffff
#define C_RED		0xff0000
#define C_BLUE		0x0000ff
#define C_GREY		0x808080
#define C_WHITE		0xffffff

static const char page_html[] =
	"<!doctype html><html><head><meta charset=\"utf-8\" />"
	"<style>"
	"body { margin: 0; background-color: #808080 }"
	"div { height: 100px; width: 240px }"
	"#a { width: 400px; background-color: #0f0 }"
	"#b { background-color: #ff0 }"
	"#c { background-color: #0ff }"
	"#i { height: 160px }"
	"img { display: block }"
	"#d { background-color: #f0f }"
	"#e { background-color: #000 }"
	"</style></head><body>"
	"<div id=\"a\"></div><div id=\"b\"></div><div id=\"c\"></div>"
	"<div id=\"i\"><img src=\"file://dlofs/stripes.png\"></div>"
	"<div id=\"d\"></div><div id=\"e\"></div>"
	"</body></html>";

static const lws_dlo_filesystem_t fs_page = {
	.name			= "pan.html",
	.data			= page_html,
	.len			= sizeof(page_html) - 1,
};

/* a page shorter and narrower than the display */

static const char short_html[] =
	"<!doctype html><html><head><meta charset=\"utf-8\" />"
	"<style>"
	"body { margin: 0; background-color: #808080 }"
	"div { height: 100px; width: 150px; background-color: #0f0 }"
	"</style></head><body><div></div></body></html>";

static const lws_dlo_filesystem_t fs_short = {
	.name			= "short.html",
	.data			= short_html,
	.len			= sizeof(short_html) - 1,
};

static const uint8_t stripes_png[] = {
#include "stripes.png.h"
};

static const lws_dlo_filesystem_t fs_png = {
	.name			= "stripes.png",
	.data			= stripes_png,
	.len			= sizeof(stripes_png),
};

static const lws_display_t disp_round = {
	.name			= "pretend 240 round",
	.ic = {
		.wh_px		= { { W, 0 }, { H, 0 } },
		.wh_mm		= { { 32, 0 }, { 32, 0 } },
		.type		= LWSSURF_TRUECOLOR32,
		.round		= 1,
	},
}, disp_rect = {
	.name			= "pretend 240 rectangular",
	.ic = {
		.wh_px		= { { W, 0 }, { H, 0 } },
		.wh_mm		= { { 32, 0 }, { 32, 0 } },
		.type		= LWSSURF_TRUECOLOR32,
	},
};

static struct lws_context *cx;
static struct lws_plat_file_ops dlo_fops;
static lws_display_state_t lds;
static lws_display_render_state_t rs;
static lws_sorted_usec_list_t sul_step, sul_timeout;
static int step, pass, fail, scanning, moved;

/* what the display shows, RGB */
static uint8_t fb[W * H * 3];

static void
next_step(lws_sorted_usec_list_t *sul);

/*
 * Render the whole display from the retained display list, from the top, at
 * the pan as it is now.  The first time, when the html has completed
 */

static void
render(lws_sorted_usec_list_t *sul)
{
	lws_stateful_ret_t r;

	if (!scanning || rs.html == 1)
		return;

	while (rs.curr < H) {
		r = lws_display_list_render_line(&rs);
		if (r & LWS_SRET_FATAL) {
			lwsl_err("%s: render failed at line %d\n", __func__,
				 (int)rs.curr);
			fail = 1;
			lws_default_loop_exit(cx);
			return;
		}
		if (r) {
			/* eg, the png isn't here yet */
			lws_sul_schedule(cx, 0, &rs.sul, render, LWS_US_PER_MS);
			return;
		}

		memcpy(&fb[rs.curr * W * 3], rs.line, W * 3);
		rs.curr++;
	}

	scanning = 0;
	lws_sul_schedule(cx, 0, &sul_step, next_step, 1);
}

static void
scan(void)
{
	memset(rs.st, 0, sizeof(rs.st));
	rs.sp = 0;
	rs.curr = 0;
	scanning = 1;
	lws_sul_schedule(cx, 0, &rs.sul, render, 1);
}

/* the colour shown where point x, y of the page is, if it's on the display */

static int
expect(int x, int y, uint32_t c, const char *what)
{
	int dx = x - rs.pan_x, dy = y - rs.pan_y;
	const uint8_t *p;
	uint32_t got;

	if (dx < 0 || dx >= W || dy < 0 || dy >= H) {
		lwsl_err("%s: %d, %d (%s) isn't on the display at pan %d, %d\n",
			 __func__, x, y, what, (int)rs.pan_x, (int)rs.pan_y);
		fail = 1;
		return 1;
	}

	p = &fb[(dy * W + dx) * 3];
	got = (uint32_t)((p[0] << 16) | (p[1] << 8) | p[2]);
	if (got != c) {
		lwsl_err("%s: %d, %d (%s): 0x%06x, not 0x%06x, at pan %d, %d\n",
			 __func__, x, y, what, (unsigned int)got,
			 (unsigned int)c, (int)rs.pan_x, (int)rs.pan_y);
		fail = 1;
		return 1;
	}

	return 0;
}

static int
expect_pan(int x, int y)
{
	if (rs.pan_x == x && rs.pan_y == y)
		return 0;

	lwsl_err("%s: pan %d, %d, not %d, %d\n", __func__, (int)rs.pan_x,
		 (int)rs.pan_y, x, y);
	fail = 1;

	return 1;
}

static void
pan(int dx, int dy)
{
	moved = lws_display_render_pan(&rs, dx, dy);
	scan();
}

static int
browse(const char *url)
{
	memset(&lds, 0, sizeof(lds));
	lds.disp = pass ? &disp_rect : &disp_round;
	lds.ctx = cx;

	lws_display_dl_init(&rs.displaylist, &lds);
	rs.ic = &lds.disp->ic;
	rs.lds = &lds;
	rs.retained = 1;
	rs.layout_h = LAYOUT_H;

	if (!rs.line) {
		rs.line = malloc(W * 3);
		if (!rs.line)
			return 1;
	}

	scanning = 1;
	rs.curr = 0;

	return lws_lhp_ss_browse(cx, &rs, url, render);
}

static void
done(void)
{
	lws_lhp_ss_cancel(&rs);
	lws_display_list_destroy(cx, &rs.displaylist);
	lws_display_render_free_ids(&rs);
	free(rs.line);
	rs.line = NULL;
}

static void
next_step(lws_sorted_usec_list_t *sul)
{
	int aff = pass ? 0 : AFF;

	lwsl_user("%s: pass %d, step %d, pan %d, %d\n", __func__, pass, step,
		  (int)rs.pan_x, (int)rs.pan_y);

	switch (step++) {
	case 0:
		/* the page as it came, at the top left */
		if (rs.layout_clipped || rs.layout_failed) {
			lwsl_err("%s: the layout was cut short\n", __func__);
			fail = 1;
		}
		expect_pan(0, 0);
		expect(120, 50, C_GREEN, "first band");
		expect(120, 150, C_YELLOW, "second band");

		/* down to the png, partway into it */
		pan(0, 200);
		if (!moved) {
			lwsl_err("%s: pan down didn't move\n", __func__);
			fail = 1;
		}
		break;

	case 1:
		expect_pan(0, 200);
		expect(120, 250, C_CYAN, "third band");
		expect(10, PNG_Y + 10, C_RED, "top of the png");
		expect(10, PNG_Y + 100, C_BLUE, "bottom of the png");
		expect(100, PNG_Y + 10, C_GREY, "beside the png");

		/*
		 * Back up a bit: the png was decoded as far as the bottom of
		 * the display, it has to start again for its top
		 */
		pan(0, -50);
		break;

	case 2:
		expect_pan(0, 150);
		expect(10, PNG_Y, C_RED, "first row of the png again");
		expect(10, PNG_Y + 79, C_RED, "last red row of the png");
		expect(10, PNG_Y + 80, C_BLUE, "first blue row of the png");

		/* as far down as it goes */
		pan(0, 100000);
		break;

	case 3:
		expect_pan(0, PAGE_H - H + aff);
		expect(120, PAGE_H - 10, 0, "last band");
		if (aff)
			/* the page is laid out longer than its content */
			expect(120, PAGE_H + aff - 10, C_GREY,
			       "below the content");

		/* as far up and left as it goes */
		pan(-100000, -100000);
		break;

	case 4:
		expect_pan(-aff, -aff);
		expect(5, 5, C_GREEN, "top left of the page");
		if (aff) {
			expect(-5, 120, C_WHITE, "left of the page");
			expect(120, -5, C_WHITE, "above the page");
		}

		/* as far right as it goes */
		pan(100000, 0);
		break;

	case 5:
		expect_pan(PAGE_W - W + aff, -aff);
		expect(PAGE_W - 5, 50, C_GREEN, "right of the wide band");
		expect(PAGE_W - 5, 150, C_WHITE, "right of a narrow band");
		if (aff)
			expect(PAGE_W + 5, 50, C_WHITE, "right of the page");

		/* no further */
		moved = lws_display_render_pan(&rs, 1, 0);
		if (moved) {
			lwsl_err("%s: panned beyond the right\n", __func__);
			fail = 1;
		}

		done();
		if (browse("file://dlofs/short.html")) {
			fail = 1;
			lws_default_loop_exit(cx);
		}
		break;

	case 6:
		/* a short page is shown where it was laid out */
		expect_pan(0, 0);
		expect(5, 5, C_GREEN, "top left of the short page");

		/* the bottom of what is in it is on the display already */
		pan(100000, 100000);
		break;

	case 7:
		expect_pan(aff, 0);
		expect(W - 5, 5, C_GREY, "right of the short page");

		pan(-100000, -100000);
		break;

	case 8:
		expect_pan(-aff, -aff);
		expect(5, 5, C_GREEN, "top left of the short page");

		done();
		if (pass++) {
			lws_default_loop_exit(cx);
			break;
		}

		/* again on the rectangular display */
		step = 0;
		if (browse("file://dlofs/pan.html")) {
			fail = 1;
			lws_default_loop_exit(cx);
		}
		break;
	}

	if (fail)
		lws_default_loop_exit(cx);
}

static void
timeout_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("%s: timed out at pass %d, step %d\n", __func__, pass, step);
	fail = 1;
	lws_default_loop_exit(cx);
}

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(cx);
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;

	signal(SIGINT, sigint_handler);

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	lwsl_user("LWS API Test - dlo pan\n");

	info.port = CONTEXT_PORT_NO_LISTEN;
	/* the secure streams lhp fetches with make their own vhost */
	info.options |= LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
			LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* the dlo filesystem after the platform one, where the page is */

	dlo_fops = lws_dlo_fops;
	dlo_fops.cx = cx;
	dlo_fops.next = lws_get_fops(cx)->next;
	lws_get_fops(cx)->next = &dlo_fops;

	lws_dlo_file_register(cx, &fs_page);
	lws_dlo_file_register(cx, &fs_short);
	lws_dlo_file_register(cx, &fs_png);

	if (browse("file://dlofs/pan.html")) {
		lws_context_destroy(cx);
		return 1;
	}

	lws_sul_schedule(cx, 0, &sul_timeout, timeout_cb,
			 20 * LWS_US_PER_SEC);

	lws_context_default_loop_run_destroy(cx);

	if (rs.line)
		done();

	lwsl_user("Completed: %s\n", fail ? "FAIL" : "PASS");

	return fail;
}
