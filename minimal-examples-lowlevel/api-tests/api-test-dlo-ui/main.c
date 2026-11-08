/*
 * lws-api-test-dlo-ui
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Shows the strip ui (lws-dlo-ui.h) on a pretend 240 x 240 round display,
 * like the Waveshare ESP32-S3-Touch-LCD-1.28's, which keeps what is sent to
 * it in a framebuffer and notes the window of each update.  It checks
 *
 *  - the first update is of the whole display, and only white is drawn
 *    outside the circle that can be seen
 *
 *  - the title and the list's rows were drawn where they should be
 *
 *  - pressing a row picks it, and pressing below the last row doesn't;
 *    pressing the title calls the title callback instead
 *
 *  - dragging the list scrolls it, and only the list's band of lines is sent
 *    to the display again; setting the title only sends the title's band
 *
 *  - the edit page (where the keyboard can be dragged anywhere, so keys may
 *    be drawn outside the circle): typing on its keyboard, with shift and the
 *    symbols layer, only sends the edit strip's band, or the keyboard's when
 *    that changes; dragging the keyboard moves it, without typing anything, and
 *    Done gives what was typed and shows the list page again.  Pressing the
 *    title abandons an edit.
 *
 *  - the status capsule: it's drawn at the right end of the title strip, inside
 *    the circle, only the title strip's band is sent when it changes, and not
 *    at all when what it shows doesn't.  Pressing it issues its button's
 *    interaction event, as a button of that name would
 *
 *  - using it with buttons: lws_dlo_ui_nav(), or button events given to
 *    lws_dlo_ui_interaction(), move a cursor down the list and pick its row,
 *    or go back like the title; on the edit page, which can start with
 *    something already typed, they move the cursor over the keys, type with
 *    them, and press Done
 *
 *  - the frame page: drawn all at once with its body white, then its title
 *    strip is drawn by the caller with lws_dlo_ui_frame_line() in an update
 *    of its own, around its body, which touches and nav leave to the caller.
 *    Changing the title or status then only sends the title strip's band,
 *    leaving the body alone, or on a display that can't take a band, asks
 *    the caller to draw it all again.  Laying the title strip out again
 *    while the body's page is fetching an image doesn't stop the image.
 *
 *  - the theme: the first time, the default theme's title strip colour is
 *    drawn; the second time, the ui is given css that makes the title strip
 *    white with red text, which is drawn instead, and with nothing then drawn
 *    outside the circle at all
 *
 *  - destroying the ui gives back all the heap it took.  The context makes
 *    some things the first time they are used, eg, the vhost the secure
 *    streams lhp fetches with use, so all this is done twice, and the heap is
 *    checked across the second time
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>

#define W		240
#define H		240
/* the ui makes the title strip a sixth of a round display, then 36px rows */
#define TITLE_H		(H / 6)
#define ROW_H		36
#define ROWS		12

/* the edit page: the edit strip is a row high, the keyboard strip below it */
#define EDIT_Y0		TITLE_H
#define KB_Y0		(TITLE_H + ROW_H)
/* the keys are ROW_H apart; the keyboard is 10 keys wide, starting centred */
#define KB_X0		((W - 10 * ROW_H) / 2)

/* the second time, the title strip is white with red text */
static const char css_red_title[] =
	"#t { background-color: #fff } #tt { color: #f00 }";

static const uint8_t fira_c_r_16[] = {
#include "../contrib/mcufont/fonts/FiraSansCondensed-Regular16.mcufont.h"
};
static const uint8_t fira_c_r_20[] = {
#include "../contrib/mcufont/fonts/FiraSansCondensed-Regular20.mcufont.h"
};

/* a simple icon, as the dlo filesystem holds them */

static const char icon_svg[] =
	"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"24\" height=\"24\" "
	"viewBox=\"0 0 24 24\"><circle cx=\"12\" cy=\"12\" r=\"10\" "
	"fill=\"#2a7fff\"/></svg>";

static const lws_dlo_filesystem_t fs_icon = {
	.name			= "icon.svg",
	.data			= icon_svg,
	.len			= sizeof(icon_svg) - 1,
};

/*
 * The body's page, for the frame: its image is on a server of ours that takes
 * the connection and never says anything, so it is still being fetched for as
 * long as the test needs, which lws_dlo_ss_find() tells us.  lhp fetches with
 * the default policy's __default streamtype, which mandates tls: a url's
 * scheme can't turn that off, so the url is https
 */

static char body_html[192], body_img[64];

static lws_dlo_filesystem_t fs_body = {
	.name			= "body.html",
	.data			= body_html,
};

static int
callback_silent(struct lws *wsi, enum lws_callback_reasons reason, void *user,
		void *in, size_t len)
{
	return 0;
}

static const struct lws_protocols protocols[] = {
	{ "silent", callback_silent, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static struct lws_context *cx;
static struct lws_plat_file_ops dlo_fops;
static lws_display_state_t lds;
static lws_display_render_state_t body_rs;
static struct lws_dlo_ui *ui;
static lws_sorted_usec_list_t sul_step, sul_timeout;
static int step, fail, picked = -1, updates, upd_y0, upd_y1, win_y0, win_y1,
	   lines, pass, seen_updates, done_calls, done_keep, kbx, kby,
	   titled;
static char done_text[LWS_DLO_UI_EDIT_MAX];
static char done_null, in_edit;
/* the caller drew its body all over the display, outside the circle too */
static char unclipped;
static size_t heap_before;
static int settings_clicks, frame_redraws, body_y;
/* the title strip as the ui drew it, for the caller drawing it */
static uint8_t title_band[W * (H / 6) * 3];

/* what the display shows, RGB */
static uint8_t fb[W * H * 3];

static void
next_step(lws_sorted_usec_list_t *sul);

/*
 * The pretend display: a window is opened with a blit of more than one line,
 * then it gets the lines one at a time, and a zero-height blit ends the
 * update
 */

static int
pretend_blit(lws_display_state_t *lds, const uint8_t *src, lws_box_t *box,
	     lws_dll2_owner_t *ids)
{
	int y = box->y.whole;

	if (box->h.whole > 1) {
		win_y0 = y;
		win_y1 = y + box->h.whole;
		lines = 0;
		return 0;
	}

	if (box->h.whole == 1) {
		if (y < win_y0 || y >= win_y1) {
			lwsl_err("%s: line %d outside window %d..%d\n",
				 __func__, y, win_y0, win_y1);
			fail = 1;
			return 0;
		}
		memcpy(&fb[y * W * 3], src, W * 3);
		lines++;
		return 0;
	}

	/* the update is finished */

	if (lines != win_y1 - win_y0) {
		lwsl_err("%s: %d lines for window %d..%d\n", __func__, lines,
			 win_y0, win_y1);
		fail = 1;
	}

	updates++;
	upd_y0 = win_y0;
	upd_y1 = win_y1;
	lds->display_busy = 0;

	/* as a display's completion callback must */
	lws_dlo_ui_kick(ui);

	/* see what came of it when the ui has had its say */
	lws_sul_schedule(cx, 0, &sul_step, next_step, 300 * LWS_US_PER_MS);

	return 0;
}

static const lws_display_t disp = {
	.blit			= pretend_blit,
	.name			= "pretend 240 round",
	.ic = {
		.wh_px		= { { W, 0 }, { H, 0 } },
		.wh_mm		= { { 32, 0 }, { 32, 0 } },
		.type		= LWSSURF_TRUECOLOR32,
		.band		= 1,
		.round		= 1,
	},
};

/* the same, but it can only take an update of all of it */

static const lws_display_t disp_whole = {
	.blit			= pretend_blit,
	.name			= "pretend 240 round, whole updates",
	.ic = {
		.wh_px		= { { W, 0 }, { H, 0 } },
		.wh_mm		= { { 32, 0 }, { 32, 0 } },
		.type		= LWSSURF_TRUECOLOR32,
		.round		= 1,
	},
};

/* the capsule is a button, as a physical one called "settings" would be */

static int
smd_cb(void *opaque, lws_smd_class_t _class, lws_usec_t timestamp, void *buf,
       size_t len)
{
	if (!lws_json_simple_strcmp(buf, len, "\"type\":", "button") &&
	    !lws_json_simple_strcmp(buf, len, "\"src\":", "ui/settings") &&
	    !lws_json_simple_strcmp(buf, len, "\"event\":", "click"))
		settings_clicks++;

	return 0;
}

static void
frame_redraw_cb(void *opaque)
{
	frame_redraws++;
}

static int
row_cb(void *opaque, int idx, lws_dlo_ui_row_t *row)
{
	if (idx >= ROWS)
		return 1;

	/* markup in the text must be shown as text */
	lws_snprintf(row->text, sizeof(row->text), idx == 2 ?
		     "<b>AP %d</b> &amp;" : "AP %d", idx);
	if (!idx)
		row->icon = "icon.svg";
	if (idx == 1)
		row->state = LWS_DLO_UI_ROW_DIM;

	return 0;
}

static void
pick_cb(void *opaque, int idx)
{
	picked = idx;
}

static void
title_cb(void *opaque)
{
	titled++;
}

static int
done_cb(void *opaque, const char *text)
{
	done_calls++;
	done_null = !text;
	if (text)
		lws_strncpy(done_text, text, sizeof(done_text));

	return done_keep;
}

static int
dark(int x, int y)
{
	const uint8_t *p = &fb[(y * W + x) * 3];

	return p[0] + p[1] + p[2] < 3 * 160;
}

static int
dark_in(int x0, int y0, int x1, int y1)
{
	int x, y, n = 0;

	for (y = y0; y < y1; y++)
		for (x = x0; x < x1; x++)
			n += dark(x, y);

	return n;
}

/* pixels of about the colour r, g, b in the box */

static int
colour_in(int x0, int y0, int x1, int y1, int r, int g, int b)
{
	int x, y, n = 0;

	for (y = y0; y < y1; y++)
		for (x = x0; x < x1; x++) {
			const uint8_t *p = &fb[(y * W + x) * 3];

			n += abs(p[0] - r) < 24 && abs(p[1] - g) < 24 &&
			     abs(p[2] - b) < 24;
		}

	return n;
}

/*
 * Nothing but white may be drawn where the circle can't be seen.  The default
 * theme's title strip is coloured across the whole display, so the first time
 * that is left out
 */

static int
outside_circle_white(void)
{
	int x, y, n = 0;

	for (y = pass ? 0 : TITLE_H; y < H; y++)
		for (x = 0; x < W; x++) {
			int dx = 2 * x + 1 - W, dy = 2 * y + 1 - H;
			const uint8_t *p = &fb[(y * W + x) * 3];

			if (dx * dx + dy * dy > W * W &&
			    (p[0] != 0xff || p[1] != 0xff || p[2] != 0xff))
				n++;
		}

	if (n)
		lwsl_err("%s: %d pixels outside the circle drawn\n",
			 __func__, n);

	return !n;
}

static void
touch(const char *event, int x, int y, int dx, int dy)
{
	char buf[128];
	int n;

	n = lws_snprintf(buf, sizeof(buf), "{\"type\":\"touch\",\"src\":\"ts\","
			 "\"event\":\"%s\",\"x\":%d,\"y\":%d,\"dx\":%d,"
			 "\"dy\":%d}", event, x, y, dx, dy);
	lws_dlo_ui_touch(ui, buf, (size_t)n);
}

/* a drag: the finger comes down, then moves */

static void
drag(int x, int y, int dx, int dy)
{
	touch("down", x, y, 0, 0);
	touch("scroll", x + dx, y + dy, dx, dy);
	touch("up", x + dx, y + dy, 0, 0);
}

/*
 * The keys moved with the keyboard, backgrounds and all, where it was dragged
 * to: the top of the g key in its second row, between its rounded corners and
 * above its letter, is key coloured, and the gap before it isn't
 */

static int
keys_at_kb(void)
{
	int left = kbx + ROW_H / 2 + 4 * ROW_H, top = KB_Y0 + kby + ROW_H;

	if (colour_in(left + 6, top + 3, left + ROW_H - 6, top + 6,
		      0xdd, 0xdd, 0xdd) != (ROW_H - 12) * 3 ||
	    colour_in(left - 1, top + 8, left + 1, top + 12,
		      0xdd, 0xdd, 0xdd)) {
		lwsl_err("keys not where the keyboard was dragged\n");

		return 0;
	}

	return 1;
}

/* press the key in half key hx of keyboard row r, as the keyboard is now */

static void
key(int r, int hx)
{
	touch("press", kbx + (hx * ROW_H) / 2 + ROW_H / 4,
	      KB_Y0 + kby + r * ROW_H + ROW_H / 2, 0, 0);
}

/* there was one more update, of lines y0 to y1 */

static int
updated(const char *what, int y0, int y1)
{
	if (updates != ++seen_updates || upd_y0 != y0 || upd_y1 != y1) {
		lwsl_err("%s: update %d (%d): %d..%d, not %d..%d\n", what,
			 updates, seen_updates, upd_y0, upd_y1, y0, y1);
		return 0;
	}

	/* the keyboard is dragged anywhere: its keys may be drawn outside */
	return in_edit || unclipped || outside_circle_white();
}

/* a button event, as lws-button.h issues them */

static int
button(const char *name)
{
	char buf[96];
	int n;

	n = lws_snprintf(buf, sizeof(buf), "{\"type\":\"button\","
			 "\"src\":\"bc/%s\",\"event\":\"click\"}", name);

	return lws_dlo_ui_interaction(ui, buf, (size_t)n);
}

/*
 * The capsule: the theme's white, with the theme's dark blue bars in it, at
 * the right end of the title's line, inside the circle
 */

static int
capsule_drawn(void)
{
	int x0 = W / 2 + 20, x1 = W - 30, y0 = TITLE_H / 2, y1 = TITLE_H;

	if (colour_in(x0, y0, x1, y1, 0xff, 0xff, 0xff) < 40 ||
	    colour_in(x0, y0, x1, y1, 0x24, 0x47, 0x6b) < 10) {
		lwsl_err("%s: no capsule\n", __func__);
		return 0;
	}

	return 1;
}

static int
body_img_fetching(void)
{
	lws_dlo_image_t u;

	return !lws_dlo_ss_find(cx, body_img, &u);
}

static void
body_render(lws_sorted_usec_list_t *sul)
{
	/* the body's page is never drawn here, only fetched */
}

/* browse the body's page onto the frame's body surface */

static int
body_browse(const lws_surface_info_t *b)
{
	lws_display_dl_init(&body_rs.displaylist, &lds);
	body_rs.ic = b;
	body_rs.lds = &lds;

	if (lws_lhp_ss_browse(cx, &body_rs, "file://dlofs/body.html",
			      body_render)) {
		lwsl_err("body browse failed\n");
		return 1;
	}

	return 0;
}

/*
 * The ui's own layouts didn't stop the body's image: cancelling the body's
 * browse does.  Returns nonzero if that isn't so
 */

static int
body_survived(void)
{
	if (!body_img_fetching()) {
		lwsl_err("frame layout stopped the body's image\n");
		return 1;
	}

	lws_lhp_ss_cancel(&body_rs);
	lws_display_list_destroy(cx, &body_rs.displaylist);
	lws_display_render_free_ids(&body_rs);

	if (body_img_fetching()) {
		lwsl_err("body cancel left its image\n");
		return 1;
	}

	return 0;
}

/*
 * Draw all of the display as a caller with something in the frame's body
 * does: the title strip's lines from the ui, then the body's, here grey
 */

static int
caller_draw(void)
{
	uint8_t line[W * 3];
	lws_stateful_ret_t r;
	lws_box_t box;
	int y, tries;

	if (lds.display_busy)
		return 1;

	unclipped = 1;
	lds.display_busy = 1;
	memset(&box, 0, sizeof(box));
	box.w.whole = W;
	box.h.whole = H;
	lds.disp->blit(&lds, (uint8_t *)&body_rs, &box, NULL);

	box.h.whole = 1;
	for (y = 0; y < H; y++) {
		if (y < body_y) {
			tries = 0;
			do {
				r = lws_dlo_ui_frame_line(ui, y, line);
			} while ((r & LWS_SRET_YIELD) && tries++ < 100);
			if (r) {
				lwsl_err("%s: line %d: 0x%x\n", __func__, y,
					 (unsigned int)r);
				return 1;
			}
		} else
			memset(line, 0x80, sizeof(line));

		box.y.whole = y;
		lds.disp->blit(&lds, line, &box, NULL);
	}

	box.y.whole = 0;
	box.h.whole = 0;
	lds.disp->blit(&lds, line, &box, NULL);

	return 0;
}

/* the body is still all of what is was drawn as, the ui didn't touch it */

static int
body_is(uint8_t v)
{
	int y, x;

	for (y = body_y; y < H; y++)
		for (x = 0; x < W * 3; x++)
			if (fb[y * W * 3 + x] != v) {
				lwsl_err("%s: %d,%d is %d, not %d\n",
					 __func__, x / 3, y,
					 fb[y * W * 3 + x], v);
				return 0;
			}

	return 1;
}


static void
finish(int ok)
{
	if (!ok)
		fail = 1;

	lws_sul_cancel(&sul_timeout);
	lws_sul_cancel(&sul_step);
	lws_default_loop_exit(cx);
}

static int
start(void)
{
	lws_dlo_ui_info_t ui_info;

	step = 0;
	updates = 0;
	seen_updates = 0;
	picked = -1;
	done_calls = 0;
	titled = 0;
	settings_clicks = 0;
	frame_redraws = 0;
	lds.disp = &disp;
	memset(fb, 0xff, sizeof(fb));

	heap_before = lws_get_allocated_heap();

	memset(&ui_info, 0, sizeof(ui_info));
	ui_info.cx = cx;
	ui_info.lds = &lds;
	ui_info.row = row_cb;
	ui_info.pick = pick_cb;
	ui_info.title = title_cb;
	ui_info.done = done_cb;
	ui_info.frame_redraw = frame_redraw_cb;
	ui_info.status_button = "settings";
	if (pass)
		ui_info.css = css_red_title;

	ui = lws_dlo_ui_create(&ui_info);
	if (!ui) {
		lwsl_err("ui create failed\n");
		return 1;
	}

	lws_dlo_ui_set_title(ui, "AP");
	lws_dlo_ui_set_list(ui, ROWS, -1);

	return 0;
}

static void
next_step(lws_sorted_usec_list_t *sul)
{
	int top;

	if (fail) {
		finish(0);
		return;
	}

	switch (step++) {
	case 0:
		/* the first update */

		if (!updated("first", 0, H)) {
			finish(0);
			return;
		}
		if (!dark_in(W / 2 - 40, 0, W / 2 + 40, TITLE_H)) {
			lwsl_err("no title\n");
			finish(0);
			return;
		}
		/* the title strip is themed */
		if (pass ? !colour_in(W / 2 - 40, 0, W / 2 + 40, TITLE_H,
				      0xff, 0, 0) :
			   colour_in(W / 2 - 40, 0, W / 2 + 40, TITLE_H,
				     0x24, 0x47, 0x6b) < 40 * TITLE_H) {
			lwsl_err("title strip not themed\n");
			finish(0);
			return;
		}
		if (!dark_in(30, TITLE_H, W - 30, TITLE_H + ROW_H) ||
		    !dark_in(30, TITLE_H + 2 * ROW_H, W - 30,
			     TITLE_H + 3 * ROW_H)) {
			lwsl_err("rows not drawn\n");
			finish(0);
			return;
		}

		/* pressing the middle of the fourth row picks row 3 */

		touch("press", W / 2, TITLE_H + 3 * ROW_H + ROW_H / 2, 0, 0);
		if (picked != 3) {
			lwsl_err("press picked %d\n", picked);
			finish(0);
			return;
		}
		picked = -1;

		/* the title isn't the list, but says it was pressed */
		titled = 0;
		touch("press", W / 2, TITLE_H / 2, 0, 0);
		if (picked != -1 || titled != 1) {
			lwsl_err("title press picked %d, titled %d\n", picked,
				 titled);
			finish(0);
			return;
		}

		/* dragging up scrolls the list down */

		drag(W / 2, H / 2, 0, -50);
		break;

	case 1:
		if (!updated("scroll", TITLE_H, H)) {
			finish(0);
			return;
		}

		/* row 3 is now 50px further up */

		top = TITLE_H + 3 * ROW_H + ROW_H / 2 - 50;
		touch("press", W / 2, top, 0, 0);
		if (picked != 3) {
			lwsl_err("scrolled press picked %d\n", picked);
			finish(0);
			return;
		}

		lws_dlo_ui_set_title(ui, "AP 3");
		break;

	case 2:
		if (!updated("title", 0, TITLE_H)) {
			finish(0);
			return;
		}

		/* a list too short to scroll can't be */

		lws_dlo_ui_set_list(ui, 2, -1);
		break;

	case 3:
		if (!updated("short list", TITLE_H, H)) {
			finish(0);
			return;
		}
		picked = -1;
		touch("press", W / 2, TITLE_H + 3 * ROW_H + ROW_H / 2, 0, 0);
		if (picked != -1) {
			lwsl_err("press below the list picked %d\n", picked);
			finish(0);
			return;
		}

		/* the edit page replaces the whole list page */

		kbx = KB_X0;
		kby = 0;
		in_edit = 1;
		if (lws_dlo_ui_edit(ui, "Passphrase", 63,
				    LWS_DLO_UI_EDIT_MASKED)) {
			lwsl_err("edit failed\n");
			finish(0);
			return;
		}
		break;

	case 4:
		if (!updated("edit page", 0, H)) {
			finish(0);
			return;
		}
		if (!dark_in(30, KB_Y0, W - 30, H)) {
			lwsl_err("no keyboard\n");
			finish(0);
			return;
		}

		/* typing changes only the edit strip */

		key(0, 6); /* r */
		break;

	case 5:
		if (!updated("typed", EDIT_Y0, KB_Y0)) {
			finish(0);
			return;
		}
		if (!dark_in(30, EDIT_Y0, W - 30, KB_Y0)) {
			lwsl_err("nothing in the edit strip\n");
			finish(0);
			return;
		}

		/*
		 * Shift is off the left: drag the keyboard right to it, and up
		 * half a row, into the top of its strip.  The page is as it was
		 * laid out, so just the keyboard's dlo is moved, and only the
		 * lines of its strip are drawn again
		 */

		drag(W / 2, KB_Y0 + 2 * ROW_H, -KB_X0, -ROW_H / 2);
		kbx = 0;
		kby = -ROW_H / 2;
		break;

	case 6:
		if (!updated("keyboard dragged", KB_Y0, H)) {
			finish(0);
			return;
		}

		if (!keys_at_kb()) {
			finish(0);
			return;
		}

		key(2, 0);	/* Shift */
		key(0, 8);	/* T, then the layer is lower case again */
		key(3, 0);	/* ?123 */
		key(0, 0);	/* 1 */
		key(4, 0);	/* abc */
		break;

	case 7:
		/* what was typed and the keys both changed */
		if (!updated("shifted", EDIT_Y0, H)) {
			finish(0);
			return;
		}

		/* Done is off the right: drag the keyboard left to it */

		drag(W / 2, KB_Y0 + 2 * ROW_H, -120, 0);
		kbx = -120;
		break;

	case 8:
		if (!updated("keyboard dragged again", KB_Y0, H)) {
			finish(0);
			return;
		}

		if (!keys_at_kb()) {
			finish(0);
			return;
		}

		/* the caller can refuse it, and editing goes on */

		done_keep = 1;
		key(3, 16);	/* Done */
		if (done_calls != 1 || done_null || strcmp(done_text, "rT1")) {
			lwsl_err("done %d: got the wrong text\n", done_calls);
			finish(0);
			return;
		}

		done_keep = 0;
		in_edit = 0;
		key(3, 16);	/* Done */
		if (done_calls != 2 || strcmp(done_text, "rT1")) {
			lwsl_err("done %d: got the wrong text\n", done_calls);
			finish(0);
			return;
		}
		break;

	case 9:
		/* the list page is back, with what changed meanwhile */
		if (!updated("list page again", 0, H)) {
			finish(0);
			return;
		}
		picked = -1;
		touch("press", W / 2, TITLE_H + ROW_H / 2, 0, 0);
		if (picked != 0) {
			lwsl_err("list page press picked %d\n", picked);
			finish(0);
			return;
		}

		lws_dlo_ui_edit(ui, "Passphrase", 63, LWS_DLO_UI_EDIT_MASKED);
		kbx = KB_X0;
		kby = 0;
		in_edit = 1;
		break;

	case 10:
		if (!updated("edit page again", 0, H)) {
			finish(0);
			return;
		}

		/* pressing the title abandons it */

		key(0, 6);
		in_edit = 0;
		touch("press", W / 2, TITLE_H / 2, 0, 0);
		if (done_calls != 3 || !done_null || titled != 1) {
			lwsl_err("title press didn't abandon the edit\n");
			finish(0);
			return;
		}
		break;

	case 11:
		if (!updated("abandoned", 0, H)) {
			finish(0);
			return;
		}

		/* the status capsule only changes the title strip */
		{
			lws_dlo_ui_status_t st = { 3, 60, 0 };

			lws_dlo_ui_set_status(ui, &st);
		}
		break;

	case 12:
		if (!updated("status", 0, TITLE_H) || !capsule_drawn()) {
			finish(0);
			return;
		}

		/* pressing it clicks its button, not the title */

		touch("press", W / 2 + 34, TITLE_H - 6, 0, 0);
		if (titled != 1) {
			lwsl_err("capsule press was a title press\n");
			finish(0);
			return;
		}

		/* what is shown doesn't change: nothing is drawn for it */
		{
			lws_dlo_ui_status_t st = { 3, 58, 0 };

			lws_dlo_ui_set_status(ui, &st);
		}

		/* the first nav shows the cursor, on the first row */

		if (!lws_dlo_ui_nav(ui, LWS_DLO_UI_NAV_DOWN)) {
			lwsl_err("nav refused\n");
			finish(0);
			return;
		}
		break;

	case 13:
		/* the click's smd event has been delivered by now */
		if (settings_clicks != 1) {
			lwsl_err("capsule clicked %d times\n", settings_clicks);
			finish(0);
			return;
		}
		if (!updated("cursor", TITLE_H, H)) {
			finish(0);
			return;
		}
		/* the cursor's row is the theme's dark blue */
		if (colour_in(60, TITLE_H + 4, W - 60, TITLE_H + ROW_H - 4,
			      0x24, 0x47, 0x6b) < 20 * (W - 120)) {
			lwsl_err("no cursor\n");
			finish(0);
			return;
		}

		/*
		 * Buttons move it and pick its row, or go back.  The list has
		 * two rows, the cursor stays on the last going down from it
		 */

		picked = -1;
		if (!button("down") || !button("down") || !button("up") ||
		    !button("enter") || picked != 0 || !button("down") ||
		    !button("enter") || picked != 1) {
			lwsl_err("button picked %d\n", picked);
			finish(0);
			return;
		}
		if (button("left") || button("settings")) {
			lwsl_err("list page took a button it doesn't use\n");
			finish(0);
			return;
		}
		if (!button("esc") || titled != 2) {
			lwsl_err("esc wasn't the title\n");
			finish(0);
			return;
		}

		/* an edit that starts with something already there */

		kbx = KB_X0;
		kby = 0;
		in_edit = 1;
		if (lws_dlo_ui_edit(ui, "Hostname", 32, 0) ||
		    lws_dlo_ui_edit_set(ui, "ab")) {
			lwsl_err("edit failed\n");
			finish(0);
			return;
		}
		break;

	case 14:
		if (!updated("hostname edit", 0, H)) {
			finish(0);
			return;
		}

		/*
		 * The cursor was shown on the list, so it starts on q: right to
		 * w and type it.  Down three rows goes a, Shift, then ?123, the
		 * first key of the last row: left from there goes round to Done
		 */

		done_calls = 0;
		if (!lws_dlo_ui_nav(ui, LWS_DLO_UI_NAV_RIGHT) ||
		    !lws_dlo_ui_nav(ui, LWS_DLO_UI_NAV_ENTER) ||
		    !lws_dlo_ui_nav(ui, LWS_DLO_UI_NAV_DOWN) ||
		    !lws_dlo_ui_nav(ui, LWS_DLO_UI_NAV_DOWN) ||
		    !lws_dlo_ui_nav(ui, LWS_DLO_UI_NAV_DOWN) ||
		    !lws_dlo_ui_nav(ui, LWS_DLO_UI_NAV_LEFT)) {
			lwsl_err("edit nav refused\n");
			finish(0);
			return;
		}
		in_edit = 0;
		if (!lws_dlo_ui_nav(ui, LWS_DLO_UI_NAV_ENTER) ||
		    done_calls != 1 || strcmp(done_text, "abw")) {
			lwsl_err("nav typed '%s' (%d)\n", done_text,
				 done_calls);
			finish(0);
			return;
		}
		break;

	case 15:
		if (!updated("list page after nav edit", 0, H)) {
			finish(0);
			return;
		}

		/* the frame, drawn all at once to begin with, its body white */

		lws_dlo_ui_frame(ui, LWS_DLO_UI_FRAME_DRAW);
		break;

	case 16:
		if (!updated("frame", 0, H) || !capsule_drawn() ||
		    !dark_in(W / 2 - 40, 0, W / 2 + 40, TITLE_H)) {
			finish(0);
			return;
		}
		{
			const lws_surface_info_t *b =
					lws_dlo_ui_frame_body(ui, &body_y);

			if (body_y != TITLE_H || b->round ||
			    b->wh_px[0].whole != W ||
			    b->wh_px[1].whole != H - TITLE_H) {
				lwsl_err("frame body %dx%d at %d\n",
					 (int)b->wh_px[0].whole,
					 (int)b->wh_px[1].whole, body_y);
				finish(0);
				return;
			}

			/*
			 * The caller's page, still fetching its image.  Only
			 * the first time: the connections and dns cache it
			 * makes come and go in their own time, which the heap
			 * check of the ui the second time mustn't see
			 */

			if (!pass && body_browse(b)) {
				finish(0);
				return;
			}
		}
		if (!body_is(0xff)) {
			finish(0);
			return;
		}
		memcpy(title_band, fb, sizeof(title_band));

		/* the body and nav are the caller's */

		picked = -1;
		touch("down", W / 2, H / 2, 0, 0);
		touch("scroll", W / 2, H / 2 - 30, 0, -30);
		touch("press", W / 2, H / 2, 0, 0);
		if (picked != -1 || lws_dlo_ui_nav(ui, LWS_DLO_UI_NAV_DOWN) ||
		    button("enter")) {
			lwsl_err("frame took the body's input\n");
			finish(0);
			return;
		}

		/* the caller draws it all, with the ui's title strip */

		if (caller_draw()) {
			finish(0);
			return;
		}
		break;

	case 17:
		if (!updated("caller", 0, H) || !body_is(0x80) ||
		    memcmp(title_band, fb, sizeof(title_band))) {
			lwsl_err("caller's title strip differs\n");
			finish(0);
			return;
		}

		/* the body's image is on its way */

		if (!pass && !body_img_fetching()) {
			lwsl_err("body image isn't being fetched\n");
			finish(0);
			return;
		}

		/* the title, laid out again, is only drawn in its band */

		lws_dlo_ui_set_title(ui, "Page 2");
		break;

	case 18:
		if (!updated("frame title", 0, TITLE_H) || !body_is(0x80)) {
			finish(0);
			return;
		}

		/* laying the title out again didn't stop the body's image */

		if (!pass && body_survived()) {
			finish(0);
			return;
		}

		/*
		 * On a display that can only take all of it, the caller is
		 * asked to draw it again, and the ui draws nothing itself
		 */

		lds.disp = &disp_whole;
		{
			lws_dlo_ui_status_t st = { 1, 60, 1 };

			lws_dlo_ui_set_status(ui, &st);
		}
		lws_sul_schedule(cx, 0, &sul_step, next_step,
				 300 * LWS_US_PER_MS);
		break;

	case 19:
		if (frame_redraws != 1 || updates != seen_updates) {
			lwsl_err("whole display frame: %d redraws, %d updates\n",
				 frame_redraws, updates - seen_updates);
			finish(0);
			return;
		}
		if (caller_draw()) {
			finish(0);
			return;
		}
		break;

	case 20:
		if (!updated("caller again", 0, H) || !body_is(0x80)) {
			finish(0);
			return;
		}
		lds.disp = &disp;

		/* the list takes the whole display back */

		unclipped = 0;
		lws_dlo_ui_set_list(ui, ROWS, -1);
		break;

	case 21:
		if (!updated("list after frame", 0, H)) {
			finish(0);
			return;
		}

		lws_dlo_ui_destroy(&ui);
		if (pass++ && lws_get_allocated_heap() > heap_before) {
			lwsl_err("ui kept %u bytes of heap\n", (unsigned int)
				 (lws_get_allocated_heap() - heap_before));
			finish(0);
			return;
		}

		if (pass == 2) {
			finish(1);
			return;
		}

		/* again, now the context has made what it makes on first use */

		if (start())
			finish(0);
		break;
	}
}

static void
timeout_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("%s: timed out at step %d\n", __func__, step);
	finish(0);
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
	struct lws_vhost *vh;

	signal(SIGINT, sigint_handler);

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	lwsl_user("LWS API Test - dlo strip ui\n");

	info.port = CONTEXT_PORT_NO_LISTEN;
	/* the secure streams lhp fetches with make their own vhost */
	info.options |= LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
			LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	/* the silent server, on a port nothing else is using */

	info.port = 0;
	info.vhost_name = "silent";
	info.protocols = protocols;
	info.listen_accept_role = "raw-skt";
	info.listen_accept_protocol = "silent";
	vh = lws_create_vhost(cx, &info);
	if (!vh) {
		lwsl_err("silent vhost failed\n");
		lws_context_destroy(cx);
		return 1;
	}
	lws_snprintf(body_img, sizeof(body_img), "https://127.0.0.1:%d/x.png",
		     lws_get_vhost_listen_port(vh));
	fs_body.len = (size_t)lws_snprintf(body_html, sizeof(body_html),
			"<!doctype html><html><head><meta charset=\"utf-8\">"
			"</head><body><img src=\"%s\"></body></html>",
			body_img);

	/* the dlo filesystem after the platform one, where the ui's html is */

	dlo_fops = lws_dlo_fops;
	dlo_fops.cx = cx;
	dlo_fops.next = lws_get_fops(cx)->next;
	lws_get_fops(cx)->next = &dlo_fops;

	lws_font_register(cx, fira_c_r_16, sizeof(fira_c_r_16));
	lws_font_register(cx, fira_c_r_20, sizeof(fira_c_r_20));
	lws_dlo_file_register(cx, &fs_icon);
	lws_dlo_file_register(cx, &fs_body);

	/* the capsule's button event */
	if (!lws_smd_register(cx, NULL, 0, LWSSMDCL_INTERACTION, smd_cb)) {
		lwsl_err("smd register failed\n");
		lws_context_destroy(cx);
		return 1;
	}

	memset(&lds, 0, sizeof(lds));
	lds.disp = &disp;
	lds.ctx = cx;

	if (start()) {
		lws_context_destroy(cx);
		return 1;
	}

	lws_sul_schedule(cx, 0, &sul_timeout, timeout_cb,
			 40 * LWS_US_PER_SEC);

	lws_context_default_loop_run_destroy(cx);

	lwsl_user("Completed: %s\n", fail ? "FAIL" : "PASS");

	return fail;
}
