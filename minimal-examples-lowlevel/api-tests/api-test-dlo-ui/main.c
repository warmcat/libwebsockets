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

static struct lws_context *cx;
static struct lws_plat_file_ops dlo_fops;
static lws_display_state_t lds;
static struct lws_dlo_ui *ui;
static lws_sorted_usec_list_t sul_step, sul_timeout;
static int step, fail, picked = -1, updates, upd_y0, upd_y1, win_y0, win_y1,
	   lines, pass, seen_updates, done_calls, done_keep, kbx, titled;
static char done_text[LWS_DLO_UI_EDIT_MAX];
static char done_null, in_edit;
static size_t heap_before;

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

/* press the key in half key hx of keyboard row r, as the keyboard is now */

static void
key(int r, int hx)
{
	touch("press", kbx + (hx * ROW_H) / 2 + ROW_H / 4,
	      KB_Y0 + r * ROW_H + ROW_H / 2, 0, 0);
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
	return in_edit || outside_circle_white();
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
	memset(fb, 0xff, sizeof(fb));

	heap_before = lws_get_allocated_heap();

	memset(&ui_info, 0, sizeof(ui_info));
	ui_info.cx = cx;
	ui_info.lds = &lds;
	ui_info.row = row_cb;
	ui_info.pick = pick_cb;
	ui_info.title = title_cb;
	ui_info.done = done_cb;
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

		/* Shift is off the left: drag the keyboard right to it */

		drag(W / 2, KB_Y0 + 2 * ROW_H, -KB_X0, 0);
		kbx = 0;
		break;

	case 6:
		if (!updated("keyboard dragged", KB_Y0, H)) {
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

	/* the dlo filesystem after the platform one, where the ui's html is */

	dlo_fops = lws_dlo_fops;
	dlo_fops.cx = cx;
	dlo_fops.next = lws_get_fops(cx)->next;
	lws_get_fops(cx)->next = &dlo_fops;

	lws_font_register(cx, fira_c_r_16, sizeof(fira_c_r_16));
	lws_font_register(cx, fira_c_r_20, sizeof(fira_c_r_20));
	lws_dlo_file_register(cx, &fs_icon);

	memset(&lds, 0, sizeof(lds));
	lds.disp = &disp;
	lds.ctx = cx;

	if (start()) {
		lws_context_destroy(cx);
		return 1;
	}

	lws_sul_schedule(cx, 0, &sul_timeout, timeout_cb,
			 20 * LWS_US_PER_SEC);

	lws_context_default_loop_run_destroy(cx);

	lwsl_user("Completed: %s\n", fail ? "FAIL" : "PASS");

	return fail;
}
