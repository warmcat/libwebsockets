/*
 * devices for Waveshare ESP32 driver board
 *
 * Written in 2010-2022 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#define LWIP_PROVIDE_ERRNO 1
#define _ESP_PLATFORM_ERRNO_H_

#include "main.h"

/*
 * How often, and how many times, we try to browse the page again to lay it
 * out in faces it can keep: the heap may still be short just after the
 * render gave up
 */
#define RELAYOUT_RETRY_US	(250 * LWS_US_PER_MS)
#define RELAYOUT_TRIES		40

/*
 * On a touch display, a page is laid out as far down as this, so all of a page
 * longer than the display can be dragged into view, if there's the memory for
 * it.  It's only a ceiling: the layout holds what is in the page, not what is
 * below it
 */
#define LAYOUT_H_MAX		16384

static lws_sorted_usec_list_t sul_relayout;
static lws_display_render_state_t *relayout_rs;
static int relayout_tries;
/* where the view of the page was moved to, kept across a relayout */
static int32_t relayout_pan_x, relayout_pan_y;
/* render() is drawing a page laid out before again, eg, panned */
static char redraw;
/*
 * The page is the body of the strip ui's frame page, below its title strip:
 * the title strip's lines come from the ui, the page's after them
 */
static char framed;
/* how many lines the title strip is, and how many of them were drawn */
static int frame_top, frame_y;
/*
 * A band of the page's lines being drawn again, eg, what changed on it: they
 * are all drawn here first, then sent to the display together, so they
 * appear on it at once, not as fast as they can be drawn
 */
static uint8_t *band;
static int band_y, band_h;

/*
 * The display updates are always sent whole, or as a band of lines, so no ids
 * are given to the blit: some EPD drivers take the first as the part of the
 * panel to update, but the page's ids are only elements it changes in place,
 * see redraw_damage().
 *
 * Where the time of a display update went, logged when it ends: what isn't
 * spent drawing lines or sending them to the display was spent waiting, eg,
 * for an image's data, or to be scheduled again
 */
static struct {
	lws_usec_t	start;
	lws_usec_t	lines;
	lws_usec_t	blit;
	int		wakes;
} upd;

static void
render(lws_sorted_usec_list_t *sul);

/*
 * Whatever the render was drawing its lines into is finished with: one line,
 * or while a band is drawn, the band's lines, which rs->line is one of
 */

static void
line_free(lws_display_render_state_t *rs)
{
	if (band) {
		free(band);
		band = NULL;
	} else
		free(rs->line);

	rs->line = NULL;
}

static void
relayout_browse(lws_sorted_usec_list_t *sul)
{
	lws_display_render_state_t *rs = relayout_rs;
	lws_box_t box;

	if (!lws_lhp_ss_browse(rs->lds->ctx, rs, rs->lds->current_url, render))
		return;

	if (++relayout_tries < RELAYOUT_TRIES) {
		lws_sul_schedule(rs->lds->ctx, 0, &sul_relayout,
				 relayout_browse, RELAYOUT_RETRY_US);
		return;
	}

	/*
	 * We can't lay it out again: finish the display update with what it
	 * had of the page, rather than leave the display busy for ever
	 */

	lwsl_err("%s: unable to lay %s out again\n", __func__,
		 rs->lds->current_url);

	memset(&box, 0, sizeof(box));
	box.w = rs->lds->disp->ic.wh_px[0];
	rs->lds->disp->blit(rs->lds, NULL, &box, NULL);
	lhp_demo_phase(LWS_LHPCD_PHASE_IDLE);
}

/*
 * The render couldn't have a face from the server some text was laid out
 * in.  Drawing it in a built-in face where the other was laid out can't look
 * right, so we throw the display list away and lay the page out again, this
 * time keeping the faces from the server it uses until the display list is
 * destroyed.  The heap the old list held is free, so most can likely be had
 * again; any that can't is replaced, as the layout goes, by the closest face
 * that can, as if it had been chosen from the start.
 *
 * The display has had the start of the update and some lines of it: the
 * render of the new layout starts the update again, and its lines replace
 * them.
 */

static void
relayout(lws_display_render_state_t *rs)
{
	lwsl_notice("%s: laying %s out again in faces it can keep\n",
		    __func__, rs->lds->current_url);

	lws_lhp_ss_cancel(rs);

	line_free(rs);
	redraw = 0;

	/* browsing it again resets the pan: it's put back when it renders */
	relayout_pan_x = rs->pan_x;
	relayout_pan_y = rs->pan_y;

	lws_display_list_destroy(rs->lds->ctx, &rs->displaylist);
	lws_display_render_free_ids(rs);
	lws_display_dl_init(&rs->displaylist, &lds);

	memset(rs->st, 0, sizeof(rs->st));
	rs->sp = 0;
	rs->curr = 0;
	rs->lowest_id_y = 0;

	/* the redone layout can't need doing again */
	rs->fonts_hold = 1;
	rs->relayout_ok = 0;

	relayout_rs = rs;
	relayout_tries = 0;
	relayout_browse(&sul_relayout);
}

/*
 * The ids' boxes are where they are on the page: on the display, they are
 * below the title strip
 */

static void
ids_below_frame(lws_display_render_state_t *rs)
{
	lws_fx_t t;

	lws_fx_set(t, frame_top, 0);

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&rs->ids)) {
		lws_display_id_t *id = lws_container_of(d, lws_display_id_t,
							list);

		lws_fx_add(&id->box.y, &id->box.y, &t);
	} lws_end_foreach_dll(d);
}

static void
render(lws_sorted_usec_list_t *sul)
{
	lws_display_render_state_t *rs = lws_container_of(sul,
					lws_display_render_state_t, sul);
	const lws_surface_info_t *dic = &rs->lds->disp->ic;
	lws_stateful_ret_t r;
	lws_usec_t t0, t1;
	lws_box_t box;
	int budget = 10;
	size_t lb;

	lws_fx_set(box.x, 0, 0);
	lws_fx_set(box.y, 0, 0);

	/*
	 * An image's payload arriving wakes the render, so it can carry on
	 * with a line waiting for it, even while the page is still being laid
	 * out.  The render can't begin until the layout is complete, which
	 * schedules it again then: before that, the display list isn't
	 * finished, and an update started on it ends at once, as if the page
	 * was shown.
	 */
	if (rs->html == 1)
		return;

	if (!rs->line) {

		if (!redraw) {
			/*
			 * The ids' boxes are where their elements were laid
			 * out, eg, for changing them in place later
			 */

			lws_display_get_ids_boxes(rs);
			if (frame_top)
				ids_below_frame(rs);

#if defined(LWS_WITH_FOOTPRINT)
			/* the layout is complete: what holds the heap at its
			 * peak */
			lws_footprint_dump(rs->lds->ctx, 1);
#endif

			if (rs->layout_clipped)
				lwsl_notice("%s: the page is longer than it "
					    "was laid out, it's cut short\n",
					    __func__);

			/* laid out again, the view goes back where it was */
			lws_display_render_pan(rs, relayout_pan_x,
					       relayout_pan_y);
			relayout_pan_x = relayout_pan_y = 0;
		}

		/*
		 * The update is of all of the display, so all of its lines are
		 * drawn, below the end of a short page too: what the display
		 * showed before stays on the lines that aren't
		 */
		rs->lowest_id_y = (lws_display_scalar)rs->ic->wh_px[1].whole;

		rs->sp = 0;
		rs->st[0].dlo = NULL;

		/* allocate one line of output pixels to render into */

		rs->line = malloc((size_t)dic->wh_px[0].whole *
				  (dic->greyscale ? 1 : 3));
		if (!rs->line) {
			lwsl_err("%s: OOM\n", __func__);
			/* !!! cleanup */
			return;
		}

		rs->curr = 0;
		frame_y = 0;
		memset(&upd, 0, sizeof(upd));
		upd.start = lws_now_usecs();

		/*
		 * Initialize the blitter with the dimensions of the data we
		 * will send: all of the display, the title strip too if the
		 * page is framed
		 */

		box.w = dic->wh_px[0];
		box.h = dic->wh_px[1];

		rs->lds->disp->blit(rs->lds, (uint8_t *)rs, &box, NULL);

		lhp_demo_phase(LWS_LHPCD_PHASE_RENDERING);

#if defined(LWS_WITH_ALLOC_METADATA_LWS)
		_lws_alloc_metadata_dump_lws(lws_alloc_metadata_dump_stdout, NULL);
#endif
	}

	/* single-line blits are line data */

	box.w = dic->wh_px[0];
	box.h.whole = 1;
	upd.wakes++;
	lb = (size_t)dic->wh_px[0].whole * (dic->greyscale ? 1 : 3);

	/* the frame's title strip, as the ui has it now */

	while (frame_y < frame_top) {

		if (!budget--) {
			lws_sul_schedule(rs->lds->ctx, 0, &rs->sul, render, 1);

			return;
		}

		r = sui ? lws_dlo_ui_frame_line(sui, frame_y, rs->line) :
			  LWS_SRET_FATAL;
		if (r & (LWS_SRET_YIELD | LWS_SRET_WANT_INPUT)) {
			/* eg, it's being laid out again: the same line again */
			lws_sul_schedule(rs->lds->ctx, 0, &rs->sul, render,
					 r & LWS_SRET_YIELD ? 1 : LWS_US_PER_MS);
			return;
		}
		if (r)
			/* there's no title strip to draw now, it's left white */
			memset(rs->line, 0xff, lb);

		box.y.whole = frame_y++;
		rs->lds->disp->blit(rs->lds, (uint8_t *)rs->line, &box,
				    NULL);
	}

	/* then the page */

	while (rs->curr != rs->lowest_id_y) {

		if (!budget--) {
			lws_sul_schedule(rs->lds->ctx, 0, &rs->sul, render, 1);

			return;
		}

		t0 = lws_now_usecs();
		r = lws_display_list_render_line(rs);
		t1 = lws_now_usecs();
		upd.lines += t1 - t0;
		if ((r & LWS_SRET_FATAL) && rs->relayout) {
			relayout(rs);
			return;
		}
		if (r & (LWS_SRET_YIELD | LWS_SRET_WANT_INPUT)) {
			/*
			 * The line isn't finished: something on it is waiting
			 * for its data, or for memory.  Come back to the same
			 * line, the walk carries on from where it stopped
			 */
			lws_sul_schedule(rs->lds->ctx, 0, &rs->sul, render,
					 r & LWS_SRET_YIELD ? 1 : LWS_US_PER_MS);
			return;
		}
		if (r)
			lwsl_warn("%s: line %d: 0x%x\n", __func__,
				  (int)rs->curr, (unsigned int)r);

		box.y.whole = rs->curr + frame_top;

		/* rs->line is a line of Y or RGB pixels, the blitter will
		 * convert to the panel's packed format and deal with diffusion
		 */

		rs->lds->disp->blit(rs->lds, (uint8_t *)rs->line, &box, NULL);
		upd.blit += lws_now_usecs() - t1;

		rs->curr++;
	}

	lws_sul_cancel(sul);
	lwsl_info("%s: %d lines in %dms: drawing %dms, blitting %dms, "
		    "%d wakes\n", __func__, (int)rs->curr + frame_top,
		    (int)((lws_now_usecs() - upd.start) / LWS_US_PER_MS),
		    (int)(upd.lines / LWS_US_PER_MS),
		    (int)(upd.blit / LWS_US_PER_MS), upd.wakes);
	/* zero-height blit indicates update finished */
	box.h.whole = 0;
	rs->lds->disp->blit(rs->lds, (uint8_t *)rs->line, &box, NULL);

	line_free(rs);
	redraw = 0;

	/*
	 * A retained display list stays with the render state while what it
	 * rendered is on the display, so touches can be resolved against it.
	 * It is replaced when the next browse begins.
	 */
	if (!rs->retained)
		lws_display_list_destroy(rs->lds->ctx, &rs->displaylist);

	lhp_demo_phase(LWS_LHPCD_PHASE_IDLE);
}

/*
 * The band of lines is drawn into the band buffer, then sent to the display
 * as a band of its lines
 */

static void
render_band(lws_sorted_usec_list_t *sul)
{
	lws_display_render_state_t *rs = lws_container_of(sul,
					lws_display_render_state_t, sul);
	const lws_surface_info_t *dic = &rs->lds->disp->ic;
	size_t lb = (size_t)dic->wh_px[0].whole * (dic->greyscale ? 1 : 3);
	lws_stateful_ret_t r;
	lws_usec_t t0, t1;
	int budget = 10, y;
	lws_box_t box;

	upd.wakes++;

	while (rs->curr != band_y + band_h) {

		if (!budget--) {
			lws_sul_schedule(rs->lds->ctx, 0, &rs->sul,
					 render_band, 1);
			return;
		}

		rs->line = band + (size_t)(rs->curr - band_y) * lb;

		t0 = lws_now_usecs();
		r = lws_display_list_render_line(rs);
		upd.lines += lws_now_usecs() - t0;
		if ((r & LWS_SRET_FATAL) && rs->relayout) {
			/* it's laid out again, and drawn whole */
			relayout(rs);
			return;
		}
		if (r & (LWS_SRET_YIELD | LWS_SRET_WANT_INPUT)) {
			/* the same line again, when what it waits for comes */
			lws_sul_schedule(rs->lds->ctx, 0, &rs->sul, render_band,
					 r & LWS_SRET_YIELD ? 1 : LWS_US_PER_MS);
			return;
		}
		if (r)
			lwsl_warn("%s: line %d: 0x%x\n", __func__,
				  (int)rs->curr, (unsigned int)r);

		rs->curr++;
	}

	/* it's all drawn: send it to the display, as a band of its lines */

	t1 = lws_now_usecs();

	memset(&box, 0, sizeof(box));
	box.w = dic->wh_px[0];
	box.y.whole = band_y + frame_top;
	box.h.whole = band_h;
	rs->lds->disp->blit(rs->lds, (uint8_t *)rs, &box, NULL);

	box.h.whole = 1;
	for (y = 0; y < band_h; y++) {
		box.y.whole = band_y + frame_top + y;
		rs->lds->disp->blit(rs->lds, band + (size_t)y * lb, &box,
				    NULL);
	}

	box.h.whole = 0;
	rs->lds->disp->blit(rs->lds, band, &box, NULL);
	upd.blit = lws_now_usecs() - t1;

	lwsl_info("%s: %d lines in %dms: drawing %dms, blitting %dms, "
		    "%d wakes\n", __func__, band_h,
		    (int)((lws_now_usecs() - upd.start) / LWS_US_PER_MS),
		    (int)(upd.lines / LWS_US_PER_MS),
		    (int)(upd.blit / LWS_US_PER_MS), upd.wakes);

	line_free(rs);
	redraw = 0;

	lhp_demo_phase(LWS_LHPCD_PHASE_IDLE);
}

int
init_browse(struct lws_context *cx, lws_display_render_state_t *rs,
	    const char *url, int frame, const char * const *ids)
{
	int n;

        lhp_demo_phase(LWS_LHPCD_PHASE_FETCHING);

	/*
	 * The page before may still be on its way, eg, the carousel or a link
	 * moved on from a big page before its layout finished.  It lays out
	 * into this render state's display list, and its assets wake the
	 * render on it: stop all of that before the display list goes.
	 */
	lws_lhp_ss_cancel(rs);
	line_free(rs);

	/*
	 * Whatever was displayed is about to be overwritten.  With a touch
	 * panel, its display list was kept to resolve touches until now.
	 */
	lws_sul_cancel(&sul_relayout);
	lws_display_list_destroy(cx, &rs->displaylist);
	lws_display_render_free_ids(rs);
	relayout_pan_x = relayout_pan_y = 0;
	redraw = 0;

	/*
	 * Elements the caller changes in place once it's laid out are found
	 * by their ids: the display list is kept for that too
	 */
	for (n = 0; ids && ids[n]; n++)
		if (!lws_display_render_add_id(rs, ids[n], NULL)) {
			lwsl_err("%s: OOM\n", __func__);
			return 1;
		}
	rs->retained = tcs || n;

	/*
	 * Lay it out in faces from the server where we can, and if the render
	 * then can't have one of them, lay it out again keeping them
	 */
	rs->fonts_hold = 0;
	rs->relayout_ok = 1;

	lws_display_dl_init(&rs->displaylist, &lds);
	rs->lds = &lds;

	/*
	 * Framed, the page is laid out on the body of the strip ui's frame
	 * page, below its title strip, otherwise on all of the display
	 */
	framed = (char)(frame && sui);
	frame_top = 0;
	rs->ic = framed ? lws_dlo_ui_frame_body(sui, &frame_top) :
			  &lds.disp->ic;

	/*
	 * With a touch panel, the page can be dragged around on the display:
	 * lay all of it out, however long, so the rest of a long one can be
	 * seen.  On a round display, it can be dragged a little beyond its
	 * edges too, to see what is in the corners the circle doesn't show
	 */
	rs->layout_h = tcs ? LAYOUT_H_MAX : 0;

	rs->lds->display_busy = 1;
	lws_strncpy(rs->lds->current_url, url, sizeof(rs->lds->current_url));

	/* animated svg, eg, the update spinner, are drawn as they are now */
	rs->anim_t = lws_now_usecs();

	return lws_lhp_ss_browse(cx, rs, url, render);
}

/*
 * Draw the page on the display again as it was laid out, eg, after
 * lws_display_render_pan() moved the view of it.  The display list was kept
 * for that, see init_browse().  Returns 0 if it was started: the display is
 * busy until it's finished
 */

int
redraw_page(lws_display_render_state_t *rs)
{
	if (rs->html != 2 || !rs->retained || rs->line || redraw ||
	    rs->lds->display_busy ||
	    !lws_dll2_get_head(&rs->displaylist.dl))
		return 1;

	memset(rs->st, 0, sizeof(rs->st));
	rs->sp = 0;
	redraw = 1;
	rs->anim_t = lws_now_usecs();

	rs->lds->display_busy = 1;
	lws_sul_schedule(rs->lds->ctx, 0, &rs->sul, render, 1);

	return 0;
}

/*
 * Bring the page on the display up to date after it was changed in place, eg,
 * with lws_display_render_set_text(), and move on what is animated on it.
 * Only what changed is drawn again, if the display can be sent a band of its
 * lines, otherwise all of the page, as it was laid out.  The display list was
 * kept for that, see init_browse().  Returns 0 if it was started: the display
 * is busy until it's finished, -1 if nothing changed, or 1 if it can't be
 * done, eg, the page wasn't kept
 */

int
redraw_damage(lws_display_render_state_t *rs)
{
	const lws_surface_info_t *dic = &rs->lds->disp->ic;
	lws_box_t b;

	if (rs->html != 2 || !rs->retained || rs->line || redraw ||
	    rs->lds->display_busy ||
	    !lws_dll2_get_head(&rs->displaylist.dl))
		return 1;

	/* animated images are drawn as they are now */
	rs->anim_t = lws_now_usecs();

	if (!lws_display_render_damage(rs, &b))
		return -1;

	if (!dic->band)
		/* the display can only be updated whole */
		return redraw_page(rs);

	/* a band is at least two lines */

	band_y = b.y.whole;
	band_h = b.h.whole;
	if (band_h < 2) {
		band_h = 2;
		if (band_y + band_h > rs->ic->wh_px[1].whole)
			band_y = rs->ic->wh_px[1].whole - band_h;
	}

	band = malloc((size_t)band_h * (size_t)dic->wh_px[0].whole *
		      (dic->greyscale ? 1 : 3));
	if (!band)
		/* all of it is drawn again, a line at a time, instead */
		return redraw_page(rs);

	memset(rs->st, 0, sizeof(rs->st));
	rs->sp = 0;
	rs->curr = (lws_display_scalar)band_y;
	redraw = 1;
	memset(&upd, 0, sizeof(upd));
	upd.start = lws_now_usecs();

	rs->lds->display_busy = 1;
	lhp_demo_phase(LWS_LHPCD_PHASE_RENDERING);
	lws_sul_schedule(rs->lds->ctx, 0, &rs->sul, render_band, 1);

	return 0;
}
