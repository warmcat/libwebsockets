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

static lws_sorted_usec_list_t sul_relayout;
static lws_display_render_state_t *relayout_rs;
static int relayout_tries;

static void
render(lws_sorted_usec_list_t *sul);

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
	box.w = rs->ic->wh_px[0];
	rs->lds->disp->blit(rs->lds, NULL, &box, &rs->ids);
	show_demo_phase(LWS_LHPCD_PHASE_IDLE);
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

	free(rs->line);
	rs->line = NULL;

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

static void
render(lws_sorted_usec_list_t *sul)
{
	lws_display_render_state_t *rs = lws_container_of(sul,
					lws_display_render_state_t, sul);
	lws_stateful_ret_t r;
	lws_box_t box;
	int budget = 10;

	lws_fx_set(box.x, 0, 0);
	lws_fx_set(box.y, 0, 0);

	if (!rs->line) {

		/*
		 * We must finalize the ids list with the accurate dlo box info
		 * before starting the render, since some EPD need to keep
		 * copies of the pixel data for that region in order to over-
		 * write it later.
		 */

		lws_display_get_ids_boxes(rs);
		rs->sp = 0;

#if defined(LWS_WITH_FOOTPRINT)
		/* the layout is complete: what holds the heap at its peak */
		lws_footprint_dump(rs->lds->ctx, 1);
#endif
		rs->st[0].dlo = NULL;

		/* allocate one line of output pixels to render into */

		rs->line = malloc((size_t)rs->ic->wh_px[0].whole * (rs->ic->greyscale ? 1 : 3));
		if (!rs->line) {
			lwsl_err("%s: OOM\n", __func__);
			/* !!! cleanup */
			return;
		}

		rs->curr = 0;

		/*
		 * Initialize the blitter with the dimensions of the data we
		 * will send.
		 */

		box.w = rs->ic->wh_px[0];
		box.h = rs->ic->wh_px[1];

		rs->lds->disp->blit(rs->lds, (uint8_t *)rs, &box, &rs->ids);

		show_demo_phase(LWS_LHPCD_PHASE_RENDERING);

#if defined(LWS_WITH_ALLOC_METADATA_LWS)
		_lws_alloc_metadata_dump_lws(lws_alloc_metadata_dump_stdout, NULL);
#endif
	}

	/* single-line blits are line data */

	box.w = rs->ic->wh_px[0];
	box.h.whole = 1;

	while (rs->curr != rs->lowest_id_y) {

		if (!budget--) {
			lws_sul_schedule(rs->lds->ctx, 0, &rs->sul, render, 1);

			return;
		}

		r = lws_display_list_render_line(rs);
		if ((r & LWS_SRET_FATAL) && rs->relayout) {
			relayout(rs);
			return;
		}
		if (r & LWS_SRET_YIELD)
			lws_sul_schedule(rs->lds->ctx, 0, &rs->sul, render, 1);
		if (r) {
			if (r & LWS_SRET_WANT_INPUT) {
				lws_sul_schedule(rs->lds->ctx, 0, &rs->sul, render, LWS_US_PER_MS);
				return;
			}
		}

		box.y.whole = rs->curr;

		/* rs->line is a line of Y or RGB pixels, the blitter will
		 * convert to the panel's packed format and deal with diffusion
		 */

		rs->lds->disp->blit(rs->lds, (uint8_t *)rs->line, &box, &rs->ids);

		rs->curr++;
	}

	lws_sul_cancel(sul);
	lwsl_notice("%s: zero-height blit for end\n", __func__);
	/* zero-height blit indicates update finished */
	box.h.whole = 0;
	rs->lds->disp->blit(rs->lds, (uint8_t *)rs->line, &box, &rs->ids);

        free(rs->line);
        rs->line = NULL;

	/*
	 * A retained display list stays with the render state while what it
	 * rendered is on the display, so touches can be resolved against it.
	 * It is replaced when the next browse begins.
	 */
	if (!rs->retained)
		lws_display_list_destroy(rs->lds->ctx, &rs->displaylist);

	show_demo_phase(LWS_LHPCD_PHASE_IDLE);
}

int
init_browse(struct lws_context *cx, lws_display_render_state_t *rs,
	    const char *url)
{
        show_demo_phase(LWS_LHPCD_PHASE_FETCHING);

	/*
	 * Whatever was displayed is about to be overwritten.  With a touch
	 * panel, its display list was kept to resolve touches until now.
	 */
	lws_sul_cancel(&sul_relayout);
	lws_display_list_destroy(cx, &rs->displaylist);
	rs->retained = !!tcs;

	/*
	 * Lay it out in faces from the server where we can, and if the render
	 * then can't have one of them, lay it out again keeping them
	 */
	rs->fonts_hold = 0;
	rs->relayout_ok = 1;

	lws_display_dl_init(&rs->displaylist, &lds);
	rs->ic = &lds.disp->ic;
	rs->lds = &lds;

	rs->lds->display_busy = 1;
	lws_strncpy(rs->lds->current_url, url, sizeof(rs->lds->current_url));

	return lws_lhp_ss_browse(cx, rs, url, render);
}

