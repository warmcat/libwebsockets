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
	lws_display_list_destroy(&rs->displaylist);

	show_demo_phase(LWS_LHPCD_PHASE_IDLE);
}

int
init_browse(struct lws_context *cx, lws_display_render_state_t *rs,
	    const char *url)
{
        show_demo_phase(LWS_LHPCD_PHASE_FETCHING);

	lws_display_dl_init(&rs->displaylist, &lds);
	rs->ic = &lds.disp->ic;
	rs->lds = &lds;

	rs->lds->display_busy = 1;
	lws_strncpy(rs->lds->current_url, url, sizeof(rs->lds->current_url));

	return lws_lhp_ss_browse(cx, rs, url, render);
}

