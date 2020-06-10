/*
 * lws abstract display
 *
 * Copyright (C) 2019 - 2020 Andy Green <andy@warmcat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <libwebsockets.h>

static void
sul_cb(lws_sorted_usec_list_t *sul)
{
	lws_display_state_t *lds = lws_container_of(sul, lws_display_state_t,
						    sul);

	if (lds->bl_target > lds->bl_current) {
		if (lds->bl_target - lds->bl_current < lds->bl_step)
			lds->bl_current = lds->bl_target;
		else
			lds->bl_current += lds->bl_step;
	} else {
		if (lds->bl_current - lds->bl_target < lds->bl_step)
			lds->bl_current = lds->bl_target;
		else
			lds->bl_current -= lds->bl_step;
	}

	lds->disp->brightness(lds->disp, lds->bl_current);

	if (lds->bl_current != lds->bl_target)
		/*
		 * Come back and move towards the target again in 50ms
		 */
		lws_sul_schedule(lds->ctx, 0, &lds->sul,
				 sul_cb, 50 * LWS_US_PER_MS);
}

static void
sul_autodim_cb(lws_sorted_usec_list_t *sul)
{
	lws_display_state_t *lds = lws_container_of(sul, lws_display_state_t,
						   sul_autodim);

	/* we fire both to dim and to blank... if already in dim state, blank */

	if (lds->state == LWSDISPS_AUTODIMMED) {
		lws_display_state_off(lds);
		return;
	}

	lds->state = LWSDISPS_AUTODIMMED;
	lws_display_state_set_brightness(lds, lds->bl_dim, lds->bl_step);

	if (lds->off_ms >= 0)
		lws_sul_schedule(lds->ctx, 0, &lds->sul_autodim, sul_autodim_cb,
				 lds->off_ms * LWS_US_PER_MS);
}

void
lws_display_state_init(lws_display_state_t *ds, struct lws_context *ctx,
		       int dim_ms, int off_ms, lws_display_brightness active,
		       lws_display_brightness dim, const lws_display_t *disp)
{
	memset(ds, 0, sizeof(*ds));
	ds->disp = disp;
	ds->ctx = ctx;
	ds->autodim_ms = dim_ms;
	ds->off_ms = off_ms;
	ds->bl_active = active;
	ds->bl_dim = dim;
}

void
lws_display_state_set_brightness(lws_display_state_t *lds,
				 lws_display_brightness target,
				 lws_display_brightness step)
{
	lds->bl_target = target;
	lds->bl_step = step;

	lws_sul_schedule(lds->ctx, 0, &lds->sul, sul_cb, 1);
}

void
lws_display_state_active(lws_display_state_t *lds)
{
	if (lds->state == LWSDISPS_OFF)
		lds->disp->power(lds->disp, 1);

	if (lds->bl_current != lds->bl_active)
		lws_display_state_set_brightness(lds, lds->bl_active, 2);

	/* reset the autodim timer */
	if (lds->autodim_ms >= 0)
		lws_sul_schedule(lds->ctx, 0, &lds->sul_autodim, sul_autodim_cb,
				 lds->autodim_ms * LWS_US_PER_MS);

	lds->state = LWSDISPS_ACTIVE;
}

void
lws_display_state_off(lws_display_state_t *lds)
{
	lds->disp->power(lds->disp, 0);
	lws_sul_cancel(&lds->sul);
	lws_sul_cancel(&lds->sul_autodim);
	lds->bl_current = 0;
	lds->state = LWSDISPS_OFF;
}
