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

#if !defined(__LWS_DISPLAY_H__)
#define __LWS_DISPLAY_H__

#include <stdint.h>

typedef uint16_t lws_display_scalar;
typedef uint8_t lws_display_brightness;

/*
 * This is embedded in the actual display implementation object at the top,
 * so a pointer to this can be cast to a pointer to the implementation object
 * by any code that is specific to how it was implemented.
 */

typedef struct lws_display {
	int (*init)(const struct lws_display *disp);
	int (*brightness)(const struct lws_display *disp, lws_display_brightness b);
	int (*blit)(const struct lws_display *disp, const uint8_t *src,
		    lws_display_scalar x, lws_display_scalar y,
		    lws_display_scalar w, lws_display_scalar h);
	int (*power)(const struct lws_display *disp, int state);
	void			*variant;
	lws_display_scalar	w;
	lws_display_scalar	h;
} lws_display_t;

/*
 * This contains dynamic data related to display state
 */

enum lws_display_state {
	LWSDISPS_OFF, /* managed in display_state */
	LWSDISPS_AUTODIMMED,
	LWSDISPS_ACTIVE,
};

typedef struct lws_diplay_state {

	lws_sorted_usec_list_t	sul;
	lws_sorted_usec_list_t	sul_autodim;
	const lws_display_t	*disp;
	struct lws_context	*ctx;

	int			autodim_ms;
	int			off_ms;

	lws_display_brightness	bl_current;
	lws_display_brightness	bl_target;
	lws_display_brightness	bl_step;
	lws_display_brightness	bl_active;
	lws_display_brightness	bl_dim;
	enum lws_display_state	state;

} lws_display_state_t;

/**
 * lws_display_state_init() - initialize display states
 *
 * \param lds: the display state object
 * \param ctx: the lws context
 * \param autodim_ms: ms since last active report to dim display (<0 = never)
 * \param off_ms: ms since dim to turn display off (<0 = never)
 * \param active: brightness level to use when active (0-255)
 * \param dim: brightness level to use when dim (0-255)
 * \param disp: generic display object we belong to
 *
 * This initializes a display's state, and sets up the optional screen auto-dim
 * and blanking on inactive, and gradual brightness change timer.
 *
 *  - auto-dim then off: set autodim to some ms and off_ms to some ms
 *  - auto-dim only: set autodim to some ms and off_ms to -1
 *  - off-only: set autodim to some ms and off_ms to 0
 *  - neither: set both autodim and off_ms to -1
 */
LWS_VISIBLE LWS_EXTERN void
lws_display_state_init(lws_display_state_t *lds, struct lws_context *ctx,
		       int autodim_ms, int off_ms, lws_display_brightness active,
		       lws_display_brightness dim, const lws_display_t *disp);

/**
 * lws_display_state_set_brightness() - gradually change the brightness
 *
 * \param lds: the display state we are changing
 * \param target: the target brightness
 * \param step: the step change for each gradual brightness change
 *
 * Adjusts the brightness gradually twoards the target at 20Hz
 */
LWS_VISIBLE LWS_EXTERN void
lws_display_state_set_brightness(lws_display_state_t *lds,
				 lws_display_brightness target,
				 lws_display_brightness step);

/*
 * lws_display_state_active() - inform the system the display is active
 *
 * \param lds: the display state we are marking as active
 *
 * Resets the auto-dim and auto-off timers and makes sure the display is on and
 * at the active brightness level
 */
LWS_VISIBLE LWS_EXTERN void
lws_display_state_active(lws_display_state_t *lds);

/*
 * lws_display_state_off() - turns off the related display
 *
 * \param lds: the display state we are turning off
 *
 * Turns the display to least power mode or completely off if possible.
 * Disables the timers related to dimming and blanking.
 */
LWS_VISIBLE LWS_EXTERN void
lws_display_state_off(lws_display_state_t *lds);

#endif
