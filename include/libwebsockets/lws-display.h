/*
 * lws abstract display
 *
 * Copyright (C) 2019 - 2022 Andy Green <andy@warmcat.com>
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

typedef int16_t lws_display_list_coord_t;
typedef uint16_t lws_display_scalar;
typedef uint16_t lws_display_rotation_t;
typedef uint32_t lws_display_colour_t;
typedef uint16_t lws_display_palette_idx_t;

typedef struct lws_box {
	lws_fx_t		x;
	lws_fx_t		y;
	lws_fx_t		w;
	lws_fx_t		h;
} lws_box_t;

struct lws_display_state;
struct lws_display;

typedef enum {
	LWSSURF_TRUECOLOR32,
	LWSSURF_565,
	LWSSURF_PALETTE,
	LWSSURF_QUANTIZED_4BPP
} lws_surface_type_t;

typedef struct lws_surface_info {
	lws_fx_t			wh_px[2];
	lws_fx_t			wh_mm[2];
	const lws_display_colour_t	*palette;
	size_t				palette_depth;
	lws_surface_type_t		type;
	uint8_t				greyscale:1; /* line: 0 = RGBA, 1 = YA */
	uint8_t				partial:1; /* can handle partial */
	uint8_t				render_to_rgba:1; /* render to 32-bit RGBA, not 24-bit RGB */
} lws_surface_info_t;

typedef struct lws_greyscale_error {
	int16_t				rgb[1];
} lws_greyscale_error_t;

typedef struct lws_colour_error {
	int16_t				rgb[3];
} lws_colour_error_t;

typedef union {
	lws_greyscale_error_t		grey;	/* when ic->greyscale set */
	lws_colour_error_t		colour; /* when ic->greyscale == 0 */
} lws_surface_error_t;

LWS_VISIBLE LWS_EXTERN void
lws_surface_set_px(const lws_surface_info_t *ic, uint8_t *line, int x,
		   const lws_display_colour_t *c);

LWS_VISIBLE LWS_EXTERN lws_display_palette_idx_t
lws_display_palettize_grey(const lws_surface_info_t *ic,
			   const lws_display_colour_t *palette, size_t pdepth,
			   lws_display_colour_t c, lws_greyscale_error_t *ectx);

LWS_VISIBLE LWS_EXTERN lws_display_palette_idx_t
lws_display_palettize_col(const lws_surface_info_t *ic,
			  const lws_display_colour_t *palette, size_t pdepth,
			  lws_display_colour_t c, lws_colour_error_t *ectx);

/*
 * This is embedded in the actual display implementation object at the top,
 * so a pointer to this can be cast to a pointer to the implementation object
 * by any code that is specific to how it was implemented.
 *
 * Notice for the backlight / display intensity we contain pwm_ops... these can
 * be some other pwm_ops like existing gpio pwm ops, or handled in a customized
 * way like set oled contrast.  Either way, the pwm level is arrived at via a
 * full set of lws_led_sequences capable of generic lws transitions
 */

typedef struct lws_display {
	int (*init)(struct lws_display_state *lds);
	const lws_pwm_ops_t		*bl_pwm_ops;
	int (*contrast)(struct lws_display_state *lds, uint8_t contrast);
	int (*blit)(struct lws_display_state *lds, const uint8_t *src,
		    lws_box_t *box, lws_dll2_owner_t *ids);
	int (*power)(struct lws_display_state *lds, int state);

	const lws_led_sequence_def_t	*bl_active;
	const lws_led_sequence_def_t	*bl_dim;
	const lws_led_sequence_def_t	*bl_transition;

	const char			*name;
	void				*variant;

	int				bl_index;

	lws_surface_info_t		ic;

	uint16_t			latency_wake_ms;
	/**< ms required after wake from sleep before display usable again...
	 * delay bringing up the backlight for this amount of time on wake.
	 * This is managed via a sul on the event loop, not blocking. */
	uint16_t			latency_update_ms;
	/**< nominal update latency in ms */
} lws_display_t;

/*
 * This contains dynamic data related to display state
 */

enum lws_display_controller_state {
	LWSDISPS_OFF,
	LWSDISPS_AUTODIMMED,	  /* is in pre- blanking static dim mode */
	LWSDISPS_BECOMING_ACTIVE, /* waiting for wake latency before active */
	LWSDISPS_ACTIVE,	  /* is active */
	LWSDISPS_GOING_OFF	  /* dimming then off */
};

typedef struct lws_display_state {

	lws_sorted_usec_list_t		sul_autodim;

	char				current_url[96];

	const lws_display_t		*disp;
	struct lws_context		*ctx;

	void				*priv; /* subclass driver alloc'd priv */

	int				autodim_ms;
	int				off_ms;

	struct lws_led_state		*bl_lcs;

	lws_led_state_chs_t		chs;
	/* set of sequencer transition channels */

	enum lws_display_controller_state state;

	char				display_busy;

} lws_display_state_t;

/* Used for async display driver events, eg, EPD refresh completion */
typedef int (*lws_display_completion_t)(lws_display_state_t *lds, int a);

/**
 * lws_display_state_init() - initialize display states
 *
 * \param lds: the display state object
 * \param ctx: the lws context
 * \param autodim_ms: ms since last active report to dim display (<0 = never)
 * \param off_ms: ms since dim to turn display off (<0 = never)
 * \param bl_lcs: the led controller instance that has the backlight
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
		       int autodim_ms, int off_ms, struct lws_led_state *bl_lcs,
		       const lws_display_t *disp);

/**
 * lws_display_state_set_brightness() - gradually change the brightness
 *
 * \param lds: the display state we are changing
 * \param target: the target brightness to transition to
 *
 * Adjusts the brightness gradually twoards the target at 20Hz
 */
LWS_VISIBLE LWS_EXTERN void
lws_display_state_set_brightness(lws_display_state_t *lds,
				 const lws_led_sequence_def_t *pwmseq);

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
