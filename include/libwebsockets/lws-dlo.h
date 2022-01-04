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
 *
 * lws display_list and display_list objects (dlo)
 */

#include <stdint.h>

typedef int16_t lws_display_list_coord_t;
typedef uint16_t lws_display_scalar;
typedef uint16_t lws_display_rotation_t;
typedef uint32_t lws_display_colour_t;
typedef uint16_t lws_display_palette_idx_t;
typedef uint32_t lws_display_gline_t; /* type for 1 line of glyph px */

struct lws_surface_info;
struct lws_display_state;
struct lws_display_font;
struct lws_display;
struct lws_dlo_text;
struct lws_dlo;

#define LWSDC_RGBA(_r, _g, _b, _a) \
		(((uint32_t)(_r) & 0xff) | (((uint32_t)(_g) & 0xff) << 8) | (((uint32_t)(_b) & 0xff) << 16) | (((uint32_t)(_a) & 0xff) << 24))

#define LWSDC_R(_c) ((_c) & 0xff)
#define LWSDC_G(_c) ((_c >> 8) & 0xff)
#define LWSDC_B(_c) ((_c >> 16) & 0xff)
#define LWSDC_ALPHA(_c) ((_c >> 24) & 0xff)

#define MAX_FONT_HEIGHT 32

typedef struct lws_box {
	lws_fixed3232_t		x;
	lws_fixed3232_t		y;
	lws_fixed3232_t		w;
	lws_fixed3232_t		h;
} lws_box_t;

typedef struct lws_colour_error {
	int16_t		rgb[3];
} lws_colour_error_t;

typedef void (*lws_dlo_renderer_t)(const struct lws_surface_info *ic,
				   struct lws_dlo *dlo, const lws_box_t *origin,
				   lws_display_scalar curr,
				   uint8_t *line,
				   lws_colour_error_t **nle);
typedef void (*lws_dlo_destroy_t)(struct lws_dlo *dlo);

/*
 * Common dlo object that joins the display list, composed into a subclass
 * object like lws_dlo_rect_t etc
 */

typedef struct lws_dlo {
	lws_dll2_t			list;

	lws_colour_error_t		*nle[2];

	/* children are rendered "inside" the parent DLO box after allowing
	 * for parent padding */
	lws_dll2_owner_t		children;

	lws_dlo_destroy_t		_destroy;
	lws_dlo_renderer_t		render;

	lws_box_t			box;
	lws_display_colour_t		dc;

	uint8_t				flag_runon:1; /* continues same line */
	uint8_t				flag_done_align:1; /* continues same line */

	/* render-specific members ... */
} lws_dlo_t;

typedef struct lws_dlo_rect {
	lws_dlo_t			dlo;
	lws_fixed3232_t			radius[4]; /* t-l, t-r, b-l, b-r radii */
} lws_dlo_rect_t;

typedef struct lws_dlo_circle {
	lws_dlo_t			dlo;
} lws_dlo_circle_t;

typedef struct lws_font_choice {
	const char			*family_name;
	const char			*generic_name;
	uint16_t			weight;
	uint16_t			style; /* normal, italic, oblique */
	uint16_t			fixed_height;
} lws_font_choice_t;

typedef struct lws_display_font {
	lws_dll2_t			list;

	lws_font_choice_t		choice;

	const uint8_t			*data;
	uint8_t				*priv; /* only used by implementation */
	size_t				data_len;
	lws_dlo_renderer_t		renderer;

	lws_fixed3232_t			em;	/* 1 em in pixels */
	lws_fixed3232_t			ex;	/* 1 ex in pixels */
} lws_display_font_t;

typedef struct lws_display_png {
	lws_dll2_t			list;

	const char			*name;
	const void			*data;
	size_t				len;
} lws_display_png_t;

#define LWSDLO_TEXT_FLAG_WRAP					(1 << 0)

typedef struct lws_dlo_text {
	lws_dlo_t			dlo;
	const lws_display_font_t	*font;
	lws_box_t			bounding_box; /* { 0, 0, w, h } relative
						       * to and subject to
						       * clipping by .dlo.box */
	char				*text;
	uint8_t				*kern;
	size_t				text_len;
	lws_display_list_coord_t	clkernpx;
	lws_display_list_coord_t	cwidth;

	uint32_t			flags;
} lws_dlo_text_t;

typedef struct lws_dlo_png {
	lws_dlo_t			dlo;
	lws_upng_t			*png;

	const uint8_t			*data;
	size_t				len;
} lws_dlo_png_t;

typedef struct lws_display_state lws_display_state_t;

typedef struct lws_displaylist {
	lws_dll2_owner_t		dl;
	struct lws_display_state 	*ds;
} lws_displaylist_t;

typedef struct lws_dl_rend {
	lws_displaylist_t		*dl;
	int				w;
	int				h;
} lws_dl_rend_t;

typedef struct lws_display_render_state {
	lws_sorted_usec_list_t		sul; /* return to event loop statefully */
	lws_display_state_t		*lds; /* optional, if using lws_display */

	const struct lws_surface_info	*ic; /* display dimensions, palette */

	int				state; /* meaning private to driver */

	uint8_t				*line;

	int				budget;

	lws_displaylist_t		*displaylist;
	lws_box_t			box;
	lws_display_scalar		curr;
} lws_display_render_state_t;


/**
 * lws_display_dl_init() - init display list object
 *
 * \param dl: Pointer to the display list
 * \param ds: Lws display state to bind the list to
 *
 * Initializes the display list \p dl and binds it to the display state \p ds.
 */
LWS_VISIBLE LWS_EXTERN void
lws_display_dl_init(lws_displaylist_t *dl, struct lws_display_state  *ds);

/**
 * lws_display_list_destroy() - destroys display list and objects on it
 *
 * \param dl: Pointer to the display list pointer
 *
 * Destroys every DLO on the list and sets the list pointer to NULL.
 */
LWS_VISIBLE LWS_EXTERN void
lws_display_list_destroy(lws_displaylist_t **dl);

LWS_VISIBLE LWS_EXTERN void
lws_display_dlo_destroy(lws_dlo_t **r);

LWS_VISIBLE LWS_EXTERN int
lws_display_dlo_add(lws_displaylist_t *dl, lws_dlo_t *dlo_parent, lws_dlo_t *dlo);

LWS_VISIBLE LWS_EXTERN lws_display_palette_idx_t
lws_display_palettize(const struct lws_surface_info *ic, lws_display_colour_t c,
		       lws_display_colour_t oc, lws_colour_error_t *ectx);

LWS_VISIBLE LWS_EXTERN int
lws_dlo_ensure_err_diff(lws_dlo_t *dlo);

/*
 * lws_display_list_render_line() - render a single raster line of the list
 *
 * \param rs: prepared render state object
 *
 * Allocates a line pair buffer into ds->line if necessary, and renders the
 * current line (set by ds->curr) of the display list rasterization into it
 */
LWS_VISIBLE LWS_EXTERN int
lws_display_list_render_line(lws_display_render_state_t *rs);

/*
 * rect
 */

LWS_VISIBLE LWS_EXTERN lws_dlo_rect_t *
lws_display_dlo_rect_new(lws_displaylist_t *dl, lws_dlo_t *dlo_parent,
			 lws_box_t *box,  const lws_fixed3232_t *radii,
			 lws_display_colour_t dc);

LWS_VISIBLE LWS_EXTERN void
lws_display_render_rect(const struct lws_surface_info *ic, struct lws_dlo *dlo,
			const lws_box_t *origin, lws_display_scalar curr,
			uint8_t *line, lws_colour_error_t **nle);

/*
 * PSFU (unicode bitmap terminal) fonts + text
 */

LWS_VISIBLE LWS_EXTERN lws_dlo_text_t *
lws_display_dlo_text_new(lws_displaylist_t *dl, lws_dlo_t *dlo_parent,
			 lws_box_t *box, const lws_display_font_t *font);

LWS_VISIBLE LWS_EXTERN int
lws_display_dlo_text_update(lws_dlo_text_t *text, lws_display_colour_t dc,
		lws_fixed3232_t indent, const char *utf8, size_t text_len);

LWS_VISIBLE LWS_EXTERN void
lws_display_font_psfu_bounding(struct lws_dlo *dlo, const char *txt,
			       lws_box_t *box);

LWS_VISIBLE LWS_EXTERN void
lws_display_font_psfu_render(const struct lws_surface_info *ic, struct lws_dlo *dlo,
			     const lws_box_t *origin, lws_display_scalar curr,
			     uint8_t *line, lws_colour_error_t **nle);

void
lws_display_dlo_text_destroy(struct lws_dlo *dlo);

/*
 * PNG
 */

LWS_VISIBLE LWS_EXTERN lws_dlo_png_t *
lws_display_dlo_png_new(lws_displaylist_t *dl, lws_dlo_t *dlo_parent,
			lws_box_t *box, const uint8_t *png, size_t png_size);

LWS_VISIBLE LWS_EXTERN void
lws_display_render_png(const struct lws_surface_info *ic, struct lws_dlo *dlo,
		       const lws_box_t *origin, lws_display_scalar curr,
		       uint8_t *line, lws_colour_error_t **nle);

typedef struct lhp_ctx lhp_ctx_t;

LWS_VISIBLE LWS_EXTERN signed char
lhp_dl_render(lhp_ctx_t *ctx, char reason);

