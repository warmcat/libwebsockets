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

struct lws_display_render_state;
struct lws_surface_info;
struct lws_display_state;
struct lws_display_font;
struct lws_dlo_text;
struct lws_display;
struct lws_dlo_text;
struct lws_dlo;

#define LWSDC_RGBA(_r, _g, _b, _a) (((uint32_t)(_r) & 0xff) | \
				   (((uint32_t)(_g) & 0xff) << 8) | \
				   (((uint32_t)(_b) & 0xff) << 16) | \
				   (((uint32_t)(_a) & 0xff) << 24))

#define LWSDC_R(_c)		((_c) & 0xff)
#define LWSDC_G(_c)		((_c >> 8) & 0xff)
#define LWSDC_B(_c)		((_c >> 16) & 0xff)
#define LWSDC_ALPHA(_c)		((_c >> 24) & 0xff)

#define RGB_TO_Y(_r, _g, _b) ((((_r) * 299) + ((_g) * 587) + ((_b) * 114)) / 1000)
/* stores Y in RGBY */
#define PALETTE_RGBY(_r, _g, _b) LWSDC_RGBA(_r, _g, _b, (RGB_TO_Y(_r, _g, _b)))

typedef struct {
	lws_fx_t	w;
	lws_fx_t	h;
} lws_dlo_dim_t;

/*
 * When using RGBA to describe native greyscale, R is Y and A is A, GB is ignored
 */

/* composed at start of larger, font-specific glyph struct */

typedef struct lws_font_glyph {
	lws_dll2_t		list;

	lws_fx_t		xorg;
	lws_fx_t		xpx;
	lws_fx_t		height;
	lws_fx_t		cwidth;

	int8_t			x;	/* x offset inside the glyph */

} lws_font_glyph_t;

typedef lws_stateful_ret_t (*lws_dlo_renderer_t)(struct lws_display_render_state *rs);
typedef lws_font_glyph_t * (*lws_dlo_image_glyph_t)(
				struct lws_dlo_text *text,
				uint32_t unicode, char attach);
typedef void (*lws_dlo_destroy_t)(struct lws_dlo *dlo);

typedef struct lws_display_id {
	lws_dll2_t			list;

	char				id[16];
	lws_box_t			box; /* taken from DLO after layout */

	void				*priv_user;
	void				*priv_driver;

	char				exists;
	char				iframe; /* 1 = render html as if partial
						 * is the origin, otherwise
						 * render html with surface
						 * (0,0) as origin and rs->box
						 * is a viewport on to that */
} lws_display_id_t;

/*
 * Common dlo object that joins the display list, composed into a subclass
 * object like lws_dlo_rect_t etc
 */

typedef struct lws_dlo {
	lws_dll2_t			list;

	lws_dll2_t			col_list; /* lws_dlo_t: column-mates */
	lws_dll2_t			row_list; /* lws_dlo_t: row-mates */

	/* children are rendered "inside" the parent DLO box after allowing
	 * for parent padding */
	lws_dll2_owner_t		children;

	/* only used for dlo rect representing whole table */

	lws_dll2_owner_t		table_cols; /* lhp_table_col_t */
	lws_dll2_owner_t		table_rows; /* lhp_table_row_t */

	/* may point to dlo whose width or height decides our x or y */

	struct lws_dlo			*abut_x;
	struct lws_dlo			*abut_y;

	lws_dlo_destroy_t		_destroy; /* dlo-type specific cb */
	lws_dlo_renderer_t		render;   /* dlo-type specific cb */

	lws_fx_t			margin[4];
	lws_fx_t			padding[4]; /* child origin */

	lws_display_id_t		*id; /* only valid until ids destroyed */

	lws_box_t			box;
	lws_display_colour_t		dc;

	uint8_t				flag_runon:1; /* continues same line */
	uint8_t				flag_done_align:1;
	uint8_t				flag_toplevel:1; /* don't scan up with me (different owner) */

	/* render-specific members ... */
} lws_dlo_t;

typedef struct lws_circle {
	lws_fx_t			r;

	/* rasterization temps */
	lws_fx_t			orx; /* abs pixel x for centre */
	lws_fx_t			ory; /* abs pixel y for centre */
	lws_fx_t			rsq;
	lws_fx_t			ys;
} lws_circle_t;

typedef struct lws_dlo_rect {
	lws_dlo_t			dlo;
	lws_circle_t			c[4]; /* t-l, t-r, b-l, b-r */
	lws_fx_t			b[4]; /* border width on t/r/b/l */
	lws_display_colour_t		dcb;  /* border colour */

	/* rasterization temps */

	lws_fx_t			btm;
	lws_fx_t			right;
	lws_box_t			db;

	uint8_t				init;
	uint8_t				alt;
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

	const uint8_t			*data; /* may be cast to imp struct */
	uint8_t				*priv; /* only used by implementation */
	size_t				data_len;
	lws_dlo_renderer_t		renderer;
	lws_dlo_image_glyph_t		image_glyph;

	lws_fx_t			em;	/* 1 em in pixels */
	lws_fx_t			ex;	/* 1 ex in pixels */
} lws_display_font_t;

typedef struct lws_dlo_filesystem {
	lws_dll2_t			list;

	const char			*name;
	const void			*data;
	size_t				len;
} lws_dlo_filesystem_t;

#define LWSDLO_TEXT_FLAG_WRAP					(1 << 0)

typedef struct lws_dlo_text {
	lws_dlo_t			dlo;
	const lws_display_font_t	*font;
	lws_dll2_owner_t		glyphs;
	lws_box_t			bounding_box; /* { 0, 0, w, h } relative
						       * to and subject to
						       * clipping by .dlo.box */

	/* referred to by glyphs */
	const struct lws_surface_info	*ic;
	struct lwsac			*ac_glyphs;
	uint8_t				*line;
	uint16_t			curr;

	char				*text;
	uint8_t				*kern;
	size_t				text_len;
	lws_display_list_coord_t	clkernpx;
	lws_display_list_coord_t	cwidth;

	lws_fx_t			indent;

	uint32_t			flags;
	int16_t				font_y_baseline;
	int16_t				font_height;
	int16_t				font_line_height;

	int16_t				group_height;
	int16_t				group_y_baseline;

	lws_fx_t			_cwidth;
} lws_dlo_text_t;

typedef struct lws_dlo_rasterize {
	lws_dll2_owner_t		owner; /* lws_flow_t */
	lws_sorted_usec_list_t		sul;
	int				lines;
} lws_dlo_rasterize_t;

typedef struct lws_dlo_png {
	lws_dlo_t			dlo;  /* ordering: first */
	lws_flow_t			flow; /* ordering: second */
	lws_upng_t			*png;
} lws_dlo_png_t;

typedef struct lws_dlo_jpeg {
	lws_dlo_t			dlo;  /* ordering: first */
	lws_flow_t			flow; /* ordering: second */
	lws_jpeg_t			*j;
} lws_dlo_jpeg_t;

typedef enum {
	LWSDLOSS_TYPE_JPEG,
	LWSDLOSS_TYPE_PNG,
	LWSDLOSS_TYPE_CSS,
} lws_dlo_image_type_t;

typedef struct {
	union {
		lws_dlo_jpeg_t		*dlo_jpeg;
		lws_dlo_png_t		*dlo_png;
	} u;
	lws_dlo_image_type_t		type;
	char				failed;
} lws_dlo_image_t;

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

typedef struct lws_display_render_stack {
	lws_dlo_t			*dlo;	/* position in dlo owner */
	lws_box_t			co;	/* our origin as parent */
} lws_display_render_stack_t;

typedef struct lws_display_render_state {
	lws_sorted_usec_list_t		sul; /* return to event loop statefully */
	lws_display_state_t		*lds; /* optional, if using lws_display */

	lws_dll2_owner_t		ids;

	const struct lws_surface_info	*ic; /* display dimensions, palette */

	lws_display_render_stack_t	st[12]; /* DLO child stack */
	int				sp;	/* DLO child stack level */

	uint8_t				*line; /* Y or RGB line comp buffer */

	lws_displaylist_t		displaylist;

	lws_display_scalar		curr;
	lws_display_scalar		lowest_id_y;

	char				html;

} lws_display_render_state_t;


LWS_VISIBLE LWS_EXTERN void
lws_display_render_free_ids(lws_display_render_state_t *rs);

LWS_VISIBLE LWS_EXTERN lws_display_id_t *
lws_display_render_add_id(lws_display_render_state_t *rs, const char *id, void *priv);

LWS_VISIBLE LWS_EXTERN lws_display_id_t *
lws_display_render_get_id(lws_display_render_state_t *rs, const char *id);

LWS_VISIBLE LWS_EXTERN void
lws_display_render_dump_ids(lws_dll2_owner_t *ids);

LWS_VISIBLE LWS_EXTERN void
lws_dlo_contents(lws_dlo_t *parent, lws_dlo_dim_t *dim);

LWS_VISIBLE LWS_EXTERN void
lws_display_dlo_adjust_dims(lws_dlo_t *dlo, lws_dlo_dim_t *dim);

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

//#if defined(_DEBUG)
LWS_VISIBLE LWS_EXTERN void
lws_display_dl_dump(lws_displaylist_t *dl);
//#endif

/**
 * lws_display_list_destroy() - destroys display list and objects on it
 *
 * \param dl: Pointer to the display list
 *
 * Destroys every DLO on the list.
 */
LWS_VISIBLE LWS_EXTERN void
lws_display_list_destroy(lws_displaylist_t *dl);

LWS_VISIBLE LWS_EXTERN void
lws_display_dlo_destroy(lws_dlo_t **r);

LWS_VISIBLE LWS_EXTERN int
lws_display_dlo_add(lws_displaylist_t *dl, lws_dlo_t *dlo_parent, lws_dlo_t *dlo);

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
LWS_VISIBLE LWS_EXTERN lws_stateful_ret_t
lws_display_list_render_line(lws_display_render_state_t *rs);

LWS_VISIBLE LWS_EXTERN lws_stateful_ret_t
lws_display_get_ids_boxes(lws_display_render_state_t *rs);

/*
 * rect
 */

LWS_VISIBLE LWS_EXTERN lws_dlo_rect_t *
lws_display_dlo_rect_new(lws_displaylist_t *dl, lws_dlo_t *dlo_parent,
			 lws_box_t *box,  const lws_fx_t *radii,
			 lws_display_colour_t dc);

LWS_VISIBLE LWS_EXTERN lws_stateful_ret_t
lws_display_render_rect(struct lws_display_render_state *rs);

/*
 * dlo text
 */

LWS_VISIBLE LWS_EXTERN lws_dlo_text_t *
lws_display_dlo_text_new(lws_displaylist_t *dl, lws_dlo_t *dlo_parent,
			 lws_box_t *box, const lws_display_font_t *font);

LWS_VISIBLE LWS_EXTERN int
lws_display_dlo_text_update(lws_dlo_text_t *text, lws_display_colour_t dc,
		lws_fx_t indent, const char *utf8, size_t text_len);

LWS_VISIBLE LWS_EXTERN void
lws_display_dlo_text_destroy(struct lws_dlo *dlo);

/*
 * PNG
 */

LWS_VISIBLE LWS_EXTERN lws_dlo_png_t *
lws_display_dlo_png_new(lws_displaylist_t *dl, lws_dlo_t *dlo_parent,
			lws_box_t *box);

LWS_VISIBLE LWS_EXTERN lws_stateful_ret_t
lws_display_render_png(struct lws_display_render_state *rs);

LWS_VISIBLE LWS_EXTERN lws_stateful_ret_t
lws_display_dlo_png_metadata_scan(lws_dlo_png_t *dp);

LWS_VISIBLE LWS_EXTERN void
lws_display_dlo_png_destroy(struct lws_dlo *dlo);

/*
 * JPEG
 */

LWS_VISIBLE LWS_EXTERN lws_dlo_jpeg_t *
lws_display_dlo_jpeg_new(lws_displaylist_t *dl, lws_dlo_t *dlo_parent,
			 lws_box_t *box);

LWS_VISIBLE LWS_EXTERN lws_stateful_ret_t
lws_display_render_jpeg(struct lws_display_render_state *rs);

LWS_VISIBLE LWS_EXTERN lws_stateful_ret_t
lws_display_dlo_jpeg_metadata_scan(lws_dlo_jpeg_t *dj);

LWS_VISIBLE LWS_EXTERN void
lws_display_dlo_jpeg_destroy(struct lws_dlo *dlo);

/*
 * SS / dlo images
 */

struct lhp_ctx;

typedef struct {
	struct lws_context		*cx;
	lws_displaylist_t		*dl;
	lws_dlo_t			*dlo_parent;
	lws_box_t			*box;
	sul_cb_t			on_rx;
	lws_sorted_usec_list_t		*on_rx_sul;
	const char			*url;
	struct lhp_ctx			*lhp;
	lws_dlo_image_t			*u;
	int32_t				window;

	uint8_t				type;
} lws_dlo_ss_create_info_t;

LWS_VISIBLE LWS_EXTERN int
lws_dlo_ss_create(lws_dlo_ss_create_info_t *i, lws_dlo_t **pdlo);

typedef struct lhp_ctx lhp_ctx_t;

LWS_VISIBLE LWS_EXTERN int
lws_dlo_ss_find(struct lws_context *cx, const char *url, lws_dlo_image_t *u);

LWS_VISIBLE LWS_EXTERN lws_stateful_ret_t
lhp_displaylist_layout(lhp_ctx_t *ctx, char reason);

#define lws_dlo_image_width(_u) ((_u)->failed ? -1 : \
		((_u)->type == LWSDLOSS_TYPE_JPEG ? \
				(int)lws_jpeg_get_width((_u)->u.dlo_jpeg->j) : \
				(int)lws_upng_get_width((_u)->u.dlo_png->png)))
#define lws_dlo_image_height(_u) ((_u)->failed ? -1 : \
		((_u)->type == LWSDLOSS_TYPE_JPEG ? \
				(int)lws_jpeg_get_height((_u)->u.dlo_jpeg->j) : \
				(int)lws_upng_get_height((_u)->u.dlo_png->png)))

#define lws_dlo_image_metadata_scan(_u) ((_u)->failed ? LWS_SRET_FATAL : \
	((_u)->type == LWSDLOSS_TYPE_JPEG ? \
		lws_display_dlo_jpeg_metadata_scan((_u)->u.dlo_jpeg) : \
		lws_display_dlo_png_metadata_scan((_u)->u.dlo_png)))

/*
 * Font registry
 *
 * Register fonts (currently, psfu) to the lws_context, and select the closest
 * matching.  Used to pick fonts from whatever CSS information is available.
 */

LWS_VISIBLE LWS_EXTERN int
lws_font_register(struct lws_context *cx, const uint8_t *data, size_t data_len);

LWS_VISIBLE LWS_EXTERN const lws_display_font_t *
lws_font_choose(struct lws_context *cx, const lws_font_choice_t *hints);

LWS_VISIBLE LWS_EXTERN void
lws_fonts_destroy(struct lws_context *cx);

/*
 * Static blob registry (built-in, name-accessible blobs)
 */

LWS_VISIBLE LWS_EXTERN lws_dlo_filesystem_t *
lws_dlo_file_register(struct lws_context *cx, const lws_dlo_filesystem_t *f);

/* only needed if f dynamically heap-allocated... doesn't free data; data
 * is typically overallocated after the lws_dlo_filesystem_t and freed when
 * that is freed by this. */

LWS_VISIBLE LWS_EXTERN void
lws_dlo_file_unregister(lws_dlo_filesystem_t **f);

LWS_VISIBLE LWS_EXTERN void
lws_dlo_file_unregister_by_name(struct lws_context *cx, const char *name);

LWS_VISIBLE LWS_EXTERN const lws_dlo_filesystem_t *
lws_dlo_file_choose(struct lws_context *cx, const char *name);

LWS_VISIBLE LWS_EXTERN void
lws_dlo_file_destroy(struct lws_context *cx);

LWS_VISIBLE extern const struct lws_plat_file_ops lws_dlo_fops;
