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

#if !defined(__LWS_DLO_H__)
#define __LWS_DLO_H__

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

	void			*pin;	/* font-private: what to unpin on free */
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

	/* may point to dlo whose width or height decides our x or y:
	 * abut_y is the positioned ancestor a bottom-anchored absolute
	 * box waits on, box.y meanwhile holding the offset up from its
	 * bottom edge (layout) */

	struct lws_dlo			*abut_x;
	struct lws_dlo			*abut_y;

	lws_dlo_destroy_t		_destroy; /* dlo-type specific cb */
	lws_dlo_renderer_t		render;   /* dlo-type specific cb */
#if defined(LWS_WITH_FOOTPRINT)
	size_t				(*_heap)(struct lws_dlo *dlo);
	/**< dlo-type specific: the heap it holds besides the dlo itself, or
	 * NULL for none */
	const char			*fp_name; /**< what it is, for dumps */
#endif

	lws_fx_t			margin[4];
	lws_fx_t			padding[4]; /* child origin */

	lws_display_id_t		*id; /* only valid until ids destroyed */

	lws_box_t			box;
	lws_display_colour_t		dc;

	uint8_t				budget; /* limit spinning */
	int16_t				base_up; /* baseline: distance up from the
						  * box bottom, 0 = bottom edge
						  * (layout) */

	uint8_t				flag_toplevel:1; /* don't scan up with me (different owner) */
	uint8_t				flag_block:1; /* block-level box (layout) */
	uint8_t				flag_row:1;   /* table row box (layout) */
	uint8_t				flag_cell:1;  /* table cell box (layout) */
	uint8_t				flag_abs:1;   /* positioned box (layout) */
	uint8_t				flag_float:1; /* floated box (layout) */
	uint8_t				flag_zraise:1; /* positioned, z-index > 0 */
	uint8_t				flag_online:1; /* item of the line being ended (layout) */
	uint8_t				flag_bg_homed:1; /* css background image moved into
						  * its element's own dlo (layout) */
	uint8_t				flag_inline_bg:1; /* background rect of the text
						   * run that follows it (layout) */
	uint8_t				flag_flex_item:1; /* item of a row flex container
						   * (layout) */
	uint8_t				flag_fixed_h:1; /* has a css height: not
						 * stretched (layout) */
	uint8_t				flag_clip:1; /* css overflow hidden:
						 * our children are clipped to
						 * our box */
	uint8_t				flag_positioned:1; /* css position other
						 * than static (layout) */
	uint8_t				flag_abs_stretch:1; /* waiting on abut_y
						 * to stretch between top and
						 * bottom, box.h meanwhile the
						 * bottom offset (layout) */
	uint8_t				flex_grow; /* flex-grow, for flag_flex_item */
	uint8_t				align_self; /* LCSP_PROPVAL_* or 0 = auto */
	uint8_t				opacity_inv; /* 255 - the alpha that we
						 * and our children are composed
						 * with: 0, the default, is
						 * opaque */
	uint8_t				flag_ext:1; /* ext[] is valid */
	uint8_t				flag_animated:1; /* it looks different
						 * at another rs->anim_t, eg, an
						 * svg with SMIL animation, once
						 * it has been rendered */

	int32_t				ext[2]; /* the surface lines we and
						 * our children may draw on, top
						 * and bottom inclusive, for a
						 * retained render to skip us
						 * on the others */

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
	/*
	 * The border on each side, t / r / b / l: its width, inside the box,
	 * and its colour.  The corners of the box inside it are rounded by
	 * the box's radii less the border.
	 */
	lws_fx_t			b[4];
	lws_display_colour_t		dcb[4];

	/* rasterization temps */

	lws_fx_t			btm;
	lws_fx_t			right;
	lws_box_t			db;

	uint8_t				init;
	uint8_t				alt;
	/* 0 = full box, else fill the triangle at the named corner: the css
	 * border-triangle idiom (transparent adjacent borders on an empty
	 * box) */
	uint8_t				tri;  /* 1 t-l, 2 t-r, 3 b-l, 4 b-r */
} lws_dlo_rect_t;

/* what a rect covers of one line of the surface, see dlo-rect.c */

typedef struct lws_dlo_rect_row {
	lws_fx_t			cov;	/* of the line's height */
	lws_fx_t			sfy;	/* where it starts */
	lws_fx_t			e;	/* where it ends */
	int				curr;	/* the line */
	int				os, le;	/* first and last px touched */
	int				pa, pb;	/* first and last px covered */
} lws_dlo_rect_row_t;

typedef struct lws_dlo_circle {
	lws_dlo_t			dlo;
} lws_dlo_circle_t;

/*
 * Non-printing hit region: renders nothing, but marks the area of its box
 * as belonging to something, eg, the link whose url it carries.  Being a
 * dlo it is placed and moved by the layout with the things around it, and
 * its position in the paint order decides which of several overlapping
 * regions a point belongs to (the last, as a viewer sees it on top).
 */

/*
 * The pointer shape a hit region asks for while the pointer is over it, in
 * platform-neutral terms: a windowing backend maps these to whatever it
 * has (X11 font cursors, NSCursor, LoadCursor...).  A link asks for the
 * pointing hand, editable text for the I-beam, css cursor: for the rest.
 */
typedef enum {
	LWS_DLO_CURSOR_DEFAULT,		/* the platform arrow */
	LWS_DLO_CURSOR_POINTER,		/* pointing hand: links, buttons */
	LWS_DLO_CURSOR_TEXT,		/* I-beam: editable / selectable text */
	LWS_DLO_CURSOR_CROSSHAIR,
	LWS_DLO_CURSOR_MOVE,
	LWS_DLO_CURSOR_WAIT,
	LWS_DLO_CURSOR_HELP,
	LWS_DLO_CURSOR_NOT_ALLOWED,
	LWS_DLO_CURSOR_NONE,		/* hidden */
} lws_dlo_cursor_t;

typedef struct lws_dlo_hit {
	lws_dlo_t			dlo;
	const char			*url; /* as written in the document, in
					       * the same allocation; NULL for a
					       * region that only sets the
					       * cursor */
	uint8_t				fill; /* takes its parent's size */
	uint8_t				cursor; /* lws_dlo_cursor_t */
} lws_dlo_hit_t;

typedef struct lws_font_choice {
	const char			*family_name;
	const char			*generic_name;
	uint16_t			weight;
	uint16_t			style; /* normal, italic, oblique */
	uint16_t			fixed_height;
} lws_font_choice_t;

/*
 * Something that can be waiting for a font to arrive from the server (a
 * document's layout, a render): when the fetch it waits on completes, or
 * fails, sul is scheduled with cb.  Embedded in the waiting object, and
 * removed from the wait when that is destroyed
 */
typedef struct lws_font_waiter {
	lws_dll2_t			list;
	lws_sorted_usec_list_t		*sul;
	sul_cb_t			cb;
} lws_font_waiter_t;

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

enum {
	LWS_DLO_TEXT_ALIGN_LEFT,
	LWS_DLO_TEXT_ALIGN_CENTER,
	LWS_DLO_TEXT_ALIGN_RIGHT,
};

typedef struct lws_dlo_text {
	lws_dlo_t			dlo;
	const lws_display_font_t	*font;
	lws_dll2_owner_t		glyphs;
	lws_box_t			bounding_box; /* { 0, 0, w, h } relative
						       * to and subject to
						       * clipping by .dlo.box */

	/* referred to by glyphs */
	struct lws_display_render_state	*rs; /* during render only */
	struct lwsac			*ac_glyphs;
	lws_dll2_t			glyphed; /* on the display list's
						  * .glyphed while it has
						  * glyphs attached */
	uint16_t			curr;
	uint16_t			glyph_row; /* rows the glyph run decoders
						    * have produced since attach */

	char				*text;
	size_t				text_len;
	lws_display_list_coord_t	cwidth;

	lws_fx_t			indent;

	uint32_t			flags;
	lws_fx_t			line_free; /* how much of the width
						* of the line this run is on
						* was left over, and ... */
	uint8_t				align; /* ... LWS_DLO_TEXT_ALIGN_*,
						* how the layout placed the line
						* in it: so the run can be
						* placed again the same way if
						* its text is changed */
	int16_t				font_y_baseline;
	int16_t				font_height;
	int16_t				font_line_height;

	int16_t				group_height;
	int16_t				group_y_baseline;

	uint16_t			font_gen; /* the font copy the glyphs
						   * were attached from */
	const lws_display_font_t	*font_held; /* pinned while we live,
						     * see .hold_fonts */
} lws_dlo_text_t;

typedef struct lws_dlo_rasterize {
	lws_dll2_owner_t		owner; /* lws_flow_t */
	lws_sorted_usec_list_t		sul;
	int				lines;
} lws_dlo_rasterize_t;

/*
 * How to fetch an image dlo's payload again, when it came from a document
 * asset: an image is only held while the raster is on it, and fetched again
 * if a retained render comes back to it
 */

typedef struct lws_dlo_refetch {
	struct lws_context		*cx;
	char				*url; /* heap, or NULL: it can't be */
	sul_cb_t			on_rx; /* wakes the render as the */
	lws_sorted_usec_list_t		*on_rx_sul; /* payload arrives */
	lws_dll2_t			released; /* on the context's list
						   * while its fetch is given
						   * back before the raster
						   * reaches it, so the layout
						   * can still find it by url */
	uint8_t				type; /* LWSDLOSS_TYPE_ */
} lws_dlo_refetch_t;

/*
 * Until the raster reaches it, all a png or jpeg from a document asset has
 * to offer the layout is its dimensions, from the start of its header.  So
 * its fetch is only allowed to send this much at first (or the window, if
 * less), and is given more only as the raster's decoder consumes it.  When
 * the raster has passed its last row, its payload, decoder and stream are
 * given back.
 */

#define LWS_DLO_IMAGE_HEAD_CREDIT	1024

typedef struct lws_dlo_png {
	lws_dlo_t			dlo;  /* ordering: first */
	lws_flow_t			flow; /* ordering: second */
	char				name[25];
	lws_upng_t			*png;
	uint32_t			emitted; /* decoded rows issued so far,
						* for viewport re-scans */
	uint8_t				*row; /* copy of the last row issued, for
					       * repeating it when scaled up */
	uint32_t			row_len;
	lws_reclaimable_t		rc; /* payload + decoder, once complete */
	lws_dlo_refetch_t		rf;
	uint8_t				evicted; /* renew from the asset cache,
						  * or fetch it again, before
						  * the next render */
	uint8_t				yields; /* consecutive OOM yields */
	uint8_t				failed; /* the decoder returned FATAL:
						 * nothing more from it */
} lws_dlo_png_t;

typedef struct lws_dlo_jpeg {
	lws_dlo_t			dlo;  /* ordering: first */
	lws_flow_t			flow; /* ordering: second */
	char				name[25];
	lws_jpeg_t			*j;
	uint32_t			emitted; /* decoded rows issued so far,
						* for viewport re-scans */
	uint8_t				*row; /* copy of the last row issued, for
					       * repeating it when scaled up */
	uint32_t			row_len;
	lws_reclaimable_t		rc; /* payload + decoder, once complete */
	lws_dlo_refetch_t		rf;
	uint8_t				evicted; /* renew from the asset cache,
						  * or fetch it again, before
						  * the next render */
	uint8_t				failed; /* the decoder returned FATAL:
						 * nothing more from it */
} lws_dlo_jpeg_t;

/*
 * An svg is held, as its payload and parsed scene, only while something needs
 * it.  The scene object is created when the payload starts to arrive.  One
 * from a local file (eg, file://dlofs/...) is not even fetched until the
 * raster reaches a line of it that shows, if the document gave its size: the
 * document lays out from the box alone.  Like the png and jpeg, it is given
 * back after its last line, and fetched again if the raster comes back to it.
 * A page of icons stacked vertically so holds one at a time.
 */

typedef struct lws_dlo_svg {
	lws_dlo_t			dlo;  /* ordering: first */
	lws_flow_t			flow; /* ordering: second */
	char				name[25];
	lws_svg_t			*svg; /* NULL until payload arrives */

	lws_dlo_refetch_t		rf;

	uint8_t				local:1; /* url is a local file: not
						  * fetched until it is rendered */
	uint8_t				failed:1; /* nothing usable came: don't
						   * fetch it again */
} lws_dlo_svg_t;

/*
 * Unlike the png and jpeg dlos, the gif dlo keeps the whole asset payload
 * retained in one buffer, so the decode can start again from the top when the
 * render does.  It is freed once the frame has decoded.  Interlaced rows
 * arrive out of screen order, so those images are decoded once into a frame
 * of palette indices (bounded in size) that the render reads lines from.
 */

typedef struct lws_dlo_gif {
	lws_dlo_t			dlo;  /* ordering: first */
	lws_flow_t			flow; /* ordering: second */
	char				name[25];
	lws_gif_t			*gif;
	uint8_t				*whole;	/* retained asset payload */
	size_t				whole_len;
	size_t				whole_size;
	size_t				pos;	/* decode feed cursor in whole */
	uint8_t				*frame;	/* interlaced: decoded rows */
	uint8_t				*frame_have; /* bitmap of rows in frame */
	char				whole_done; /* whole fully decoded */
} lws_dlo_gif_t;

typedef enum {
	LWSDLOSS_TYPE_JPEG,
	LWSDLOSS_TYPE_PNG,
	LWSDLOSS_TYPE_SVG,
	LWSDLOSS_TYPE_GIF,
	LWSDLOSS_TYPE_CSS,
} lws_dlo_image_type_t;

typedef struct {
	union {
		lws_dlo_jpeg_t		*dlo_jpeg;
		lws_dlo_png_t		*dlo_png;
		lws_dlo_svg_t		*dlo_svg;
		lws_dlo_gif_t		*dlo_gif;
	} u;
	lws_dlo_image_type_t		type;
	char				failed;
} lws_dlo_image_t;

typedef struct lws_displaylist {
	lws_dll2_owner_t		dl;
	lws_dll2_owner_t		glyphed; /* text dlos with glyphs
						  * attached for rendering */
	struct lws_display_state 	*ds;
	char				hold_fonts; /* the text keeps the
						* pages of the faces from a
						* server it is set in resident
						* until it is destroyed, so its
						* render can't lose them */
#if defined(LWS_WITH_FOOTPRINT)
	lws_footprint_t			fp; /* "display list" participant */
#endif
} lws_displaylist_t;

typedef struct lws_dl_rend {
	lws_displaylist_t		*dl;
	int				w;
	int				h;
	char				clipped; /* the layout dropped content that
					  * landed below h */
} lws_dl_rend_t;

typedef struct lws_display_render_stack {
	lws_dlo_t			*dlo;	/* position in dlo owner */
	lws_box_t			co;	/* our origin as parent */
	int32_t				clip[4]; /* surface x0, y0, x1, y1
						  * our children are clipped to */
	struct lws_dlo_rect		*rclip;	/* the innermost of clip[]'s
						 * boxes with rounded corners,
						 * which clip too, or NULL */
	uint8_t				opacity; /* alpha our children are
						  * composed with, 255 = opaque */
} lws_display_render_stack_t;

/*
 * How deep a display list the dlo tree walkers (render, dump, hit test) can
 * follow.  Deeper nesting than this is truncated, it is not an error: the
 * walkers all carry the stack by value, so on a constrained target the
 * ceiling is what keeps them off a couple of KB of stack apiece.
 */

#if !defined(LWS_DLO_STACK_DEPTH)
#if defined(LWS_ESP_PLATFORM)
#define LWS_DLO_STACK_DEPTH	16
#else
#define LWS_DLO_STACK_DEPTH	64
#endif
#endif

typedef struct lws_display_render_state {
	lws_sorted_usec_list_t		sul; /* return to event loop statefully */
	struct lws_display_state	*lds; /* optional, if using lws_display */

	lws_dll2_owner_t		ids;

	const struct lws_surface_info	*ic; /* display dimensions, palette */

	lws_display_render_stack_t	st[LWS_DLO_STACK_DEPTH];
						/* DLO child stack */
	int				sp;	/* DLO child stack level */

	uint8_t				*line; /* Y or RGB line comp buffer */
	int32_t				clip_x0; /* the dlo being rendered */
	int32_t				clip_x1; /* only composes pixels from
						  * x0 up to x1 on this line */
	struct lws_dlo_rect		*rclip;	/* the dlo being rendered is
						 * also clipped to this one's
						 * rounded corners, on
						 * rclip_row */
	struct lws_dlo_rect		*rclip_for; /* rclip_row is of
						     * this, for its line */
	lws_dlo_rect_row_t		rclip_row;
	unsigned int			rclip_alpha; /* of all of the row */
	uint8_t				opacity; /* alpha the dlo being
						  * rendered is composed with,
						  * 255 = opaque: see
						  * lws_display_render_set_px() */
	uint8_t				rclip_none; /* rclip_row covers
						     * nothing of the line */

	lws_displaylist_t		displaylist;

	/* the html document ss currently bound to this render state, when
	 * browsed with lws_lhp_ss_browse(); used by lws_lhp_ss_cancel() */

	struct lws_ss_handle		*hss_html;

	lws_display_scalar		curr;
	lws_display_scalar		lowest_id_y;

	int32_t				pan_x; /* the display list point at */
	int32_t				pan_y; /* the surface's top left: 0, or
						* where lws_display_render_pan()
						* moved the view of a retained
						* display list to */

	char				html;
	char				retained; /* nonzero: keep DLOs when the
						* render cursor passes them, so
						* the display list can be re-
						* scanned at other offsets */
	char				layout_clipped; /* set when the html
						* completes if the layout dropped
						* content below the surface: a
						* taller surface would show more */
	char				layout_failed; /* set when the html
						* completes if the layout ended
						* early: it ran out of memory, or
						* the document could not be
						* parsed.  The display list holds
						* what was laid out before that */
	char				fonts_local; /* set by the caller
						* before browsing: lay the page
						* out in the faces built in only,
						* not any from a server */
	char				fonts_hold; /* set by the caller
						* before browsing: the display
						* list keeps the faces from a
						* server its text is set in
						* resident until it's destroyed,
						* so the layout only uses those
						* it can have for the render too.
						* For browsing again after the
						* render set .relayout */
	char				relayout_ok; /* set by the caller:
						* it can act on .relayout.  If
						* not, text whose face can't be
						* had at render is drawn in a
						* built-in face, as much of it
						* as fits where it was laid out */
	char				relayout; /* set by the render,
						* if .relayout_ok, when text
						* can't be drawn in the face from
						* a server it was laid out in:
						* the render gives up with
						* LWS_SRET_FATAL, and the caller
						* should destroy the display list
						* and browse the page again with
						* .fonts_hold set, so it is laid
						* out in faces it can draw in */
	uint16_t			reclaim_elems; /* 0, or evict every
						* reclaimable heap occupant as
						* every n-th element of the
						* layout opens: a test aid, so
						* the faces and other tenants
						* have to renew themselves during
						* the layout whatever the
						* allocator does */
	int32_t				viewport_h; /* 0, or the height css
						* viewport units and the root
						* element's height resolve
						* against, when the layout
						* surface is taller than what is
						* shown at once (a scrolling
						* window) */
	int32_t				layout_h; /* 0, or the height
						* lws_lhp_ss_browse() lays the
						* page out to, when it's more
						* than the surface's: a page that
						* long can be panned down to its
						* end with
						* lws_display_render_pan().  The
						* viewport is still the surface,
						* unless .viewport_h says else */
	int32_t				window; /* 0, or the flow control
						* window lws_lhp_ss_browse()
						* fetches the document and its
						* image payloads with: the most
						* of each it lets the server
						* send ahead of what has been
						* consumed.  0 is the platform
						* default, 4KB on the small
						* targets, 64KB elsewhere */
	struct lws_context		*cx; /* set by lws_lhp_ss_browse_filter() */

	lws_font_waiter_t		font_wait; /* render waiting for a
						    * font from the server */
	uint8_t				font_retries; /* times this render
						* came back for pages it
						* couldn't have yet */

	lws_usec_t			anim_t; /* the time, in us, that
						* animated images, eg, svg with
						* SMIL animation, are drawn as
						* they are at: set by the caller
						* before the render.  Indefinitely
						* repeating animations look right
						* with any free running clock,
						* eg, lws_now_usecs().  0 if not
						* set, so a render is the same
						* each time */
	int32_t				damage[4]; /* x0, y0, x1, y1 of
						* what was changed in place in
						* the display list since
						* lws_display_render_damage()
						* last took it: none if x1 <= x0
						*/

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
 *
 * With LWS_WITH_FOOTPRINT, a list bound to a display state with a context
 * takes part in the context's footprint as a "display list", until
 * lws_display_list_destroy(), which must be called before the list's memory
 * goes.
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
 * \param cx: lws_context
 * \param dl: Pointer to the display list
 *
 * Destroys every DLO on the list.
 */
LWS_VISIBLE LWS_EXTERN void
lws_display_list_destroy(struct lws_context *cx, lws_displaylist_t *dl);

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

/**
 * lws_display_render_pan() - move the view of a laid out display list
 *
 * \param rs: the render state, whose display list is laid out
 * \param dx: how far to move the view right, in pixels, or left if negative
 * \param dy: how far to move the view down, in pixels, or up if negative
 *
 * Lines rendered afterwards show the display list from rs->pan_x, rs->pan_y
 * at the top left of the surface: what is laid out is only drawn somewhere
 * else, it is not laid out again.  Each line starts white wherever the view
 * shows something the display list doesn't cover.
 *
 * The view is kept to what is laid out, as far as the display list's content
 * reaches across and down: a page longer than the surface can be moved down
 * to its end, if it was laid out that long, see .layout_h.  On a round
 * surface (lws_surface_info_t .round) the view can also go beyond each edge
 * of the content, but only as far as it takes to bring a corner of it, eg,
 * the content's (0, 0), to the first pixel of the circle that can be seen
 * there, so everything in the corners the circle doesn't show can be brought
 * into it.
 *
 * Call with dx and dy of 0 to only keep a pan made before to what is laid
 * out now, eg, after a relayout.  Points on the surface, eg, a touch, are at
 * the display list's (x + rs->pan_x, y + rs->pan_y), eg, for
 * lws_display_dl_hit_test().
 *
 * To show the move, the display list is then rendered again from the top of
 * the surface, as a retained display list can be (see .retained).  Images
 * the raster passed are fetched again for it, from the document asset cache
 * if there is one, and those it was partway down are only drawn from the top
 * again if lws_dlo_ss_renew_images() can renew them from the cache.
 *
 * Returns nonzero if the view moved.
 */
LWS_VISIBLE LWS_EXTERN int
lws_display_render_pan(lws_display_render_state_t *rs, int dx, int dy);

/*
 * lws_display_render_set_px() - compose one pixel of the dlo being rendered
 *
 * \param rs: render state, during the dlo's render callback
 * \param x: surface x of the pixel on the current line
 * \param c: the colour, with its alpha
 *
 * Dlo renderers compose their pixels into rs->line with this rather than
 * lws_surface_set_px(), so that what the layout said about how the dlo and
 * its ancestors are composed, such as css opacity and clipping by an
 * ancestor with css overflow: hidden, is applied to them
 */
LWS_VISIBLE LWS_EXTERN void
lws_display_render_set_px(lws_display_render_state_t *rs, int x,
			  const lws_display_colour_t *c);

/*
 * lws_display_render_fill_span() - compose a run of pixels of one colour
 *
 * \param rs: render state, during the dlo's render callback
 * \param x0: surface x of the first pixel on the current line
 * \param x1: surface x of the pixel after the last
 * \param c: the colour, with its alpha
 *
 * The same as lws_display_render_set_px() for each pixel from x0 up to x1,
 * but the clipping and opacity are dealt with once for the run, eg, for the
 * part of a line a box fills
 */
LWS_VISIBLE LWS_EXTERN void
lws_display_render_fill_span(lws_display_render_state_t *rs, int x0, int x1,
			     const lws_display_colour_t *c);

/**
 * lws_display_get_ids_boxes() - where the elements with the ids ended up
 *
 * \param rs: the render state, whose display list is laid out
 *
 * Sets the .box of each of rs->ids that the layout found an element for to
 * where that element is in the layout, and .lowest_id_y to the lowest line
 * any element is on.
 *
 * If the display list is retained (.retained), the ids stay tagged on the
 * elements' dlos afterwards, so they can be found with
 * lws_display_dlo_by_id() and changed in place, eg, with
 * lws_display_render_set_text().  Otherwise they are let go of then.
 */
LWS_VISIBLE LWS_EXTERN lws_stateful_ret_t
lws_display_get_ids_boxes(lws_display_render_state_t *rs);

/**
 * lws_display_dlo_by_id() - the dlo an id is tagged on
 *
 * \param dl: the display list, laid out
 * \param id: one of the render state's ids, eg, from
 *	      lws_display_render_get_id()
 *
 * Returns the dlo of the element the layout gave the id to, or NULL if there
 * is none, or it was let go of, see lws_display_get_ids_boxes().
 */
LWS_VISIBLE LWS_EXTERN lws_dlo_t *
lws_display_dlo_by_id(lws_displaylist_t *dl, const lws_display_id_t *id);

/**
 * lws_display_dlo_origin() - where a dlo is in the layout
 *
 * \param dl: the display list, laid out
 * \param target: a dlo on it
 * \param x: set to the x of its top left, in the layout
 * \param y: set to the y of its top left, in the layout
 *
 * The layout is the display list as it would be drawn unpanned, see
 * lws_display_render_pan().  Returns 0, or nonzero if the dlo isn't on the
 * display list.
 */
LWS_VISIBLE LWS_EXTERN int
lws_display_dlo_origin(lws_displaylist_t *dl, const lws_dlo_t *target,
		       int *x, int *y);

/**
 * lws_display_render_set_width() - change how wide an element is, in place
 *
 * \param rs: the render state, whose display list is retained and laid out
 * \param id: the id of the element, one of rs->ids
 * \param w: its new width, in px
 *
 * Only the element's own box changes: nothing is laid out again, so nothing
 * else moves, eg, what is in it stays where it is, as do its siblings.  It
 * suits, eg, the fill of a progress bar.
 *
 * What the element's box covered before and covers after is added to the
 * damage, see lws_display_render_damage().
 *
 * Returns 0, or nonzero if there is no element with that id.
 */
LWS_VISIBLE LWS_EXTERN int
lws_display_render_set_width(lws_display_render_state_t *rs, const char *id,
			     const lws_fx_t *w);

/**
 * lws_display_render_set_text() - change the text of an element, in place
 *
 * \param rs: the render state, whose display list is retained and laid out
 * \param id: the id of the element, one of rs->ids
 * \param utf8: its new text
 *
 * The element's content must be a single run of text, on one line, eg, a
 * label or a figure.  The new text is set in the same face and colour, and
 * placed on the line as the layout placed the old, eg, centred if the css
 * said text-align: center.  Nothing else is laid out again, so the new text
 * must fit in the element.
 *
 * What the old text covered and the new text covers is added to the damage,
 * see lws_display_render_damage().
 *
 * Returns 0, or nonzero if there is no element with that id, its content
 * isn't a single run of text, or the new text doesn't fit in it.  Then the
 * element is unchanged.
 */
LWS_VISIBLE LWS_EXTERN int
lws_display_render_set_text(lws_display_render_state_t *rs, const char *id,
			    const char *utf8);

/**
 * lws_display_render_damage() - what of the surface to draw again
 *
 * \param rs: the render state, whose display list is retained and was drawn
 * \param box: set to the part of the surface to draw again
 *
 * The part of the surface, panned as it is now, showing what was changed in
 * place since the last call, eg, by lws_display_render_set_text(), and what
 * is animated and looks different at another .anim_t, eg, an svg with SMIL
 * animation.  What was changed in place is forgotten.
 *
 * Animated content is only known once it has been drawn, so this is for a
 * display list that has been drawn once already.  Drawing the lines of the
 * box again, eg, with .curr set to the first of them, brings the surface up
 * to date.  Displays that can only be updated whole are brought up to date
 * by drawing all of it again from the retained display list.
 *
 * Returns 0 if there's nothing to draw again, else nonzero.
 */
LWS_VISIBLE LWS_EXTERN int
lws_display_render_damage(lws_display_render_state_t *rs, lws_box_t *box);

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
 * hit region
 */

/**
 * lws_display_dlo_hit_new() - add a non-printing hit region to the display list
 *
 * \param dl: the display list
 * \param dlo_parent: the dlo whose child it becomes, or NULL for the list head
 * \param box: its box relative to the parent, or NULL for all zeros
 * \param url: the url (or other metadata string) the region carries, or NULL
 * \param url_len: the length of url
 *
 * The url is copied into the region's own allocation.  Set .fill on the
 * result for a region that always has its parent's size, and .cursor to
 * the lws_dlo_cursor_t the pointer should take over it.
 */
LWS_VISIBLE LWS_EXTERN lws_dlo_hit_t *
lws_display_dlo_hit_new(lws_displaylist_t *dl, lws_dlo_t *dlo_parent,
			const lws_box_t *box, const char *url, size_t url_len);

LWS_VISIBLE LWS_EXTERN void
lws_display_dlo_hit_destroy(struct lws_dlo *dlo);

LWS_VISIBLE LWS_EXTERN lws_stateful_ret_t
lws_display_render_hit(struct lws_display_render_state *rs);

/**
 * lws_display_dl_hit_test() - find the hit region at a point
 *
 * \param dl: the display list
 * \param x: x in the display list's coordinates
 * \param y: y in the display list's coordinates
 * \param abox: NULL, or filled with the region's absolute box if one is hit
 *
 * Returns the topmost hit region containing the point, or NULL if none.
 * For a laid-out html document the coordinates are those of the document,
 * so a viewport offset must be added to a window position first.
 */
LWS_VISIBLE LWS_EXTERN lws_dlo_hit_t *
lws_display_dl_hit_test(lws_displaylist_t *dl, int x, int y, lws_box_t *abox);

/*
 * Told about a hit region, see lws_display_dl_hit_foreach(): abox is its
 * absolute box.  Return nonzero to stop.
 */
typedef int (*lws_dlo_hit_cb_t)(void *opaque, lws_dlo_hit_t *hit,
				const lws_box_t *abox);

/**
 * lws_display_dl_hit_foreach() - each hit region of a display list
 *
 * \param dl: the display list
 * \param cb: told about each hit region
 * \param opaque: passed to cb
 *
 * The hit regions are told in paint order, which for a laid-out html
 * document is the order of the document, eg, so a cursor can be moved from
 * one link to the next.  The regions of a link that was laid out in several
 * pieces, eg, wrapped text, are told one after the other.  cb must not change
 * the display list.  Returns nonzero if cb stopped it.
 */
LWS_VISIBLE LWS_EXTERN int
lws_display_dl_hit_foreach(lws_displaylist_t *dl, lws_dlo_hit_cb_t cb,
			   void *opaque);

/**
 * lws_display_dl_cursor_at() - the pointer shape for a point
 *
 * \param dl: the display list
 * \param x: x in the display list's coordinates
 * \param y: y in the display list's coordinates
 *
 * Returns the cursor the topmost hit region containing the point asks for,
 * or LWS_DLO_CURSOR_DEFAULT if there is none.  A windowing app calls this
 * on pointer motion and sets the platform cursor to match.
 */
LWS_VISIBLE LWS_EXTERN lws_dlo_cursor_t
lws_display_dl_cursor_at(lws_displaylist_t *dl, int x, int y);

/*
 * dlo text
 */

LWS_VISIBLE LWS_EXTERN lws_dlo_text_t *
lws_display_dlo_text_new(lws_displaylist_t *dl, lws_dlo_t *dlo_parent,
			 lws_box_t *box, const lws_display_font_t *font);

LWS_VISIBLE LWS_EXTERN int
lws_display_dlo_text_update(lws_dlo_text_t *text, lws_display_colour_t dc,
		lws_fx_t indent, const char *utf8, size_t text_len);

/**
 * lws_display_dlo_text_measure() - width of a string in a text dlo's font
 *
 * \p text: a text dlo, used for its font
 * \p utf8: the string
 * \p text_len: its length in bytes
 * \p total: set to the width if laid out on one line
 * \p longest_word: set to the width of the widest space-delimited word
 */
LWS_VISIBLE LWS_EXTERN void
lws_display_dlo_text_measure(lws_dlo_text_t *text, const char *utf8,
			     size_t text_len, lws_fx_t *total,
			     lws_fx_t *longest_word);

LWS_VISIBLE LWS_EXTERN void
lws_display_dlo_text_destroy(struct lws_dlo *dlo);

/*
 * PNG
 */

LWS_VISIBLE LWS_EXTERN lws_dlo_png_t *
lws_display_dlo_png_new(lws_displaylist_t *dl, lws_dlo_t *dlo_parent,
			lws_box_t *box, const char *name, size_t len);

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
			 lws_box_t *box, const char *name, size_t len);

LWS_VISIBLE LWS_EXTERN lws_stateful_ret_t
lws_display_render_jpeg(struct lws_display_render_state *rs);

LWS_VISIBLE LWS_EXTERN lws_stateful_ret_t
lws_display_dlo_jpeg_metadata_scan(lws_dlo_jpeg_t *dj);

LWS_VISIBLE LWS_EXTERN void
lws_display_dlo_jpeg_destroy(struct lws_dlo *dlo);

/*
 * SVG
 */

LWS_VISIBLE LWS_EXTERN lws_dlo_svg_t *
lws_display_dlo_svg_new(lws_displaylist_t *dl, lws_dlo_t *dlo_parent,
			lws_box_t *box, const char *name, size_t len);

LWS_VISIBLE LWS_EXTERN lws_stateful_ret_t
lws_display_render_svg(struct lws_display_render_state *rs);

LWS_VISIBLE LWS_EXTERN lws_stateful_ret_t
lws_display_dlo_svg_metadata_scan(lws_dlo_svg_t *ds);

LWS_VISIBLE LWS_EXTERN void
lws_display_dlo_svg_destroy(struct lws_dlo *dlo);

/*
 * GIF
 */

LWS_VISIBLE LWS_EXTERN lws_dlo_gif_t *
lws_display_dlo_gif_new(lws_displaylist_t *dl, lws_dlo_t *dlo_parent,
			lws_box_t *box, const char *name, size_t len);

LWS_VISIBLE LWS_EXTERN lws_stateful_ret_t
lws_display_render_gif(struct lws_display_render_state *rs);

LWS_VISIBLE LWS_EXTERN lws_stateful_ret_t
lws_display_dlo_gif_metadata_scan(lws_dlo_gif_t *dg);

LWS_VISIBLE LWS_EXTERN void
lws_display_dlo_gif_destroy(struct lws_dlo *dlo);

/*
 * Take rx payload for a gif dlo into its retained buffer; the gif flow
 * keeps the payload rather than consuming it from the flow buflist.
 * Returns 0, or nonzero on allocation failure or over the retention cap.
 */

LWS_VISIBLE LWS_EXTERN int
lws_display_dlo_gif_rx(lws_dlo_gif_t *dlo_gif, const uint8_t *buf, size_t len);

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

LWS_VISIBLE LWS_EXTERN int
lws_dlo_ss_find(struct lws_context *cx, const char *url, lws_dlo_image_t *u);

/**
 * lws_dlo_ss_assets_active() - are any document assets fetching or queued?
 *
 * \param cx: the lws_context
 *
 * Returns nonzero if any image or stylesheet asset is being fetched, or is
 * queued waiting for an in-flight slot.  A document whose own stream has
 * ended should defer considering itself complete until this returns 0.
 */
LWS_VISIBLE LWS_EXTERN int
lws_dlo_ss_assets_active(struct lws_context *cx);

/**
 * lws_dlo_ss_stop_any_active() - destroy all tracked document assets
 *
 * \param cx: the lws_context
 *
 * Destroys every document asset that is fetching or queued for a fetch
 * slot, if any.  Used to tear a document down; see lws_lhp_ss_cancel().
 */
LWS_VISIBLE LWS_EXTERN int
lws_dlo_ss_stop_any_active(struct lws_context *cx);

/**
 * lws_dlo_ss_stop_rs() - destroy the document assets of one render state
 *
 * \param cx: the lws_context
 * \param rs: the render state the assets were fetched for
 *
 * Destroys the document assets fetching, or queued for a fetch slot, that
 * wake rs as their data arrives, ie, those of documents browsed into rs.
 * Other documents' assets, eg, those of another render state showing a
 * different part of the display, carry on.  See lws_lhp_ss_cancel().
 */
LWS_VISIBLE LWS_EXTERN void
lws_dlo_ss_stop_rs(struct lws_context *cx,
		   struct lws_display_render_state *rs);

/**
 * lws_dlo_ss_detach_lhp() - forget a document parser in its asset streams
 *
 * \param cx: the lws context
 * \param lhp: the html parser context that is about to be destroyed
 *
 * Asset streams (images, stylesheets) created for a document keep pointers
 * to its parser context and to the sul and callback of the stream that
 * owns it, to resume the parse when they have something.  If that stream is
 * destroyed while assets are still in flight (a failure of the html stream,
 * a context destroy), call this from its DESTROYING so the assets stop
 * referring to memory that is going away; they then finish or fail on their
 * own and are destroyed with their dlos or by lws_dlo_ss_stop_any_active().
 */
LWS_VISIBLE LWS_EXTERN void
lws_dlo_ss_detach_lhp(struct lws_context *cx, struct lhp_ctx *lhp);

/**
 * lws_dlo_ss_renew_images() - reset tracked images for a re-scan
 *
 * \param cx: the lws_context
 *
 * Image decode state only moves forwards, but a retained display list can
 * be re-scanned at a different vertical offset (eg, an interactive
 * viewport scrolling).  This re-stashes each tracked image's payload from
 * the document asset cache and gives it a fresh decoder, so the next scan
 * can decode the rows the viewport wants.  Images not in the cache are
 * left as they are.
 */
LWS_VISIBLE LWS_EXTERN void
lws_dlo_ss_renew_images(struct lws_context *cx);

/**
 * lws_dlo_ss_renew_image() - re-stash one image's payload from the asset cache
 *
 * \param cx: the lws context
 * \param dlo: the png or jpeg dlo
 *
 * As lws_dlo_ss_renew_images() for one image whose payload and decoder
 * were evicted to make room: returns 0 if it is decodable again.
 */
LWS_VISIBLE LWS_EXTERN int
lws_dlo_ss_renew_image(struct lws_context *cx, lws_dlo_t *dlo);


/*
 * The context dlo asset cache stores fetched assets, so still-valid ones are
 * reused instead of fetched again, eg, an image a retained display list is
 * redrawn over at another pan.  Given the dlo_asset_cache_dir member of
 * lws_context_creation_info, it's an in-memory level over a self-maintaining
 * file-backed one (with LWS_WITH_CACHE_BLOB, on posix); given only
 * dlo_asset_cache_max_footprint, it's the in-memory level alone, of that
 * size, eg, for a device with no filesystem.
 */

#if !defined(LWS_DLO_ASSET_BLOB_DEFAULT_MAX_FOOTPRINT)
#define LWS_DLO_ASSET_BLOB_DEFAULT_MAX_FOOTPRINT	(64 * 1024 * 1024)
/**< default max bytes on disk for the asset cache, when the context creation
 * info gives 0 for dlo_asset_cache_max_footprint */
#endif

#if !defined(LWS_DLO_ASSET_BLOB_MAX_PAYLOAD)
#define LWS_DLO_ASSET_BLOB_MAX_PAYLOAD		(16 * 1024 * 1024)
/**< individual assets larger than this are not cached */
#endif

#if !defined(LWS_DLO_ASSET_L1_MAX_FOOTPRINT)
#define LWS_DLO_ASSET_L1_MAX_FOOTPRINT		(8 * 1024 * 1024)
/**< max heap bytes for the in-memory level of the asset cache, when it is
 * over the file-backed level */
#endif

#if !defined(LWS_DLO_ASSET_HEAP_PAYLOAD_DIV)
#define LWS_DLO_ASSET_HEAP_PAYLOAD_DIV		4
/**< an in-memory only asset cache doesn't take assets larger than this
 * fraction of its footprint, so one big one can't push out all the rest */
#endif

#if !defined(LWS_DLO_ASSET_L1_MAX_ITEMS)
#define LWS_DLO_ASSET_L1_MAX_ITEMS		256
/**< max items in the in-memory level of the asset cache */
#endif

#if !defined(LWS_DLO_ASSET_CACHE_EXPIRY_S)
#define LWS_DLO_ASSET_CACHE_EXPIRY_S		(24 * 60 * 60)
/**< how long fetched assets stay valid in the cache, in seconds.  Set to 0
 * to keep them until the cache needs the space (LRU eviction) */
#endif

/**
 * lws_dlo_asset_cache() - get the context's document asset cache, if any
 *
 * \param cx: the lws_context
 *
 * Returns NULL if the context was created without an asset cache, else
 * the L1 cache handle of the context asset cache, for inspection or manual
 * invalidation using the lws_cache_ttl apis.  The cache belongs to the
 * context and is destroyed with it.
 */
LWS_VISIBLE LWS_EXTERN struct lws_cache_ttl_lru *
lws_dlo_asset_cache(struct lws_context *cx);

LWS_VISIBLE LWS_EXTERN lws_stateful_ret_t
lhp_displaylist_layout(struct lhp_ctx *ctx, char reason);

/*
 * These image accessor macros adapt to the image types that were built in.
 * Because they are macros, the svg arms have to be selected at compile time
 * or they would reference svg apis that were not built.
 */

#if defined(LWS_WITH_SVG) && defined(LWS_WITH_GIF)

#define lws_dlo_image_width(_u) ((_u)->failed ? -1 : \
	((_u)->type == LWSDLOSS_TYPE_JPEG ? \
		(int)lws_jpeg_get_width((_u)->u.dlo_jpeg->j) : \
	 (_u)->type == LWSDLOSS_TYPE_SVG ? \
		(int)lws_svg_get_width((_u)->u.dlo_svg->svg) : \
	 (_u)->type == LWSDLOSS_TYPE_GIF ? \
		(int)lws_gif_get_width((_u)->u.dlo_gif->gif) : \
		(int)lws_upng_get_width((_u)->u.dlo_png->png)))
#define lws_dlo_image_height(_u) ((_u)->failed ? -1 : \
	((_u)->type == LWSDLOSS_TYPE_JPEG ? \
		(int)lws_jpeg_get_height((_u)->u.dlo_jpeg->j) : \
	 (_u)->type == LWSDLOSS_TYPE_SVG ? \
		(int)lws_svg_get_height((_u)->u.dlo_svg->svg) : \
	 (_u)->type == LWSDLOSS_TYPE_GIF ? \
		(int)lws_gif_get_height((_u)->u.dlo_gif->gif) : \
		(int)lws_upng_get_height((_u)->u.dlo_png->png)))

#define lws_dlo_image_metadata_scan(_u) ((_u)->failed ? LWS_SRET_FATAL : \
	((_u)->type == LWSDLOSS_TYPE_JPEG ? \
		lws_display_dlo_jpeg_metadata_scan((_u)->u.dlo_jpeg) : \
	 (_u)->type == LWSDLOSS_TYPE_SVG ? \
		lws_display_dlo_svg_metadata_scan((_u)->u.dlo_svg) : \
	 (_u)->type == LWSDLOSS_TYPE_GIF ? \
		lws_display_dlo_gif_metadata_scan((_u)->u.dlo_gif) : \
		lws_display_dlo_png_metadata_scan((_u)->u.dlo_png)))

#elif defined(LWS_WITH_SVG)

#define lws_dlo_image_width(_u) ((_u)->failed ? -1 : \
	((_u)->type == LWSDLOSS_TYPE_JPEG ? \
		(int)lws_jpeg_get_width((_u)->u.dlo_jpeg->j) : \
	 (_u)->type == LWSDLOSS_TYPE_SVG ? \
		(int)lws_svg_get_width((_u)->u.dlo_svg->svg) : \
		(int)lws_upng_get_width((_u)->u.dlo_png->png)))
#define lws_dlo_image_height(_u) ((_u)->failed ? -1 : \
	((_u)->type == LWSDLOSS_TYPE_JPEG ? \
		(int)lws_jpeg_get_height((_u)->u.dlo_jpeg->j) : \
	 (_u)->type == LWSDLOSS_TYPE_SVG ? \
		(int)lws_svg_get_height((_u)->u.dlo_svg->svg) : \
		(int)lws_upng_get_height((_u)->u.dlo_png->png)))

#define lws_dlo_image_metadata_scan(_u) ((_u)->failed ? LWS_SRET_FATAL : \
	((_u)->type == LWSDLOSS_TYPE_JPEG ? \
		lws_display_dlo_jpeg_metadata_scan((_u)->u.dlo_jpeg) : \
	 (_u)->type == LWSDLOSS_TYPE_SVG ? \
		lws_display_dlo_svg_metadata_scan((_u)->u.dlo_svg) : \
		lws_display_dlo_png_metadata_scan((_u)->u.dlo_png)))

#elif defined(LWS_WITH_GIF)

#define lws_dlo_image_width(_u) ((_u)->failed ? -1 : \
	((_u)->type == LWSDLOSS_TYPE_JPEG ? \
		(int)lws_jpeg_get_width((_u)->u.dlo_jpeg->j) : \
	 (_u)->type == LWSDLOSS_TYPE_GIF ? \
		(int)lws_gif_get_width((_u)->u.dlo_gif->gif) : \
		(int)lws_upng_get_width((_u)->u.dlo_png->png)))
#define lws_dlo_image_height(_u) ((_u)->failed ? -1 : \
	((_u)->type == LWSDLOSS_TYPE_JPEG ? \
		(int)lws_jpeg_get_height((_u)->u.dlo_jpeg->j) : \
	 (_u)->type == LWSDLOSS_TYPE_GIF ? \
		(int)lws_gif_get_height((_u)->u.dlo_gif->gif) : \
		(int)lws_upng_get_height((_u)->u.dlo_png->png)))

#define lws_dlo_image_metadata_scan(_u) ((_u)->failed ? LWS_SRET_FATAL : \
	((_u)->type == LWSDLOSS_TYPE_JPEG ? \
		lws_display_dlo_jpeg_metadata_scan((_u)->u.dlo_jpeg) : \
	 (_u)->type == LWSDLOSS_TYPE_GIF ? \
		lws_display_dlo_gif_metadata_scan((_u)->u.dlo_gif) : \
		lws_display_dlo_png_metadata_scan((_u)->u.dlo_png)))

#else

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

#endif

/*
 * Font registry
 *
 * Register fonts (currently, psfu) to the lws_context, and select the closest
 * matching.  Used to pick fonts from whatever CSS information is available.
 */

LWS_VISIBLE LWS_EXTERN int
lws_font_register(struct lws_context *cx, const uint8_t *data, size_t data_len);

/**
 * lws_font_register_file() - register an mcufont kept in a file
 *
 * \param cx: the lws context
 * \param path: the file, opened through the context's fops
 *
 * Only the face's name and metrics stay in memory.  Its dictionary and the
 * glyph strings text needs are read in when text is set in it, and are
 * reclaimable heap occupants: they are given back when memory runs short
 * and read again when next needed.
 */
LWS_VISIBLE LWS_EXTERN int
lws_font_register_file(struct lws_context *cx, const char *path);

/**
 * lws_fonts_register_dir() - register every .mcufont in a directory
 *
 * \param cx: the lws context
 * \param dirpath: the directory to scan
 *
 * Returns the number of faces registered (0 if the directory can't be read
 * or holds none).  Needs LWS_WITH_DIR, which is off by default on esp32;
 * without it, this always returns 0 and lws_font_register_file() is the
 * way to register file-backed faces.
 */
LWS_VISIBLE LWS_EXTERN int
lws_fonts_register_dir(struct lws_context *cx, const char *dirpath);

/**
 * lws_fonts_register_manifest() - use the faces a server lists as well
 *
 * \param cx: the lws context
 * \param url: the manifest, eg "https://fonts.example.com/fonts/fonts.json"
 *
 * Fonts are a system attribute: the device keeps at least one face in flash
 * (lws_font_register()) so text can always be shown, and learns about the
 * rest from a manifest on a server, fetched once each boot when the system
 * reaches OPERATIONAL (retried until it succeeds).  The manifest is JSON,
 *
 *   {"fonts": [{ "name": "Fira Sans Condensed Bold",
 *                "path": "FiraSansCondensed-Bold", "sizes": "6-100",
 *                "height": 1200, "units_per_em": 1000,
 *                "pages": "0000-0001,0020" }, ...]}
 *
 * name being the name of the face's pages, which the chooser matches css
 * font-family against and gets the weight and style from, sizes the pixel
 * sizes the server has it at, as ascending runs of decimal sizes, and pages
 * the pages of 256 codepoints the face has glyphs on, as ascending runs of
 * hex page numbers.  At a size, the face's line height is
 * (height * size + units_per_em / 2) / units_per_em.
 *
 * The chooser takes the size of a face whose line height is closest to the
 * height it is asked for, and the first time a size is chosen, the face is
 * made at that size, with nothing of it in memory yet.  Up to 8 sizes of a
 * face are made; after that, the closest of those is used.  Each page of
 * the face at a size is its own small mcufont, fetched from
 * <path>/<size>/<page>.mcufont beside the manifest, size being decimal and
 * page four hex digits, eg FiraSansCondensed-Bold/14/0020.mcufont for the
 * codepoints from U+2000 at 14px.  The first page listed is the face's core
 * page, whose fallback glyph is shown for codepoints on pages the face
 * doesn't have.  plugins/protocol_lws_mcufonts serves a manifest and pages
 * made from .ttf files at any size as they are asked for, and
 * contrib/mcufont/fonts-manifest.cmake lays out a directory of .mcufont
 * files, each at the one size it was made, to be served statically.
 *
 * The listed faces can be chosen from as soon as the manifest has arrived.
 * A page of a face at a size is fetched when text is to be set using it, and
 * is a reclaimable heap occupant: it can be evicted when memory is short,
 * and is fetched again when needed, even several times during one render.
 * Layout and render wait for pages being fetched; if a page text needs
 * can't be had, the text is set in the closest face in flash instead.  A
 * page the server refuses (eg, 404 while it is still making it) is asked for
 * again after 20s; a server that can't be reached is left alone for 30s.
 *
 * Needs LWS_WITH_SECURE_STREAMS and a policy with the __default streamtype.
 * Returns 0 if the manifest will be fetched, or nonzero if it can't be, eg
 * if no face has been registered with lws_font_register() as the fallback.
 */
LWS_VISIBLE LWS_EXTERN int
lws_fonts_register_manifest(struct lws_context *cx, const char *url);

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

LWS_VISIBLE LWS_EXTERN_FOR_DATA const struct lws_plat_file_ops lws_dlo_fops;
#endif
