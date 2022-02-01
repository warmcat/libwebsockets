/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2022 Andy Green <andy@warmcat.com>
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
 * Extremely Lightweight HTML5 Stream Parser, same approach as lecp but for
 * html5.
 */

#if !defined(LHP_MAX_ELEMS_NEST)
#define LHP_MAX_ELEMS_NEST		32
#endif
#if !defined(LHP_MAX_DEPTH)
#define LHP_MAX_DEPTH			12
#endif
#if !defined(LHP_STRING_CHUNK)
#define LHP_STRING_CHUNK		254
#endif

enum lhp_callbacks {

	LHPCB_ERR_ATTRIB_SYNTAX		= -5,
	LHPCB_ERR_ATTRIB_LEN		= -4,
	LHPCB_ERR_OOM			= -3,
	LHPCB_ERR_ELEM_DEPTH		= -2,
	LHPCB_CONTINUE			= -1,

	LHPCB_CONSTRUCTED		= 0,
	LHPCB_DESTRUCTED		= 1,

	LHPCB_COMPLETE			= 2,
	LHPCB_FAILED			= 3,

	LHPCB_ELEMENT_START		= 4,	/* reported at end of <> */
	LHPCB_ELEMENT_END		= 5,

	LHPCB_CONTENT			= 6,

	LHPCB_COMMENT			= 7,
};

/*
 * CSS v2.1 full property set, taken from
 *
 * https://www.w3.org/TR/CSS21/propidx.html
 */

typedef enum lcsp_props {
	LCSP_PROP_AZIMUTH,
	LCSP_PROP_BACKGROUND_ATTACHMENT,
	LCSP_PROP_BACKGROUND_COLOR,
	LCSP_PROP_BACKGROUND_IMAGE,
	LCSP_PROP_BACKGROUND_POSITION,
	LCSP_PROP_BACKGROUND_REPEAT,
	LCSP_PROP_BACKGROUND,
	LCSP_PROP_BORDER_COLLAPSE,
	LCSP_PROP_BORDER_COLOR,
	LCSP_PROP_BORDER_SPACING,
	LCSP_PROP_BORDER_STYLE,
	LCSP_PROP_BORDER_TOP,
	LCSP_PROP_BORDER_RIGHT,
	LCSP_PROP_BORDER_BOTTOM,
	LCSP_PROP_BORDER_LEFT,
	LCSP_PROP_BORDER_TOP_COLOR,
	LCSP_PROP_BORDER_RIGHT_COLOR,
	LCSP_PROP_BORDER_BOTTOM_COLOR,
	LCSP_PROP_BORDER_LEFT_COLOR,
	LCSP_PROP_BORDER_TOP_STYLE,
	LCSP_PROP_BORDER_RIGHT_STYLE,
	LCSP_PROP_BORDER_BOTTOM_STYLE,
	LCSP_PROP_BORDER_LEFT_STYLE,
	LCSP_PROP_BORDER_TOP_WIDTH,
	LCSP_PROP_BORDER_RIGHT_WIDTH,
	LCSP_PROP_BORDER_BOTTOM_WIDTH,
	LCSP_PROP_BORDER_LEFT_WIDTH,
	LCSP_PROP_BORDER_WIDTH,
	LCSP_PROP_BORDER_TOP_LEFT_RADIUS,
	LCSP_PROP_BORDER_TOP_RIGHT_RADIUS,
	LCSP_PROP_BORDER_BOTTOM_LEFT_RADIUS,
	LCSP_PROP_BORDER_BOTTOM_RIGHT_RADIUS,
	LCSP_PROP_BORDER_RADIUS,
	LCSP_PROP_BORDER,
	LCSP_PROP_BOTTOM,
	LCSP_PROP_CAPTION_SIDE,
	LCSP_PROP_CLEAR,
	LCSP_PROP_CLIP,
	LCSP_PROP_COLOR,
	LCSP_PROP_CONTENT,
	LCSP_PROP_COUNTER_INCREMENT,
	LCSP_PROP_COUNTER_RESET,
	LCSP_PROP_CUE_AFTER,
	LCSP_PROP_CUE_BEFORE,
	LCSP_PROP_CUE,
	LCSP_PROP_CURSOR,
	LCSP_PROP_DIRECTION,
	LCSP_PROP_DISPLAY,
	LCSP_PROP_ELEVATION,
	LCSP_PROP_EMPTY_CELLS,
	LCSP_PROP_FLOAT,
	LCSP_PROP_FONT_FAMILY,
	LCSP_PROP_FONT_SIZE,
	LCSP_PROP_FONT_STYLE,
	LCSP_PROP_FONT_VARAIANT,
	LCSP_PROP_FONT_WEIGHT,
	LCSP_PROP_FONT,
	LCSP_PROP_HEIGHT,
	LCSP_PROP_LEFT,
	LCSP_PROP_LETTER_SPACING,
	LCSP_PROP_LINE_HEIGHT,
	LCSP_PROP_LIST_STYLE_IMAGE,
	LCSP_PROP_LIST_STYLE_POSITION,
	LCSP_PROP_LIST_STYLE_TYPE,
	LCSP_PROP_LIST_STYLE,
	LCSP_PROP_MARGIN_RIGHT,
	LCSP_PROP_MARGIN_LEFT,
	LCSP_PROP_MARGIN_TOP,
	LCSP_PROP_MARGIN_BOTTOM,
	LCSP_PROP_MARGIN,
	LCSP_PROP_MAX_HEIGHT,
	LCSP_PROP_MAX_WIDTH,
	LCSP_PROP_MIN_HEIGHT,
	LCSP_PROP_MIN_WIDTH,
	LCSP_PROP_ORPHANS,
	LCSP_PROP_OUTLINE_COLOR,
	LCSP_PROP_OUTLINE_STYLE,
	LCSP_PROP_OUTLINE_WIDTH,
	LCSP_PROP_OUTLINE,
	LCSP_PROP_OVERFLOW,
	LCSP_PROP_PADDING_TOP,
	LCSP_PROP_PADDING_RIGHT,
	LCSP_PROP_PADDING_BOTTOM,
	LCSP_PROP_PADDING_LEFT,
	LCSP_PROP_PADDING,
	LCSP_PROP_PAGE_BREAK_AFTER,
	LCSP_PROP_PAGE_BREAK_BEFORE,
	LCSP_PROP_PAGE_BREAK_INSIDE,
	LCSP_PROP_PAUSE_AFTER,
	LCSP_PROP_PAUSE_BEFORE,
	LCSP_PROP_PAUSE,
	LCSP_PROP_PITCH_RANGE,
	LCSP_PROP_PITCH,
	LCSP_PROP_PLAY_DURING,
	LCSP_PROP_POSITION,
	LCSP_PROP_QUOTES,
	LCSP_PROP_RICHNESS,
	LCSP_PROP_RIGHT,
	LCSP_PROP_SPEAK_HEADER,
	LCSP_PROP_SPEAK_NUMERAL,
	LCSP_PROP_SPEAK_PUNCTUATION,
	LCSP_PROP_SPEAK,
	LCSP_PROP_SPEECH_RATE,
	LCSP_PROP_STRESS,
	LCSP_PROP_TABLE_LAYOUT,
	LCSP_PROP_TEXT_ALIGN,
	LCSP_PROP_TEXT_DECORATION,
	LCSP_PROP_TEXT_INDENT,
	LCSP_PROP_TEXT_TRANSFORM,
	LCSP_PROP_TOP,
	LCSP_PROP_UNICODE_BIDI,
	LCSP_PROP_VERTICAL_ALIGN,
	LCSP_PROP_VISIBILITY,
	LCSP_PROP_VOICE_FAMILY,
	LCSP_PROP_VOLUME,
	LCSP_PROP_WHITE_SPACE,
	LCSP_PROP_WIDOWS,
	LCSP_PROP_WIDTH,
	LCSP_PROP_WORD_SPACING,
	LCSP_PROP_Z_INDEX,

	LCSP_PROP__COUNT /* always last */
} lcsp_props_t;

/*
 * Indexes for the well-known property values
 */

typedef enum {
	LCSP_PROPVAL_ABOVE,
	LCSP_PROPVAL_ABSOLUTE,
	LCSP_PROPVAL_ALWAYS,
	LCSP_PROPVAL_ARMENIAN,
	LCSP_PROPVAL_AUTO,
	LCSP_PROPVAL_AVOID,
	LCSP_PROPVAL_BASELINE,
	LCSP_PROPVAL_BEHIND,
	LCSP_PROPVAL_BELOW,
	LCSP_PROPVAL_BIDI_OVERRIDE,
	LCSP_PROPVAL_BLINK,
	LCSP_PROPVAL_BLOCK,
	LCSP_PROPVAL_BOLD,
	LCSP_PROPVAL_BOLDER,
	LCSP_PROPVAL_BOTH,
	LCSP_PROPVAL_BOTTOM,
	LCSP_PROPVAL_CAPITALIZE,
	LCSP_PROPVAL_CAPTION,
	LCSP_PROPVAL_CENTER,
	LCSP_PROPVAL_CIRCLE,
	LCSP_PROPVAL_CLOSE_QUOTE,
	LCSP_PROPVAL_CODE,
	LCSP_PROPVAL_COLLAPSE,
	LCSP_PROPVAL_CONTINUOUS,
	LCSP_PROPVAL_CROSSHAIR,
	LCSP_PROPVAL_DECIMAL_LEADING_ZERO,
	LCSP_PROPVAL_DECIMAL,
	LCSP_PROPVAL_DIGITS,
	LCSP_PROPVAL_DISC,
	LCSP_PROPVAL_EMBED,
	LCSP_PROPVAL_E_RESIZE,
	LCSP_PROPVAL_FIXED,
	LCSP_PROPVAL_GEORGIAN,
	LCSP_PROPVAL_HELP,
	LCSP_PROPVAL_HIDDEN,
	LCSP_PROPVAL_HIDE,
	LCSP_PROPVAL_HIGH,
	LCSP_PROPVAL_HIGHER,
	LCSP_PROPVAL_ICON,
	LCSP_PROPVAL_INHERIT,
	LCSP_PROPVAL_INLINE,
	LCSP_PROPVAL_INLINE_BLOCK,
	LCSP_PROPVAL_INLINE_TABLE,
	LCSP_PROPVAL_INVERT,
	LCSP_PROPVAL_ITALIC,
	LCSP_PROPVAL_JUSTIFY,
	LCSP_PROPVAL_LEFT,
	LCSP_PROPVAL_LIGHTER,
	LCSP_PROPVAL_LINE_THROUGH,
	LCSP_PROPVAL_LIST_ITEM,
	LCSP_PROPVAL_LOW,
	LCSP_PROPVAL_LOWER,
	LCSP_PROPVAL_LOWER_ALPHA,
	LCSP_PROPVAL_LOWERCASE,
	LCSP_PROPVAL_LOWER_GREEK,
	LCSP_PROPVAL_LOWER_LATIN,
	LCSP_PROPVAL_LOWER_ROMAN,
	LCSP_PROPVAL_LTR,
	LCSP_PROPVAL_MENU,
	LCSP_PROPVAL_MESSAGE_BOX,
	LCSP_PROPVAL_MIDDLE,
	LCSP_PROPVAL_MIX,
	LCSP_PROPVAL_MOVE,
	LCSP_PROPVAL_NE_RESIZE,
	LCSP_PROPVAL_NO_CLOSE_QUOTE,
	LCSP_PROPVAL_NONE,
	LCSP_PROPVAL_NO_OPEN_QUOTE,
	LCSP_PROPVAL_NO_REPEAT,
	LCSP_PROPVAL_NORMAL,
	LCSP_PROPVAL_NOWRAP,
	LCSP_PROPVAL_N_RESIZE,
	LCSP_PROPVAL_NW_RESIZE,
	LCSP_PROPVAL_OBLIQUE,
	LCSP_PROPVAL_ONCE,
	LCSP_PROPVAL_OPEN_QUOTE,
	LCSP_PROPVAL_OUTSIDE,
	LCSP_PROPVAL_OVERLINE,
	LCSP_PROPVAL_POINTER,
	LCSP_PROPVAL_PRE,
	LCSP_PROPVAL_PRE_LINE,
	LCSP_PROPVAL_PRE_WRAP,
	LCSP_PROPVAL_PROGRESS,
	LCSP_PROPVAL_RELATIVE,
	LCSP_PROPVAL_REPEAT,
	LCSP_PROPVAL_REPEAT_X,
	LCSP_PROPVAL_REPEAT_Y,
	LCSP_PROPVAL_RIGHT,
	LCSP_PROPVAL_RTL,
	LCSP_PROPVAL_SCROLL,
	LCSP_PROPVAL_SEPARATE,
	LCSP_PROPVAL_SE_RESIZE,
	LCSP_PROPVAL_SHOW,
	LCSP_PROPVAL_SILENT,
	LCSP_PROPVAL_SMALL_CAPS,
	LCSP_PROPVAL_SMALL_CAPTION,
	LCSP_PROPVAL_SPELL_OUT,
	LCSP_PROPVAL_SQUARE,
	LCSP_PROPVAL_S_RESIZE,
	LCSP_PROPVAL_STATIC,
	LCSP_PROPVAL_STATUS_BAR,
	LCSP_PROPVAL_SUB,
	LCSP_PROPVAL_SUPER,
	LCSP_PROPVAL_SW_RESIZE,
	LCSP_PROPVAL_TABLE,
	LCSP_PROPVAL_TABLE_CAPTION,
	LCSP_PROPVAL_TABLE_CELL,
	LCSP_PROPVAL_TABLE_COLUMN,
	LCSP_PROPVAL_TABLE_COLUMN_GROUP,
	LCSP_PROPVAL_TABLE_FOOTER_GROUP,
	LCSP_PROPVAL_TABLE_HEADER_GROUP,
	LCSP_PROPVAL_TABLE_ROW,
	LCSP_PROPVAL_TABLE_ROW_GROUP,
	LCSP_PROPVAL_TEXT_BOTTOM,
	LCSP_PROPVAL_TEXT_TOP,
	LCSP_PROPVAL_TEXT,
	LCSP_PROPVAL_TOP,
	LCSP_PROPVAL_TRANSPARENT,
	LCSP_PROPVAL_UNDERLINE,
	LCSP_PROPVAL_UPPER_ALPHA,
	LCSP_PROPVAL_UPPERCASE,
	LCSP_PROPVAL_UPPER_LATIN,
	LCSP_PROPVAL_UPPER_ROMAN,
	LCSP_PROPVAL_VISIBLE,
	LCSP_PROPVAL_WAIT,
	LCSP_PROPVAL_W_RESIZE,

	LCSP_PROPVAL__COUNT /* always last */
} lcsp_propvals_t;

struct lhp_ctx;
typedef lws_stateful_ret_t (*lhp_callback)(struct lhp_ctx *ctx, char reason);

/* html attribute */

typedef struct lhp_atr {
	lws_dll2_t		list;
	size_t			name_len;	/* 0 if it is elem tag */
	size_t			value_len;

	/* name+NUL then value+NUL follow */
} lhp_atr_t;

/*
 * In order to lay out the table, we have to incrementally adjust all foregoing
 * DLOs as newer cells change the situation.  So we have to keep track of all
 * cell DLOs in a stack of tables until it's all done.
 */

typedef struct {
	lws_dll2_t			list; /* ps->table_cols */

	lws_dll2_owner_t		row_dlos; /* lws_dlo_t in column */

	lws_fx_t			height; /* currently computed row height */
} lhp_table_row_t;

typedef struct {
	lws_dll2_t			list; /* ps->table_cols */

	lws_dll2_owner_t		col_dlos; /* lws_dlo_t in column */

	lws_fx_t			width; /* currently computed column width */
} lhp_table_col_t;

struct lcsp_atr;

#define CCPAS_TOP 0
#define CCPAS_RIGHT 1
#define CCPAS_BOTTOM 2
#define CCPAS_LEFT 3

typedef struct lhp_pstack {
	lws_dll2_t			list;
	void				*user;	/* private to the stack level */
	lhp_callback			cb;

	/* static: x,y: offset from parent, w,h: surface size of this object */
	lws_box_t			drt;

	/* dynamic cursor inside drt for progressive child placement */
	lws_fx_t			curx;
	lws_fx_t			cury;
	lws_fx_t			widest;
	lws_fx_t			deepest;

	lws_dlo_t			*dlo_set_curx;
	lws_dlo_t			*dlo_set_cury;

	lws_dll2_owner_t		atr; /* lhp_atr_t */

	const lws_display_font_t	*f;

	const struct lcsp_atr		*css_background_color;
	const struct lcsp_atr		*css_color;

	const struct lcsp_atr		*css_position;
	const struct lcsp_atr		*css_display;
	const struct lcsp_atr		*css_width;
	const struct lcsp_atr		*css_height;

	const struct lcsp_atr		*css_border_radius[4];

	const struct lcsp_atr		*css_pos[4];
	const struct lcsp_atr		*css_margin[4];
	const struct lcsp_atr		*css_padding[4];

	uint16_t			tr_idx; /* in table */
	uint16_t			td_idx; /* in current tr */

	uint8_t				is_block:1; /* children use space in our drt */
	uint8_t				is_table:1;

	/* user layout owns these after initial values set */

	lws_dlo_t			*dlo;
	const lws_display_font_t	*font;
	int				oi[4];
	int				positioned[4];
	int				rel_layout_cursor[4];
	uint8_t				runon; /* continues same line */

} lhp_pstack_t;

typedef enum lcsp_css_units {
	LCSP_UNIT_NONE,

	LCSP_UNIT_NUM,			/* u.i */

	LCSP_UNIT_LENGTH_EM,		/* u.i */
	LCSP_UNIT_LENGTH_EX,		/* u.i */
	LCSP_UNIT_LENGTH_IN,		/* u.i */
	LCSP_UNIT_LENGTH_CM,		/* u.i */
	LCSP_UNIT_LENGTH_MM,		/* u.i */
	LCSP_UNIT_LENGTH_PT,		/* u.i */
	LCSP_UNIT_LENGTH_PC,		/* u.i */
	LCSP_UNIT_LENGTH_PX,		/* u.i */
	LCSP_UNIT_LENGTH_PERCENT,	/* u.i */

	LCSP_UNIT_ANGLE_ABS_DEG,	/* u.i */
	LCSP_UNIT_ANGLE_REL_DEG,	/* u.i */

	LCSP_UNIT_FREQ_HZ,		/* u.i */

	LCSP_UNIT_RGBA,			/* u.rgba */

	LCSP_UNIT_URL,			/* string at end of atr */
	LCSP_UNIT_STRING,		/* string at end of atr */
	LCSP_UNIT_DATA,			/* binary data at end of atr */

} lcsp_css_units_t;

typedef struct lcsp_atr {
	lws_dll2_t		list;

	int			propval; /* lcsp_propvals_t LCSP_PROPVAL_ */

	size_t			value_len;	/* for string . url */
	lcsp_css_units_t	unit;

	union {
		lws_fx_t	i;
		uint32_t 	rgba;	/* for colours */
	} u;

	lws_fx_t		r;

	uint8_t			op;

	/* .value_len bytes follow (for strings and blobs) */
} lcsp_atr_t;

/* css definitions like font-weight:  */
typedef struct lcsp_defs {
	lws_dll2_t		list;
	lws_dll2_owner_t	atrs;		/* lcsp_atr_t */
	lcsp_props_t		prop;		/* lcsp_props_t, LCSP_PROP_* */
} lcsp_defs_t;

typedef struct lcsp_names {
	lws_dll2_t		list;
	size_t			name_len;

	/* name + NUL follow */
} lcsp_names_t;

typedef struct lcsp_stanza { /* css stanza, with names and defs */
	lws_dll2_t		list;

	lws_dll2_owner_t	names; /* lcsp_names_t */
	lws_dll2_owner_t	defs; /* lcsp_defs_t */

} lcsp_stanza_t;

/*
 * A list of stanza references can easily have to bring in the same stanza
 * multiple times, eg, <div><span class=x><div> won't work unless the div
 * stanzas are listed twice at different places in the list.  It means we can't
 * use dll2 directly since the number of references is open-ended.
 *
 * lcsp_stanza_ptr provides indirection that allows multiple listings.
 */

typedef struct lcsp_stanza_ptr {
	lws_dll2_t		list;

	lcsp_stanza_t		*stz;
} lcsp_stanza_ptr_t;

typedef struct lcsp_atr_ptr {
	lws_dll2_t		list;

	lcsp_atr_t		*atr;
} lcsp_atr_ptr_t;

#define LHP_FLAG_DOCUMENT_END					(1 << 0)

typedef struct lhp_ctx {
	lws_dll2_owner_t	stack; /* lhp_pstack_t */

	struct lwsac		*cssac; /* css allocations all in an ac */
	struct lwsac		*cascadeac; /* active_stanzas ac */
	struct lwsac		*propatrac; /* prop atr query results ac */
	lws_dll2_owner_t	css; /* lcsp_stanza_t (all in ac) */

	lws_dll2_owner_t	*ids;

	lws_fx_t		tf;
	lcsp_css_units_t	unit;
	lcsp_stanza_t		*stz; /* current stanza getting properties */
	lcsp_defs_t		*def; /* current property getting values */

	lws_dll2_owner_t	active_stanzas; /* lcsp_stanza_ptr_t allocated
						 * in cascadeac */
	lws_dll2_owner_t	active_atr; /* lcsp_atr_ptr_t allocated in
					     * propatrac */

	lws_surface_info_t	ic;

	const char		*base_url; /* strdup of https://x.com/y.html */
	sul_cb_t		ssevcb; /* callback for ss events */
	lws_sorted_usec_list_t	*ssevsul; /* sul to use to resume rz */
	sul_cb_t		sshtmlevcb; /* callback for more html parse */
	lws_sorted_usec_list_t	*sshtmlevsul; /* sul for more html parse */

	void			*user;
	void			*user1;
	const char		*tag; /* private */
	size_t			tag_len; /* private */

	int			npos;
	int			state; /* private */
	int			state_css_comm; /* private */
	int			nl_temp;
	int			temp_count;

	uint32_t		flags;
	uint32_t		temp;
	int32_t			window; /* 0, or ss item flow control limit */

	union {
		uint32_t	s;
		struct {
			uint32_t	first:1;
			uint32_t	closing:1;
			uint32_t	void_element:1;
			uint32_t	doctype:1;
			uint32_t	inq:1;
			uint32_t	tag_used:1;
			uint32_t	arg:1;
			uint32_t	default_css:1;
#define LHP_CSS_PROPVAL_INT_WHOLE	1
#define LHP_CSS_PROPVAL_INT_FRAC	2
#define LHP_CSS_PROPVAL_INT_UNIT	3
			uint32_t	integer:2;
			uint32_t	color:2;
		} f;
	} u;

	int			prop; /* lcsp_props_t */
	int			propval; /* lcsp_propvals_t */
	int16_t			css_state; /* private */
	int16_t			cssval_state; /* private */

	uint8_t			in_body:1;
	uint8_t			finish_css:1;
	uint8_t			is_css:1;
	uint8_t			await_css_done:1;

	/* at end so we can memset members above it in one go */

	char			buf[LHP_STRING_CHUNK + 1];

} lhp_ctx_t;

/*
 * lws_lhp_construct() - Construct an lhp context
 *
 * \param ctx: the lhp context to prepare
 * \param cb: the stream parsing callback
 * \param user: opaque user pointer available from the lhp context
 * \param ic: struct with arguments for lhp context
 *
 * The lhp context is allocated by the caller (the size is known).
 * Prepares an lhp context to parse html.  Returns 0 for OK, or nonzero if OOM.
 */
LWS_VISIBLE LWS_EXTERN int
lws_lhp_construct(lhp_ctx_t *ctx, lhp_callback cb, void *user,
		  const lws_surface_info_t *ic);

/*
 * lws_lhp_destruct() - Destroy an lhp context
 *
 * \param ctx: the lhp context to prepare
 *
 * Destroys an lhp context.  The lhp context is allocated by the caller (the
 * size is known).  But there are suballocations that must be destroyed with
 * this.
 */
LWS_VISIBLE LWS_EXTERN void
lws_lhp_destruct(lhp_ctx_t *ctx);

/**
 * lws_lhp_ss_browse() - browse url using SS and parse via lhp to DLOs
 *
 * \param cx: the lws_context
 * \param rs: the user's render state object
 * \param url: the https://x.com/y.xyz URL to browse
 * \param render: the user's linewise render callback (called from \p rs.sul)
 *
 * High level network fetch via SS and render html via lhp / DLO
 *
 * rs->ic must be prepared before calling.
 *
 * Returns nonzero if an early, fatal problem, else returns 0 and  continues
 * asynchronously.
 *
 * If rs->box is (0,0,0,0) on entry, it is set to represent the whole display
 * surface.  Otherwise if not representing the whole display surface, it
 * indicates partial mode should be used.
 */
LWS_VISIBLE LWS_EXTERN int
lws_lhp_ss_browse(struct lws_context *cx, lws_display_render_state_t *rs,
		  const char *url, sul_cb_t render);

/**
 * lws_lhp_parse() - parses a chunk of input HTML
 *
 * \p ctx: the parsing context
 * \p buf: pointer to the start of the chunk of html
 * \p len: pointer the number of bytes of html available at *\pbuf
 *
 * Parses up to *len bytes at *buf.  On exit, *buf and *len are adjusted
 * according to how much data was used.  May return before processing all the
 * input.
 *
 * Returns LWS_SRET_WANT_INPUT if the parsing is stalled on some other async
 * event (eg, fetch of image to find out the dimensions).
 *
 * The lws_lhp_ss_browse() api wraps this.
 */
LWS_VISIBLE LWS_EXTERN lws_stateful_ret_t
lws_lhp_parse(lhp_ctx_t *ctx, const uint8_t **buf, size_t *len);

/**
 * lws_css_cascade_get_prop_atr() - create active css atr list for property
 *
 * \p ctx: the parsing context
 * \p prop: the LCSP_PROP_ property to generate the attribute list for
 *
 * Returns NULL if no atr or OOM.
 *
 * Otherwise produces a list of active CSS property attributes walkable via
 * ctx->active_atr, and returns the tail one.  For simple attributes where the
 * last definition is the active one, this points to the last definition.
 */
LWS_VISIBLE LWS_EXTERN const lcsp_atr_t *
lws_css_cascade_get_prop_atr(lhp_ctx_t *ctx, lcsp_props_t prop);

/**
 * lws_http_rel_to_url() - make absolute url from base and relative
 *
 * \param dest: place to store the result
 * \param len: max length of result including NUL
 * \param base: a reference url including a file part
 * \param rel: the absolute or relative url or path to apply to base
 *
 * Copy the url formof rel into dest, using base to fill in missing context
 *
 * If base is https://x.com/y/z.html
 *
 *   a.html               -> https://x.com/y/a/html
 *   ../b.html            -> https://x.com/b.html
 *   /c.html              -> https://x.com/c.html
 *   https://y.com/a.html -> https://y.com/a.html
 */
LWS_VISIBLE LWS_EXTERN int
lws_http_rel_to_url(char *dest, size_t len, const char *base, const char *rel);

LWS_VISIBLE LWS_EXTERN lhp_pstack_t *
lws_css_get_parent_block(lhp_ctx_t *ctx, lhp_pstack_t *ps);

LWS_VISIBLE LWS_EXTERN const char *
lws_css_pstack_name(lhp_pstack_t *ps);

LWS_VISIBLE LWS_EXTERN const char *
lws_html_get_atr(lhp_pstack_t *ps, const char *aname, size_t aname_len);

LWS_VISIBLE LWS_EXTERN const lws_fx_t *
lws_csp_px(const lcsp_atr_t *a, lhp_pstack_t *ps);

LWS_VISIBLE LWS_EXTERN void
lws_lhp_tag_dlo_id(lhp_ctx_t *ctx, lhp_pstack_t *ps, lws_dlo_t *dlo);

void
lhp_set_dlo_padding_margin(lhp_pstack_t *ps, lws_dlo_t *dlo);

#define LWS_LHPREF_WIDTH		0
#define LWS_LHPREF_HEIGHT		1
#define LWS_LHPREF_NONE			2

LWS_VISIBLE LWS_EXTERN int
lhp_prop_axis(const lcsp_atr_t *a);
