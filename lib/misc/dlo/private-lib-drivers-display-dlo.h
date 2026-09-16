#if !defined(__MISC_DLO_PRIVATE_LIB_DRIVERS_DISPLAY_DLO__)
#define __MISC_DLO_PRIVATE_LIB_DRIVERS_DISPLAY_DLO__

enum {
	MCUFO_MAGIC			= 0,
	MCUFO_FLAGS_VER			= 4,
	MCUFO_FOFS_FULLNAME		= 8,
	MCUFO_FOFS_NAME			= 0xc,
	MCUFO_FOFS_DICT_DATA		= 0x10,
	MCUFO_SIZE_DICT_DATA		= 0x14,
	MCUFO_FOFS_DICT_OFS		= 0x18,
	MCUFO_COUNT_RLE_DICT		= 0x1C,
	MCUFO_COUNT_REF_RLE_DICT	= 0x20,
	MCUFO_FOFS_CHAR_RANGE_TABLES	= 0x24,
	MCUFO_COUNT_CHAR_RANGE_TABLES	= 0x28,
	MCUFO_UNICODE_FALLBACK		= 0x2C,

	MCUFO16_WIDTH			= 0x30,
	MCUFO16_HEIGHT			= 0x32,
	MCUFO16_MIN_X_ADV		= 0x34,
	MCUFO16_MAX_X_ADV		= 0x36,
	MCUFO16_BASELINE_X		= 0x38,
	MCUFO16_BASELINE_Y		= 0x3a,
	MCUFO16_LINE_HEIGHT		= 0x3c,

	MCUFO_HDR_LEN			= 0x40,
	MCUFO_MAX_RANGES		= 8,
};

/*
 * A glyph's compressed string, cached from a file-backed font.  Pinned while
 * a text dlo has it attached (its decoder keeps a pointer into data)
 */
typedef struct mcuf_gent {
	lws_dll2_t		list;	/* lws_mcufont_file_t.glyphs, MRU at tail */
	uint32_t		fofs;	/* file offset: the cache key */
	uint16_t		len;
	uint16_t		pins;
	/* len bytes follow */
} mcuf_gent_t;

/*
 * The resident state of a file-backed mcufont, hung off lws_display_font_t
 * .priv.  The "core" is the part every glyph decode needs: the file's
 * prefix (header, names, dictionary and its offsets, so the decoder's
 * absolute offsets into the blob stay valid), plus copies of the char range
 * tables and each range's glyph offset table.  The glyph strings come and
 * go through the cache.  Both are reclaimable heap occupants.
 */
typedef struct lws_mcufont_file {
	lws_reclaimable_t	rc_core;
	lws_reclaimable_t	rc_glyphs;
	struct lws_context	*cx;
	lws_display_font_t	*f;
	char			*path;

	uint8_t			*prefix;
	uint8_t			*ranges;	/* 16 * nranges */
	uint16_t		*gofs[MCUFO_MAX_RANGES];
	uint32_t		gend[MCUFO_MAX_RANGES]; /* end of each range's data */
	lws_fop_fd_t		fd;		/* open while the core is */

	lws_dll2_owner_t	glyphs;		/* mcuf_gent_t */
	size_t			glyph_bytes;

	uint32_t		file_len;
	uint32_t		prefix_len;
	uint16_t		nranges;
	uint16_t		core_pins;
} lws_mcufont_file_t;

int
lws_display_font_mcufont_file_core(lws_display_font_t *f);

size_t
mcuf_file_core_evict_cb(lws_reclaimable_t *r);

size_t
mcuf_file_glyphs_evict_cb(lws_reclaimable_t *r);

void
lws_display_font_mcufont_file_destroy(lws_display_font_t *f);

void
lws_display_font_mcufont_release_glyphs(lws_dlo_text_t *text);

void
dist_err_floyd_steinberg_grey(int n, int width, lws_greyscale_error_t *gedl_this,
			      lws_greyscale_error_t *gedl_next);

void
dist_err_floyd_steinberg_col(int n, int width, lws_colour_error_t *edl_this,
			     lws_colour_error_t *edl_next);

int
lws_display_alloc_diffusion(const lws_surface_info_t *ic, lws_surface_error_t **se);

size_t
utf8_bytes(uint8_t u);

int
lws_display_font_mcufont_getcwidth(lws_dlo_text_t *text, uint32_t unicode,
				   lws_fx_t *fx);

int
lws_display_dlo_text_attach_glyphs(lws_dlo_text_t *text);

lws_stateful_ret_t
lws_display_font_mcufont_render(struct lws_display_render_state *rs);

lws_font_glyph_t *
lws_display_font_mcufont_image_glyph(lws_dlo_text_t *text, uint32_t unicode,
					char attach);

void
lws_lhp_ss_html_parse_from_lhp(lhp_ctx_t *lhp);

void
lws_lhp_image_dimensions_cb(lws_sorted_usec_list_t *sul);

int
lws_dlo_ss_stop_any_active(struct lws_context *cx);

#endif

