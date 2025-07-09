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
};

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

#endif

