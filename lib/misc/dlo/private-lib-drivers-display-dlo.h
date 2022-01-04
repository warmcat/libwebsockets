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

#define set_nyb(_line, _x, _c) \
	{ if ((_x) & 1) { _line[(_x) >> 1] &= 0xf0; _line[(_x) >> 1]  |= _c; } else \
		    { _line[(_x) >> 1] &= 0x0f; _line[(_x) >> 1] |= (uint8_t)((_c) << 4); }}

#define get_nyb(_line, _x)  ((unsigned int)(((_x) & 1) ? ((line[(_x) >> 1]) >> 4) : \
					 ((line[(_x) >> 1]) & 0xf)))

void
dist_err(const lws_colour_error_t *in, lws_colour_error_t *out, int sixteenths);

size_t
utf8_bytes(uint8_t u);

int
lws_display_font_mcufont_getcwidth(lws_dlo_text_t *text, uint32_t unicode,
				   lws_fx_t *fx);

int
lws_display_dlo_text_attach_glyphs(lws_dlo_text_t *text);

lws_stateful_ret_t
lws_display_font_mcufont_render(const struct lws_surface_info *ic,
				struct lws_dlo *dlo, const lws_box_t *origin,
				lws_display_scalar curr, uint8_t *line,
				lws_colour_error_t **nle);

lws_font_glyph_t *
lws_display_font_mcufont_image_glyph(lws_dlo_text_t *text, uint32_t unicode,
					char attach);
