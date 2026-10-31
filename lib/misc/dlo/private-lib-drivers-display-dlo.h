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
 * A face that isn't simply in flash has a struct hung off its .priv, which
 * starts with one of these to say which kind it is
 */
enum {
	LWS_MCUF_KIND_FILE		= 1,
	LWS_MCUF_KIND_REMOTE,
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
	uint8_t			kind;		/* LWS_MCUF_KIND_FILE: first */
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

/*
 * A face listed in the font manifest, fetched whole from the server when
 * text needs it.  The blob is the unit of residency: once it has arrived it
 * is the face's .data, exactly as a flash face's is, and it is a single
 * reclaimable heap occupant.  It is pinned while layout has an element open
 * in the face, and for the duration of each render call drawing it; the
 * rest of the time it can be evicted, and is fetched again when next needed.
 * Each arrival bumps gen, since anything left pointing into an earlier copy
 * has to start again from the new one.
 */
typedef struct lws_mcufont_remote {
	uint8_t			kind;		/* LWS_MCUF_KIND_REMOTE: first */
	uint8_t			bad;		/* the server's copy is unusable */
	uint16_t		gen;		/* bumped each time it arrives */
	lws_reclaimable_t	rc;		/* the blob */
	lws_dll2_t		queue;		/* fr->queue, waiting to fetch */
	struct lws_fonts_remote	*fr;
	struct lws_context	*cx;
	lws_display_font_t	*f;
	const char		*file;		/* in the manifest lwsac */
	uint8_t			*blob;
	lws_usec_t		nomem_until;	/* couldn't make room for it */
	uint32_t		len;		/* the manifest says */
} lws_mcufont_remote_t;

static LWS_INLINE lws_mcufont_file_t *
mcuf_file(const lws_display_font_t *f)
{
	return f->priv && *f->priv == LWS_MCUF_KIND_FILE ?
				(lws_mcufont_file_t *)f->priv : NULL;
}

static LWS_INLINE lws_mcufont_remote_t *
mcuf_remote(const lws_display_font_t *f)
{
	return f->priv && *f->priv == LWS_MCUF_KIND_REMOTE ?
				(lws_mcufont_remote_t *)f->priv : NULL;
}

/* whether a face can be used now, see lws_font_resident() */

typedef enum {
	LWS_FONT_RESIDENT,
	LWS_FONT_PENDING,	/* being fetched: the waiter will be woken */
	LWS_FONT_UNAVAILABLE,	/* can't be had for now: use another face */
} lws_font_residency_t;

lws_font_residency_t
lws_font_resident(const lws_display_font_t *f, lws_font_waiter_t *w);

void
lws_font_pin(const lws_display_font_t *f);

void
lws_font_unpin(const lws_display_font_t *f);

const lws_display_font_t *
lws_font_choose_local(struct lws_context *cx, const lws_font_choice_t *hints);

int
lws_font_blob_check(const uint8_t *data, size_t data_len, const char **pname);

int
lws_font_register_common(struct lws_context *cx, lws_display_font_t *a);

void
lws_font_set_em(lws_display_font_t *a);

#if defined(LWS_DLO_REMOTE_FONTS)
/* a face from a server is here, or could be fetched now */
int
lws_mcufont_remote_available(const lws_mcufont_remote_t *r);

lws_font_residency_t
lws_mcufont_remote_resident(lws_mcufont_remote_t *r, lws_font_waiter_t *w);

void
lws_mcufont_remote_destroy(lws_display_font_t *f);

int
lws_fonts_remote_manifest_pending(struct lws_context *cx, lws_font_waiter_t *w);

void
lws_fonts_remote_too_slow(struct lws_context *cx, int manifest);

void
lws_fonts_remote_stop(struct lws_context *cx);

void
lws_fonts_remote_free(struct lws_context *cx);
#else
static LWS_INLINE int
lws_fonts_remote_manifest_pending(struct lws_context *cx, lws_font_waiter_t *w)
{
	(void)cx;
	(void)w;

	return 0;
}

static LWS_INLINE void
lws_fonts_remote_too_slow(struct lws_context *cx, int manifest)
{
	(void)cx;
	(void)manifest;
}
#endif

int
lws_display_font_mcufont_check_dict(const uint8_t *bf, size_t len);

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
lws_display_dlo_png_reclaimable(lws_dlo_png_t *dlo_png);

void
lws_display_dlo_jpeg_reclaimable(lws_dlo_jpeg_t *dlo_jpeg);

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

