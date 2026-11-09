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
	MCUFO_KERN_BANDS		= 0x3e,
	MCUFO_KERN_GAP			= 0x3f,

	MCUFO_HDR_LEN			= 0x40,
	MCUFO_MAX_RANGES		= 8,

	MCUFO_VERSION			= 6,
	MCUFO_MAX_KERN_BANDS		= 64,
	MCUFO_NO_INK			= 0xff,
	MCUFO_KERN_ESCAPE		= 0x88,
};

/*
 * What layout needs to know about a glyph to place it: its advance, and the
 * kerning profile from its string, unpacked and copied out, so it stays valid
 * however the font's cache moves while the next glyph is looked up
 */

typedef struct lws_glyph_metrics {
	lws_fx_t		adv;
	uint8_t			first; /* inked bands, or MCUFO_NO_INK */
	uint8_t			last;
	uint8_t			gap;  /* the font's target gap */
	uint8_t			blx;  /* the columns' origin: BASELINE_X */
	uint8_t			valid;
	uint8_t			l[MCUFO_MAX_KERN_BANDS];
	uint8_t			r[MCUFO_MAX_KERN_BANDS];
} lws_glyph_metrics_t;

/*
 * A face that isn't simply in flash has a struct hung off its .priv, which
 * starts with one of these to say which kind it is
 */
enum {
	LWS_MCUF_KIND_FILE		= 1,
	LWS_MCUF_KIND_REMOTE,
	LWS_MCUF_KIND_FAMILY,
};

/*
 * A glyph's compressed string, cached from a blob that isn't in memory in one
 * piece.  Pinned while a text dlo has it attached (its decoder keeps a pointer
 * into data)
 */
typedef struct mcuf_gent {
	lws_dll2_t		list;	/* lws_mcuf_core_t.glyphs, MRU at tail */
	uint32_t		fofs;	/* blob offset: the cache key */
	uint16_t		len;
	uint16_t		pins;
	/* len bytes follow */
} mcuf_gent_t;

/*
 * The part of an mcufont blob that every glyph decode needs, for a blob that
 * isn't simply all in one piece in memory: the blob's prefix (header, names,
 * dictionary and its offsets, so the decoder's absolute offsets into the
 * blob stay valid), plus copies of the char range tables and each range's
 * glyph offset table.  The glyph strings are read from the rest of the blob
 * when they are needed, through read, and kept in the glyph cache.  If the
 * rest of the blob is in memory, but in pieces, at gives a glyph string in
 * place when it is all in one piece: only those that span two pieces are
 * copied into the cache.
 */
typedef struct lws_mcuf_core lws_mcuf_core_t;

/* read len bytes of the blob at ofs into buf: nonzero if it can't */
typedef int (*lws_mcuf_core_read_t)(lws_mcuf_core_t *c, uint32_t ofs,
				    uint8_t *buf, uint32_t len);

/* the byte of the blob at ofs in memory, and how many follow it there */
typedef const uint8_t *(*lws_mcuf_core_at_t)(lws_mcuf_core_t *c, uint32_t ofs,
					     size_t *avail);

struct lws_mcuf_core {
	lws_mcuf_core_read_t	read;
	lws_mcuf_core_at_t	at;		/* NULL: all glyphs are read */

	/*
	 * the heap occupant that the glyph cache is counted in, as
	 * rc_glyphs_base and the glyph cache's bytes
	 */
	lws_reclaimable_t	*rc_glyphs;
	size_t			rc_glyphs_base;

	uint8_t			*prefix;
	uint8_t			*ranges;	/* 16 * nranges */
	uint16_t		*gofs[MCUFO_MAX_RANGES];
	uint32_t		gend[MCUFO_MAX_RANGES]; /* end of each range's data */

	lws_dll2_owner_t	glyphs;		/* mcuf_gent_t */
	size_t			glyph_bytes;

	size_t			core_bytes;	/* prefix and tables */
	uint32_t		blob_len;
	uint32_t		prefix_len;
	uint16_t		nranges;
};

/*
 * The resident state of a file-backed mcufont, hung off lws_display_font_t
 * .priv.  The core and the glyph strings in its cache are both reclaimable
 * heap occupants: the core comes and goes with the file open.
 */
typedef struct lws_mcufont_file {
	uint8_t			kind;		/* LWS_MCUF_KIND_FILE: first */
	lws_reclaimable_t	rc_core;
	lws_reclaimable_t	rc_glyphs;
	struct lws_context	*cx;
	lws_display_font_t	*f;
	char			*path;

	lws_mcuf_core_t		core;
	lws_fop_fd_t		fd;		/* open while the core is */

	uint16_t		core_pins;
} lws_mcufont_file_t;

/*
 * Faces from a server come a page at a time: the glyphs for the 256
 * codepoints from page * 256, fetched when text needs one of them.  Each
 * page is a whole mcufont, sharing the face's height, baseline, line height
 * and kerning gap so text set from several pages lines up and kerns as one
 * face, and is a reclaimable heap occupant of its own.  A page that can be
 * evicted is fetched again when next needed.  A page is never in one piece:
 * it stays in the pieces it was collected in, with a core of its own, so it
 * doesn't need a block of the heap its own size.
 */
typedef struct lws_mcufont_page {
	lws_reclaimable_t	rc;		/* bl, core and its glyph cache */
	lws_dll2_t		list;		/* r->pages */
	lws_dll2_t		queue;		/* fr->queue, waiting to fetch */
	struct lws_mcufont_remote *r;
	/*
	 * The page's blob, held in the pieces it was collected in, after the
	 * prefix the core has its own copy of: trimmed bytes from its start
	 */
	struct lws_buflist	*bl;
	uint32_t		trimmed;
	lws_mcuf_core_t		core;		/* .prefix set while resident */
	lws_usec_t		holdoff_until;	/* refused or no memory: until */
	uint16_t		page;
	uint8_t			bad;		/* the server's copy is unusable */
	uint8_t			nomem;		/* held off for want of heap */
} lws_mcufont_page_t;

/*
 * A face listed in the font manifest, that the server makes at any of the
 * sizes it lists.  This is what the chooser sees; text is set in one of its
 * sizes, an lws_mcufont_remote_t made the first time that size is chosen,
 * and kept in sizes rather than cx->fonts.  At a size, its line height is
 * (height * size + units_per_em / 2) / units_per_em, as the server makes it.
 * The pages it has are listed as ranges, the same at every size.
 */
typedef struct lws_mcufont_family {
	uint8_t			kind;		/* LWS_MCUF_KIND_FAMILY: first */
	uint16_t		nranges;
	uint16_t		nsizes;
	uint32_t		height;
	uint32_t		units_per_em;
	lws_dll2_owner_t	sizes_made;	/* lws_display_font_t */
	struct lws_fonts_remote	*fr;
	lws_display_font_t	*f;
	const char		*path;		/* in the manifest lwsac */
	const uint16_t		*ranges;	/* first, last page pairs */
	const uint16_t		*sizes;		/* first, last size pairs */
} lws_mcufont_family_t;

/*
 * A family at one size.  A codepoint on a page the family doesn't have is
 * drawn with the fallback glyph of its core page, the first it lists.  The
 * pages that text has needed are in pages, whether or not they are resident
 * just now.
 *
 * The face is usable for layout once its core page is resident: the face's
 * header is copied from the first page to arrive, and is its .data from
 * then on, so the face's metrics stay to hand when every page has been
 * evicted.  The pages pinned while layout has an element open in the face,
 * and for the duration of each render call drawing it, are every page that
 * is resident: a page arriving while the face is pinned is pinned as many
 * times as the face.  Each arrival bumps gen, since glyphs being decoded
 * from an earlier copy of a page have to start again from the new one.
 */
typedef struct lws_mcufont_remote {
	uint8_t			kind;		/* LWS_MCUF_KIND_REMOTE: first */
	uint8_t			hdr_valid;
	uint16_t		gen;		/* bumped as each page arrives */
	uint16_t		pins;
	uint16_t		nranges;
	uint16_t		size;
	lws_dll2_owner_t	pages;		/* lws_mcufont_page_t */
	struct lws_fonts_remote	*fr;
	struct lws_context	*cx;
	lws_display_font_t	*f;
	lws_mcufont_family_t	*fam;
	const char		*path;		/* "<family path>/<size>" */
	const uint16_t		*ranges;	/* the family's */
	uint8_t			hdr[MCUFO_HDR_LEN];
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

static LWS_INLINE lws_mcufont_family_t *
mcuf_family(const lws_display_font_t *f)
{
	return f->priv && *f->priv == LWS_MCUF_KIND_FAMILY ?
				(lws_mcufont_family_t *)f->priv : NULL;
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

void
lws_font_init_common(lws_display_font_t *a);

int
lws_font_register_common(struct lws_context *cx, lws_display_font_t *a);

void
lws_font_set_em(lws_display_font_t *a);

lws_font_residency_t
lws_font_text_resident(const lws_display_font_t *f, const char *utf8,
		       size_t len, lws_font_waiter_t *w);

#if defined(LWS_DLO_REMOTE_FONTS)
int
lws_mcufont_family_pick(lws_mcufont_family_t *fam, unsigned int want,
			uint16_t *size, uint16_t *line_height);

const lws_display_font_t *
lws_mcufont_family_face(lws_mcufont_family_t *fam, uint16_t size);

void
lws_mcufont_family_destroy(lws_display_font_t *f);

lws_font_residency_t
lws_mcufont_remote_resident(lws_mcufont_remote_t *r, const char *utf8,
			    size_t len, lws_font_waiter_t *w);

const uint8_t *
lws_mcufont_remote_blob(lws_mcufont_remote_t *r, uint32_t unicode,
			size_t *len, lws_mcuf_core_t **core);

void
lws_mcufont_remote_pin(lws_mcufont_remote_t *r, int pin);

int
lws_fonts_remote_manifest_pending(struct lws_context *cx, lws_font_waiter_t *w);

void
lws_fonts_remote_too_slow(struct lws_context *cx, int manifest);

void
lws_fonts_remote_heap_freed(struct lws_context *cx);

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

static LWS_INLINE void
lws_fonts_remote_heap_freed(struct lws_context *cx)
{
	(void)cx;
}
#endif

int
lws_display_font_mcufont_check(const uint8_t *bf, size_t len);

/* decode one codepoint, consuming its bytes; nonzero if they aren't utf8 */
int
lws_dlo_utf8_unicode(const char *utf8, size_t *utf8_len, uint32_t *unicode);

int
lws_mcuf_core_load(lws_mcuf_core_t *c, uint32_t blob_len);

void
lws_mcuf_core_free(lws_mcuf_core_t *c);

size_t
lws_mcuf_core_glyphs_free(lws_mcuf_core_t *c, int unpinned_only);

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
lws_display_dlo_text_detach_glyphs(lws_dlo_text_t *text);

/*
 * A rect's coverage of a line, used to draw it, and to clip what is in it to
 * its rounded corners: see dlo-rect.c
 */

void
lws_display_dlo_rect_place(lws_dlo_rect_t *r, const lws_fx_t *ox,
			   const lws_fx_t *oy);
int
lws_display_dlo_rect_rounded(const lws_dlo_rect_t *r);
int
lws_display_dlo_rect_row(lws_dlo_rect_t *r, int curr, int w,
			 lws_dlo_rect_row_t *row);
unsigned int
lws_display_dlo_rect_row_alpha(const lws_dlo_rect_row_t *row,
			       unsigned int alpha);
unsigned int
lws_display_dlo_rect_px_alpha(lws_dlo_rect_t *r, const lws_dlo_rect_row_t *row,
			      int x, unsigned int alpha);

int
lws_display_dlo_text_refit(lws_dlo_text_t *text);

void
lws_display_dlo_text_align_shift(uint8_t align, const lws_fx_t *room,
				 lws_fx_t *shift);

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
lws_display_font_mcufont_metrics(lws_dlo_text_t *text, uint32_t unicode,
				 lws_glyph_metrics_t *m);

int
lws_display_font_mcufont_kern(const lws_glyph_metrics_t *a,
			      const lws_glyph_metrics_t *b);

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

const lws_fx_t *
lws_lhp_viewport_h(lhp_ctx_t *ctx);

int
lws_dlo_ss_stop_any_active(struct lws_context *cx);

#if defined(LWS_WITH_SVG)
void
lws_display_dlo_svg_release(lws_dlo_svg_t *dlo_svg);
#endif
void
lws_display_dlo_png_release(lws_dlo_png_t *dlo_png);
void
lws_display_dlo_jpeg_release(lws_dlo_jpeg_t *dlo_jpeg);

#if defined(LWS_WITH_CLIENT) && defined(LWS_WITH_SECURE_STREAMS) && \
    defined(LWS_WITH_LHP)
int
lws_dlo_ss_refetch(lws_dlo_t *dlo, const lws_dlo_refetch_t *rf,
		   int32_t window, uint8_t type);
#endif

#endif

