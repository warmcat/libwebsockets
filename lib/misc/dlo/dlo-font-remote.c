/*
 * lws abstract display
 *
 * Copyright (C) 2026 Andy Green <andy@warmcat.com>
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
 * Faces from a server: the manifest listing them is fetched once per boot,
 * and each face is fetched a page at a time, as text needs glyphs from the
 * page.  Each page is a reclaimable heap occupant, that may be evicted and
 * fetched again any number of times.  See lws_fonts_register_manifest().
 */

#include <private-lib-core.h>
#include "private-lib-drivers-display-dlo.h"

#if defined(LWS_DLO_REMOTE_FONTS)

/* the manifest is small: a line per face */
#define LWS_FONTS_MANIFEST_MAX_LEN	16384
#define LWS_FONTS_MANIFEST_MAX_FACES	64
/* the most runs of pages a face's entry may list */
#define LWS_FONTS_MANIFEST_MAX_RANGES	32
/* the most runs of sizes a face's entry may list */
#define LWS_FONTS_MANIFEST_MAX_SIZE_RUNS 16
/* the sizes the server's encoder can make */
#define LWS_FONTS_SIZE_MIN		4
#define LWS_FONTS_SIZE_MAX		255
/*
 * the most sizes of a family set text at once: after that, text is set in
 * the closest size already made
 */
#define LWS_FONTS_FAMILY_MAX_SIZES	8
/* a page bigger than this is not something a small device should fetch */
#define LWS_FONTS_PAGE_MAX_LEN		(128 * 1024)
/*
 * A page is collected into, and kept in, pieces of this size: it is the
 * biggest block of heap a page needs, besides its core.  Smaller is easier on
 * a fragmented heap, at the cost of a little more overhead per piece, and
 * more of the glyphs spanning two pieces, which are copied to be decoded
 */
#define LWS_FONTS_PAGE_PIECE		1024
/* after the server failed us, how long to use the local faces instead */
#define LWS_FONTS_REMOTE_HOLDOFF_S	30
/*
 * after the server refused a page, eg, because it is still making it, how
 * long to set text that needs it in a local face, before asking again
 */
#define LWS_FONTS_PAGE_HOLDOFF_S	20
/* after we couldn't find the memory for a page, how long to not try */
#define LWS_FONTS_NOMEM_HOLDOFF_US	(2 * LWS_US_PER_SEC)

enum {
	LWS_FONTS_MANIFEST_IDLE,	/* not asked for yet */
	LWS_FONTS_MANIFEST_FETCHING,	/* first attempt in progress */
	LWS_FONTS_MANIFEST_RETRYING,	/* failed, will try again later */
	LWS_FONTS_MANIFEST_DONE,
};

typedef struct lws_fonts_remote {
	lws_state_notify_link_t		notify;
	lws_sorted_usec_list_t		sul_retry;
	struct lws_context		*cx;
	struct lws_ss_handle		*ss_manifest;
	struct lws_ss_handle		*ss_page; /* one page fetch at a time */
	struct lwsac			*ac;	/* the parsed manifest */
	lws_dll2_owner_t		queue;	/* lws_mcufont_page_t to fetch */
	lws_dll2_owner_t		waiters; /* lws_font_waiter_t */
	lws_usec_t			down_until; /* local faces until then */
	unsigned int			fetches; /* pages fetched */
	unsigned int			evictions; /* pages given back */
	uint8_t				manifest_state;
	char				*url;
} lws_fonts_remote_t;

typedef struct {
	lws_dll2_t			list;
	char				name[64];
	char				path[64];
	char				pages[160];
	char				sizes[64];
	unsigned int			height;
	unsigned int			units_per_em;
} lws_fonts_manifest_face_t;

typedef struct {
	lws_dll2_owner_t		fonts;
} lws_fonts_manifest_t;

static const lws_struct_map_t lsm_fonts_manifest_face[] = {
	LSM_CARRAY	(lws_fonts_manifest_face_t, name,	"name"),
	LSM_CARRAY	(lws_fonts_manifest_face_t, path,	"path"),
	LSM_CARRAY	(lws_fonts_manifest_face_t, pages,	"pages"),
	LSM_CARRAY	(lws_fonts_manifest_face_t, sizes,	"sizes"),
	LSM_UNSIGNED	(lws_fonts_manifest_face_t, height,	"height"),
	LSM_UNSIGNED	(lws_fonts_manifest_face_t, units_per_em,
							"units_per_em"),
};

static const lws_struct_map_t lsm_fonts_manifest[] = {
	LSM_LIST	(lws_fonts_manifest_t, fonts, lws_fonts_manifest_face_t,
			 list, NULL, lsm_fonts_manifest_face,	"fonts"),
};

static const lws_struct_map_t lsm_fonts_manifest_schema[] = {
	LSM_SCHEMA	(lws_fonts_manifest_t, NULL, lsm_fonts_manifest,
			 "lws-fonts-manifest"),
};

LWS_SS_USER_TYPEDEF
	lws_fonts_remote_t		*fr;
	lws_mcufont_page_t		*p;	/* NULL: this is the manifest */
	struct lws_buflist		*bl;	/* the page as it arrives */
	uint8_t				*piece;	/* the piece being filled */
	size_t				piece_len;
	size_t				pos;
	struct lejp_ctx			jctx;
	lws_struct_args_t		a;
	uint8_t				parsing:1;
	uint8_t				parsed:1; /* the JSON is complete */
	uint8_t				complete:1; /* it all arrived */
	uint8_t				refused:1; /* with an http error */
	uint8_t				done:1;	/* nothing more to do with it */
} fontss_t;

static void
lws_fonts_remote_kick(lws_fonts_remote_t *fr);

/* a page is resident while it has its core */

static int
lws_mcufont_page_resident(const lws_mcufont_page_t *p)
{
	return !!p->core.prefix;
}

static void
lws_fonts_remote_wake(lws_fonts_remote_t *fr)
{
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&fr->waiters)) {
		lws_font_waiter_t *w = lws_container_of(d, lws_font_waiter_t,
							list);

		lws_dll2_remove(&w->list);
		lws_sul_schedule(fr->cx, 0, w->sul, w->cb, 1);
	} lws_end_foreach_dll_safe(d, d1);
}

static void
lws_fonts_remote_wait(lws_fonts_remote_t *fr, lws_font_waiter_t *w)
{
	/* without a way to wake it, the waiter's own retry has to do */
	if (!w || !w->sul || !w->cb || w->list.owner)
		return;

	lws_dll2_add_tail(&w->list, &fr->waiters);
}

static int
lws_fonts_remote_down(lws_fonts_remote_t *fr)
{
	return fr->down_until && lws_now_usecs() < fr->down_until;
}

/*
 * The server failed us: use the local faces for a while, rather than have
 * every page that is wanted meanwhile wait for its own failure
 */

static void
lws_fonts_remote_set_down(lws_fonts_remote_t *fr)
{
	fr->down_until = lws_now_usecs() +
			 (LWS_FONTS_REMOTE_HOLDOFF_S * LWS_US_PER_SEC);

	while (lws_dll2_get_head(&fr->queue))
		lws_dll2_remove(lws_dll2_get_head(&fr->queue));
}

/*
 * The page's file, in the directory of the face's size next to the manifest,
 * eg, ".../fonts.json" -> ".../FiraSansCondensed-Regular/14/0020.mcufont".
 * The face's path has already been checked
 */

static int
lws_fonts_remote_url(lws_fonts_remote_t *fr, const lws_mcufont_page_t *p,
		     char *url, size_t len)
{
	const char *q = strchr(fr->url, '?'), *s;
	size_t bl;
	int n;

	if (!q)
		q = fr->url + strlen(fr->url);
	s = q;
	while (s > fr->url && s[-1] != '/')
		s--;
	bl = lws_ptr_diff_size_t(s, fr->url);

	if (bl >= len)
		return 1;

	memcpy(url, fr->url, bl);
	n = lws_snprintf(url + bl, len - bl, "%s/%04x.mcufont", p->r->path,
			 (unsigned int)p->page);

	return (size_t)n >= len - bl - 1;
}

static lws_ss_state_return_t
fontss_rx(void *userobj, const uint8_t *buf, size_t len, int flags);

static lws_ss_state_return_t
fontss_state(void *userobj, void *sh, lws_ss_constate_t state,
	     lws_ss_tx_ordinal_t ack);

static LWS_SS_INFO("__default", fontss_t)
	.rx				= fontss_rx,
	.state				= fontss_state
};

static struct lws_ss_handle *
lws_fonts_remote_fetch(lws_fonts_remote_t *fr, lws_mcufont_page_t *p,
		       const char *url)
{
	struct lws_ss_handle *h;
	fontss_t *m;

	if (lws_ss_create(fr->cx, 0, &ssi_fontss_t, NULL, &h, NULL, NULL)) {
		lwsl_cx_warn(fr->cx, "unable to create ss for %s", url);
		return NULL;
	}

	m = (fontss_t *)lws_ss_to_user_object(h);
	m->fr = fr;
	m->p = p;

	if (lws_ss_alloc_set_metadata(h, "endpoint", url, strlen(url)) ||
	    lws_ss_client_connect(h)) {
		lwsl_cx_warn(fr->cx, "unable to fetch %s", url);
		lws_ss_destroy(&h);
		return NULL;
	}

	return h;
}

/* fetch the next page that is waiting, if nothing is being fetched */

static void
lws_fonts_remote_kick(lws_fonts_remote_t *fr)
{
	lws_mcufont_page_t *p;
	char url[256];

	if (fr->ss_page || fr->cx->being_destroyed)
		return;

	while (lws_dll2_get_head(&fr->queue)) {
		p = lws_container_of(lws_dll2_get_head(&fr->queue),
				     lws_mcufont_page_t, queue);

		lws_dll2_remove(&p->queue);
		if (lws_mcufont_page_resident(p) || p->bad)
			continue;

		if (lws_fonts_remote_url(fr, p, url, sizeof(url))) {
			p->bad = 1;
			continue;
		}

		lwsl_cx_info(fr->cx, "fetching %s", url);
		fr->ss_page = lws_fonts_remote_fetch(fr, p, url);
		if (fr->ss_page)
			return;

		/*
		 * Not the server's fault: we couldn't even start asking it,
		 * most likely there wasn't the memory for the stream.  This
		 * page is held off as when there isn't the memory for it,
		 * and the rest are asked for when they are next wanted
		 */
		p->holdoff_until = lws_now_usecs() + LWS_FONTS_NOMEM_HOLDOFF_US;
		p->nomem = 1;
		break;
	}

	/* nothing is coming: whoever waits for it can choose again */
	lws_fonts_remote_wake(fr);
}

/* what a resident page holds, and the pieces it holds it in, go */

static void
lws_mcufont_page_free(lws_mcufont_page_t *p)
{
	lws_mcuf_core_glyphs_free(&p->core, 0);
	lws_mcuf_core_free(&p->core);
	lws_buflist_destroy_all_segments(&p->bl);
	p->trimmed = 0;
	p->rc.resident = 0;
}

static size_t
lws_mcufont_page_evict_cb(lws_reclaimable_t *rc)
{
	lws_mcufont_page_t *p = lws_container_of(rc, lws_mcufont_page_t, rc);
	size_t freed = rc->resident;

	lwsl_info("%s: %s %04x: %u\n", __func__, p->r->path,
		  (unsigned int)p->page, (unsigned int)freed);
	p->r->fr->evictions++;
	lws_mcufont_page_free(p);

	return freed;
}

/*
 * The core reads the page from the pieces it is in.  The prefix is gone from
 * them once the core has its own copy, and nothing should want it again
 */

static int
lws_mcufont_page_read(lws_mcuf_core_t *c, uint32_t ofs, uint8_t *buf,
		      uint32_t len)
{
	lws_mcufont_page_t *p = lws_container_of(c, lws_mcufont_page_t, core);

	if (ofs < p->trimmed)
		return 1;

	return lws_buflist_linear_copy(&p->bl, ofs - p->trimmed, buf, len) !=
								(int)len;
}

static const uint8_t *
lws_mcufont_page_at(lws_mcuf_core_t *c, uint32_t ofs, size_t *avail)
{
	lws_mcufont_page_t *p = lws_container_of(c, lws_mcufont_page_t, core);

	*avail = 0;
	if (ofs < p->trimmed)
		return NULL;

	return lws_buflist_at(&p->bl, ofs - p->trimmed, avail);
}

/*
 * The core page, the face's first, has the glyph for a codepoint on a page
 * the face doesn't list
 */

static uint16_t
lws_mcufont_remote_page_of(const lws_mcufont_remote_t *r, uint32_t unicode)
{
	uint32_t pg = unicode >> 8;
	uint16_t n;

	for (n = 0; n < r->nranges; n++) {
		if (pg < r->ranges[n * 2])
			break; /* the ranges are in order */
		if (pg <= r->ranges[(n * 2) + 1])
			return (uint16_t)pg;
	}

	return r->ranges[0];
}

static lws_mcufont_page_t *
lws_mcufont_remote_page(lws_mcufont_remote_t *r, uint16_t page, int create)
{
	lws_mcufont_page_t *p;

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&r->pages)) {
		p = lws_container_of(d, lws_mcufont_page_t, list);
		if (p->page == page)
			return p;
	} lws_end_foreach_dll(d);

	if (!create)
		return NULL;

	p = lws_zalloc(sizeof(*p), __func__);
	if (!p)
		return NULL;

	p->r = r;
	p->page = page;
	p->rc.evict = lws_mcufont_page_evict_cb;
	p->core.read = lws_mcufont_page_read;
	p->core.at = lws_mcufont_page_at;
	p->core.rc_glyphs = &p->rc;
	lws_reclaimable_add(&p->rc);
	lws_dll2_add_tail(&p->list, &r->pages);

	return p;
}

static int
lws_mcufont_page_available(const lws_mcufont_remote_t *r,
			   const lws_mcufont_page_t *p)
{
	if (p && lws_mcufont_page_resident(p))
		return 1;

	return !lws_fonts_remote_down(r->fr) &&
	       (!p || (!p->bad && lws_now_usecs() >= p->holdoff_until));
}

/*
 * A page's whole payload has arrived, in the pieces in p->bl: if it is a page
 * of the face the manifest promised, and safe for the decoder, it becomes
 * resident.  The first page to arrive sets the face's header, that the others
 * must match: only the width and the baseline's x may differ, since each page
 * is only as wide as its own glyphs need.
 *
 * 1 if it isn't such a page, -1 if it may be but there's no memory for its
 * core just now: that's not the page's fault, it may be wanted again later.
 */

static const uint8_t lws_mcufont_face_hdr[] = {
	MCUFO16_HEIGHT, MCUFO16_HEIGHT + 1,
	MCUFO16_BASELINE_Y, MCUFO16_BASELINE_Y + 1,
	MCUFO16_LINE_HEIGHT, MCUFO16_LINE_HEIGHT + 1,
	MCUFO_KERN_BANDS, MCUFO_KERN_GAP,
};

static int
lws_mcufont_page_arrived(lws_mcufont_page_t *p, size_t len)
{
	lws_mcufont_remote_t *r = p->r;
	lws_display_font_t *f = r->f;
	const uint8_t *pf;
	size_t n, left;
	int ret;

	p->trimmed = 0;
	if (len > LWS_FONTS_PAGE_MAX_LEN)
		goto bad;

	ret = lws_mcuf_core_load(&p->core, (uint32_t)len);
	if (ret < 0)
		return -1;
	if (ret)
		goto bad;

	pf = p->core.prefix;
	if (strcmp((const char *)pf + lws_ser_ru32be(pf + MCUFO_FOFS_FULLNAME),
		   f->choice.family_name) ||
	    lws_ser_ru16be(pf + MCUFO16_LINE_HEIGHT) !=
						f->choice.fixed_height)
		goto bad;

	if (r->hdr_valid) {
		for (n = 0; n < LWS_ARRAY_SIZE(lws_mcufont_face_hdr); n++)
			if (pf[lws_mcufont_face_hdr[n]] !=
					r->hdr[lws_mcufont_face_hdr[n]])
				goto bad;
	} else {
		memcpy(r->hdr, pf, sizeof(r->hdr));
		r->hdr_valid = 1;
		f->data = r->hdr;
		f->data_len = sizeof(r->hdr);
	}

	/* the core has its own copy of the prefix: let the pieces of it go */

	left = p->core.prefix_len;
	while (left) {
		size_t s = lws_buflist_next_segment_len(&p->bl, NULL);

		if (!s)
			break;
		if (s > left)
			s = left;
		lws_buflist_use_segment(&p->bl, s);
		left -= s;
	}
	p->trimmed = p->core.prefix_len;

	p->nomem = 0;
	r->gen++;
	r->fr->fetches++;

	/* the pieces, each with its buflist header, and the core */
	n = lws_buflist_total_len(&p->bl);
	p->core.rc_glyphs_base = n + p->core.core_bytes +
			(((n + LWS_FONTS_PAGE_PIECE - 1) / LWS_FONTS_PAGE_PIECE) *
			 (sizeof(struct lws_buflist) + LWS_PRE));
	p->rc.resident = p->core.rc_glyphs_base;
	p->rc.pins = r->pins;
	lws_reclaimable_touch(&p->rc);

	if (p->page == r->ranges[0] && !f->em.whole && !f->em.frac)
		lws_font_set_em(f);

	return 0;

bad:
	lwsl_cx_warn(r->fr->cx, "%s/%04x isn't a page of the face the "
		     "manifest described, not using it", r->path,
		     (unsigned int)p->page);

	return 1;
}

static int
lws_fonts_manifest_path_ok(const char *path)
{
	const char *p = path;

	/*
	 * Only a plain name, so the pages are fetched from beside the
	 * manifest whatever the manifest says: no path, scheme or escapes
	 */

	if (!*p || *p == '.')
		return 0;

	for (; *p; p++)
		if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
		      (*p >= '0' && *p <= '9') || *p == '.' || *p == '-' ||
		      *p == '_'))
			return 0;

	return 1;
}

/* a number of up to 4 hex digits, or up to 3 decimal digits */

static int
lws_fonts_manifest_num(const char *s, size_t len, int hex, uint32_t *v)
{
	size_t n;

	if (!len || len > (hex ? 4u : 3u))
		return 1;

	*v = 0;
	for (n = 0; n < len; n++) {
		char c = s[n];

		*v *= hex ? 16u : 10u;
		if (c >= '0' && c <= '9')
			*v += (uint32_t)(c - '0');
		else if (hex && c >= 'a' && c <= 'f')
			*v += (uint32_t)(c - 'a' + 10);
		else if (hex && c >= 'A' && c <= 'F')
			*v += (uint32_t)(c - 'A' + 10);
		else
			return 1;
	}

	return 0;
}

/*
 * The pages a face lists, like "0000-0005,0020,00a7" in hex, or the sizes,
 * like "4-255" or "12,14,16" in decimal, into first, last pairs in ranges.
 * They must be from lo to hi, in order and not overlap.  Returns the count
 * of pairs, or -1 if the list is bad
 */

static int
lws_fonts_manifest_runs(const char *list, int hex, uint32_t lo, uint32_t hi,
			uint16_t *ranges, int max)
{
	struct lws_tokenize ts;
	lws_tokenize_elem e;
	int n = 0, dash = 0, have = 0;
	uint32_t v;

	lws_tokenize_init(&ts, list, LWS_TOKENIZE_F_NO_INTEGERS |
				     LWS_TOKENIZE_F_NO_FLOATS);
	ts.len = strlen(list);

	do {
		e = lws_tokenize(&ts);
		switch (e) {
		case LWS_TOKZE_TOKEN:
			if (lws_fonts_manifest_num(ts.token, ts.token_len,
						   hex, &v) || v < lo || v > hi)
				return -1;
			if (dash) {
				/* the end of the run started before */
				if (v < ranges[(n - 1) * 2])
					return -1;
				ranges[((n - 1) * 2) + 1] = (uint16_t)v;
				dash = 0;
				break;
			}
			if (have || n == max ||
			    (n && v <= ranges[((n - 1) * 2) + 1]))
				return -1;
			ranges[n * 2] = ranges[(n * 2) + 1] = (uint16_t)v;
			n++;
			have = 1;
			break;

		case LWS_TOKZE_DELIMITER:
			if (*ts.token == '-' && have && !dash) {
				dash = 1;
				break;
			}
			if (*ts.token == ',' && have && !dash) {
				have = 0;
				break;
			}
			return -1;

		case LWS_TOKZE_ENDED:
			break;

		default:
			return -1;
		}
	} while (e > 0);

	if (dash || !have)
		return -1;

	return n;
}

/* the manifest is parsed: register a family for each usable entry */

static void
lws_fonts_manifest_apply(lws_fonts_remote_t *fr, lws_fonts_manifest_t *man)
{
	uint16_t ranges[LWS_FONTS_MANIFEST_MAX_RANGES * 2],
		 sizes[LWS_FONTS_MANIFEST_MAX_SIZE_RUNS * 2];
	int n = 0, nr, ns;

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&man->fonts)) {
		lws_fonts_manifest_face_t *e = lws_container_of(d,
					lws_fonts_manifest_face_t, list);
		lws_mcufont_family_t *fam;
		lws_display_font_t *a;

		if (n == LWS_FONTS_MANIFEST_MAX_FACES) {
			lwsl_cx_warn(fr->cx, "too many faces, ignoring the rest");
			break;
		}

		nr = lws_fonts_manifest_runs(e->pages, 1, 0, 0x10ff, ranges,
					     LWS_FONTS_MANIFEST_MAX_RANGES);
		ns = lws_fonts_manifest_runs(e->sizes, 0, LWS_FONTS_SIZE_MIN,
					     LWS_FONTS_SIZE_MAX, sizes,
					     LWS_FONTS_MANIFEST_MAX_SIZE_RUNS);
		/*
		 * Every size must have a line height, that fits in 16 bits:
		 * the least is the first size's, the most is the last one's
		 */
		if (!e->name[0] || !lws_fonts_manifest_path_ok(e->path) ||
		    nr <= 0 || ns <= 0 || !e->height || e->height > 0xffff ||
		    !e->units_per_em || e->units_per_em > 0xffff ||
		    ((uint64_t)e->height * sizes[0]) + (e->units_per_em / 2) <
							e->units_per_em ||
		    ((uint64_t)e->height * sizes[(ns * 2) - 1]) +
				(e->units_per_em / 2) >=
				(uint64_t)e->units_per_em * 0x10000) {
			lwsl_cx_warn(fr->cx, "ignoring bad entry '%s'", e->path);
			continue;
		}

		/* the family, its remote state, and its page and size runs */

		a = lws_zalloc(sizeof(*a) + sizeof(*fam) +
			       ((size_t)(nr + ns) * 2 * sizeof(uint16_t)),
			       __func__);
		if (!a)
			break;
		fam = (lws_mcufont_family_t *)&a[1];

		fam->kind = LWS_MCUF_KIND_FAMILY;
		fam->fr = fr;
		fam->f = a;
		fam->path = e->path;
		fam->height = e->height;
		fam->units_per_em = e->units_per_em;
		fam->nranges = (uint16_t)nr;
		fam->nsizes = (uint16_t)ns;
		memcpy(&fam[1], ranges, (size_t)nr * 2 * sizeof(uint16_t));
		fam->ranges = (const uint16_t *)&fam[1];
		memcpy((uint16_t *)&fam[1] + (nr * 2), sizes,
		       (size_t)ns * 2 * sizeof(uint16_t));
		fam->sizes = fam->ranges + (nr * 2);

		a->priv = (uint8_t *)fam;
		a->choice.family_name = e->name;

		lws_font_register_common(fr->cx, a);
		n++;
	} lws_end_foreach_dll(d);

	lwsl_cx_notice(fr->cx, "%d faces from %s", n, fr->url);
}

static void
lws_fonts_manifest_retry_cb(lws_sorted_usec_list_t *sul);

static void
_lws_fonts_manifest_retry_cb(lws_sorted_usec_list_t *sul)
{
	lws_fonts_remote_t *fr = lws_container_of(sul, lws_fonts_remote_t,
						  sul_retry);

	if (fr->ss_manifest || fr->manifest_state == LWS_FONTS_MANIFEST_DONE)
		return;

	fr->ss_manifest = lws_fonts_remote_fetch(fr, NULL, fr->url);
	if (fr->ss_manifest)
		return;

	fr->manifest_state = LWS_FONTS_MANIFEST_RETRYING;
	lws_sul_schedule(fr->cx, 0, &fr->sul_retry,
			 lws_fonts_manifest_retry_cb,
			 LWS_FONTS_REMOTE_HOLDOFF_S * LWS_US_PER_SEC);
}

static void
lws_fonts_manifest_retry_cb(lws_sorted_usec_list_t *sul)
{
	lws_alloc_arena_t a = lws_alloc_arena_set(LWS_ALLOC_ARENA_BULK);

	_lws_fonts_manifest_retry_cb(sul);
	lws_alloc_arena_set(a);
}

/* the first time the manifest is wanted: when we're OPERATIONAL, or a page
 * needs fonts, whichever comes first */

static void
lws_fonts_manifest_start(lws_fonts_remote_t *fr)
{
	if (fr->manifest_state != LWS_FONTS_MANIFEST_IDLE)
		return;

	fr->manifest_state = LWS_FONTS_MANIFEST_FETCHING;
	lws_fonts_manifest_retry_cb(&fr->sul_retry);
}

/*
 * Not the server's fault: what is resident is all in use.  Text that needs
 * the page is set in a local face for a little while, then we ask again
 */

static void
lws_fonts_page_nomem(lws_mcufont_page_t *p)
{
	lwsl_cx_notice(p->r->fr->cx, "no memory for %s/%04x", p->r->path,
		       (unsigned int)p->page);
	p->holdoff_until = lws_now_usecs() + LWS_FONTS_NOMEM_HOLDOFF_US;
	p->nomem = 1;
}

/*
 * A display list was destroyed: the heap it held is free, so the pages held
 * off for want of it may be asked for again at once.  A page the server
 * refused stays held off
 */

void
lws_fonts_remote_heap_freed(struct lws_context *cx)
{
	if (!cx)
		return;

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&cx->fonts)) {
		lws_display_font_t *f = lws_container_of(d,
						lws_display_font_t, list);
		lws_mcufont_family_t *fam = mcuf_family(f);

		if (!fam)
			continue;

		lws_start_foreach_dll(struct lws_dll2 *, ds,
				      lws_dll2_get_head(&fam->sizes_made)) {
			lws_mcufont_remote_t *r = mcuf_remote(
					lws_container_of(ds,
						lws_display_font_t, list));

			lws_start_foreach_dll(struct lws_dll2 *, dp,
					      lws_dll2_get_head(&r->pages)) {
				lws_mcufont_page_t *p = lws_container_of(dp,
						lws_mcufont_page_t, list);

				if (p->nomem) {
					p->nomem = 0;
					p->holdoff_until = 0;
				}
			} lws_end_foreach_dll(dp);
		} lws_end_foreach_dll(ds);
	} lws_end_foreach_dll(d);
}

/*
 * What arrives is only used once the stream ends without the server having
 * said it's an error: an http server sends its error page as the payload
 * too.  So the manifest is parsed and a page collected as they come, but
 * they are only applied when the stream is destroyed
 */

/* the piece being filled becomes one of the page's pieces */

static int
fontss_piece_done(fontss_t *m)
{
	if (!m->piece_len)
		return 0;

	if (lws_buflist_append_segment(&m->bl, m->piece, m->piece_len) < 0)
		return 1;

	m->piece_len = 0;

	return 0;
}

static lws_ss_state_return_t
_fontss_rx(void *userobj, const uint8_t *buf, size_t len, int flags)
{
	fontss_t *m = (fontss_t *)userobj;
	int n;

	if (m->done)
		return LWSSSSRET_OK;

	if (!m->p) {
		/* the manifest, parsed as it comes */

		if (!m->parsing) {
			memset(&m->a, 0, sizeof(m->a));
			m->a.map_st[0] = lsm_fonts_manifest_schema;
			m->a.map_entries_st[0] =
				LWS_ARRAY_SIZE(lsm_fonts_manifest_schema);
			m->a.ac_block_size = 1024;
			lws_struct_json_init_parse(&m->jctx, NULL, &m->a);
			m->parsing = 1;
		}

		m->pos += len;
		if (m->pos > LWS_FONTS_MANIFEST_MAX_LEN) {
			lwsl_cx_warn(m->fr->cx, "manifest too large");
			m->done = 1;
			return LWSSSSRET_DESTROY_ME;
		}

		/* http says it's all here with an empty one at the end */
		if (len && !m->parsed) {
			n = lejp_parse(&m->jctx, buf, (int)len);
			if (n < 0 && n != LEJP_CONTINUE) {
				lwsl_cx_warn(m->fr->cx, "manifest JSON: %s",
					     lejp_error_to_string(n));
				m->done = 1;
				return LWSSSSRET_DESTROY_ME;
			}
			if (n >= 0)
				m->parsed = 1;
		}

		if (!(flags & LWSSS_FLAG_EOM))
			return LWSSSSRET_OK;

		if (!m->parsed || !m->a.dest) {
			lwsl_cx_warn(m->fr->cx, "manifest incomplete");
			m->done = 1;
			return LWSSSSRET_DESTROY_ME;
		}

		m->complete = 1;

		return LWSSSSRET_OK;
	}

	/*
	 * A page, collected into pieces of LWS_FONTS_PAGE_PIECE whatever size
	 * it arrives in, and kept in them: it never needs a block of heap the
	 * size of the page
	 */

	if (len > LWS_FONTS_PAGE_MAX_LEN - m->pos) {
		lwsl_cx_warn(m->fr->cx, "%s/%04x is too large", m->p->r->path,
			     (unsigned int)m->p->page);
		m->p->bad = 1;
		m->done = 1;
		return LWSSSSRET_DESTROY_ME;
	}

	m->pos += len;
	while (len) {
		size_t s = LWS_FONTS_PAGE_PIECE - m->piece_len;

		if (!m->piece) {
			m->piece = lws_malloc(LWS_FONTS_PAGE_PIECE, __func__);
			if (!m->piece)
				goto nomem;
		}

		if (s > len)
			s = len;
		memcpy(m->piece + m->piece_len, buf, s);
		m->piece_len += s;
		buf += s;
		len -= s;

		if (m->piece_len == LWS_FONTS_PAGE_PIECE &&
		    fontss_piece_done(m))
			goto nomem;
	}

	if (flags & LWSSS_FLAG_EOM)
		m->complete = 1;

	return LWSSSSRET_OK;

nomem:
	lws_fonts_page_nomem(m->p);
	m->done = 1;

	return LWSSSSRET_DESTROY_ME;
}

static lws_ss_state_return_t
fontss_rx(void *userobj, const uint8_t *buf, size_t len, int flags)
{
	lws_alloc_arena_t a = lws_alloc_arena_set(LWS_ALLOC_ARENA_BULK);
	lws_ss_state_return_t r = _fontss_rx(userobj, buf, len, flags);

	lws_alloc_arena_set(a);

	return r;
}

/* the stream is over: use what it brought, or note why it didn't */

static void
fontss_finished(fontss_t *m)
{
	lws_fonts_remote_t *fr = m->fr;
	lws_mcufont_page_t *p = m->p;

	if (!p) {
		fr->ss_manifest = NULL;

		if (m->complete && !m->refused && !m->done) {
			/* the faces' names and paths stay in its ac */
			fr->ac = m->a.ac;
			m->a.ac = NULL;
			fr->manifest_state = LWS_FONTS_MANIFEST_DONE;
			lws_fonts_manifest_apply(fr,
					(lws_fonts_manifest_t *)m->a.dest);
			return;
		}

		if (fr->manifest_state == LWS_FONTS_MANIFEST_DONE)
			return;

		/*
		 * Layout goes on with the local faces while we keep trying
		 * in the background
		 */
		lwsl_cx_notice(fr->cx, "font manifest %s unavailable, "
			       "retrying", fr->url);
		fr->manifest_state = LWS_FONTS_MANIFEST_RETRYING;
		lws_sul_schedule(fr->cx, 0, &fr->sul_retry,
				 lws_fonts_manifest_retry_cb,
				 LWS_FONTS_REMOTE_HOLDOFF_S * LWS_US_PER_SEC);
		return;
	}

	fr->ss_page = NULL;

	if (m->done)
		/* it was too big, or we had no memory for it */
		return;

	if (m->refused) {
		/*
		 * The server is there, but doesn't have this page for us
		 * now: maybe it is still making it.  Text that needs it is
		 * set in a local face for a while, then we ask again
		 */
		lwsl_cx_notice(fr->cx, "%s/%04x refused, for now", p->r->path,
			       (unsigned int)p->page);
		p->holdoff_until = lws_now_usecs() +
				   (LWS_FONTS_PAGE_HOLDOFF_S * LWS_US_PER_SEC);
		p->nomem = 0;
		return;
	}

	if (!m->complete) {
		lwsl_cx_notice(fr->cx, "%s/%04x unavailable", p->r->path,
			       (unsigned int)p->page);
		lws_fonts_remote_set_down(fr);
		return;
	}

	/* the pieces it came in become the page */

	if (fontss_piece_done(m)) {
		lws_fonts_page_nomem(p);
		return;
	}

	lws_buflist_destroy_all_segments(&p->bl);
	p->bl = m->bl;
	m->bl = NULL;

	switch (lws_mcufont_page_arrived(p, m->pos)) {
	case 0:
		break;
	case -1:
		lws_mcufont_page_free(p);
		lws_fonts_page_nomem(p);
		break;
	default:
		lws_mcufont_page_free(p);
		p->bad = 1;
		break;
	}
}

static lws_ss_state_return_t
_fontss_state(void *userobj, void *sh, lws_ss_constate_t state,
	      lws_ss_tx_ordinal_t ack)
{
	fontss_t *m = (fontss_t *)userobj;
	lws_fonts_remote_t *fr = m->fr;

	switch (state) {
	case LWSSSCS_QOS_NACK_REMOTE:
		/* eg, a 404: what came was the error page */
		m->refused = 1;
		return LWSSSSRET_DESTROY_ME;

	case LWSSSCS_QOS_ACK_REMOTE:
	case LWSSSCS_UNREACHABLE:
	case LWSSSCS_ALL_RETRIES_FAILED:
	case LWSSSCS_DISCONNECTED:
		return LWSSSSRET_DESTROY_ME;

	case LWSSSCS_DESTROYING:
		if (m->parsing)
			lejp_destruct(&m->jctx);

		if (fr) {
			if (fr->cx->being_destroyed) {
				/* the context is going: nothing more to do */
				if (m->p)
					fr->ss_page = NULL;
				else
					fr->ss_manifest = NULL;
			} else {
				fontss_finished(m);
				lws_fonts_remote_wake(fr);
				lws_fonts_remote_kick(fr);
			}
		}

		lwsac_free(&m->a.ac);
		lws_buflist_destroy_all_segments(&m->bl);
		lws_free_set_NULL(m->piece);
		break;

	default:
		break;
	}

	return LWSSSSRET_OK;
}

static lws_ss_state_return_t
fontss_state(void *userobj, void *sh, lws_ss_constate_t state,
	     lws_ss_tx_ordinal_t ack)
{
	lws_alloc_arena_t a = lws_alloc_arena_set(LWS_ALLOC_ARENA_BULK);
	lws_ss_state_return_t r = _fontss_state(userobj, sh, state, ack);

	lws_alloc_arena_set(a);

	return r;
}
static int
lws_fonts_remote_notify(struct lws_state_manager *mgr,
			struct lws_state_notify_link *link, int current,
			int target)
{
	lws_fonts_remote_t *fr = lws_container_of(link, lws_fonts_remote_t,
						  notify);

	if (target == LWS_SYSTATE_OPERATIONAL)
		lws_fonts_manifest_start(fr);

	return 0;
}

int
lws_fonts_register_manifest(struct lws_context *cx, const char *url)
{
	lws_fonts_remote_t *fr;
	int local = 0;

	if (cx->fonts_remote) {
		lwsl_cx_err(cx, "font manifest already registered");
		return 1;
	}

	/* we must always be able to show text, if not as intended */

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&cx->fonts)) {
		lws_display_font_t *f = lws_container_of(d,
						lws_display_font_t, list);

		if (!f->priv)
			local = 1;
	} lws_end_foreach_dll(d);

	if (!local) {
		lwsl_cx_err(cx, "register a font in flash before the manifest");
		return 1;
	}

	fr = lws_zalloc(sizeof(*fr), __func__);
	if (!fr)
		return 1;

	fr->url = lws_strdup(url);
	if (!fr->url) {
		lws_free(fr);
		return 1;
	}

	fr->cx = cx;
	fr->notify.notify_cb = lws_fonts_remote_notify;
	fr->notify.name = "fonts";
	cx->fonts_remote = fr;

	if (cx->mgr_system.state >= LWS_SYSTATE_OPERATIONAL)
		lws_fonts_remote_notify(&cx->mgr_system, &fr->notify,
					cx->mgr_system.state,
					LWS_SYSTATE_OPERATIONAL);
	else
		lws_state_reg_notifier(&cx->mgr_system, &fr->notify);

	return 0;
}

/*
 * Layout must not start choosing faces while the manifest that lists most
 * of them is on its way, the first time (and asking for it starts it, if
 * nothing did yet).  After that, or if it failed, it goes on with what
 * there is.
 */

int
lws_fonts_remote_manifest_pending(struct lws_context *cx, lws_font_waiter_t *w)
{
	lws_fonts_remote_t *fr = cx->fonts_remote;

	if (!fr)
		return 0;

	lws_fonts_manifest_start(fr);
	if (fr->manifest_state != LWS_FONTS_MANIFEST_FETCHING)
		return 0;

	lws_fonts_remote_wait(fr, w);

	return 1;
}

/* exactly as the server's encoder works it out */

static uint16_t
lws_mcufont_family_lh(const lws_mcufont_family_t *fam, uint32_t size)
{
	return (uint16_t)(((fam->height * size) + (fam->units_per_em / 2)) /
			  fam->units_per_em);
}

static uint32_t
lws_mcufont_lh_diff(uint32_t a, uint32_t b)
{
	return a > b ? a - b : b - a;
}

static lws_mcufont_remote_t *
lws_mcufont_family_made(lws_mcufont_family_t *fam, uint16_t size)
{
	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&fam->sizes_made)) {
		lws_display_font_t *f = lws_container_of(d, lws_display_font_t,
							 list);
		lws_mcufont_remote_t *r = mcuf_remote(f);

		if (r->size == size)
			return r;
	} lws_end_foreach_dll(d);

	return NULL;
}

/*
 * The size of the family whose line height is closest to want, or if as
 * many sizes as we keep are made already, the closest of those.  If that size
 * can't be had now, its core page isn't here and can't be fetched now (no
 * memory for it, the server failed us, or its copy is bad), the closest size
 * whose core page is here.  Returns nonzero if there's none of those either
 */

int
lws_mcufont_family_pick(lws_mcufont_family_t *fam, unsigned int want,
			uint16_t *size, uint16_t *line_height)
{
	uint32_t best = 0, bd = 0xffffffff, s, d, c;
	lws_mcufont_remote_t *r;
	uint64_t w;
	uint16_t n;

	if (fam->sizes_made.count >= LWS_FONTS_FAMILY_MAX_SIZES) {
		lws_start_foreach_dll(struct lws_dll2 *, dd,
				      lws_dll2_get_head(&fam->sizes_made)) {
			lws_display_font_t *f = lws_container_of(dd,
						lws_display_font_t, list);

			d = lws_mcufont_lh_diff(f->choice.fixed_height, want);
			if (d < bd) {
				bd = d;
				best = mcuf_remote(f)->size;
			}
		} lws_end_foreach_dll(dd);
	} else {
		/*
		 * The line height grows with the size, so the size closest to
		 * want in each run is the one that wants it exactly, or next to
		 * it, or else the end of the run nearest it
		 */
		w = (((uint64_t)want * fam->units_per_em) +
		     (fam->height / 2)) / fam->height;
		c = w > LWS_FONTS_SIZE_MAX ? LWS_FONTS_SIZE_MAX : (uint32_t)w;

		for (n = 0; n < fam->nsizes; n++)
			for (s = c ? c - 1 : 0; s <= c + 1; s++) {
				uint32_t t = s;

				if (t < fam->sizes[n * 2])
					t = fam->sizes[n * 2];
				if (t > fam->sizes[(n * 2) + 1])
					t = fam->sizes[(n * 2) + 1];

				d = lws_mcufont_lh_diff(
					lws_mcufont_family_lh(fam, t), want);
				if (d < bd || (d == bd && t < best)) {
					bd = d;
					best = t;
				}
			}
	}

	*size = (uint16_t)best;
	*line_height = lws_mcufont_family_lh(fam, best);

	r = lws_mcufont_family_made(fam, *size);
	if (r ? lws_mcufont_page_available(r,
			lws_mcufont_remote_page(r, r->ranges[0], 0)) :
		!lws_fonts_remote_down(fam->fr))
		return 0;

	/* the face in another size that is here is closer than a local one */

	bd = 0xffffffff;
	lws_start_foreach_dll(struct lws_dll2 *, dd,
			      lws_dll2_get_head(&fam->sizes_made)) {
		lws_display_font_t *f = lws_container_of(dd,
					lws_display_font_t, list);
		lws_mcufont_page_t *p;

		r = mcuf_remote(f);
		p = lws_mcufont_remote_page(r, r->ranges[0], 0);
		if (p && lws_mcufont_page_resident(p)) {
			d = lws_mcufont_lh_diff(f->choice.fixed_height, want);
			if (d < bd) {
				bd = d;
				best = r->size;
			}
		}
	} lws_end_foreach_dll(dd);

	if (bd == 0xffffffff)
		return 1;

	*size = (uint16_t)best;
	*line_height = lws_mcufont_family_lh(fam, best);

	return 0;
}

/*
 * The family at a size, made the first time it's wanted.  It's named as the
 * family is, and its pages are checked against that and its line height
 */

const lws_display_font_t *
lws_mcufont_family_face(lws_mcufont_family_t *fam, uint16_t size)
{
	size_t pl = strlen(fam->path) + 5; /* "/255" and the NUL */
	lws_mcufont_remote_t *r = lws_mcufont_family_made(fam, size);
	lws_display_font_t *a;

	if (r)
		return r->f;

	a = lws_zalloc(sizeof(*a) + sizeof(*r) + pl, __func__);
	if (!a)
		return NULL;
	r = (lws_mcufont_remote_t *)&a[1];

	r->kind = LWS_MCUF_KIND_REMOTE;
	r->fr = fam->fr;
	r->cx = fam->fr->cx;
	r->f = a;
	r->fam = fam;
	r->size = size;
	r->nranges = fam->nranges;
	r->ranges = fam->ranges;
	lws_snprintf((char *)&r[1], pl, "%s/%u", fam->path, size);
	r->path = (const char *)&r[1];

	a->priv = (uint8_t *)r;
	a->choice.family_name = fam->f->choice.family_name;
	a->choice.fixed_height = lws_mcufont_family_lh(fam, size);

	lws_font_init_common(a);
	lws_dll2_add_tail(&a->list, &fam->sizes_made);

	return a;
}

static int
lws_mcufont_page_fetching(lws_mcufont_page_t *p)
{
	return p->r->fr->ss_page &&
	       ((fontss_t *)lws_ss_to_user_object(p->r->fr->ss_page))->p == p;
}

/*
 * Layout gave up waiting for the manifest, or a page: the server is too slow
 * to be useful now.  Without this, each element after would wait as long
 * again before giving up in its turn.  Layout goes on without the manifest
 * (it is still applied if it arrives), or uses the local faces for a while
 */

void
lws_fonts_remote_too_slow(struct lws_context *cx, int manifest)
{
	lws_fonts_remote_t *fr = cx->fonts_remote;

	if (!fr)
		return;

	lwsl_cx_notice(cx, "font %s too slow, using local faces",
		       manifest ? "manifest" : "server");

	if (!manifest) {
		lws_fonts_remote_set_down(fr);
		return;
	}

	if (fr->manifest_state == LWS_FONTS_MANIFEST_FETCHING)
		fr->manifest_state = LWS_FONTS_MANIFEST_RETRYING;
}

/* the page is wanted: whether it is here, coming, or can't be had now */

static lws_font_residency_t
lws_mcufont_page_want(lws_mcufont_remote_t *r, uint16_t page)
{
	lws_mcufont_page_t *p = lws_mcufont_remote_page(r, page, 1);

	if (!p)
		return LWS_FONT_UNAVAILABLE;

	if (lws_mcufont_page_resident(p)) {
		lws_reclaimable_touch(&p->rc);
		return LWS_FONT_RESIDENT;
	}

	if (!lws_mcufont_page_available(r, p))
		return LWS_FONT_UNAVAILABLE;

	if (!p->queue.owner && !lws_mcufont_page_fetching(p))
		lws_dll2_add_tail(&p->queue, &r->fr->queue);

	return LWS_FONT_PENDING;
}

/*
 * Whether the face can draw the utf8 text now: if its core page, and the
 * page of every codepoint in it, is resident.  Text NULL asks only about
 * the core page, ie, whether the face can be used for layout at all.  The
 * pages that aren't here are fetched; if any is being fetched, w is woken
 * when that completes.  If one can't be had for now, the text has to be set
 * in another face, but the others are still fetched for next time
 */

lws_font_residency_t
lws_mcufont_remote_resident(lws_mcufont_remote_t *r, const char *utf8,
			    size_t len, lws_font_waiter_t *w)
{
	lws_font_residency_t ret, worst;
	uint32_t page = r->ranges[0], last = 0x10000, unicode;
	size_t tlen = len;

	worst = lws_mcufont_page_want(r, (uint16_t)page);

	while (utf8 && tlen) {
		size_t ot = tlen;

		if (lws_dlo_utf8_unicode(utf8, &tlen, &unicode)) {
			utf8++;
			continue;
		}
		utf8 += ot - tlen;

		page = lws_mcufont_remote_page_of(r, unicode);
		if (page == last || page == r->ranges[0])
			continue;
		last = page;

		ret = lws_mcufont_page_want(r, (uint16_t)page);
		if (ret > worst)
			worst = ret;
	}

	if (worst == LWS_FONT_RESIDENT)
		return worst;

	if (worst == LWS_FONT_PENDING)
		lws_fonts_remote_wait(r->fr, w);
	lws_fonts_remote_kick(r->fr);

	/* the kick may have found the server can't be reached */
	if (worst == LWS_FONT_PENDING && lws_fonts_remote_down(r->fr)) {
		if (w)
			lws_dll2_remove(&w->list);
		return LWS_FONT_UNAVAILABLE;
	}

	return worst;
}

/*
 * The blob with the glyph for unicode in it, if it is resident: the page the
 * codepoint is on, or the core page if the face doesn't have that page.  It
 * is the page's prefix, and the rest of it is through *core
 */

const uint8_t *
lws_mcufont_remote_blob(lws_mcufont_remote_t *r, uint32_t unicode,
			size_t *len, lws_mcuf_core_t **core)
{
	lws_mcufont_page_t *p = lws_mcufont_remote_page(r,
				lws_mcufont_remote_page_of(r, unicode), 0);

	if (!p || !lws_mcufont_page_resident(p))
		return NULL;

	lws_reclaimable_touch(&p->rc);
	*len = p->core.blob_len;
	*core = &p->core;

	return p->core.prefix;
}

/*
 * Pin (or with pin 0, unpin) every resident page of the face.  A page that
 * arrives meanwhile is pinned as many times as the face is
 */

void
lws_mcufont_remote_pin(lws_mcufont_remote_t *r, int pin)
{
	if (!pin && !r->pins)
		return;

	r->pins = (uint16_t)(pin ? r->pins + 1 : r->pins - 1);

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&r->pages)) {
		lws_mcufont_page_t *p = lws_container_of(d, lws_mcufont_page_t,
							 list);
		if (lws_mcufont_page_resident(p))
			p->rc.pins = r->pins;
	} lws_end_foreach_dll(d);
}

static void
lws_mcufont_remote_destroy(lws_display_font_t *f)
{
	lws_mcufont_remote_t *r = mcuf_remote(f);

	while (lws_dll2_get_head(&r->pages)) {
		lws_mcufont_page_t *p = lws_container_of(
				lws_dll2_get_head(&r->pages),
				lws_mcufont_page_t, list);

		lws_reclaimable_remove(&p->rc);
		lws_dll2_remove(&p->queue);
		lws_dll2_remove(&p->list);
		lws_mcufont_page_free(p);
		lws_free(p);
	}

	lws_dll2_remove(&f->list);
	lws_free(f);
}

/* the sizes made of a family: the family itself is freed by the caller */

void
lws_mcufont_family_destroy(lws_display_font_t *f)
{
	lws_mcufont_family_t *fam = mcuf_family(f);

	if (!fam)
		return;

	while (lws_dll2_get_head(&fam->sizes_made))
		lws_mcufont_remote_destroy(lws_container_of(
				lws_dll2_get_head(&fam->sizes_made),
				lws_display_font_t, list));
}

/* the fetches refer to the faces: stop them before the faces go */

void
lws_fonts_remote_stop(struct lws_context *cx)
{
	lws_fonts_remote_t *fr = cx->fonts_remote;

	if (!fr)
		return;

	lws_state_reg_deregister(&fr->notify);
	lws_sul_cancel(&fr->sul_retry);

	/* the ss go without telling us any more */

	if (fr->ss_manifest)
		((fontss_t *)lws_ss_to_user_object(fr->ss_manifest))->fr = NULL;
	lws_ss_destroy(&fr->ss_manifest);
	if (fr->ss_page)
		((fontss_t *)lws_ss_to_user_object(fr->ss_page))->fr = NULL;
	lws_ss_destroy(&fr->ss_page);

	while (lws_dll2_get_head(&fr->waiters))
		lws_dll2_remove(lws_dll2_get_head(&fr->waiters));
}

void
lws_fonts_remote_free(struct lws_context *cx)
{
	lws_fonts_remote_t *fr = cx->fonts_remote;

	if (!fr)
		return;

	lwsl_cx_notice(cx, "pages fetched %u times, evicted %u times",
		       fr->fetches, fr->evictions);

	lwsac_free(&fr->ac);
	lws_free(fr->url);
	lws_free(fr);
	cx->fonts_remote = NULL;
}
#endif
