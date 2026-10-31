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
/* a page bigger than this is not something a small device should fetch */
#define LWS_FONTS_PAGE_MAX_LEN		(128 * 1024)
/* a page's buffer grows by this as it arrives */
#define LWS_FONTS_PAGE_GRANULE		4096
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
	unsigned int			line_height;
} lws_fonts_manifest_face_t;

typedef struct {
	lws_dll2_owner_t		fonts;
} lws_fonts_manifest_t;

static const lws_struct_map_t lsm_fonts_manifest_face[] = {
	LSM_CARRAY	(lws_fonts_manifest_face_t, name,	"name"),
	LSM_CARRAY	(lws_fonts_manifest_face_t, path,	"path"),
	LSM_CARRAY	(lws_fonts_manifest_face_t, pages,	"pages"),
	LSM_UNSIGNED	(lws_fonts_manifest_face_t, line_height, "line_height"),
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
	uint8_t				*buf;	/* the page as it arrives */
	size_t				pos;
	size_t				alloc;
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
 * The page's file, in the face's directory next to the manifest, eg,
 * ".../fonts.json" -> ".../FiraSansCondensed-Regular-14/0020.mcufont".  The
 * face's path has already been checked
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
		if (p->blob || p->bad)
			continue;

		if (lws_fonts_remote_url(fr, p, url, sizeof(url))) {
			p->bad = 1;
			continue;
		}

		lwsl_cx_info(fr->cx, "fetching %s", url);
		fr->ss_page = lws_fonts_remote_fetch(fr, p, url);
		if (fr->ss_page)
			return;

		lws_fonts_remote_set_down(fr);
		break;
	}

	/* nothing is coming: whoever waits for it can choose again */
	lws_fonts_remote_wake(fr);
}

static size_t
lws_mcufont_page_evict_cb(lws_reclaimable_t *rc)
{
	lws_mcufont_page_t *p = lws_container_of(rc, lws_mcufont_page_t, rc);
	size_t freed = rc->resident;

	lwsl_info("%s: %s %04x: %u\n", __func__, p->r->path,
		  (unsigned int)p->page, (unsigned int)freed);
	p->r->fr->evictions++;
	lws_free_set_NULL(p->blob);
	p->len = 0;
	rc->resident = 0;

	return freed;
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
	lws_reclaimable_add(&p->rc);
	lws_dll2_add_tail(&p->list, &r->pages);

	return p;
}

static int
lws_mcufont_page_available(const lws_mcufont_remote_t *r,
			   const lws_mcufont_page_t *p)
{
	if (p && p->blob)
		return 1;

	return !lws_fonts_remote_down(r->fr) &&
	       (!p || (!p->bad && lws_now_usecs() >= p->holdoff_until));
}

/*
 * A page's whole payload has arrived: if it is a page of the face the
 * manifest promised, and safe for the decoder, it becomes resident.  The
 * first page to arrive sets the face's header, that the others must match:
 * only the width and the baseline's x may differ, since each page is only
 * as wide as its own glyphs need
 */

static const uint8_t lws_mcufont_face_hdr[] = {
	MCUFO16_HEIGHT, MCUFO16_HEIGHT + 1,
	MCUFO16_BASELINE_Y, MCUFO16_BASELINE_Y + 1,
	MCUFO16_LINE_HEIGHT, MCUFO16_LINE_HEIGHT + 1,
	MCUFO_KERN_BANDS, MCUFO_KERN_GAP,
};

static int
lws_mcufont_page_arrived(lws_mcufont_page_t *p, uint8_t *blob, size_t len)
{
	lws_mcufont_remote_t *r = p->r;
	lws_display_font_t *f = r->f;
	const char *name;
	size_t n;

	if (lws_font_blob_check(blob, len, &name) ||
	    strcmp(name, f->choice.family_name) ||
	    lws_ser_ru16be(blob + MCUFO16_LINE_HEIGHT) !=
						f->choice.fixed_height)
		goto bad;

	if (r->hdr_valid) {
		for (n = 0; n < LWS_ARRAY_SIZE(lws_mcufont_face_hdr); n++)
			if (blob[lws_mcufont_face_hdr[n]] !=
					r->hdr[lws_mcufont_face_hdr[n]])
				goto bad;
	} else {
		memcpy(r->hdr, blob, sizeof(r->hdr));
		r->hdr_valid = 1;
		f->data = r->hdr;
		f->data_len = sizeof(r->hdr);
	}

	p->blob = blob;
	p->len = len;
	r->gen++;
	r->fr->fetches++;

	p->rc.resident = len;
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

static int
lws_fonts_manifest_hex(const char *s, size_t len, uint32_t *v)
{
	size_t n;

	if (!len || len > 4)
		return 1;

	*v = 0;
	for (n = 0; n < len; n++) {
		char c = s[n];

		*v <<= 4;
		if (c >= '0' && c <= '9')
			*v |= (uint32_t)(c - '0');
		else if (c >= 'a' && c <= 'f')
			*v |= (uint32_t)(c - 'a' + 10);
		else if (c >= 'A' && c <= 'F')
			*v |= (uint32_t)(c - 'A' + 10);
		else
			return 1;
	}

	return 0;
}

/*
 * The pages a face lists, like "0000-0005,0020,00a7", into first, last pairs
 * in ranges.  They must be in order and not overlap.  Returns the count of
 * pairs, or -1 if the list is bad
 */

static int
lws_fonts_manifest_pages(const char *pages, uint16_t *ranges, int max)
{
	struct lws_tokenize ts;
	lws_tokenize_elem e;
	int n = 0, dash = 0, have = 0;
	uint32_t v;

	lws_tokenize_init(&ts, pages, LWS_TOKENIZE_F_COMMA_SEP_LIST |
				      LWS_TOKENIZE_F_NO_INTEGERS |
				      LWS_TOKENIZE_F_NO_FLOATS);
	ts.len = strlen(pages);

	do {
		e = lws_tokenize(&ts);
		switch (e) {
		case LWS_TOKZE_TOKEN:
			if (lws_fonts_manifest_hex(ts.token, ts.token_len,
						   &v) || v > 0x10ff)
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

/* the manifest is parsed: register a face for each usable entry */

static void
lws_fonts_manifest_apply(lws_fonts_remote_t *fr, lws_fonts_manifest_t *man)
{
	uint16_t ranges[LWS_FONTS_MANIFEST_MAX_RANGES * 2];
	int n = 0, nr;

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&man->fonts)) {
		lws_fonts_manifest_face_t *e = lws_container_of(d,
					lws_fonts_manifest_face_t, list);
		lws_mcufont_remote_t *r;
		lws_display_font_t *a;

		if (n == LWS_FONTS_MANIFEST_MAX_FACES) {
			lwsl_cx_warn(fr->cx, "too many faces, ignoring the rest");
			break;
		}

		nr = lws_fonts_manifest_pages(e->pages, ranges,
					      LWS_FONTS_MANIFEST_MAX_RANGES);
		if (!e->name[0] || !lws_fonts_manifest_path_ok(e->path) ||
		    !e->line_height || e->line_height > 0xffff || nr <= 0) {
			lwsl_cx_warn(fr->cx, "ignoring bad entry '%s'", e->path);
			continue;
		}

		/* the face, its remote state and its page ranges, together */

		a = lws_zalloc(sizeof(*a) + sizeof(*r) +
			       ((size_t)nr * 2 * sizeof(uint16_t)), __func__);
		if (!a)
			break;
		r = (lws_mcufont_remote_t *)&a[1];

		r->kind = LWS_MCUF_KIND_REMOTE;
		r->fr = fr;
		r->cx = fr->cx;
		r->f = a;
		r->path = e->path;
		r->nranges = (uint16_t)nr;
		memcpy(&r[1], ranges, (size_t)nr * 2 * sizeof(uint16_t));
		r->ranges = (const uint16_t *)&r[1];

		a->priv = (uint8_t *)r;
		a->choice.family_name = e->name;
		a->choice.fixed_height = (uint16_t)e->line_height;

		lws_font_register_common(fr->cx, a);
		n++;
	} lws_end_foreach_dll(d);

	lwsl_cx_notice(fr->cx, "%d faces from %s", n, fr->url);
}

static void
lws_fonts_manifest_retry_cb(lws_sorted_usec_list_t *sul)
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
 * What arrives is only used once the stream ends without the server having
 * said it's an error: an http server sends its error page as the payload
 * too.  So the manifest is parsed and a page collected as they come, but
 * they are only applied when the stream is destroyed
 */

static lws_ss_state_return_t
fontss_rx(void *userobj, const uint8_t *buf, size_t len, int flags)
{
	fontss_t *m = (fontss_t *)userobj;
	uint8_t *nb;
	size_t na;
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

	/* a page, collected in a buffer grown as it comes */

	if (len > LWS_FONTS_PAGE_MAX_LEN - m->pos) {
		lwsl_cx_warn(m->fr->cx, "%s/%04x is too large", m->p->r->path,
			     (unsigned int)m->p->page);
		m->p->bad = 1;
		m->done = 1;
		return LWSSSSRET_DESTROY_ME;
	}

	if (m->pos + len > m->alloc) {
		na = m->pos + len + LWS_FONTS_PAGE_GRANULE;
		if (na > LWS_FONTS_PAGE_MAX_LEN)
			na = LWS_FONTS_PAGE_MAX_LEN;
		nb = lws_realloc(m->buf, na, __func__);
		if (!nb) {
			/*
			 * Not the server's fault: what is resident is all in
			 * use.  Use a local face instead for a little while
			 */
			lwsl_cx_notice(m->fr->cx, "no memory for %s/%04x",
				       m->p->r->path, (unsigned int)m->p->page);
			m->p->holdoff_until = lws_now_usecs() +
					      LWS_FONTS_NOMEM_HOLDOFF_US;
			m->done = 1;
			return LWSSSSRET_DESTROY_ME;
		}
		m->buf = nb;
		m->alloc = na;
	}

	if (len)
		memcpy(m->buf + m->pos, buf, len);
	m->pos += len;

	if (flags & LWSSS_FLAG_EOM)
		m->complete = 1;

	return LWSSSSRET_OK;
}

/* the stream is over: use what it brought, or note why it didn't */

static void
fontss_finished(fontss_t *m)
{
	lws_fonts_remote_t *fr = m->fr;
	lws_mcufont_page_t *p = m->p;
	uint8_t *nb;

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
		return;
	}

	if (!m->complete) {
		lwsl_cx_notice(fr->cx, "%s/%04x unavailable", p->r->path,
			       (unsigned int)p->page);
		lws_fonts_remote_set_down(fr);
		return;
	}

	/* give back what the buffer grew by beyond the page */

	if (m->pos && m->pos < m->alloc) {
		nb = lws_realloc(m->buf, m->pos, __func__);
		if (nb)
			m->buf = nb;
	}

	if (lws_mcufont_page_arrived(p, m->buf, m->pos))
		p->bad = 1;
	else
		m->buf = NULL; /* the page's now */
}

static lws_ss_state_return_t
fontss_state(void *userobj, void *sh, lws_ss_constate_t state,
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
		lws_free_set_NULL(m->buf);
		break;

	default:
		break;
	}

	return LWSSSSRET_OK;
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

/* the face can be chosen: its core page is here, or could be fetched now */

int
lws_mcufont_remote_available(const lws_mcufont_remote_t *r)
{
	return lws_mcufont_page_available(r, lws_mcufont_remote_page(
				(lws_mcufont_remote_t *)r, r->ranges[0], 0));
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

	if (p->blob) {
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
 * codepoint is on, or the core page if the face doesn't have that page
 */

const uint8_t *
lws_mcufont_remote_blob(lws_mcufont_remote_t *r, uint32_t unicode,
			size_t *len)
{
	lws_mcufont_page_t *p = lws_mcufont_remote_page(r,
				lws_mcufont_remote_page_of(r, unicode), 0);

	if (!p || !p->blob)
		return NULL;

	lws_reclaimable_touch(&p->rc);
	*len = p->len;

	return p->blob;
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
		if (p->blob)
			p->rc.pins = r->pins;
	} lws_end_foreach_dll(d);
}

void
lws_mcufont_remote_destroy(lws_display_font_t *f)
{
	lws_mcufont_remote_t *r = mcuf_remote(f);

	if (!r)
		return;

	while (lws_dll2_get_head(&r->pages)) {
		lws_mcufont_page_t *p = lws_container_of(
				lws_dll2_get_head(&r->pages),
				lws_mcufont_page_t, list);

		lws_reclaimable_remove(&p->rc);
		lws_dll2_remove(&p->queue);
		lws_dll2_remove(&p->list);
		lws_free(p->blob);
		lws_free(p);
	}

	f->data = NULL;
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
