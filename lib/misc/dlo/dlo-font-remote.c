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
 * and each face is fetched whole into the heap when text needs it, as a
 * reclaimable occupant that may be evicted and fetched again any number of
 * times.  See lws_fonts_register_manifest().
 */

#include <private-lib-core.h>
#include "private-lib-drivers-display-dlo.h"

#if defined(LWS_DLO_REMOTE_FONTS)

/* the manifest is small: a line per face */
#define LWS_FONTS_MANIFEST_MAX_LEN	16384
#define LWS_FONTS_MANIFEST_MAX_FACES	64
/* a face bigger than this is not something a small device should fetch */
#define LWS_FONTS_REMOTE_MAX_LEN	(256 * 1024)
/* after the server failed us, how long to use the local faces instead */
#define LWS_FONTS_REMOTE_HOLDOFF_S	30
/* after we couldn't find the memory for a face, how long to not try */
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
	struct lws_ss_handle		*ss_face; /* one face fetch at a time */
	struct lwsac			*ac;	/* the parsed manifest */
	lws_dll2_owner_t		queue;	/* lws_mcufont_remote_t to fetch */
	lws_dll2_owner_t		waiters; /* lws_font_waiter_t */
	lws_usec_t			down_until; /* local faces until then */
	unsigned int			fetches; /* faces fetched */
	unsigned int			evictions; /* faces given back */
	uint8_t				manifest_state;
	char				*url;
} lws_fonts_remote_t;

typedef struct {
	lws_dll2_t			list;
	char				name[64];
	char				file[64];
	unsigned int			line_height;
	unsigned int			len;
} lws_fonts_manifest_face_t;

typedef struct {
	lws_dll2_owner_t		fonts;
} lws_fonts_manifest_t;

static const lws_struct_map_t lsm_fonts_manifest_face[] = {
	LSM_CARRAY	(lws_fonts_manifest_face_t, name,	"name"),
	LSM_CARRAY	(lws_fonts_manifest_face_t, file,	"file"),
	LSM_UNSIGNED	(lws_fonts_manifest_face_t, line_height, "line_height"),
	LSM_UNSIGNED	(lws_fonts_manifest_face_t, len,	"len"),
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
	lws_mcufont_remote_t		*r;	/* NULL: this is the manifest */
	uint8_t				*buf;	/* the face as it arrives */
	size_t				pos;
	struct lejp_ctx			jctx;
	lws_struct_args_t		a;
	uint8_t				parsing:1;
	uint8_t				done:1;	/* the payload was used */
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
 * every face that is wanted meanwhile wait for its own failure
 */

static void
lws_fonts_remote_set_down(lws_fonts_remote_t *fr)
{
	fr->down_until = lws_now_usecs() +
			 (LWS_FONTS_REMOTE_HOLDOFF_S * LWS_US_PER_SEC);

	while (lws_dll2_get_head(&fr->queue))
		lws_dll2_remove(lws_dll2_get_head(&fr->queue));
}

/* the face's file next to the manifest: file has already been checked */

static int
lws_fonts_remote_url(lws_fonts_remote_t *fr, const char *file, char *url,
		     size_t len)
{
	const char *q = strchr(fr->url, '?'), *s;
	size_t bl;

	if (!q)
		q = fr->url + strlen(fr->url);
	s = q;
	while (s > fr->url && s[-1] != '/')
		s--;
	bl = lws_ptr_diff_size_t(s, fr->url);

	if (bl + strlen(file) + 1 > len)
		return 1;

	memcpy(url, fr->url, bl);
	lws_strncpy(url + bl, file, len - bl);

	return 0;
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
lws_fonts_remote_fetch(lws_fonts_remote_t *fr, lws_mcufont_remote_t *r,
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
	m->r = r;

	if (lws_ss_alloc_set_metadata(h, "endpoint", url, strlen(url)) ||
	    lws_ss_client_connect(h)) {
		lwsl_cx_warn(fr->cx, "unable to fetch %s", url);
		lws_ss_destroy(&h);
		return NULL;
	}

	return h;
}

/* fetch the next face that is waiting, if nothing is being fetched */

static void
lws_fonts_remote_kick(lws_fonts_remote_t *fr)
{
	lws_mcufont_remote_t *r;
	char url[256];

	if (fr->ss_face || fr->cx->being_destroyed)
		return;

	while (lws_dll2_get_head(&fr->queue)) {
		r = lws_container_of(lws_dll2_get_head(&fr->queue),
				     lws_mcufont_remote_t, queue);

		lws_dll2_remove(&r->queue);
		if (r->blob || r->bad)
			continue;

		if (lws_fonts_remote_url(fr, r->file, url, sizeof(url))) {
			r->bad = 1;
			continue;
		}

		lwsl_cx_info(fr->cx, "fetching %s", url);
		fr->ss_face = lws_fonts_remote_fetch(fr, r, url);
		if (fr->ss_face)
			return;

		lws_fonts_remote_set_down(fr);
		break;
	}

	/* nothing is coming: whoever waits for it can choose again */
	lws_fonts_remote_wake(fr);
}

static size_t
lws_mcufont_remote_evict_cb(lws_reclaimable_t *rc)
{
	lws_mcufont_remote_t *r = lws_container_of(rc, lws_mcufont_remote_t,
						   rc);
	size_t freed = rc->resident;

	lwsl_info("%s: %s: %u\n", __func__, r->file, (unsigned int)freed);
	r->fr->evictions++;
	lws_free_set_NULL(r->blob);
	r->f->data = NULL;
	rc->resident = 0;

	return freed;
}

/*
 * A face's whole payload has arrived: if it is the face the manifest
 * promised, and safe for the decoder, it becomes the face's .data
 */

static int
lws_mcufont_remote_arrived(lws_mcufont_remote_t *r, uint8_t *blob, size_t len)
{
	lws_display_font_t *f = r->f;
	const char *name;

	if (len != r->len ||
	    lws_font_blob_check(blob, len, &name) ||
	    strcmp(name, f->choice.family_name) ||
	    lws_ser_ru16be(blob + MCUFO16_LINE_HEIGHT) !=
						f->choice.fixed_height) {
		lwsl_cx_warn(r->fr->cx, "%s isn't the face the manifest "
			     "described, not using it", r->file);
		return 1;
	}

	r->blob = blob;
	r->gen++;
	r->fr->fetches++;
	f->data = blob;
	f->data_len = len;
	if (!f->em.whole && !f->em.frac)
		lws_font_set_em(f);

	r->rc.resident = len;
	lws_reclaimable_touch(&r->rc);

	return 0;
}

static int
lws_fonts_manifest_file_ok(const char *file)
{
	const char *p = file;

	/*
	 * Only a plain name, so the face is fetched from beside the manifest
	 * whatever the manifest says: no path, scheme or escapes
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

/* the manifest is parsed: register a face for each usable entry */

static void
lws_fonts_manifest_apply(lws_fonts_remote_t *fr, lws_fonts_manifest_t *man)
{
	int n = 0;

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

		if (!e->name[0] || !lws_fonts_manifest_file_ok(e->file) ||
		    !e->line_height || e->line_height > 0xffff ||
		    e->len < MCUFO_HDR_LEN || e->len > LWS_FONTS_REMOTE_MAX_LEN) {
			lwsl_cx_warn(fr->cx, "ignoring bad entry '%s'", e->file);
			continue;
		}

		/* the face and its remote state, freed together */

		a = lws_zalloc(sizeof(*a) + sizeof(*r), __func__);
		if (!a)
			break;
		r = (lws_mcufont_remote_t *)&a[1];

		r->kind = LWS_MCUF_KIND_REMOTE;
		r->fr = fr;
		r->cx = fr->cx;
		r->f = a;
		r->file = e->file;
		r->len = e->len;
		r->rc.evict = lws_mcufont_remote_evict_cb;
		lws_reclaimable_add(&r->rc);

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

static lws_ss_state_return_t
fontss_rx(void *userobj, const uint8_t *buf, size_t len, int flags)
{
	fontss_t *m = (fontss_t *)userobj;
	lws_fonts_remote_t *fr = m->fr;
	int n;

	if (m->done)
		return LWSSSSRET_OK;

	if (!m->r) {
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
			lwsl_cx_warn(fr->cx, "manifest too large");
			return LWSSSSRET_DESTROY_ME;
		}

		n = lejp_parse(&m->jctx, buf, (int)len);
		if (n < 0 && n != LEJP_CONTINUE) {
			lwsl_cx_warn(fr->cx, "manifest JSON: %s",
				     lejp_error_to_string(n));
			return LWSSSSRET_DESTROY_ME;
		}

		if (!(flags & LWSSS_FLAG_EOM))
			return LWSSSSRET_OK;

		if (n < 0 || !m->a.dest) {
			lwsl_cx_warn(fr->cx, "manifest incomplete");
			return LWSSSSRET_DESTROY_ME;
		}

		/* the faces' names and files stay in the manifest's ac */

		fr->ac = m->a.ac;
		m->a.ac = NULL;
		m->done = 1;
		fr->manifest_state = LWS_FONTS_MANIFEST_DONE;
		lws_fonts_manifest_apply(fr, (lws_fonts_manifest_t *)m->a.dest);

		return LWSSSSRET_DESTROY_ME;
	}

	/* a face */

	if (!m->buf) {
		m->buf = lws_malloc(m->r->len, __func__);
		if (!m->buf) {
			/*
			 * Not the server's fault: what is resident is all in
			 * use.  Use a local face instead for a little while
			 */
			lwsl_cx_notice(fr->cx, "no memory for %s", m->r->file);
			m->r->nomem_until = lws_now_usecs() +
					    LWS_FONTS_NOMEM_HOLDOFF_US;
			m->done = 1;
			return LWSSSSRET_DESTROY_ME;
		}
	}

	if (len > m->r->len - m->pos) {
		lwsl_cx_warn(fr->cx, "%s longer than the manifest says",
			     m->r->file);
		m->r->bad = 1;
		return LWSSSSRET_DESTROY_ME;
	}

	memcpy(m->buf + m->pos, buf, len);
	m->pos += len;

	if (!(flags & LWSSS_FLAG_EOM))
		return LWSSSSRET_OK;

	m->done = 1;
	if (lws_mcufont_remote_arrived(m->r, m->buf, m->pos))
		m->r->bad = 1;
	else
		m->buf = NULL; /* the face's now */

	return LWSSSSRET_DESTROY_ME;
}

static lws_ss_state_return_t
fontss_state(void *userobj, void *sh, lws_ss_constate_t state,
	     lws_ss_tx_ordinal_t ack)
{
	fontss_t *m = (fontss_t *)userobj;
	lws_fonts_remote_t *fr = m->fr;

	switch (state) {
	case LWSSSCS_UNREACHABLE:
	case LWSSSCS_ALL_RETRIES_FAILED:
	case LWSSSCS_QOS_NACK_REMOTE:
	case LWSSSCS_DISCONNECTED:
		if (!m->done)
			/* it isn't coming this time */
			return LWSSSSRET_DESTROY_ME;
		break;

	case LWSSSCS_DESTROYING:
		if (m->parsing)
			lejp_destruct(&m->jctx);
		lwsac_free(&m->a.ac);
		lws_free_set_NULL(m->buf);

		if (!fr)
			break;

		if (fr->cx->being_destroyed) {
			/* the context is going: nothing more to do */
			if (m->r)
				fr->ss_face = NULL;
			else
				fr->ss_manifest = NULL;
			break;
		}

		if (!m->r) {
			fr->ss_manifest = NULL;
			if (fr->manifest_state != LWS_FONTS_MANIFEST_DONE) {
				/*
				 * Layout goes on with the local faces while
				 * we keep trying in the background
				 */
				lwsl_cx_notice(fr->cx, "font manifest %s "
					       "unavailable, retrying", fr->url);
				fr->manifest_state = LWS_FONTS_MANIFEST_RETRYING;
				lws_sul_schedule(fr->cx, 0, &fr->sul_retry,
						 lws_fonts_manifest_retry_cb,
						 LWS_FONTS_REMOTE_HOLDOFF_S *
							LWS_US_PER_SEC);
			}
		} else {
			fr->ss_face = NULL;
			if (!m->done && !m->r->bad) {
				lwsl_cx_notice(fr->cx, "%s unavailable",
					       m->r->file);
				lws_fonts_remote_set_down(fr);
			}
		}

		lws_fonts_remote_wake(fr);
		lws_fonts_remote_kick(fr);
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

int
lws_mcufont_remote_available(const lws_mcufont_remote_t *r)
{
	return r->blob || (!r->bad && !lws_fonts_remote_down(r->fr) &&
			   lws_now_usecs() >= r->nomem_until);
}

static int
lws_mcufont_remote_fetching(lws_mcufont_remote_t *r)
{
	return r->fr->ss_face &&
	       ((fontss_t *)lws_ss_to_user_object(r->fr->ss_face))->r == r;
}

/*
 * Layout gave up waiting for the manifest, or a face: the server is too slow
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

lws_font_residency_t
lws_mcufont_remote_resident(lws_mcufont_remote_t *r, lws_font_waiter_t *w)
{
	lws_fonts_remote_t *fr = r->fr;

	if (r->blob) {
		lws_reclaimable_touch(&r->rc);
		return LWS_FONT_RESIDENT;
	}

	if (!lws_mcufont_remote_available(r))
		return LWS_FONT_UNAVAILABLE;

	if (!r->queue.owner && !lws_mcufont_remote_fetching(r))
		lws_dll2_add_tail(&r->queue, &fr->queue);

	lws_fonts_remote_wait(fr, w);
	lws_fonts_remote_kick(fr);

	/* the kick may have found it can't be had */
	if (!lws_mcufont_remote_available(r)) {
		if (w)
			lws_dll2_remove(&w->list);
		return LWS_FONT_UNAVAILABLE;
	}

	return LWS_FONT_PENDING;
}

void
lws_mcufont_remote_destroy(lws_display_font_t *f)
{
	lws_mcufont_remote_t *r = mcuf_remote(f);

	if (!r)
		return;

	lws_reclaimable_remove(&r->rc);
	lws_dll2_remove(&r->queue);
	lws_free_set_NULL(r->blob);
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
	if (fr->ss_face)
		((fontss_t *)lws_ss_to_user_object(fr->ss_face))->fr = NULL;
	lws_ss_destroy(&fr->ss_face);

	while (lws_dll2_get_head(&fr->waiters))
		lws_dll2_remove(lws_dll2_get_head(&fr->waiters));
}

void
lws_fonts_remote_free(struct lws_context *cx)
{
	lws_fonts_remote_t *fr = cx->fonts_remote;

	if (!fr)
		return;

	lwsl_cx_notice(cx, "faces fetched %u times, evicted %u times",
		       fr->fetches, fr->evictions);

	lwsac_free(&fr->ac);
	lws_free(fr->url);
	lws_free(fr);
	cx->fonts_remote = NULL;
}
#endif
