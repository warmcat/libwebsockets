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
 * Secure Streams as DLO transport
 */

#include <private-lib-core.h>
#include "private-lib-drivers-display-dlo.h"

#if defined(LWS_WITH_LHP)

/*
 * Upper bound on how many assets (images, stylesheets) one document may have
 * being fetched at the same time... each one costs a connection and a rx
 * window, so an unbounded number of them is fatal on the small targets.
 * Further assets up to LWS_DLO_MAX_TRACKED_ASSETS are queued and started as
 * in-flight assets complete; beyond that, they are dropped.
 */

#define LWS_DLO_MAX_CONCURRENT_ASSETS	16
#define LWS_DLO_MAX_TRACKED_ASSETS	128

/*
 * ... and how many may be in flight to the same scheme://host[:port] at once.
 * Servers rate-limit parallel connections from one client: blasting a dozen
 * TLS connections at one CDN gets the extra ones silently hung until they
 * time out.  Browsers keep this small for the same reason.
 */

#define LWS_DLO_MAX_CONCURRENT_PER_HOST	4

LWS_SS_USER_TYPEDEF
	struct lws_context		*cx; /* m->ss is already NULL by
					      * the time DESTROYING arrives */
	sul_cb_t			on_rx;
	lhp_ctx_t			*lhp;
	lws_sorted_usec_list_t		*ssevsul; /* sul to use to resume rz */
	lws_sorted_usec_list_t		sul; /* used for initial metadata cb */
	lws_dlo_image_t			u; /* we use the lws_flow_t in here */
	lws_dll2_t			active_asset_list; /*cx->active_assets*/
#if defined(LWS_WITH_CACHE_BLOB)
	struct lws_buflist		*cache_bl; /* whole-payload mirror for
						 * the asset cache */
	uint8_t				*cache_hit; /* deferred css feed */
	size_t				cache_hit_len;
#endif
	uint8_t				type; /* LWSDLOSS_TYPE_ */
	uint8_t				inflight:1; /* holds a fetch slot */
	uint8_t				retrying:1; /* never connected, the ss
						     * is in its backoff wait */
	uint8_t				connected:1; /* got as far as CONNECTED */
	uint8_t				cl_checked:1; /* response length looked at */
	uint8_t				no_cache:1; /* don't cache this asset */
	uint8_t				in_cache:1; /* the whole payload is in the
						     * asset cache: renewable */
	uint8_t				hl; /* chars of url that are scheme://host */
	char				url[LHP_URL_LEN];
} dloss_t;


/*
 * Complete any side of the image dlo box the css left unset: both sides unset
 * take the intrinsic size, a single unset side follows the intrinsic aspect
 * ratio (css replaced-element sizing, eg background-size: 146px).  Called as
 * soon as the image dimensions exist, so geometry is settled before the
 * layout dump or render can observe it
 */

static void
dlo_image_fill_missing_dims(lws_dlo_image_t *u)
{
	lws_dlo_t *dlo = &u->u.dlo_png->dlo;
	int iw = (int)lws_dlo_image_width(u);
	int ih = (int)lws_dlo_image_height(u);

	if (u->failed || iw <= 0 || ih <= 0)
		return;

	if (!dlo->box.w.whole && !dlo->box.h.whole) {
		dlo->box.w.whole = iw;
		dlo->box.h.whole = ih;
	} else {
		if (!dlo->box.h.whole)
			dlo->box.h.whole = (int32_t)
				(((int64_t)dlo->box.w.whole * ih) / iw);
		if (!dlo->box.w.whole)
			dlo->box.w.whole = (int32_t)
				(((int64_t)dlo->box.h.whole * iw) / ih);
	}
}

/*
 * The whole payload of an image has arrived: from now the copy the dlo holds
 * (and its decoder) can be given back when memory is short, and renewed
 * from the asset cache before the next render.  Called after any magic
 * fixup has decided what kind of image it really is.  Without the asset
 * cache nothing is ever in_cache and this is a no-op.
 */

static void
dloss_arm_reclaim(dloss_t *m)
{
	if (!m->in_cache || !m->u.u.dlo_png || m->u.failed ||
	    m->u.u.dlo_png->flow.state != LWSDLOFLOW_STATE_READ_COMPLETED)
		return;

	if (m->u.u.dlo_png->dlo.render == lws_display_render_png)
		lws_display_dlo_png_reclaimable(m->u.u.dlo_png);
#if defined(LWS_WITH_JPEG)
	else if (m->u.u.dlo_jpeg->dlo.render == lws_display_render_jpeg)
		lws_display_dlo_jpeg_reclaimable(m->u.u.dlo_jpeg);
#endif
}

/*
 * dlo images call back here when they have their dimensions (or have failed)
 */

void
lws_lhp_image_dimensions_cb(lws_sorted_usec_list_t *sul)
{
	dloss_t *m = lws_container_of(sul, dloss_t, sul);
	lws_display_render_state_t *rs;
	lws_dlo_t *dlo = &m->u.u.dlo_png->dlo;

	if (m->u.failed) {
		dlo->box.w.whole = -1;
		dlo->box.h.whole = -1;
		lwsl_notice("%s: Failing %s\n", __func__, m->url);
	} else {

		/*
		 * Fill in missing dimensions only: css or element
		 * attributes may have sized the dlo already, and they take
		 * priority over the intrinsic size.  This can run after the
		 * last layout pass, when a document deferred completion for
		 * its assets, so there would be nothing later to restore
		 * the css size with
		 */

		dlo_image_fill_missing_dims(&m->u);

		lwsl_info("%s: setting dlo box %d x %d\n", __func__,
			(int)dlo->box.w.whole, (int)dlo->box.h.whole);

		/*
		 * The dimensions are captured in the dlo box now: from here
		 * the payload and decoder can be given back when memory is
		 * short, if the asset cache can renew them
		 */
		dloss_arm_reclaim(m);

		/*
		 * The html parse is stalled on these dimensions; when it
		 * resumes, the layout places the image with them.  Nothing
		 * else in the display list needs adjusting here.
		 */
	}

	/*
	 * The document these dimensions were for may already be gone
	 * (lws_dlo_ss_detach_lhp() from its stream's DESTROYING): then
	 * there is no parse to resume and no sul of its to schedule
	 */
	if (!m->ssevsul)
		return;

	rs = lws_container_of(m->ssevsul, lws_display_render_state_t, sul);
	if (rs->html != 1 || !m->lhp) {
		lws_sul_schedule(lws_ss_get_context(m->ss), 0, m->ssevsul, m->on_rx, 1);
		return;
	}

	/* we are resuming the html parsing */
	lws_lhp_ss_html_parse_from_lhp(m->lhp);
}

#if defined(LWS_WITH_SECURE_STREAMS)

/*
 * The html document's own stream may be over while assets it refers to are
 * still fetching or queued: a document defers deciding it is complete until
 * this says none are left.  Assets that finished (but are still tracked for
 * url dedup) do not hold the document up.
 */

static int
dlo_asset_holds_layout_up(const dloss_t *ds)
{
	if (!ds->inflight && !ds->retrying)
		return 0; /* nothing is coming: it cannot hold anything up */

	/*
	 * A stylesheet has to arrive whole before the cascade is right, so
	 * the layout waits for all of it.
	 */

	if (ds->type == LWSDLOSS_TYPE_CSS)
		return 1;

	/*
	 * An image is different: all the layout wants from it is its
	 * dimensions, which come out of the first part of the payload.  Once
	 * those are known (or it failed), the rest of it is pixel data that
	 * nothing needs until the raster sweep reaches the image... and the
	 * raster is downstream of the document completing.
	 *
	 * Holding the document open for the whole payload meant every byte
	 * of every image had to be buflisted first, with no consumer and so
	 * no backpressure: a 45KB page of images on a target with 100KB of
	 * heap has nowhere to put them.
	 */

	if (ds->u.failed || lws_dlo_image_width(&ds->u))
		return 0;

	return 1;
}

static int
dlo_assets_outstanding(struct lws_context *cx)
{
	/* a queued asset has not started, so it has no dimensions yet */

	if (cx->pending_assets.head)
		return 1;

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&cx->active_assets)) {
		dloss_t *ds = lws_container_of(d, dloss_t, active_asset_list);

		if (dlo_asset_holds_layout_up(ds))
			return 1;
	} lws_end_foreach_dll(d);

	return 0;
}

/*
 * The last outstanding asset finished: resume a document that deferred
 * deciding it was complete until its assets were done
 */
static void
dlo_assets_maybe_drained(struct lws_context *cx, lhp_ctx_t *lhp)
{
	/* a cancelled document must not be resumed by its assets draining */

	if (lhp && !lhp->cancelled && lhp->await_assets &&
	    !dlo_assets_outstanding(cx)) {
		lhp->await_assets = 0;
		lws_lhp_ss_html_parse_from_lhp(lhp);
	}
}

/*
 * How many assets may be actually fetching at once.  Each one holds a
 * connection, an fd, for its lifetime, so the ceiling adapts to the fd budget
 * of the context, leaving room for the document connection and the event
 * loop's own fds.  Targets with tiny fd tables end up serializing their
 * fetches instead of failing them.
 */

static unsigned int
dlo_asset_inflight_max(struct lws_context *cx)
{
	int n = ((int)cx->fd_limit_per_thread - 4) / 2;

	if (n < 1)
		n = 1;
	if (n > LWS_DLO_MAX_CONCURRENT_ASSETS)
		n = LWS_DLO_MAX_CONCURRENT_ASSETS;

	return (unsigned int)n;
}

/* how many tracked assets currently hold a fetch slot */

static int
dlo_asset_inflight_count(struct lws_context *cx)
{
	int n = 0;

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&cx->active_assets)) {
		dloss_t *ds = lws_container_of(d, dloss_t, active_asset_list);

		n += ds->inflight;
	} lws_end_foreach_dll(d);

	return n;
}

/* how many in-flight assets are going to this asset's scheme://host[:port] */

static int
dlo_asset_host_inflight(struct lws_context *cx, const dloss_t *cand)
{
	int n = 0;

	if (!cand->hl)
		/* file:///... has no host, nothing to be polite to */
		return 0;

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&cx->active_assets)) {
		dloss_t *ds = lws_container_of(d, dloss_t, active_asset_list);

		if (ds->inflight && ds->hl == cand->hl &&
		    !memcmp(ds->url, cand->url, cand->hl))
			n++;
	} lws_end_foreach_dll(d);

	return n;
}

/*
 * An in-flight asset completed (or was destroyed): bring the queue head
 * into the freed slot, if the queue has anyone on it.  Called from the ss
 * state / rx callbacks, so a nested kick from destroying a connect-failed
 * asset is safe: it just drains more of the same queue.
 */

static void
dlo_assets_kick(struct lws_context *cx);

static void
dlo_assets_kick_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_context *cx = lws_container_of(sul, struct lws_context,
						  sul_assets_kick);

	dlo_assets_kick(cx);
}

/*
 * Is the fd table full?  A client connect needs at least one fd (up to
 * LWS_MAX_PARALLEL_CONNS while its happy-eyeballs candidates race), and
 * failing at __insert_wsi_socket_into_fds() costs the asset one of its
 * retries, so don't start one that certainly can't get an fd.  Idle
 * keepalive connections to the CDNs hold fds too, so this can't demand
 * much headroom or a small table never starts anything.
 */

static int
dlo_assets_fds_short(struct lws_context *cx)
{
	struct lws_context_per_thread *pt = &cx->pt[0];

	return (unsigned int)pt->fds_count + 1 >= cx->fd_limit_per_thread;
}

static void
dlo_assets_kick(struct lws_context *cx)
{
	while (cx->pending_assets.head &&
	       dlo_asset_inflight_count(cx) < (int)dlo_asset_inflight_max(cx)) {
		dloss_t *ds = NULL;

		if (dlo_assets_fds_short(cx)) {
			/*
			 * Something else is using the fds right now (eg,
			 * the document connection's own parallel connects):
			 * come back for the queue shortly
			 */
			lws_sul_schedule(cx, 0, &cx->sul_assets_kick,
					 dlo_assets_kick_cb,
					 100 * LWS_US_PER_MS);
			break;
		}

		/*
		 * The queue head's server may already be at its per-host
		 * ceiling: a later, different-host asset can start past it
		 */

		lws_start_foreach_dll(struct lws_dll2 *, d,
				      lws_dll2_get_head(&cx->pending_assets)) {
			dloss_t *d1 = lws_container_of(d, dloss_t,
						       active_asset_list);

			if (dlo_asset_host_inflight(cx, d1) >=
						LWS_DLO_MAX_CONCURRENT_PER_HOST)
				continue;

			ds = d1;
			break;
		} lws_end_foreach_dll(d);

		if (!ds)
			/* every queued asset's server is at its ceiling */
			break;

		lws_dll2_remove(&ds->active_asset_list);
		lws_dll2_add_tail(&ds->active_asset_list,
				  &cx->active_assets);
		ds->inflight = 1;

		lwsl_notice("%s: kick %s\n", __func__, ds->url);

		if (!lws_ss_client_connect(ds->ss))
			continue;

		if (ds->retrying)
			/* it failed synchronously but is in its backoff
			 * wait: it comes back by itself at CONNECTING */
			continue;

		/* destroying it passes through DESTROYING, which re-kicks */
		lws_dll2_remove(&ds->active_asset_list);
		lws_ss_destroy(&ds->ss);
	}
}

/* secure streams payload interface */

/*
 * Stash rx payload for the asset type.  Raster images take it on the flow
 * buflist; gifs keep the whole payload retained separately, since an
 * interlaced gif must be re-decodeable from the start.  Returns nonzero on
 * failure.
 *
 * When the asset cache is active, also mirror the payload chunks as they
 * arrive: the decoders consume the flow buflist incrementally, so by the time
 * the payload has all arrived it can no longer be recovered from there for
 * the cache write-through.
 */

static int
dloss_rx_stash(dloss_t *m, const uint8_t *buf, size_t len)
{
	if (!len)
		return 0;

#if defined(LWS_WITH_CACHE_BLOB)
	if (!m->no_cache && m->type != LWSDLOSS_TYPE_GIF &&
	    lws_ss_get_context(m->ss)->dlo_asset_l1 && m->hl) {
		if (lws_buflist_append_segment(&m->cache_bl, buf, len) < 0) {
			/* we can't make a complete copy: don't cache a
			 * partial payload */
			lws_buflist_destroy_all_segments(&m->cache_bl);
			m->no_cache = 1;
		}
	}
#endif

#if defined(LWS_WITH_GIF)
	if (m->type == LWSDLOSS_TYPE_GIF)
		return lws_display_dlo_gif_rx(m->u.u.dlo_gif, buf, len);
#endif

	return lws_buflist_append_segment(&m->u.u.dlo_jpeg->flow.bl,
					  buf, len) < 0;
}

/*
 * If the payload's magic doesn't match the decoder implied by the url, the
 * server is lying about what it is sending: switch to the decoder the payload
 * says it is.  The .flow is at the same offset in the dlo image subclasses.
 * Returns nonzero if the switch could not be completed.
 */

static int
dloss_magic_fixup(dloss_t *m)
{
	uint8_t *p;
	size_t avail = lws_buflist_next_segment_len(&m->u.u.dlo_png->flow.bl, &p);

	if (m->type == LWSDLOSS_TYPE_PNG && avail >= 2 &&
	    p[0] == 0xff && p[1] == 0xd8) {
		 lwsl_warn("%s: fixing up PNG -> JPG\n", __func__);
		 lws_upng_free(&m->u.u.dlo_png->png);
		 m->u.u.dlo_jpeg->j = lws_jpeg_new();
		 if (!m->u.u.dlo_jpeg->j)
			 return 1;

		 m->u.u.dlo_jpeg->dlo.render = lws_display_render_jpeg;
		 m->u.u.dlo_jpeg->dlo._destroy = lws_display_dlo_jpeg_destroy;
		 m->type = LWSDLOSS_TYPE_JPEG;
		 m->u.type = LWSDLOSS_TYPE_JPEG;
	} else if (m->type == LWSDLOSS_TYPE_JPEG && avail >= 8 &&
		   p[0] == 0x89 && p[1] == 0x50 && p[2] == 0x4e && p[3] == 0x47 &&
		   p[4] == 0x0d && p[5] == 0x0a && p[6] == 0x1a && p[7] == 0x0a) {
		 lwsl_warn("%s: fixing up JPG -> PNG\n", __func__);
		 lws_jpeg_free(&m->u.u.dlo_jpeg->j);
		 m->u.u.dlo_png->png = lws_upng_new();
		 if (!m->u.u.dlo_png->png)
			 return 1;

		 m->u.u.dlo_png->dlo.render = lws_display_render_png;
		 m->u.u.dlo_png->dlo._destroy = lws_display_dlo_png_destroy;
		 m->type = LWSDLOSS_TYPE_PNG;
		 m->u.type = LWSDLOSS_TYPE_PNG;
	}

	return 0;
}

#if defined(LWS_WITH_CACHE_BLOB)

/*
 * The asset payload has all arrived: write it through to the context asset
 * cache, so it need not be fetched again while it is still valid
 */

static void
dloss_cache_write(dloss_t *m, struct lws_context *cx)
{
	lws_usec_t expiry = lws_now_usecs() +
			    (lws_usec_t)LWS_DLO_ASSET_CACHE_EXPIRY_S *
					    LWS_US_PER_SEC;
	size_t total, done = 0;
	uint8_t *buf;

	if (!cx->dlo_asset_l1 || m->no_cache || m->u.failed || !m->hl)
		return;

#if defined(LWS_WITH_GIF)
	if (m->type == LWSDLOSS_TYPE_GIF) {
		/* the gif dlo retains its whole payload until it renders */

		lws_dlo_gif_t *dg = m->u.u.dlo_gif;

		if (dg->whole_len)
			if (lws_cache_write_through(cx->dlo_asset_l1, m->url,
						    dg->whole, dg->whole_len,
						    expiry, NULL))
				lwsl_cx_info(cx, "cache write failed: %s",
					     m->url);

		return;
	}
#endif

	/* other image types were mirrored to cache_bl as they arrived */

	total = lws_buflist_total_len(&m->cache_bl);
	if (!total)
		return;

	buf = lws_malloc(total, __func__);
	if (!buf)
		return;

	while (lws_buflist_next_segment_len(&m->cache_bl, NULL)) {
		uint8_t *p;
		size_t len = lws_buflist_next_segment_len(&m->cache_bl, &p);

		memcpy(buf + done, p, len);
		done += len;

		lws_buflist_use_segment(&m->cache_bl, len);
	}

	if (lws_cache_write_through(cx->dlo_asset_l1, m->url, buf, total,
				    expiry, NULL))
		lwsl_cx_info(cx, "cache write failed: %s", m->url);
	else
		m->in_cache = 1;

	lws_free(buf);
}

/*
 * A still-valid copy of the whole asset payload came from the cache.  Stash
 * it and take the same steps as a fetch that just delivered its whole
 * payload, so layout and render proceed identically with no network at all.
 * Returns nonzero if the payload could not be used.
 */

static int
dloss_cache_feed(dloss_t *m, const uint8_t *data, size_t size)
{
	struct lws_context *cx = lws_ss_get_context(m->ss);
	lws_stateful_ret_t r;

	if (dloss_rx_stash(m, data, size))
		return 1;

	/* nothing more is coming on this asset */

	m->u.u.dlo_jpeg->flow.state = LWSDLOFLOW_STATE_READ_COMPLETED;
	m->in_cache = 1;

	if (!lws_dlo_image_width(&m->u)) {
		if (dloss_magic_fixup(m))
			return 1;

		lws_flow_feed(&m->u.u.dlo_jpeg->flow);
		r = lws_dlo_image_metadata_scan(&m->u);
		lws_flow_req(&m->u.u.dlo_jpeg->flow);

		if (r & LWS_SRET_FATAL)
			m->u.failed = 1;
		else
			if (r != LWS_SRET_WANT_INPUT)
				/* settle the geometry before anyone can
				 * observe it */
				dlo_image_fill_missing_dims(&m->u);
	}

	/*
	 * The html parse is stalled on these dimensions: the callback sets
	 * them (or marks the asset failed) and resumes it
	 */

	lws_sul_schedule(cx, 0, &m->sul, lws_lhp_image_dimensions_cb, 1);

	return 0;
}

#endif

#if defined(LWS_WITH_CACHE_BLOB)
/*
 * A cached stylesheet's payload is fed through the css rx path from the
 * event loop, not from inside lws_dlo_ss_create: create happens in the
 * middle of the html parse, and parsing the css synchronously would
 * reenter lws_lhp_parse on shared state
 */

static lws_ss_state_return_t
dloss_rx(void *userobj, const uint8_t *buf, size_t len, int flags);

static void
dloss_css_cache_feed_cb(lws_sorted_usec_list_t *sul)
{
	dloss_t *m = lws_container_of(sul, dloss_t, sul);
	struct lws_ss_handle *h = m->ss;

	dloss_rx(m, m->cache_hit, m->cache_hit_len, LWSSS_FLAG_EOM);

	lws_free_set_NULL(m->cache_hit);

	/* the css rx removed us from the active list at EOM; the handle
	 * has no dlo and no further purpose */

	lws_ss_destroy(&h);
}
#endif

static lws_ss_state_return_t
dloss_rx(void *userobj, const uint8_t *buf, size_t len, int flags)
{
	dloss_t *m = (dloss_t *)userobj;
	lws_stateful_ret_t r;

	lwsl_info("%s: %u\n", __func__, (unsigned int)len);

	if (m->type == LWSDLOSS_TYPE_CSS) {
		int awaited;

		if (!m->lhp) {
			/* the document this stylesheet was for is gone */
			lws_dll2_remove(&m->active_asset_list);
			dlo_assets_kick(lws_ss_get_context(m->ss));

			return LWSSSSRET_DISCONNECT_ME;
		}

		/*
		 * Streams for stylesheets complete out of order: only the
		 * stylesheet the html parse is waiting on may complete the
		 * await, a different one finishing early must not
		 */
		awaited = m->lhp->await_css_done &&
			  !strcmp(m->url, m->lhp->await_css_url);

#if defined(LWS_WITH_CACHE_BLOB)
		/* mirror the stylesheet payload for the cache write-through
		 * at EOM, like image rx chunks are */

		if (len && !m->no_cache &&
		    lws_ss_get_context(m->ss)->dlo_asset_l1 && m->hl) {
			if (lws_buflist_append_segment(&m->cache_bl, buf, len) < 0) {
				lws_buflist_destroy_all_segments(&m->cache_bl);
				m->no_cache = 1;
			}
		}
#endif

		if (awaited)
			m->lhp->finish_css = !!(flags & LWSSS_FLAG_EOM);
		m->lhp->is_css = 1;
		r = lws_lhp_parse(m->lhp, &buf, &len);
		m->lhp->is_css = 0;

		if (flags & LWSSS_FLAG_EOM) {
			lws_dll2_remove(&m->active_asset_list);
			/* the slot is free before the ss winds down */
			dlo_assets_kick(lws_ss_get_context(m->ss));
			dlo_assets_maybe_drained(lws_ss_get_context(m->ss), m->lhp);

#if defined(LWS_WITH_CACHE_BLOB)
			/* the stylesheet payload is all here: cache it */

			dloss_cache_write(m, lws_ss_get_context(m->ss));
#endif
		}

		if (r & LWS_SRET_FATAL)
			return LWSSSSRET_DISCONNECT_ME;

		if (r & LWS_SRET_AWAIT_RETRY) {
			/*
			 * If the parse just finished the awaited css, the
			 * await flag has been cleared by the parse: resume
			 * the html.  Otherwise, still waiting on some css,
			 * there is nothing to resume yet
			 */
			lwsl_warn("%s: returning to await retry\n", __func__);
			if (!m->lhp->await_css_done)
				lws_sul_schedule(lws_ss_get_context(m->ss), 0,
						 m->lhp->sshtmlevsul,
						 m->lhp->sshtmlevcb, 1);
		}
		goto okie;
	}

	/* .flow is at the same offset in both dlo_jpeg and dlo_png */

	/*
	 * A raster image payload is held whole on the flow buflist until the
	 * render consumes it, and the buflist won't take more than
	 * LWS_BUFLIST_OOM_LIMIT: if the response headers already say it can't
	 * fit, give it up at the first byte rather than after streaming 2MB
	 * of it just to fail at the end (real pages have 2 - 4MB hero images,
	 * and every one of them was fetched whole before being dropped).
	 * Checked here rather than at CONNECTED, which for a stream joining
	 * an existing h2 connection arrives before the response headers.
	 */

	if (!m->cl_checked) {
		uint64_t cl;

		m->cl_checked = 1;
		if (!lws_ss_http_rx_content_length(m->ss, &cl) &&
		    cl > LWS_BUFLIST_OOM_LIMIT) {
			lwsl_notice("%s: %s: %llu bytes, too large\n", __func__,
				    m->url, (unsigned long long)cl);
			m->u.failed = 1;
			m->u.u.dlo_jpeg->flow.state =
						LWSDLOFLOW_STATE_READ_COMPLETED;
			lws_sul_schedule(m->cx, 0, &m->sul,
					 lws_lhp_image_dimensions_cb, 1);
			return LWSSSSRET_DISCONNECT_ME;
		}
	}

	if (dloss_rx_stash(m, buf, len)) {
		m->u.failed = 1;
		lws_sul_schedule(lws_ss_get_context(m->ss), 0,
				&m->sul, lws_lhp_image_dimensions_cb, 1);
		return LWSSSSRET_DISCONNECT_ME;
	}

	// lwsl_notice("%s: buflen size %d\n", __func__,
	//	(int)lws_buflist_total_len(&m->u.u.dlo_jpeg->flow.bl));

	if (flags & LWSSS_FLAG_EOM) {
		m->u.u.dlo_jpeg->flow.state = LWSDLOFLOW_STATE_READ_COMPLETED;
		/*
		 * The asset's slot is free from the moment its payload has
		 * all arrived, even though the ss handle stays around on the
		 * active list for url dedup until its dlo goes away
		 */
		m->inflight = 0;
		dlo_assets_kick(lws_ss_get_context(m->ss));
		dlo_assets_maybe_drained(lws_ss_get_context(m->ss), m->lhp);

#if defined(LWS_WITH_CACHE_BLOB)
		/* the payload is all here: it can go into the asset cache */

		dloss_cache_write(m, lws_ss_get_context(m->ss));
#endif
	}

	if (!lws_dlo_image_width(&m->u)) {
		if (dloss_magic_fixup(m))
			return LWSSSSRET_DISCONNECT_ME;

		lws_flow_feed(&m->u.u.dlo_jpeg->flow);
		r = lws_dlo_image_metadata_scan(&m->u);
		lws_flow_req(&m->u.u.dlo_jpeg->flow);

		if (r & LWS_SRET_FATAL) {
			m->u.failed = 1;
			lws_sul_schedule(lws_ss_get_context(m->ss), 0,
					&m->sul, lws_lhp_image_dimensions_cb, 1);
			return LWSSSSRET_DISCONNECT_ME;
		}

		if (r != LWS_SRET_WANT_INPUT) {
			lwsl_info("%s: seen metadata\n", __func__);
			/* settle the geometry before anyone can observe it */
			dlo_image_fill_missing_dims(&m->u);
			lws_sul_schedule(lws_ss_get_context(m->ss), 0,
					&m->sul, lws_lhp_image_dimensions_cb, 1);
		} //else
			//lwsl_err("%s: metadata scan no end yet\n", __func__);

		return flags & LWSSS_FLAG_EOM ? LWSSSSRET_DISCONNECT_ME : LWSSSSRET_OK;
	}
okie:
	/* wake the raster: this may be the data the line it is on wants */
	if (m->ssevsul && m->on_rx)
		lws_sul_schedule(lws_ss_get_context(m->ss), 0, m->ssevsul,
				 m->on_rx, 1);

	return flags & LWSSS_FLAG_EOM ? LWSSSSRET_DISCONNECT_ME : LWSSSSRET_OK;
}

static lws_ss_state_return_t
dloss_state(void *userobj, void *sh, lws_ss_constate_t state,
	    lws_ss_tx_ordinal_t ack)
{
	dloss_t *m = (dloss_t *)userobj;

	switch (state) {
	case LWSSSCS_CREATING:
		break;

	case LWSSSCS_CONNECTING:
		/* it holds a fetch slot again, eg, after a retry */
		m->inflight = 1;
		m->retrying = 0;
		break;

	case LWSSSCS_CONNECTED:
		m->connected = 1;

		break;

	case LWSSSCS_DESTROYING:
		lws_sul_cancel(&m->sul);
#if defined(LWS_WITH_CACHE_BLOB)
		lws_buflist_destroy_all_segments(&m->cache_bl);
#endif
		/* it may be on either the active or the queued list */
		lws_dll2_remove(&m->active_asset_list);
		m->inflight = 0;
		m->retrying = 0;

		/*
		 * The dlo destroys the asset ss from its flow.h backref: if
		 * the ss is going first (eg, its connect failed and the
		 * kick destroyed it through m->ss, which lws_ss_destroy()
		 * has already NULLed), the backref must not outlive it
		 */
		if (m->u.u.dlo_jpeg &&
		    (!m->ss || m->u.u.dlo_jpeg->flow.h == m->ss))
			m->u.u.dlo_jpeg->flow.h = NULL;

		dlo_assets_kick(m->cx);
		dlo_assets_maybe_drained(m->cx, m->lhp);
		break;

	case LWSSSCS_UNREACHABLE:
		if (!m->connected && !m->u.failed &&
		    dlo_assets_fds_short(m->cx)) {
			/*
			 * The connect failed before it got anywhere with the
			 * fd table full: that is our own congestion, not
			 * anything wrong with the asset.  The ss is going
			 * into its backoff wait and will try again by
			 * itself; the asset is still outstanding for the
			 * document, but its fetch slot is free meanwhile.
			 * Only ALL_RETRIES_FAILED gives up on it.
			 */
			m->inflight = 0;
			m->retrying = 1;
			dlo_assets_kick(m->cx);
			break;
		}
		/* fallthru */

	case LWSSSCS_ALL_RETRIES_FAILED:
	case LWSSSCS_QOS_NACK_REMOTE:
	case LWSSSCS_DISCONNECTED:
		m->retrying = 0;
		/*
		 * The asset isn't coming (or stopped early).  The html parse
		 * may be waiting on it: a stylesheet that never finishes must
		 * still count as finished so the page after the <link> gets
		 * laid out, and an image that never arrives has no dims.
		 */
		if (m->type == LWSDLOSS_TYPE_CSS) {
			if (m->lhp && !m->lhp->cancelled &&
			    m->lhp->await_css_done &&
			    !strcmp(m->url, m->lhp->await_css_url)) {
				const uint8_t *b = NULL;
				size_t l = 0;

				lwsl_warn("%s: css %s failed, resuming html\n",
					  __func__, m->url);
				lws_dll2_remove(&m->active_asset_list);
				m->lhp->finish_css = 1;
				m->lhp->is_css = 1;
				lws_lhp_parse(m->lhp, &b, &l);
				m->lhp->is_css = 0;
				lws_sul_schedule(lws_ss_get_context(m->ss), 0,
						 m->lhp->sshtmlevsul,
						 m->lhp->sshtmlevcb, 1);
			}
			break;
		}

		/*
		 * Nothing more is coming on this handle unless the stream is
		 * nailed up... these asset fetches are opportunistic, so if
		 * the payload had not all arrived, the asset has failed.
		 * Mark it, and complete the flow, so whatever waits on it
		 * (layout for dimensions, the render for pixel data) is
		 * released instead of waiting for something that will never
		 * turn up
		 */

		if (!m->u.failed && m->u.u.dlo_png &&
		    (state != LWSSSCS_DISCONNECTED ||
		     !(m->ss->policy->flags & LWSSSPOLF_NAILED_UP)) &&
		    m->u.u.dlo_jpeg->flow.state !=
		    			LWSDLOFLOW_STATE_READ_COMPLETED) {
			m->u.failed = 1;
			m->u.u.dlo_jpeg->flow.state =
					LWSDLOFLOW_STATE_READ_COMPLETED;
			lws_sul_schedule(lws_ss_get_context(m->ss), 0,
					 &m->sul, lws_lhp_image_dimensions_cb, 1);
		}

		/*
		 * The connection is gone: the fetch slot is free whether
		 * that was after delivering everything or not.  A retry
		 * that reconnects marks itself in-flight again at CONNECTING
		 */
		m->inflight = 0;
		dlo_assets_kick(lws_ss_get_context(m->ss));
		dlo_assets_maybe_drained(lws_ss_get_context(m->ss), m->lhp);
		break;

	default:
		break;
	}

	return LWSSSSRET_OK;
}

static LWS_SS_INFO("__default", dloss_t)
	.rx				= dloss_rx,
	.state				= dloss_state
};
#endif

/*
 * The html document's own stream may be over while assets it refers to are
 * still being fetched (or queued for a fetch slot): the document defers
 * deciding it is complete until this says there are none left.
 *
 * The last asset out of the lists resumes the document parse from its lhp
 * backref, which is how the deferred completion is woken.
 */

int
lws_dlo_ss_assets_active(struct lws_context *cx)
{
#if defined(LWS_WITH_SECURE_STREAMS)
	return dlo_assets_outstanding(cx);
#else
	(void)cx;
	return 0;
#endif
}

/*
 * If we have an active image asset from this URL, return a pointer to its
 * dlo image (ie, dlo_jpeg or dlo_png)
 */

int
lws_dlo_ss_find(struct lws_context *cx, const char *url, lws_dlo_image_t *u)
{
#if defined(LWS_WITH_SECURE_STREAMS)
	if (!cx)
		/* standalone use with no lws_context: nothing to search */

		return 1; /* not found */

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&cx->active_assets)) {
		dloss_t *ds = lws_container_of(d, dloss_t, active_asset_list);
		// lwsl_notice("  '%s'\n", ds->url);

		if (!strcmp(url, ds->url)) {
			*u = ds->u;

			return 0; /* found */
		}

	} lws_end_foreach_dll(d);

	/*
	 * ... and one that is queued waiting for an in-flight slot is just
	 * as taken: matching only in-flight assets made each retry of an
	 * element waiting on its dimensions create a duplicate fetch
	 */

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&cx->pending_assets)) {
		dloss_t *ds = lws_container_of(d, dloss_t, active_asset_list);

		if (!strcmp(url, ds->url)) {
			*u = ds->u;

			return 0; /* found */
		}

	} lws_end_foreach_dll(d);
#endif
	return 1; /* not found */
}

int
lws_dlo_ss_create(lws_dlo_ss_create_info_t *i, lws_dlo_t **pdlo)
{
#if defined(LWS_WITH_SECURE_STREAMS)
	lws_dlo_jpeg_t *dlo_jpeg = NULL;
	lws_dlo_png_t *dlo_png = NULL;
#if defined(LWS_WITH_SVG)
	lws_dlo_svg_t *dlo_svg = NULL;
#endif
#if defined(LWS_WITH_GIF)
	lws_dlo_gif_t *dlo_gif = NULL;
#endif
	char rebased_url[LHP_URL_LEN];
	size_t ul = strlen(i->url), el;
	struct lws_ss_handle *h;
	lws_dlo_t *dlo = NULL;
	lws_ss_info_t ssi;
	const char *p, *q;
	dloss_t *dloss;
	uint8_t type;

	lwsl_notice("%s: entry\n", __func__);

	if (ul < 5)
		return 1;

	/*
	 * Assets are only ever fetched on behalf of a document, so cap how many
	 * of them one document can have tracked at once, fetching or queued
	 * for a fetch slot... on the small targets this code exists for, each
	 * one is a connection plus a window when it does start.  Over the cap,
	 * the asset is dropped and the document shows what it has.
	 */

	if (i->cx && lws_dll2_count(&i->cx->active_assets) +
		     lws_dll2_count(&i->cx->pending_assets) >=
						 LWS_DLO_MAX_TRACKED_ASSETS) {
		lwsl_warn("%s: too many assets, dropping %s\n",
			  __func__, i->url);
		return 1;
	}

	if (!i->lhp) {
		/*
		 * The dlo we create stores i->lhp and dereferences it from its
		 * rx callback and to rebase the url below... there is nothing
		 * useful we can do without it
		 */
		lwsl_warn("%s: no lhp\n", __func__);
		return 1;
	}

	p = (char *)strchr(i->url, '?');
	if (!p)
		p = i->url + ul;

	/* how many chars of url there are before any '?' */
	el = lws_ptr_diff_size_t(p, i->url);

	if (el >= 4 && !strncmp(p - 4, ".png", 4))
		type = LWSDLOSS_TYPE_PNG;
	else
		if ((el >= 4 && !strncmp(p - 4, ".jpg", 4)) ||
		    (el >= 5 && !strncmp(p - 5, ".jpeg", 5)))
			type = LWSDLOSS_TYPE_JPEG;
		else
#if defined(LWS_WITH_SVG)
			if (el >= 4 && !strncmp(p - 4, ".svg", 4))
				type = LWSDLOSS_TYPE_SVG;
			else
#endif
#if defined(LWS_WITH_GIF)
				if (el >= 4 && !strncmp(p - 4, ".gif", 4))
					type = LWSDLOSS_TYPE_GIF;
				else
#endif
					if (el >= 4 && !strncmp(p - 4, ".css", 4))
					type = LWSDLOSS_TYPE_CSS;
				else {
					lwsl_warn("%s: unknown file type %s\n", __func__, i->url);
					return 1;
				}

	/*
	 * Only a stylesheet <link> can consume css... if the document asked for
	 * a stylesheet as an image, there is no dlo we can hand back, and our
	 * success return would leave the caller with a NULL one
	 */

	if (type == LWSDLOSS_TYPE_CSS && i->lhp->npos == 3 &&
	    !strncmp(i->lhp->buf, "img", 3)) {
		lwsl_warn("%s: css asset requested as an image\n", __func__);
		return 1;
	}

	if (lws_http_rel_to_url(rebased_url, sizeof(rebased_url), i->lhp->base_url, i->url)) {
		lwsl_warn("%s: failed to rebase url\n", __func__);
		return 1;
	}

	lwsl_notice("%s: rebased_url -> %s\n", __func__, rebased_url);

	q = p;
	while (q > i->url && q[-1] != '/')
		q--;

	switch (type) {
	case LWSDLOSS_TYPE_PNG:
		dlo_png = lws_display_dlo_png_new(i->dl, i->dlo_parent, i->box, q, lws_ptr_diff_size_t(p, q));
		if (!dlo_png)
			return 1;

		i->u->u.dlo_png = dlo_png;

		/*
		 * Fill any side the css left unset (auto) from the
		 * intrinsic size... at create time the metadata may not
		 * have arrived yet, in which case the dimensions callback
		 * completes it later
		 */
		if (lws_upng_get_width(dlo_png->png) && !dlo_png->dlo.box.w.whole) {
			dlo_png->dlo.box.w.whole = (int32_t)lws_upng_get_width(dlo_png->png);
			dlo_png->dlo.box.w.frac = 0;
		}
		if (lws_upng_get_height(dlo_png->png) && !dlo_png->dlo.box.h.whole) {
			dlo_png->dlo.box.h.whole = (int32_t)lws_upng_get_height(dlo_png->png);
			dlo_png->dlo.box.h.frac = 0;
		}

		dlo = &dlo_png->dlo;
		break;

	case LWSDLOSS_TYPE_JPEG:
		dlo_jpeg = lws_display_dlo_jpeg_new(i->dl, i->dlo_parent, i->box, q, lws_ptr_diff_size_t(p, q));
		if (!dlo_jpeg)
			return 1;

		i->u->u.dlo_jpeg = dlo_jpeg;

		/*
		 * Fill any side the css left unset (auto) from the
		 * intrinsic size... at create time the metadata may not
		 * have arrived yet, in which case the dimensions callback
		 * completes it later
		 */
		if (lws_jpeg_get_width(dlo_jpeg->j) && !dlo_jpeg->dlo.box.w.whole) {
			dlo_jpeg->dlo.box.w.whole = (int32_t)lws_jpeg_get_width(dlo_jpeg->j);
			dlo_jpeg->dlo.box.w.frac = 0;
		}
		if (lws_jpeg_get_height(dlo_jpeg->j) && !dlo_jpeg->dlo.box.h.whole) {
			dlo_jpeg->dlo.box.h.whole = (int32_t)lws_jpeg_get_height(dlo_jpeg->j);
			dlo_jpeg->dlo.box.h.frac = 0;
		}

		dlo = &dlo_jpeg->dlo;
		break;

#if defined(LWS_WITH_SVG)
	case LWSDLOSS_TYPE_SVG:
		dlo_svg = lws_display_dlo_svg_new(i->dl, i->dlo_parent, i->box, q, lws_ptr_diff_size_t(p, q));
		if (!dlo_svg)
			return 1;

		i->u->u.dlo_svg = dlo_svg;

		/*
		 * Fill any side the css left unset (auto) from the
		 * intrinsic size... at create time the metadata may not
		 * have arrived yet, in which case the dimensions callback
		 * completes it later
		 */
		if (lws_svg_get_width(dlo_svg->svg) && !dlo_svg->dlo.box.w.whole) {
			dlo_svg->dlo.box.w.whole = (int32_t)lws_svg_get_width(dlo_svg->svg);
			dlo_svg->dlo.box.w.frac = 0;
		}
		if (lws_svg_get_height(dlo_svg->svg) && !dlo_svg->dlo.box.h.whole) {
			dlo_svg->dlo.box.h.whole = (int32_t)lws_svg_get_height(dlo_svg->svg);
			dlo_svg->dlo.box.h.frac = 0;
		}

		dlo = &dlo_svg->dlo;
		break;
#endif

#if defined(LWS_WITH_GIF)
	case LWSDLOSS_TYPE_GIF:
		dlo_gif = lws_display_dlo_gif_new(i->dl, i->dlo_parent, i->box, q, lws_ptr_diff_size_t(p, q));
		if (!dlo_gif)
			return 1;

		i->u->u.dlo_gif = dlo_gif;

		dlo_gif->dlo.box.w.whole = (int32_t)
			lws_gif_get_width(dlo_gif->gif);
		dlo_gif->dlo.box.w.frac = 0;
		dlo_gif->dlo.box.h.whole = (int32_t)
			lws_gif_get_height(dlo_gif->gif);
		dlo_gif->dlo.box.h.frac = 0;

		dlo = &dlo_gif->dlo;
		break;
#endif
	}

	/* we adapt the initial tx credit also to the requested window */

	ssi = ssi_dloss_t;
	ssi.manual_initial_tx_credit = i->window;

	if (lws_ss_create(i->cx, 0, &ssi, (void *)dlo, &h, NULL, NULL)) {
		lwsl_notice("%s: unable to create ss\n", __func__);
		return 1;
	}

	dloss = (dloss_t *)lws_ss_to_user_object(h);
	dloss->cx = i->cx;
	dloss->u.type = (lws_dlo_image_type_t)type;
	dloss->on_rx = i->on_rx;
	dloss->ssevsul = i->on_rx_sul;
	dloss->lhp = i->lhp;
	dloss->type = type;

	lws_strncpy(dloss->url, rebased_url, sizeof(dloss->url));

	/*
	 * How many chars of the url are its scheme://host[:port], for the
	 * per-server fetch ceiling.  file:///... has an empty host and is
	 * exempt
	 */

	dloss->hl = 0;
	q = strchr(rebased_url, '/');
	if (q && q > rebased_url && q[-1] == ':' && q[1] == '/') {
		const char *he = strchr(q + 2, '/');

		if (!he)
			he = rebased_url + strlen(rebased_url);

		if (he > q + 2 && lws_ptr_diff(he, rebased_url) < 256)
			dloss->hl = (uint8_t)lws_ptr_diff(he, rebased_url);
	}

	switch (type) {
	case LWSDLOSS_TYPE_PNG:
		dloss->u.u.dlo_png = dlo_png;
		dlo_png->flow.h = h;
		dlo_png->flow.window = i->window;
		break;
	case LWSDLOSS_TYPE_JPEG:
		dloss->u.u.dlo_jpeg = dlo_jpeg;
		dlo_jpeg->flow.h = h;
		dlo_jpeg->flow.window = i->window;
		break;
#if defined(LWS_WITH_SVG)
	case LWSDLOSS_TYPE_SVG:
		dloss->u.u.dlo_svg = dlo_svg;
		dlo_svg->flow.h = h;
		dlo_svg->flow.window = i->window;
		break;
#endif

#if defined(LWS_WITH_GIF)
	case LWSDLOSS_TYPE_GIF:
		dloss->u.u.dlo_gif = dlo_gif;
		dlo_gif->flow.h = h;
		dlo_gif->flow.window = i->window;
		break;
#endif
	}

	if (lws_ss_alloc_set_metadata(h, "endpoint", rebased_url, strlen(rebased_url))) {
		lwsl_err("%s: unable to set endpoint\n", __func__);
		goto fail;
	}

#if defined(LWS_WITH_CACHE_BLOB)
	/*
	 * If the cache has a still-valid copy of this asset, there is no need
	 * for the network at all.  Images are fed to the dlo the same way a
	 * fetch that delivered everything would have, completing the asset
	 * out of the cache; the ss handle was never connected, but it stays
	 * on the active list like a completed fetch until its dlo goes away,
	 * for url dedup.  Stylesheets are pushed through the css rx path
	 * with EOM, so the parse and the await machinery behave exactly as
	 * they do for a fetched stylesheet, and the handle is destroyed
	 * when that completes.
	 */

	if (dloss->hl && i->cx->dlo_asset_l1) {
		const void *data;
		size_t size;

		if (!lws_cache_item_get(i->cx->dlo_asset_l1, rebased_url,
					&data, &size)) {

			dloss->no_cache = 1;

			if (type == LWSDLOSS_TYPE_CSS) {
				/* the payload is only valid until we return
				 * to the event loop: take a copy */

				dloss->cache_hit = lws_malloc(size, __func__);
				if (!dloss->cache_hit)
					goto fail;
				memcpy(dloss->cache_hit, data, size);
				dloss->cache_hit_len = size;

				lws_dll2_add_tail(&dloss->active_asset_list,
						  &i->cx->active_assets);

				lws_sul_schedule(i->cx, 0, &dloss->sul,
						 dloss_css_cache_feed_cb, 1);

				lwsl_cx_notice(i->cx,
					       "asset cache hit (css): %s "
					       "(%u bytes)",
					       rebased_url, (unsigned int)size);

				*pdlo = NULL;

				return 0;
			}

			lws_dll2_add_tail(&dloss->active_asset_list,
					  &i->cx->active_assets);

			if (dloss_cache_feed(dloss, data, size)) {
				lwsl_cx_warn(i->cx, "cache payload unusable: %s",
					     rebased_url);
				lws_dll2_remove(&dloss->active_asset_list);
				goto fail;
			}

			lwsl_cx_notice(i->cx, "asset cache hit: %s (%u bytes)",
				       rebased_url, (unsigned int)size);

			*pdlo = dlo;

			return 0;
		}
	}
#endif

	/*
	 * Start it now if there's an in-flight slot.  Without a slot, the ss
	 * exists but stays unconnected until one frees up; no fd is used
	 * while it waits
	 */

	if (dlo_asset_inflight_count(i->cx) >=
					(int)dlo_asset_inflight_max(i->cx) ||
	    dlo_asset_host_inflight(i->cx, dloss) >=
						LWS_DLO_MAX_CONCURRENT_PER_HOST) {
		lws_dll2_add_tail(&dloss->active_asset_list,
				  &i->cx->pending_assets);
		lwsl_notice("%s: queued %s (dlo %p)\n", __func__, rebased_url, dlo);
		/* a different queued asset may be startable past us */
		dlo_assets_kick(i->cx);
	} else {
		/*
		 * Mark it in-flight before connecting: a file asset can
		 * complete inside lws_ss_client_connect() and release its
		 * slot again before control comes back here
		 */

		lws_dll2_add_tail(&dloss->active_asset_list,
				  &i->cx->active_assets);
		dloss->inflight = 1;
		lwsl_notice("%s: starting %s (dlo %p)\n", __func__, rebased_url, dlo);

		if (lws_ss_client_connect(dloss->ss)) {
			lws_dll2_remove(&dloss->active_asset_list);
			lwsl_err("%s: unable to do client conn '%s'\n",
				 __func__, rebased_url);
			goto fail;
		}
	}

	*pdlo = dlo;

	return 0;

fail:

	lwsl_warn("%s: failing out\n", __func__);

	lws_ss_destroy(&h);

	switch (type) {
	case LWSDLOSS_TYPE_PNG:
		dlo_png->flow.h = NULL;
		lws_display_dlo_destroy(&dlo);
		*pdlo = NULL;
		break;
	case LWSDLOSS_TYPE_JPEG:
		dlo_jpeg->flow.h = NULL;
		lws_display_dlo_destroy(&dlo);
		*pdlo = NULL;
		break;
#if defined(LWS_WITH_SVG)
	case LWSDLOSS_TYPE_SVG:
		dlo_svg->flow.h = NULL;
		lws_display_dlo_destroy(&dlo);
		*pdlo = NULL;
		break;
#endif

#if defined(LWS_WITH_GIF)
	case LWSDLOSS_TYPE_GIF:
		dlo_gif->flow.h = NULL;
		lws_display_dlo_destroy(&dlo);
		*pdlo = NULL;
		break;
#endif
	}
#endif
	return 1;
}

#if defined(LWS_WITH_CACHE_BLOB)
/*
 * Drop a flow's stashed payload and forget where the decoder had got to
 * in it.  The cursor (data / len / blseglen) refers to the segment being
 * consumed: left as it was, lws_flow_feed() would either hand the new
 * decoder a pointer into the freed segment, or use up that many bytes of
 * the replacement payload before it saw any of it
 */

static void
dloss_flow_restart(lws_flow_t *flow)
{
	lws_buflist_destroy_all_segments(&flow->bl);
	flow->data = NULL;
	flow->len = 0;
	flow->blseglen = 0;
}

/*
 * Re-stash one tracked image's payload from the asset cache and give it a
 * fresh decoder, so its next render decodes from the top
 */

static int
dloss_renew(dloss_t *ds, const void *data, size_t size)
{
	switch (ds->type) {
	case LWSDLOSS_TYPE_JPEG:
		dloss_flow_restart(&ds->u.u.dlo_jpeg->flow);
		if (lws_buflist_append_segment(&ds->u.u.dlo_jpeg->flow.bl,
					       data, size) < 0)
			return 1;

		/*
		 * A fresh decoder starts with no dimensions, which the
		 * renderers treat as an empty image: parse the header so it
		 * is usable, and zero the row counter the renderer
		 * fast-forwards with
		 */

		lws_jpeg_free(&ds->u.u.dlo_jpeg->j);
		ds->u.u.dlo_jpeg->j = lws_jpeg_new();
		if (!ds->u.u.dlo_jpeg->j)
			return 1;
		ds->u.u.dlo_jpeg->emitted = 0;
		ds->u.u.dlo_jpeg->flow.state = LWSDLOFLOW_STATE_READ_COMPLETED;
		lws_flow_feed(&ds->u.u.dlo_jpeg->flow);
		lws_display_dlo_jpeg_metadata_scan(ds->u.u.dlo_jpeg);
		ds->u.u.dlo_jpeg->rc.resident = size + (16 * 1024);
		return 0;

	case LWSDLOSS_TYPE_PNG:
		dloss_flow_restart(&ds->u.u.dlo_png->flow);
		if (lws_buflist_append_segment(&ds->u.u.dlo_png->flow.bl,
					       data, size) < 0)
			return 1;

		lws_upng_free(&ds->u.u.dlo_png->png);
		ds->u.u.dlo_png->png = lws_upng_new();
		if (!ds->u.u.dlo_png->png)
			return 1;
		ds->u.u.dlo_png->emitted = 0;
		ds->u.u.dlo_png->flow.state = LWSDLOFLOW_STATE_READ_COMPLETED;
		lws_flow_feed(&ds->u.u.dlo_png->flow);
		lws_display_dlo_png_metadata_scan(ds->u.u.dlo_png);
		ds->u.u.dlo_png->rc.resident = size + (32 * 1024);
		return 0;

#if defined(LWS_WITH_GIF)
	case LWSDLOSS_TYPE_GIF:
		/* the retained payload was freed at frame end: take it back
		 * from the cache and retarget to the top */

		ds->u.u.dlo_gif->pos = 0;
		ds->u.u.dlo_gif->whole_done = 0;
		lws_display_dlo_gif_rx(ds->u.u.dlo_gif, data, size);
		return 0;
#endif

	default:
		return 1;
	}
}

#endif /* LWS_WITH_CACHE_BLOB */

/*
 * One image, evicted to make room, is about to be rendered: its payload
 * back from the asset cache and a fresh decoder.  Without the asset cache
 * there is nowhere to renew from (and nothing is ever evicted), so the
 * public entry points exist for every build but can only say so.
 */

LWS_VISIBLE int
lws_dlo_ss_renew_image(struct lws_context *cx, lws_dlo_t *dlo)
{
#if defined(LWS_WITH_CACHE_BLOB)
	if (!cx->dlo_asset_l1)
		return 1;

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(&cx->active_assets)) {
		dloss_t *ds = lws_container_of(d, dloss_t, active_asset_list);
		const void *data;
		size_t size;

		if (!ds->u.u.dlo_png || &ds->u.u.dlo_png->dlo != dlo)
			continue;

		if (lws_cache_item_get(cx->dlo_asset_l1, ds->url, &data,
				       &size))
			return 1; /* it's gone from the cache too */

		return dloss_renew(ds, data, size);
	} lws_end_foreach_dll(d);
#else
	(void)cx;
	(void)dlo;
#endif

	return 1;
}


/*
 * Renew the tracked images from the asset cache: a retained display list
 * can be re-scanned at a different vertical offset, but image decode
 * state only moves forwards.  Re-stashing the cached payload and giving
 * the dlo a fresh decoder lets the next scan decode the rows the viewport
 * wants, from the top, without any relayout.
 */

LWS_VISIBLE void
lws_dlo_ss_renew_images(struct lws_context *cx)
{
#if defined(LWS_WITH_CACHE_BLOB)
	if (!cx->dlo_asset_l1)
		return;

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&cx->active_assets)) {
		dloss_t *ds = lws_container_of(d, dloss_t, active_asset_list);
		const void *data;
		size_t size;

		if (!ds->u.u.dlo_png || !ds->hl)
			continue;

		if (lws_cache_item_get(cx->dlo_asset_l1, ds->url, &data, &size))
			/* not in the cache: it will render as far as its
			 * decode state allows */
			continue;

		if (dloss_renew(ds, data, size))
			continue;
	} lws_end_foreach_dll_safe(d, d1);
#else
	(void)cx;
#endif
}

void
lws_dlo_ss_detach_lhp(struct lws_context *cx, lhp_ctx_t *lhp)
{
#if defined(LWS_WITH_SECURE_STREAMS)
	lws_dll2_owner_t *owners[2] = { &cx->active_assets,
					&cx->pending_assets };
	int n;

	for (n = 0; n < 2; n++)
		lws_start_foreach_dll(struct lws_dll2 *, d,
				      lws_dll2_get_head(owners[n])) {
			dloss_t *ds = lws_container_of(d, dloss_t,
						       active_asset_list);

			if (ds->lhp == lhp)
				/*
				 * Only the parser goes: an asset may still be
				 * streaming its pixel data for a document
				 * that has completed, and ssevsul / on_rx are
				 * the render's, not the parser's.  The render
				 * state outlives the document stream, and
				 * that wake is how arriving data moves the
				 * raster on.
				 */
				ds->lhp = NULL;
		} lws_end_foreach_dll(d);
#endif
}

int
lws_dlo_ss_stop_any_active(struct lws_context *cx)
{
#if defined(LWS_WITH_SECURE_STREAMS)
	/*
	 * Detach the whole queue before destroying any of it... destroying an
	 * active asset kicks the queue, which would connect queued assets
	 * straight back as we are trying to tear everything down
	 */
	{
		lws_dll2_owner_t parked;

		memset(&parked, 0, sizeof(parked));

		while (cx->pending_assets.head) {
			struct lws_dll2 *d = cx->pending_assets.head;

			lws_dll2_remove(d);
			lws_dll2_add_tail(d, &parked);
		}

		lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
					   lws_dll2_get_head(&parked)) {
			dloss_t *ds = lws_container_of(d, dloss_t,
						       active_asset_list);
			struct lws_ss_handle *h = ds->ss;

			lws_dll2_remove(&ds->active_asset_list);

			/*
			 * The dlo destroy paths destroy the asset ss from
			 * the dlo's flow.h backref: clear it, or they
			 * destroy freed handles when the display list goes
			 */
			if (ds->u.u.dlo_jpeg)
				ds->u.u.dlo_jpeg->flow.h = NULL;

			/*
			 * lws_ss_destroy() clears the pointer it is given
			 * before the DESTROYING callbacks run: destroy a
			 * copy so the user object's own ss backref stays
			 * coherent for them
			 */

			lws_ss_destroy(&h);

		} lws_end_foreach_dll_safe(d, d1);
	}

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
			      lws_dll2_get_head(&cx->active_assets)) {
		dloss_t *ds = lws_container_of(d, dloss_t, active_asset_list);
		struct lws_ss_handle *h = ds->ss;

		lws_dll2_remove(&ds->active_asset_list);

		if (ds->u.u.dlo_jpeg)
			ds->u.u.dlo_jpeg->flow.h = NULL;

		/* as above: destroy a copy, keep the user object's ss
		 * backref coherent through the DESTROYING callbacks */

		lws_ss_destroy(&h);

	} lws_end_foreach_dll_safe(d, d1);
#endif
	return 0;
}

#endif /* LWS_WITH_LHP */
