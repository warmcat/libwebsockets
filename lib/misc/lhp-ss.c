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
 * SS bindings for html5 parser
 */

#include <private-lib-core.h>

LWS_SS_USER_TYPEDEF
	lws_sorted_usec_list_t		sul;
	lws_flow_t			flow;
	lhp_ctx_t			lhp; /* html ss owns html parser */
	lws_dl_rend_t			drt;
	lws_display_render_state_t	*rs;
	struct lws_context		*cx;
#if defined(LWS_WITH_CACHE_BLOB)
	struct lws_buflist		*cache_bl; /* whole-doc mirror for the
						 * asset cache */
	char				url[LHP_URL_LEN]; /* cache key */
#endif
	uint8_t				no_cache:1; /* don't cache this doc */
	uint8_t				from_cache:1; /* fed from the cache */
	uint8_t				awaiting_retry:1; /* the parse is
						* stalled on something (image
						* dims, css): more document
						* data can't move it on */
} htmlss_t;

/*
 * The layout is complete: the display list is finished and owned by the
 * render state, which outlives us.  Nothing else needs the parser now, so
 * the document stream goes away before the render starts... its destruction
 * returns the whole css working set (the cascade arenas are tens of KB even
 * for a small page) to the heap the renderer is about to want.
 *
 * It is also what stops a browse leaking its parser: the stream has no
 * other owner, lws_lhp_ss_cancel() only deals with a page still in flight.
 */

static void
htmlss_done(lws_sorted_usec_list_t *sul)
{
	htmlss_t *m = lws_container_of(sul, htmlss_t, sul);

	lws_ss_destroy(&m->ss);
}

static void
lws_lhp_ss_html_parse(lws_sorted_usec_list_t *sul)
{
	htmlss_t *m = lws_container_of(sul, htmlss_t, sul);
	lws_stateful_ret_t r;
	size_t zero = 0;

	if (m->lhp.cancelled)
		/* the document was torn down under us */
		return;

	m->awaiting_retry = 0;

	do {
		if (lws_flow_feed(&m->flow)) {
			lwsl_notice("%s: returning from flow_feed\n", __func__);
			return;
		}

		// lwsl_notice("%s: html_parse in len %d\n", __func__, (int)m->flow.len);

		/* creates display list objects from html */
		r = lws_lhp_parse(&m->lhp, (const uint8_t **)&m->flow.data,
				       (size_t *)&m->flow.len);

		lws_flow_req(&m->flow);

		if ((r & LWS_SRET_WANT_INPUT) && !m->flow.len && !m->lhp.await_css_done) {
			if (m->flow.state == LWSDLOFLOW_STATE_READ) {
				lwsl_warn("%s: returning to await more input\n", __func__);
				return;
			}

			/*
			 * The document stream is over, but its assets may still
			 * be fetching or queued for a fetch slot: the page is
			 * not complete until they have all arrived or failed.
			 * The last one out resumes the parse from here.
			 */

			if (lws_dlo_ss_assets_active(m->cx)) {
				m->lhp.await_assets = 1;
				lwsl_notice("%s: deferring completion for "
					    "outstanding assets\n", __func__);
				return;
			}

			lwsl_notice("%s: inferring we are finished\n", __func__);
			break;
		}

		if (r & LWS_SRET_AWAIT_RETRY) {
			/*
			 * Retries are normally woken by whatever we are
			 * waiting on (image dimensions arriving, css done).
			 * This self-retry is the fallback if that never
			 * comes, so it wants to be slow: at 1us it spun the
			 * retry budget dry before a queued fetch could even
			 * start.
			 */
			m->awaiting_retry = 1;
			if (!m->lhp.await_css_done)
				lws_sul_schedule(m->cx, 0, &m->sul,
						 lws_lhp_ss_html_parse,
						 100 * LWS_US_PER_MS);

			return;
		}

		if (r & (LWS_SRET_NO_FURTHER_OUT | LWS_SRET_FATAL)) {
			lwsl_warn("%s: r 0x%x\n", __func__, r);
			break;
		}
	} while (1);

#if defined(LWS_WITH_CACHE_BLOB)
	/*
	 * The document payload is all here: it can go into the asset cache,
	 * so the next browse of the same url does not need the network
	 */

	if (m->cache_bl && !m->no_cache && *m->url) {
		size_t total = lws_buflist_total_len(&m->cache_bl), done = 0;
		uint8_t *buf = lws_malloc(total, __func__);

		if (!buf)
			goto cache_done;

		while (lws_buflist_next_segment_len(&m->cache_bl, NULL)) {
			uint8_t *p;
			size_t cl = lws_buflist_next_segment_len(&m->cache_bl, &p);

			memcpy(buf + done, p, cl);
			done += cl;

			lws_buflist_use_segment(&m->cache_bl, cl);
		}

		if (lws_cache_write_through(
				lws_ss_get_context(m->ss)->dlo_asset_l1,
				m->url, buf, total,
				lws_now_usecs() +
					(lws_usec_t)LWS_DLO_ASSET_CACHE_EXPIRY_S *
							LWS_US_PER_SEC,
				NULL))
			lwsl_cx_info(lws_ss_get_context(m->ss),
				     "doc cache write failed: %s", m->url);
		else
			lwsl_cx_notice(lws_ss_get_context(m->ss),
				       "doc cached: %s (%u bytes)", m->url,
				       (unsigned int)total);

		lws_free(buf);
	}
cache_done:
	lws_buflist_destroy_all_segments(&m->cache_bl);
#endif

	/* Finalize the html parse and clean up */

	lwsl_notice("%s: DESTROYING the lhp\n", __func__);

	m->lhp.await_assets = 0;
	m->lhp.flags = LHP_FLAG_DOCUMENT_END;
	lws_lhp_parse(&m->lhp, (const uint8_t **)NULL, &zero);
	m->rs->layout_clipped = m->drt.clipped;
	m->rs->html = 2; /* html completed.. rs outlives the html ss and priv */

	lws_display_dl_dump(m->drt.dl);

	/*
	 * Tear the document stream down from the event loop, not inline: the
	 * usual way a page with assets completes is the last asset to drain
	 * resuming the parse, and the document stream must not be destroyed
	 * from inside an asset stream's callback.
	 */

	lws_sul_schedule(m->cx, 0, &m->sul, htmlss_done, 1);

	/*
	 * Start the render behind it, on the heap the teardown just freed.
	 *
	 * This has to stay on rs->sul: an asset that arrives after the
	 * document completed schedules the render on that same sul, and the
	 * two coalescing into one render start is what stops a second render
	 * pass finding the display list already consumed.
	 */

	lws_sul_schedule(m->cx, 0, &m->rs->sul, m->lhp.ssevcb, 2);
}

void
lws_lhp_ss_html_parse_from_lhp(lhp_ctx_t *lhp)
{
	htmlss_t *m = lws_container_of(lhp, htmlss_t, lhp);

	lws_lhp_ss_html_parse(&m->sul);
}

/* secure streams payload interface */

static lws_ss_state_return_t
htmlss_rx(void *userobj, const uint8_t *buf, size_t len, int flags)
{
	htmlss_t *m = (htmlss_t *)userobj;
	lws_ss_state_return_t r = LWSSSSRET_OK;

	if (len &&
	    lws_buflist_append_segment(&m->flow.bl, buf, len) < 0) {
		/*
		 * We could not take part of the document.  What we have is
		 * truncated html, which the parser will make the best of,
		 * but it must not be written to the asset cache as if it
		 * were the page... the next visit would render the same
		 * truncation from cache with no way to notice
		 */
		lwsl_warn("%s: OOM taking %u of the document\n", __func__,
			  (unsigned int)len);
#if defined(LWS_WITH_CACHE_BLOB)
		m->no_cache = 1;
#endif
		return LWSSSSRET_DISCONNECT_ME;
	}

#if defined(LWS_WITH_CACHE_BLOB)
	/*
	 * When the document asset cache is active, keep a copy of the
	 * document payload for the write-through at document end: the parse
	 * consumes the flow buflist as it goes
	 */

	if (len && !m->no_cache && !m->from_cache &&
	    lws_ss_get_context(m->ss)->dlo_asset_l1 && *m->url &&
	    strncmp(m->url, "file://", 7)) {
		if (lws_buflist_append_segment(&m->cache_bl, buf, len) < 0) {
			/* we can't make a complete copy: don't cache a
			 * partial document */
			lws_buflist_destroy_all_segments(&m->cache_bl);
			m->no_cache = 1;
		}
	}
#endif

	lwsl_notice("%s: buflen size %d\n", __func__,
			(int)lws_buflist_total_len(&m->flow.bl));

	if (flags & LWSSS_FLAG_EOM) {
		m->flow.state = LWSDLOFLOW_STATE_READ_COMPLETED;
		r = LWSSSSRET_OK;
	}

	/*
	 * If the parse is stalled waiting for an image's dimensions, more
	 * document data can't move it on: it is buffered, and the parse
	 * resumes when the dimensions arrive (or its own slow retry fires).
	 * Re-entering it on every rx chunk burned its retry budget in
	 * microseconds, before a cached asset's dimensions callback could
	 * even run, so every image on the page was laid out without
	 * dimensions
	 */

	if (!m->awaiting_retry)
		lws_sul_schedule(m->cx, 0, &m->sul, lws_lhp_ss_html_parse, 1);

	return r;
}

static lws_ss_state_return_t
htmlss_state(void *userobj, void *sh, lws_ss_constate_t state,
	     lws_ss_tx_ordinal_t ack)
{
	htmlss_t *m = (htmlss_t *)userobj;

	switch (state) {
	case LWSSSCS_CREATING:
		break;

	case LWSSSCS_DISCONNECTED:
		m->flow.state = LWSDLOFLOW_STATE_READ_COMPLETED;
		m->flow.h = NULL;
		break;

	case LWSSSCS_DESTROYING:
		/*
		 * m (and so m->sul) dies with the ss handle... the sul is
		 * scheduled both from our rx and, via lhp.sshtmlevsul, from
		 * the asset streams' rx, so it must not be left on the
		 * context's sul owner list pointing into freed memory
		 */
		lws_sul_cancel(&m->sul);
#if defined(LWS_WITH_CACHE_BLOB)
		lws_buflist_destroy_all_segments(&m->cache_bl);
#endif
		if (m->rs)
			m->rs->hss_html = NULL;
		m->lhp.sshtmlevsul = NULL;
		m->lhp.sshtmlevcb = NULL;

		/*
		 * Assets still in flight for this document hold &m->lhp and
		 * our sul / callback, all of which die with this ss: the
		 * orderly page teardown stops them first, but a destroy
		 * from a failure of this stream or of the context does not
		 */
		lws_dlo_ss_detach_lhp(m->cx, &m->lhp);

		lws_lhp_destruct(&m->lhp);
		lws_buflist_destroy_all_segments(&m->flow.bl);
		m->drt.dl = NULL;
		break;

	default:
		break;
	}

	return LWSSSSRET_OK;
}

static LWS_SS_INFO("__default", htmlss_t)
	.rx				= htmlss_rx,
	.state				= htmlss_state,
	.manual_initial_tx_credit	= 1024
};

/* prep rs->displaylist, rs->ic */

int
lws_lhp_ss_browse_filter(struct lws_context *cx,
			 lws_display_render_state_t *rs, const char *url,
			 sul_cb_t render, const lws_lhp_filter_t *filter)
{
	struct lws_ss_handle *h = NULL;
	lws_ss_info_t ssi;
	int32_t w = 64 * 1024;
	htmlss_t *m;

	/* fetch via SS */
#if defined(LWS_PLAT_BAREMETAL) || defined(LWS_PLAT_FREERTOS)
	w = 4096;
#endif

	ssi = ssi_htmlss_t;
	ssi.manual_initial_tx_credit = w;

	if (lws_ss_create(cx, 0, &ssi, NULL, &h, NULL, NULL)) {
		lwsl_err("%s: ss create failed\n", __func__);
		return 1; /* failed */
	}

	m = (htmlss_t *)lws_ss_to_user_object(h);
	m->cx = cx;
	m->flow.h = h;
	m->flow.window = w;

	/*
	 * The assets this document refers to are fetched with the same
	 * window.  They are the big payloads... a page's images dwarf its
	 * html, and without a window the peer sends them as fast as it can
	 * and we buflist the lot.
	 */

	m->drt.dl = &rs->displaylist;
	m->drt.w = rs->ic->wh_px[0].whole;
	m->drt.h = rs->ic->wh_px[1].whole;
	m->drt.clipped = 0;

	m->rs = rs;
	m->rs->html = 1; /* render must wait for html to complete */
	m->rs->layout_clipped = 0;
	rs->hss_html = h; /* for lws_lhp_ss_cancel() */

	if (lws_lhp_construct(&m->lhp, lhp_displaylist_layout, &m->drt, rs->ic)) {
		lwsl_err("%s: lhp create %s failed\n", __func__, url);
		goto bail1;
	}

	if (filter && lws_lhp_set_filter(&m->lhp, filter)) {
		lwsl_err("%s: filter set failed\n", __func__);
		goto bail2;
	}

	m->lhp.user1 = cx;
	/* after lws_lhp_construct(), which zeroes the ctx */
	m->lhp.window = w;
	m->lhp.viewport_h = rs->viewport_h;
	m->lhp.base_url = strdup(url);
	m->lhp.ssevcb = render;
	m->lhp.ssevsul = &rs->sul;
	m->lhp.sshtmlevcb = lws_lhp_ss_html_parse;
	m->lhp.sshtmlevsul = &m->sul;
	m->lhp.ids = &rs->ids;

	if (lws_ss_set_metadata(m->ss, "endpoint", url, strlen(url))) {
		lwsl_err("%s: failed to use metadata %s\n", __func__, url);
		goto bail2;
	}

	if (lws_ss_set_metadata(m->ss, "ua", "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:95.0) Gecko/20100101 Firefox/95.0", 76)) {
		lwsl_err("%s: failed to use metadata ua\n", __func__);
		goto bail2;
	}

#if defined(LWS_WITH_CACHE_BLOB)
	/*
	 * If the cache still has a copy of this document, it can be fed to
	 * the parser through the same path the network rx uses, and the
	 * network is not needed at all.  The handle is never connected, and
	 * completes by itself when the parse reaches the document end.
	 */

	lws_strncpy(m->url, url, sizeof(m->url));

	if (cx->dlo_asset_l1 && strncmp(url, "file://", 7)) {
		const void *d;
		size_t l;

		if (!lws_cache_item_get(cx->dlo_asset_l1, url, &d, &l)) {
			m->from_cache = 1;

			if (lws_buflist_append_segment(&m->flow.bl, d, l) < 0)
				goto bail2;

			m->flow.state = LWSDLOFLOW_STATE_READ_COMPLETED;

			lwsl_cx_notice(cx, "doc cache hit: %s (%u bytes)",
				       url, (unsigned int)l);

			lws_sul_schedule(cx, 0, &m->sul,
					 lws_lhp_ss_html_parse, 1);

			return 0;
		}
	}
#endif

	if (lws_ss_set_metadata(m->ss, "acc", "text/html,image/jpeg,image/png,", 30)) {
		lwsl_err("%s: failed to use metadata ua\n", __func__);
		goto bail2;
	}

	if (lws_ss_client_connect(m->ss))
		goto bail2;

	return 0;

bail2:
	lws_lhp_destruct(&m->lhp);

bail1:
	lws_ss_destroy(&h);

	return 1;
}

int
lws_lhp_ss_browse(struct lws_context *cx, lws_display_render_state_t *rs,
		  const char *url, sul_cb_t render)
{
	return lws_lhp_ss_browse_filter(cx, rs, url, render, NULL);
}

void
lws_lhp_ss_cancel(lws_display_render_state_t *rs)
{
	htmlss_t *m;
	struct lws_ss_handle *h = rs->hss_html;

	if (!h)
		return;

	m = (htmlss_t *)lws_ss_to_user_object(h);

	/*
	 * Mark the parse dead first, so destroying the document's assets
	 * cannot resume it against render state that is about to go away
	 * (the drain paths check ->cancelled).
	 *
	 * Then the assets are stopped while the html ss and its lhp are
	 * still coherent for their teardown callbacks, the html ss is
	 * destroyed (destructing the lhp), and finally any render that the
	 * teardown had scheduled for the old document is cancelled.
	 */

	m->lhp.cancelled = 1;

	lws_dlo_ss_stop_any_active(m->cx);

	lws_ss_destroy(&h); /* rs->hss_html is cleared at DESTROYING */

	lws_sul_cancel(&rs->sul);
}
