/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
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
 */

#include "private-lib-core.h"
#include "private-lib-tls.h"

typedef struct lws_serialized_gnutls_session {
	size_t len;
	uint8_t *data;
} lws_ser_sess_t;

typedef struct lws_tls_session_cache_gnutls {
	lws_dll2_t			list;

	lws_sorted_usec_list_t		sul_ttl;
	lws_ser_sess_t			*ser_data;

	/* name is overallocated here */
} lws_tls_scm_t;

#define lwsl_tlssess lwsl_info

static void
__lws_tls_session_destroy(lws_tls_scm_t *ts)
{
	lwsl_tlssess("%s: %s (%u)\n", __func__, (const char *)&ts[1],
				     (unsigned int)(ts->list.owner->count - 1));

	lws_sul_cancel(&ts->sul_ttl);
	lws_dll2_remove(&ts->list);		/* vh lock */
	if (ts->ser_data) {
		if (ts->ser_data->data)
			lws_free(ts->ser_data->data);
		lws_free(ts->ser_data);
	}

	lws_free(ts);
}

static lws_tls_scm_t *
__lws_tls_session_lookup_by_name(struct lws_vhost *vh, const char *name)
{
	lws_start_foreach_dll(struct lws_dll2 *, p,
			      lws_dll2_get_head(&vh->tls_sessions)) {
		lws_tls_scm_t *ts = lws_container_of(p, lws_tls_scm_t, list);
		const char *ts_name = (const char *)&ts[1];

		if (!strcmp(name, ts_name))
			return ts;

	} lws_end_foreach_dll(p);

	return NULL;
}

/*
 * If possible, reuse an existing, cached session
 */

int
lws_tls_reuse_session(struct lws *wsi)
{
	char buf[LWS_SESSION_TAG_LEN];
	lws_tls_scm_t *ts;

	if (!wsi->a.vhost ||
	    wsi->a.vhost->options & LWS_SERVER_OPTION_DISABLE_TLS_SESSION_CACHE)
		return 0;

	lws_context_lock(wsi->a.context, __func__); /* -------------- cx { */
	lws_vhost_lock(wsi->a.vhost); /* -------------- vh { */

	if (lws_tls_session_tag_from_wsi(wsi, buf, sizeof(buf)))
		goto bail;

	ts = __lws_tls_session_lookup_by_name(wsi->a.vhost, buf);

	if (!ts) {
		lwsl_notice("%s: no existing session for %s\n", __func__, buf);
		goto bail;
	}

	if (!ts->ser_data || !ts->ser_data->data) { /* cache entry is invalid */
		lwsl_notice("%s: cache entry invalid for %s\n", __func__, buf);
		goto bail;
	}

	if (gnutls_session_set_data((gnutls_session_t)wsi->tls.ssl,
				     ts->ser_data->data,
				     ts->ser_data->len) != GNUTLS_E_SUCCESS) {
		lwsl_tlssess("%s: failed to set gnutls session data\n", __func__);
		goto bail;
	}

	lwsl_notice("%s: resumed session for %s\n", __func__, (const char *)&ts[1]);
	wsi->tls_session_reused = 1;

	/* keep our session list sorted in lru -> mru order */

	lws_dll2_remove(&ts->list);
	lws_dll2_add_tail(&ts->list, &wsi->a.vhost->tls_sessions);

	lws_vhost_unlock(wsi->a.vhost); /* } vh --------------  */
	lws_context_unlock(wsi->a.context); /* } cx --------------  */

	return 1;

bail:
	lws_vhost_unlock(wsi->a.vhost); /* } vh --------------  */
	lws_context_unlock(wsi->a.context); /* } cx --------------  */
	return 0;
}

static int
lws_tls_session_destroy_dll(struct lws_dll2 *d, void *user)
{
	lws_tls_scm_t *ts = lws_container_of(d, lws_tls_scm_t, list);

	__lws_tls_session_destroy(ts);

	return 0;
}

void
lws_tls_session_vh_destroy(struct lws_vhost *vh)
{
	lws_dll2_foreach_safe(&vh->tls_sessions, NULL,
			      lws_tls_session_destroy_dll);
}

static void
lws_tls_session_expiry_cb(lws_sorted_usec_list_t *sul)
{
	lws_tls_scm_t *ts = lws_container_of(sul, lws_tls_scm_t, sul_ttl);
	struct lws_vhost *vh = lws_container_of(ts->list.owner,
						struct lws_vhost, tls_sessions);

	lws_context_lock(vh->context, __func__); /* -------------- cx { */
	lws_vhost_lock(vh); /* -------------- vh { */
	__lws_tls_session_destroy(ts);
	lws_vhost_unlock(vh); /* } vh --------------  */
	lws_context_unlock(vh->context); /* } cx --------------  */
}

/*
 * Called after gnutls_handshake finishes successfully on client wsi
 */

int
lws_tls_session_new_gnutls(struct lws *wsi)
{
	char buf[LWS_SESSION_TAG_LEN];
	struct lws_vhost *vh;
	lws_tls_scm_t *ts;
	size_t nl;
	gnutls_datum_t gd;
#if (_LWS_ENABLED_LOGS & LLL_INFO)
	const char *disposition = "reuse";
#endif

	if (!wsi || !wsi->tls.ssl || !wsi->a.vhost)
		return 0;

	vh = wsi->a.vhost;
	if ((vh->options & LWS_SERVER_OPTION_DISABLE_TLS_SESSION_CACHE) ||
	    vh->being_destroyed)
		return 0;

	if (lws_tls_session_tag_from_wsi(wsi, buf, sizeof(buf))) {
		lwsl_tlssess("%s: lws_tls_session_tag_from_wsi failed\n", __func__);
		return 0;
	}

	nl = strlen(buf);

	/* Check if a session ticket has actually been received (TLS 1.3 requirement) */
	unsigned sess_flags = gnutls_session_get_flags((gnutls_session_t)wsi->tls.ssl);
	lwsl_notice("%s: QUIC session ticket check: flags=0x%x, has_ticket=%d\n", __func__,
		    sess_flags, !!(sess_flags & GNUTLS_SFLAGS_SESSION_TICKET));

	int ret = gnutls_session_get_data2((gnutls_session_t)wsi->tls.ssl, &gd);
	lwsl_notice("%s: gnutls_session_get_data2 ret=%d, len=%u\n", __func__, ret, gd.size);
	if (ret != GNUTLS_E_SUCCESS) {
		if (ret == GNUTLS_E_INTERNAL_ERROR)
			lwsl_notice("%s: gnutls_session_get_data2 INTERNAL_ERROR (no ticket yet?): %s\n", __func__, gnutls_strerror(ret));
		else
			lwsl_notice("%s: gnutls_session_get_data2 failed: %d (%s)\n", __func__, ret, gnutls_strerror(ret));
		return 0;
	}

	/* A real TLS 1.3 session ticket is always well over 32 bytes.
	 * GnuTLS may return a 4-byte placeholder before NewSessionTicket
	 * arrives.  Reject any suspiciously small blob to avoid persisting
	 * a useless stub that will fail to resume on next connection. */
	if (gd.size < 32) {
		lwsl_notice("%s: session data too small (%u bytes), ignoring stub ticket\n",
			    __func__, gd.size);
		gnutls_free(gd.data);
		return 0;
	}

	lws_context_lock(vh->context, __func__); /* -------------- cx { */
	lws_vhost_lock(vh); /* -------------- vh { */

	ts = __lws_tls_session_lookup_by_name(vh, buf);

	if (!ts) {
		/*
		 * We have to make our own, new session
		 */

		if (vh->tls_sessions.count == vh->tls_session_cache_max) {
			/*
			 * We have reached the vhost's session cache limit,
			 * prune the LRU / head
			 */
			ts = lws_container_of(vh->tls_sessions.head,
					      lws_tls_scm_t, list);

			lwsl_tlssess("%s: pruning oldest session (hit max %u)\n",
				     __func__,
				     (unsigned int)vh->tls_session_cache_max);

			__lws_tls_session_destroy(ts);
		}

		ts = lws_malloc(sizeof(*ts) + nl + 1, __func__);
		if (!ts)
			goto bail;

		memset(ts, 0, sizeof(*ts));
		memcpy(&ts[1], buf, nl + 1);

		ts->ser_data = lws_malloc(sizeof(*ts->ser_data), __func__);
		if (!ts->ser_data) {
			lws_free(ts);
			goto bail;
		}
		memset(ts->ser_data, 0, sizeof(*ts->ser_data));

		ts->ser_data->data = lws_malloc(gd.size, __func__);
		if (!ts->ser_data->data) {
			lws_free(ts->ser_data);
			lws_free(ts);
			goto bail;
		}

		memcpy(ts->ser_data->data, gd.data, gd.size);
		ts->ser_data->len = gd.size;

		lws_dll2_add_tail(&ts->list, &vh->tls_sessions);

		lws_sul_schedule(wsi->a.context, wsi->tsi, &ts->sul_ttl,
				 lws_tls_session_expiry_cb,
				 (int64_t)vh->tls.tls_session_cache_ttl *
							 LWS_US_PER_SEC);

#if (_LWS_ENABLED_LOGS & LLL_INFO)
		disposition = "new";
#endif
	} else {
		if (!ts->ser_data) {
			ts->ser_data = lws_malloc(sizeof(*ts->ser_data), __func__);
			if (!ts->ser_data)
				goto bail;
			memset(ts->ser_data, 0, sizeof(*ts->ser_data));
		}

		if (ts->ser_data->data)
			lws_free(ts->ser_data->data);

		ts->ser_data->data = lws_malloc(gd.size, __func__);
		if (!ts->ser_data->data) {
			lws_free(ts->ser_data);
			ts->ser_data = NULL;
			goto bail;
		}

		memcpy(ts->ser_data->data, gd.data, gd.size);
		ts->ser_data->len = gd.size;

		/* keep our session list sorted in lru -> mru order */

		lws_dll2_remove(&ts->list);
		lws_dll2_add_tail(&ts->list, &vh->tls_sessions);
	}

	gnutls_free(gd.data);

	lws_vhost_unlock(vh); /* } vh --------------  */
	lws_context_unlock(vh->context); /* } cx --------------  */

#if (_LWS_ENABLED_LOGS & LLL_INFO)
	lwsl_tlssess("%s: %s %s, (%s:%u)\n", __func__, disposition, buf, vh->name,
		     (unsigned int)vh->tls_sessions.count);
#else
	lwsl_tlssess("%s: %s %s, (%s:%u)\n", __func__, "", buf, vh->name,
		     (unsigned int)vh->tls_sessions.count);
#endif

	return 1;

bail:
	gnutls_free(gd.data);
	lws_vhost_unlock(vh); /* } vh --------------  */
	lws_context_unlock(vh->context); /* } cx --------------  */

	return 0;
}

void
lws_tls_session_cache(struct lws_vhost *vh, uint32_t ttl)
{
	/* Default to 1hr max recommendation from RFC5246 F.1.4 */
	vh->tls.tls_session_cache_ttl = !ttl ? 3600 : ttl;
}

static lws_tls_scm_t *
lws_tls_session_add_entry(struct lws_vhost *vh, const char *tag)
{
	lws_tls_scm_t *ts;
	size_t nl = strlen(tag);

	if (vh->tls_sessions.count == (vh->tls_session_cache_max ?
				      vh->tls_session_cache_max : 10)) {
		/*
		 * We have reached the vhost's session cache limit,
		 * prune the LRU / head
		 */
		ts = lws_container_of(vh->tls_sessions.head,
				      lws_tls_scm_t, list);

		if (ts) {
			lwsl_tlssess("%s: pruning oldest session\n", __func__);
			/* Note: we are already holding vh lock when calling this */
			__lws_tls_session_destroy(ts);
		}
	}

	ts = lws_malloc(sizeof(*ts) + nl + 1, __func__);
	if (!ts)
		return NULL;

	memset(ts, 0, sizeof(*ts));
	memcpy(&ts[1], tag, nl + 1);

	lws_dll2_add_tail(&ts->list, &vh->tls_sessions);

	return ts;
}

int
lws_tls_session_dump_save(struct lws_vhost *vh, const char *host, uint16_t port,
			   lws_tls_sess_cb_t cb_save, void *opq)
{
	struct lws_tls_session_dump d;
	lws_tls_scm_t *ts;
	int ret = 1;
	void *v;

	if (vh->options & LWS_SERVER_OPTION_DISABLE_TLS_SESSION_CACHE)
		return 1;

	lws_tls_session_tag_discrete(vh->name, host, port, d.tag, sizeof(d.tag));

	lws_context_lock(vh->context, __func__); /* -------------- cx { */
	lws_vhost_lock(vh); /* -------------- vh { */

	ts = __lws_tls_session_lookup_by_name(vh, d.tag);
	if (!ts || !ts->ser_data || !ts->ser_data->data)
		goto bail;

	d.blob_len = ts->ser_data->len;
	v = d.blob = lws_malloc(d.blob_len, __func__);
	if (!d.blob)
		goto bail;

	memcpy(d.blob, ts->ser_data->data, d.blob_len);
	d.opaque = opq;

	if (cb_save(vh->context, &d))
		lwsl_notice("%s: save failed\n", __func__);
	else
		ret = 0;

	lws_free(v);

bail:
	lws_vhost_unlock(vh); /* } vh --------------  */
	lws_context_unlock(vh->context); /* } cx --------------  */

	return ret;
}

int
lws_tls_session_dump_load(struct lws_vhost *vh, const char *host, uint16_t port,
			   lws_tls_sess_cb_t cb_load, void *opq)
{
	struct lws_tls_session_dump d;
	lws_tls_scm_t *ts;
	void *v;

	if (vh->options & LWS_SERVER_OPTION_DISABLE_TLS_SESSION_CACHE)
		return 1;

	d.opaque = opq;
	lws_tls_session_tag_discrete(vh->name, host, port, d.tag, sizeof(d.tag));
	lwsl_notice("%s: looking for tag %s\n", __func__, d.tag);

	lws_context_lock(vh->context, __func__); /* -------------- cx { */
	lws_vhost_lock(vh); /* -------------- vh { */

	ts = __lws_tls_session_lookup_by_name(vh, d.tag);
	if (ts) {
		/* session already in cache — no need to load from cold storage */
		lwsl_notice("%s: session already exists for %s\n", __func__, d.tag);
		goto bail1;
	}

	if (cb_load(vh->context, &d)) {
		lwsl_warn("%s: load failed\n", __func__);
		goto bail1;
	}

	/* cb_load allocated the blob; insert it into the session cache */
	v = d.blob;

	ts = lws_tls_session_add_entry(vh, d.tag);
	if (!ts) {
		lwsl_warn("%s: unable to add cache entry\n", __func__);
		free(v);
		goto bail1;
	}

	if (!ts->ser_data) {
		ts->ser_data = lws_malloc(sizeof(*ts->ser_data), __func__);
		if (!ts->ser_data) {
			free(v);
			goto bail1;
		}
		memset(ts->ser_data, 0, sizeof(*ts->ser_data));
	}

	ts->ser_data->data = lws_malloc(d.blob_len, __func__);
	if (!ts->ser_data->data) {
		free(v);
		goto bail1;
	}

	memcpy(ts->ser_data->data, v, d.blob_len);
	ts->ser_data->len = d.blob_len;
	free(v);

	lwsl_tlssess("%s: session loaded OK\n", __func__);

	lws_vhost_unlock(vh); /* } vh --------------  */
	lws_context_unlock(vh->context); /* } cx --------------  */

	return 0;

bail1:
	lws_vhost_unlock(vh); /* } vh --------------  */
	lws_context_unlock(vh->context); /* } cx --------------  */

	return 1;
}
