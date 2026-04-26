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

#define lwsl_tlssess lwsl_info

typedef struct lws_serialized_bearssl_session {
	size_t len;
	br_ssl_session_parameters data;
} lws_ser_sess_t;

typedef struct lws_tls_session_cache_bearssl {
	lws_dll2_t			list;

	lws_sorted_usec_list_t		sul_ttl;
	lws_ser_sess_t			*ser_data;

	/* name is overallocated here */
} lws_tls_scm_t;

static void
__lws_tls_session_destroy(lws_tls_scm_t *ts)
{
	lws_sul_cancel(&ts->sul_ttl);
	lws_dll2_remove(&ts->list);
	if (ts->ser_data) {
		lws_free(ts->ser_data);
		ts->ser_data = NULL;
	}
	lws_free(ts);
}

static lws_tls_scm_t *
__lws_tls_session_lookup_by_name(struct lws_vhost *vh, const char *name)
{
	lws_start_foreach_dll(struct lws_dll2 *, d, vh->tls_sessions.head) {
		lws_tls_scm_t *ts = lws_container_of(d, lws_tls_scm_t, list);

		if (!strcmp(name, (const char *)&ts[1]))
			return ts;

	} lws_end_foreach_dll(d);

	return NULL;
}

/*
 * If possible, reuse an existing, cached session
 */

int
lws_tls_reuse_session(struct lws *wsi)
{
	char buf[LWS_SESSION_TAG_LEN];
	struct lws_tls_conn *conn;
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
		lwsl_tlssess("%s: no existing session for %s\n", __func__, buf);
		goto bail;
	}

	if (!ts->ser_data) /* cache entry is invalid */
		goto bail;

	lwsl_tlssess("%s: %s\n", __func__, (const char *)&ts[1]);
	wsi->tls_session_reused = 1;

	conn = (struct lws_tls_conn *)wsi->tls.ssl;
	br_ssl_engine_set_session_parameters(&conn->u.client.eng, &ts->ser_data->data);

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

int
lws_tls_session_is_reused(struct lws *wsi)
{
#if defined(LWS_WITH_CLIENT)
	struct lws *nwsi = lws_get_network_wsi(wsi);

	if (!nwsi)
		return 0;

	return nwsi->tls_session_reused;
#else
	return 0;
#endif
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

	if (vh->tls.ssl_ctx && vh->tls.ssl_ctx->lru_buffer) {
		lws_free(vh->tls.ssl_ctx->lru_buffer);
		vh->tls.ssl_ctx->lru_buffer = NULL;
	}
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
 * Called after handshake completion on the wsi
 */

int
lws_tls_session_new_bearssl(struct lws *wsi)
{
	char buf[LWS_SESSION_TAG_LEN];
	struct lws_tls_conn *conn;
	struct lws_vhost *vh;
	lws_tls_scm_t *ts;
	size_t nl;
#if !defined(LWS_WITH_NO_LOGS) && defined(_DEBUG)
	const char *disposition = "reuse";
#endif

	vh = wsi->a.vhost;
	if (vh->options & LWS_SERVER_OPTION_DISABLE_TLS_SESSION_CACHE)
		return 0;

	if (lws_tls_session_tag_from_wsi(wsi, buf, sizeof(buf)))
		return 0;

	nl = strlen(buf);

	conn = (struct lws_tls_conn *)wsi->tls.ssl;

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

			lws_vhost_lock(vh); /* -------------- vh { */
			__lws_tls_session_destroy(ts);
			lws_vhost_unlock(vh); /* } vh --------------  */
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

		br_ssl_engine_get_session_parameters(&conn->u.client.eng, &ts->ser_data->data);
		ts->ser_data->len = sizeof(br_ssl_session_parameters);

		lws_dll2_add_tail(&ts->list, &vh->tls_sessions);

		lws_sul_schedule(wsi->a.context, wsi->tsi, &ts->sul_ttl,
				 lws_tls_session_expiry_cb,
				 (int64_t)vh->tls.tls_session_cache_ttl *
							 LWS_US_PER_SEC);

#if !defined(LWS_WITH_NO_LOGS) && defined(_DEBUG)
		disposition = "new";
#endif
	} else {
		if (!ts->ser_data) {
			ts->ser_data = lws_malloc(sizeof(*ts->ser_data), __func__);
			if (!ts->ser_data)
				goto bail;
		}

		br_ssl_engine_get_session_parameters(&conn->u.client.eng, &ts->ser_data->data);
		ts->ser_data->len = sizeof(br_ssl_session_parameters);

		/* keep our session list sorted in lru -> mru order */

		lws_dll2_remove(&ts->list);
		lws_dll2_add_tail(&ts->list, &vh->tls_sessions);
	}

	lws_vhost_unlock(vh); /* } vh --------------  */
	lws_context_unlock(vh->context); /* } cx --------------  */

	lwsl_tlssess("%s: %s: %s %s, (%s:%u)\n", __func__,
		     wsi->lc.gutag, disposition, buf, vh->name,
		     (unsigned int)vh->tls_sessions.count);

	return 1;

bail:
	lws_vhost_unlock(vh); /* } vh --------------  */
	lws_context_unlock(vh->context); /* } cx --------------  */

	return 0;
}

int
lws_tls_session_dump_save(struct lws_vhost *vh, const char *host, uint16_t port,
			  lws_tls_sess_cb_t cb_save, void *opq)
{
	struct lws_tls_session_dump d;
	lws_tls_scm_t *ts;
	int ret = 1;

	lws_tls_session_tag_discrete(vh->name, host, port, d.tag, sizeof(d.tag));

	lws_context_lock(vh->context, __func__); /* -------------- cx { */
	lws_vhost_lock(vh); /* -------------- vh { */

	ts = __lws_tls_session_lookup_by_name(vh, d.tag);

	if (!ts || !ts->ser_data)
		goto bail;

	d.blob_len = ts->ser_data->len;
	d.blob = &ts->ser_data->data;
	d.opaque = opq;

	if (cb_save(vh->context, &d))
		lwsl_notice("%s: save failed\n", __func__);
	else
		ret = 0;

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
	br_ssl_session_parameters sp;
	size_t nl;
	int n;

	lws_tls_session_tag_discrete(vh->name, host, port, d.tag, sizeof(d.tag));
	nl = strlen(d.tag);

	d.blob = NULL;
	d.blob_len = 0;
	d.opaque = opq;

	n = cb_load(vh->context, &d);
	if (n)
		return 0;

	if (d.blob_len != sizeof(sp)) {
		lwsl_err("%s: session dump length mismatch\n", __func__);
		free(d.blob);
		return 0;
	}

	memcpy(&sp, d.blob, sizeof(sp));
	free(d.blob);

	lws_context_lock(vh->context, __func__); /* -------------- cx { */
	lws_vhost_lock(vh); /* -------------- vh { */

	ts = __lws_tls_session_lookup_by_name(vh, d.tag);

	if (!ts) {
		ts = lws_malloc(sizeof(*ts) + nl + 1, __func__);
		if (!ts)
			goto bail;

		memset(ts, 0, sizeof(*ts));
		memcpy(&ts[1], d.tag, nl + 1);

		ts->ser_data = lws_malloc(sizeof(*ts->ser_data), __func__);
		if (!ts->ser_data) {
			lws_free(ts);
			goto bail;
		}

		memcpy(&ts->ser_data->data, &sp, sizeof(sp));
		ts->ser_data->len = sizeof(sp);

		lws_dll2_add_tail(&ts->list, &vh->tls_sessions);

		lws_sul_schedule(vh->context, 0, &ts->sul_ttl,
				 lws_tls_session_expiry_cb,
				 (int64_t)vh->tls.tls_session_cache_ttl *
							 LWS_US_PER_SEC);
	} else {
		if (!ts->ser_data) {
			ts->ser_data = lws_malloc(sizeof(*ts->ser_data), __func__);
			if (!ts->ser_data)
				goto bail;
		}

		memcpy(&ts->ser_data->data, &sp, sizeof(sp));
		ts->ser_data->len = sizeof(sp);

		lws_dll2_remove(&ts->list);
		lws_dll2_add_tail(&ts->list, &vh->tls_sessions);
	}

bail:
	lws_vhost_unlock(vh); /* } vh --------------  */
	lws_context_unlock(vh->context); /* } cx --------------  */

	return 0;
}
