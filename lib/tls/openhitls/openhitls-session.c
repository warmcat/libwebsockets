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
 */

#include "private-lib-core.h"

typedef struct lws_tls_session_cache_openhitls {
	lws_dll2_t			list;

	HITLS_Session			*session;
	lws_sorted_usec_list_t		sul_ttl;

	/* name is overallocated here */
} lws_tls_sco_t;

#define tlssess_loglevel		LLL_INFO
#if (_LWS_ENABLED_LOGS & tlssess_loglevel)
	#define lwsl_tlssess(...)		_lws_log(tlssess_loglevel, __VA_ARGS__)
	#else
	#define lwsl_tlssess(...)
	#endif

static void
__lws_tls_session_destroy(lws_tls_sco_t *ts)
{
	lwsl_tlssess("%s: %s (%u)\n", __func__, (const char *)&ts[1],
						ts->list.owner->count - 1);

	lws_sul_cancel(&ts->sul_ttl);
	HITLS_SESS_Free(ts->session);
	lws_dll2_remove(&ts->list);		/* vh lock */

	lws_free(ts);
}

static lws_tls_sco_t *
__lws_tls_session_lookup_by_name(struct lws_vhost *vh, const char *name)
{
	lws_start_foreach_dll(struct lws_dll2 *, p,
					lws_dll2_get_head(&vh->tls_sessions)) {
		lws_tls_sco_t *ts = lws_container_of(p, lws_tls_sco_t, list);
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
	char tag[LWS_SESSION_TAG_LEN];
	lws_tls_sco_t *ts;
	int reused = 0;

	if (!wsi->a.vhost ||
		wsi->a.vhost->options & LWS_SERVER_OPTION_DISABLE_TLS_SESSION_CACHE)
		return 0;

	lws_context_lock(wsi->a.context, __func__); /* -------------- cx { */
	lws_vhost_lock(wsi->a.vhost); /* -------------- vh { */

	if (lws_tls_session_tag_from_wsi(wsi, tag, sizeof(tag)))
		goto bail;
	ts = __lws_tls_session_lookup_by_name(wsi->a.vhost, tag);

	if (!ts) {
		lwsl_tlssess("%s: no existing session for %s\n", __func__, tag);
		goto bail;
	}

	lwsl_tlssess("%s: %s\n", __func__, (const char *)&ts[1]);

	if (HITLS_SetSession(wsi->tls.ssl, ts->session) != HITLS_SUCCESS) {
		lwsl_err("%s: session not set for %s\n", __func__, tag);
		goto bail;
	}
	reused = 1;

	/* keep our session list sorted in lru -> mru order */

	lws_dll2_remove(&ts->list);
	lws_dll2_add_tail(&ts->list, &wsi->a.vhost->tls_sessions);

bail:
	lws_vhost_unlock(wsi->a.vhost); /* } vh --------------  */
	lws_context_unlock(wsi->a.context); /* } cx --------------  */
	return reused;
}

int
lws_tls_session_is_reused(struct lws *wsi)
{
#if defined(LWS_WITH_CLIENT)
	struct lws *nwsi = lws_get_network_wsi(wsi);
	bool is_reused;

	if (!nwsi || !nwsi->tls.ssl)
		return 0;

	if (HITLS_IsSessionReused(nwsi->tls.ssl, &is_reused) != HITLS_SUCCESS)
		return 0;

	return (int)is_reused;
#else
	return 0;
#endif
}

static int
lws_tls_session_destroy_dll(struct lws_dll2 *d, void *user)
{
	lws_tls_sco_t *ts = lws_container_of(d, lws_tls_sco_t, list);

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
	lws_tls_sco_t *ts = lws_container_of(sul, lws_tls_sco_t, sul_ttl);
	struct lws_vhost *vh = lws_container_of(ts->list.owner,
						struct lws_vhost, tls_sessions);

	lws_context_lock(vh->context, __func__); /* -------------- cx { */
	lws_vhost_lock(vh); /* -------------- vh { */
	__lws_tls_session_destroy(ts);
	lws_vhost_unlock(vh); /* } vh --------------  */
	lws_context_unlock(vh->context); /* } cx --------------  */
}

static lws_tls_sco_t *
lws_tls_session_add_entry(struct lws_vhost *vh, const char *tag)
{
	lws_tls_sco_t *ts;
	size_t nl = strlen(tag);

	if (vh->tls_sessions.count == (vh->tls_session_cache_max ?
						vh->tls_session_cache_max : 10)) {

		/*
			* We have reached the vhost's session cache limit,
			* prune the LRU / head
			*/
		ts = lws_container_of(vh->tls_sessions.head,
						lws_tls_sco_t, list);

		if (ts) { /* centos 7 ... */
			lwsl_tlssess("%s: pruning oldest session\n", __func__);

			lws_vhost_lock(vh); /* -------------- vh { */
			__lws_tls_session_destroy(ts);
			lws_vhost_unlock(vh); /* } vh --------------  */
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

static int
lws_tls_session_new_cb(HITLS_Ctx *ssl, HITLS_Session *sess)
{
	struct lws *wsi = (struct lws *)HITLS_GetUserData(ssl);
	char tag[LWS_SESSION_TAG_LEN];
	struct lws_vhost *vh;
	lws_tls_sco_t *ts;
	long ttl;
#if (_LWS_ENABLED_LOGS & tlssess_loglevel)
	const char *disposition = "reuse";
#endif

	if (!wsi) {
		lwsl_warn("%s: can't get wsi from ssl privdata\n", __func__);

		return 0;
	}

	vh = wsi->a.vhost;
	if (vh->options & LWS_SERVER_OPTION_DISABLE_TLS_SESSION_CACHE)
		return 0;

	if (lws_tls_session_tag_from_wsi(wsi, tag, sizeof(tag)))
		return 0;

	/* api return is long, although we only support setting
		* default (300s) or max uint32_t */
	ttl = (long)HITLS_SESS_GetTimeout(sess);

	lws_context_lock(vh->context, __func__); /* -------------- cx { */
	lws_vhost_lock(vh); /* -------------- vh { */

	ts = __lws_tls_session_lookup_by_name(vh, tag);

	if (!ts) {
		ts = lws_tls_session_add_entry(vh, tag);

		if (!ts)
			goto bail;

		lws_sul_schedule(wsi->a.context, wsi->tsi, &ts->sul_ttl,
					lws_tls_session_expiry_cb,
					ttl * LWS_US_PER_SEC);

#if (_LWS_ENABLED_LOGS & tlssess_loglevel)
		disposition = "new";
#endif

		/*
			* We don't have to do a HITLS_SESS_UpRef() here, because
			* we will return from this callback indicating that we kept the
			* ref
			*/
	} else {
		/*
			* Give up our refcount on the session we are about to replace
			* with a newer one
			*/
		HITLS_SESS_Free(ts->session);

		/* keep our session list sorted in lru -> mru order */

		lws_dll2_remove(&ts->list);
		lws_dll2_add_tail(&ts->list, &vh->tls_sessions);
	}

	ts->session = sess;

	lws_vhost_unlock(vh); /* } vh --------------  */
	lws_context_unlock(vh->context); /* } cx --------------  */

	lwsl_tlssess("%s: %p: %s: %s %s, ttl %lds (%s:%u)\n", __func__,
				sess, wsi->lc.gutag, disposition, tag, ttl, vh->name,
				vh->tls_sessions.count);

	/*
		* indicate we will hold on to the HITLS_Session reference, and take
		* responsibility to call HITLS_SESS_Free() on it ourselves
		*/

	return 1;

bail:
	lws_vhost_unlock(vh); /* } vh --------------  */
	lws_context_unlock(vh->context); /* } cx --------------  */

	return 0;
}

#if defined(LWS_TLS_SYNTHESIZE_CB)

/*
	* On openssl, there is an async cb coming when the server issues the session
	* information on the link, so we can pick it up and update the cache at the
	* right time.
	*
	* On mbedtls and some version at least of borning ssl, this cb is either not
	* part of the tls library apis or fails to arrive.
	*
	* This synthetic cb is called instead for those build cases, scheduled for
	* +500ms after the tls negotiation completed.
	*/

void
lws_sess_cache_synth_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_lws_tls *tls = lws_container_of(sul, struct lws_lws_tls,
							sul_cb_synth);
	struct lws *wsi = lws_container_of(tls, struct lws, tls);
	HITLS_Session *sess;

	if (lws_tls_session_is_reused(wsi))
		return;

	sess = HITLS_GetDupSession(tls->ssl);
	if (!sess)
		return;

	if (!HITLS_SESS_IsResumable(sess) || /* not worth caching, or... */
		!lws_tls_session_new_cb(tls->ssl, sess)) { /* ...cb didn't keep it */
		/*
			* For now the policy if no session message after the wait,
			* is just let it be.  Typically the session info is sent
			* early.
			*/
		HITLS_SESS_Free(sess);
	}
}
#endif

void
lws_tls_session_cache(struct lws_vhost *vh, uint32_t ttl)
{
	long cmode;
	uint32_t mode_val = 0;
	lws_tls_ctx *ctx;
	HITLS_Config *config;

	if (vh->options & LWS_SERVER_OPTION_DISABLE_TLS_SESSION_CACHE)
		return;

	ctx = (lws_tls_ctx *)vh->tls.ssl_client_ctx;
	if (!ctx)
		return;

	config = ctx;
	HITLS_CFG_GetSessionCacheMode(config, &mode_val);
	cmode = (long)mode_val;

	HITLS_CFG_SetSessionCacheMode(config,
						(uint32_t)(cmode | HITLS_SESS_CACHE_CLIENT));

	HITLS_CFG_SetNewSessionCb(config, lws_tls_session_new_cb);

	if (!ttl)
		return;

	HITLS_CFG_SetSessionTimeout(config, (uint64_t)ttl);
}

int
lws_tls_session_dump_save(struct lws_vhost *vh, const char *host, uint16_t port,
				lws_tls_sess_cb_t cb_save, void *opq)
{
	struct lws_tls_session_dump d;
	lws_tls_sco_t *ts;
	int ret = 1;

	if (vh->options & LWS_SERVER_OPTION_DISABLE_TLS_SESSION_CACHE)
		return 1;

	lws_tls_session_tag_discrete(vh->name, host, port, d.tag, sizeof(d.tag));

	lws_context_lock(vh->context, __func__); /* -------------- cx { */
	lws_vhost_lock(vh); /* -------------- vh { */

	ts = __lws_tls_session_lookup_by_name(vh, d.tag);
	if (!ts)
		goto bail;

	uint32_t used_len = 0; HITLS_SESS_Encode(ts->session, NULL, 0, &used_len); d.blob_len = used_len;
	if (!d.blob_len || d.blob_len > UINT32_MAX)
		goto bail;

	d.blob = lws_malloc(d.blob_len, __func__);
	if (d.blob) {
		uint32_t used_len = 0;
		/*
		 * OpenHiTLS serializes its own native session format here.
		 * These blobs are intentionally backend-private and are not
		 * compatible with OpenSSL SSL_SESSION DER.
		 */
		if (HITLS_SESS_Encode(ts->session, d.blob,
				      (uint32_t)d.blob_len,
				      &used_len) == HITLS_SUCCESS &&
		    used_len && used_len <= d.blob_len) {
			d.opaque = opq;
			d.blob_len = used_len;
			if (cb_save(vh->context, &d))
				lwsl_notice("%s: save failed\n", __func__);
			else
				ret = 0;
		}

		lws_free(d.blob);
	}

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
	lws_tls_sco_t *ts;
	HITLS_Session *sess = NULL;
	void *v;
	int ret = 1;

	if (vh->options & LWS_SERVER_OPTION_DISABLE_TLS_SESSION_CACHE)
		return 1;

	memset(&d, 0, sizeof(d));
	d.opaque = opq;
	lws_tls_session_tag_discrete(vh->name, host, port, d.tag, sizeof(d.tag));

	lws_context_lock(vh->context, __func__); /* -------------- cx { */
	lws_vhost_lock(vh); /* -------------- vh { */

	ts = __lws_tls_session_lookup_by_name(vh, d.tag);

	if (ts) {
		/*
			* Since we are getting this out of cold storage, we should
			* not replace any existing session since it is likely newer
			*/
		lwsl_notice("%s: session already exists for %s\n", __func__,
				d.tag);
		goto bail1;
	}

	if (cb_load(vh->context, &d)) {
		lwsl_warn("%s: load failed\n", __func__);

		goto bail1;
	}

	/* the callback has allocated the blob and set d.blob / d.blob_len */

	v = d.blob;
	if (!v || !d.blob_len) {
		lwsl_warn("%s: no session blob\n", __func__);
		goto bail;
	}

	sess = HITLS_SESS_New();
	if (!sess)
		goto bail;

	/* See save path: the cold-storage blob is OpenHiTLS-native only. */
	if (d.blob_len > UINT32_MAX ||
	    HITLS_SESS_Decode(&sess, d.blob, (uint32_t)d.blob_len) !=
								HITLS_SUCCESS) {
		lwsl_warn("%s: HITLS_SESS_Decode failed\n", __func__);
		goto bail;
	}

	ts = lws_tls_session_add_entry(vh, d.tag);
	if (!ts) {
		lwsl_warn("%s: unable to add cache entry\n", __func__);
		goto bail;
	}

	ts->session = sess;
	sess = NULL;
	ret = 0;
	lwsl_tlssess("%s: session loaded OK\n", __func__);

bail:
	HITLS_SESS_Free(sess);
	free(v); /* user code will have used malloc() */
bail1:

	lws_vhost_unlock(vh); /* } vh --------------  */
	lws_context_unlock(vh->context); /* } cx --------------  */

	return ret;
}
