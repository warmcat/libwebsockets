/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2021 Andy Green <andy@warmcat.com>
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

typedef struct lws_tls_session_cache_openssl {
	lws_dll2_t			list;

	SSL_SESSION			*session;
	lws_sorted_usec_list_t		sul_ttl;

	/* name is overallocated here */
} lws_tls_sco_t;

#define lwsl_tlssess lwsl_info

static int
lws_tls_session_name_from_wsi(struct lws *wsi, char *buf, size_t len)
{
	size_t n;

	/*
	 * We have to include the vhost name in the session tag, since
	 * different vhosts may make connections to the same endpoint using
	 * different client certs.
	 */

	n = (size_t)lws_snprintf(buf, len, "%s.", wsi->a.vhost->name);

	buf += n;
	len = len - n;

	lws_sa46_write_numeric_address(&wsi->sa46_peer, buf, len - 8);
	lws_snprintf(buf + strlen(buf), 8, ":%u", wsi->c_port);

	return 0;
}

static void
__lws_tls_session_destroy(lws_tls_sco_t *ts)
{
	lwsl_tlssess("%s: %s (%u)\n", __func__, (const char *)&ts[1],
				     ts->list.owner->count - 1);

	SSL_SESSION_free(ts->session);
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

void
lws_tls_reuse_session(struct lws *wsi)
{
	char buf[16 + INET6_ADDRSTRLEN + 1 + 8 + 1];
	lws_tls_sco_t *ts;

	if (!wsi->a.vhost ||
	    wsi->a.vhost->options & LWS_SERVER_OPTION_DISABLE_TLS_SESSION_CACHE)
		return;

	lws_vhost_lock(wsi->a.vhost); /* -------------- vh { */

	lws_tls_session_name_from_wsi(wsi, buf, sizeof(buf));
	ts = __lws_tls_session_lookup_by_name(wsi->a.vhost, buf);

	if (!ts) {
		lwsl_tlssess("%s: no existing session for %s\n", __func__, buf);
		goto bail;
	}

	lwsl_tlssess("%s: %s\n", __func__, (const char *)&ts[1]);
	wsi->tls_session_reused = 1;

	SSL_set_session(wsi->tls.ssl, ts->session);

	/* keep our session list sorted in lru -> mru order */

	lws_dll2_remove(&ts->list);
	lws_dll2_add_tail(&ts->list, &wsi->a.vhost->tls_sessions);

bail:
	lws_vhost_unlock(wsi->a.vhost); /* } vh --------------  */
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

static int
lws_tls_session_new_cb(SSL *ssl, SSL_SESSION *sess)
{
	struct lws *wsi = (struct lws *)SSL_get_ex_data(ssl,
					openssl_websocket_private_data_index);
	char buf[16 + INET6_ADDRSTRLEN + 1 + 8 + 1];
	struct lws_vhost *vh;
	lws_tls_sco_t *ts;
	size_t nl;
#if !defined(LWS_WITH_NO_LOGS) && defined(_DEBUG)
	const char *disposition = "reuse";
	long ttl;
#endif

	if (!wsi) {
		lwsl_warn("%s: can't get wsi from ssl privdata\n", __func__);

		return 0;
	}

	vh = wsi->a.vhost;
	lws_tls_session_name_from_wsi(wsi, buf, sizeof(buf));
	nl = strlen(buf);

	if (vh->options & LWS_SERVER_OPTION_DISABLE_TLS_SESSION_CACHE)
		return 0;

#if !defined(LWS_WITH_NO_LOGS) && defined(_DEBUG)
	/* api return is long, although we only support setting
	 * default (300s) or max uint32_t */
	ttl = SSL_SESSION_get_timeout(sess);
#endif

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
					      lws_tls_sco_t, list);

			lwsl_tlssess("%s: pruning oldest session\n", __func__);

			lws_vhost_lock(vh); /* -------------- vh { */
			__lws_tls_session_destroy(ts);
			lws_vhost_unlock(vh); /* } vh --------------  */
		}

		ts = lws_malloc(sizeof(*ts) + nl + 1, __func__);

		if (!ts)
			goto bail;

		memset(ts, 0, sizeof(*ts));
		memcpy(&ts[1], buf, nl + 1);

		lws_dll2_add_tail(&ts->list, &vh->tls_sessions);

#if !defined(LWS_WITH_NO_LOGS) && defined(_DEBUG)
		disposition = "new";
#endif

		/*
		 * We don't have to do a SSL_SESSION_up_ref() here, because
		 * we will return from this callback indicating that we kept the
		 * ref
		 */
	} else {
		/*
		 * Give up our refcount on the session we are about to replace
		 * with a newer one
		 */
		SSL_SESSION_free(ts->session);

		/* keep our session list sorted in lru -> mru order */

		lws_dll2_remove(&ts->list);
		lws_dll2_add_tail(&ts->list, &vh->tls_sessions);
	}

	ts->session = sess;

	lws_vhost_unlock(vh); /* } vh --------------  */

	lwsl_tlssess("%s: %p: %s: %s %s, ttl %lds (%s:%u)\n", __func__,
		     sess, wsi->lc.gutag, disposition, buf, ttl, vh->name,
		     vh->tls_sessions.count);

	/*
	 * indicate we will hold on to the SSL_SESSION reference, and take
	 * responsibility to call SSL_SESSION_free() on it ourselves
	 */

	return 1;

bail:
	lws_vhost_unlock(vh); /* } vh --------------  */

	return 0;
}

void
lws_tls_session_cache(struct lws_vhost *vh, uint32_t ttl)
{
	long cmode;

	if (vh->options & LWS_SERVER_OPTION_DISABLE_TLS_SESSION_CACHE)
		return;

	cmode = SSL_CTX_get_session_cache_mode(vh->tls.ssl_client_ctx);

	SSL_CTX_set_session_cache_mode(vh->tls.ssl_client_ctx,
				       (int)(cmode | SSL_SESS_CACHE_CLIENT));

	SSL_CTX_sess_set_new_cb(vh->tls.ssl_client_ctx, lws_tls_session_new_cb);

	if (!ttl)
		return;

#if defined(OPENSSL_IS_BORINGSSL)
	SSL_CTX_set_timeout(vh->tls.ssl_client_ctx, ttl);
#else
	SSL_CTX_set_timeout(vh->tls.ssl_client_ctx, (long)ttl);
#endif
}
