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

int
lws_ssl_capable_read(struct lws *wsi, unsigned char *buf, size_t len)
{
	int n;

	if (!wsi->tls.ssl)
		return lws_ssl_capable_read_no_ssl(wsi, buf, len);

	n = (int)gnutls_record_recv((gnutls_session_t)wsi->tls.ssl, buf, len);
	if (n > 0) {
		struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];

		if (gnutls_record_check_pending((gnutls_session_t)wsi->tls.ssl)) {
			if (lws_dll2_is_detached(&wsi->tls.dll_pending_tls))
				lws_dll2_add_head(&wsi->tls.dll_pending_tls,
						  &pt->tls.dll_pending_tls_owner);
		} else
			__lws_ssl_remove_wsi_from_buffered_list(wsi);

		if (wsi->a.context->tls_ops->fake_POLLIN_for_buffered)
			wsi->a.context->tls_ops->fake_POLLIN_for_buffered(pt);

		return n;
	}

	if (!n) {
		__lws_ssl_remove_wsi_from_buffered_list(wsi);
		return LWS_SSL_CAPABLE_ERROR;
	}

	if (n == GNUTLS_E_AGAIN || n == GNUTLS_E_INTERRUPTED)
		return LWS_SSL_CAPABLE_MORE_SERVICE;

	lwsl_info("gnutls_record_recv error %d\n", n);

	return LWS_SSL_CAPABLE_ERROR;
}

int
lws_ssl_capable_write(struct lws *wsi, unsigned char *buf, size_t len)
{
	int n;

	if (!wsi->tls.ssl)
		return lws_ssl_capable_write_no_ssl(wsi, buf, len);

	n = (int)gnutls_record_send((gnutls_session_t)wsi->tls.ssl, buf, len);
	if (n >= 0)
		return n;

	if (n == GNUTLS_E_AGAIN || n == GNUTLS_E_INTERRUPTED)
		return LWS_SSL_CAPABLE_MORE_SERVICE;

	return LWS_SSL_CAPABLE_ERROR;
}

int
lws_ssl_pending(struct lws *wsi)
{
	if (!wsi->tls.ssl)
		return 0;

	return (int)gnutls_record_check_pending((gnutls_session_t)wsi->tls.ssl);
}

int
lws_ssl_close(struct lws *wsi)
{
	if (wsi->tls.ssl) {
		gnutls_deinit((gnutls_session_t)wsi->tls.ssl);
		wsi->tls.ssl = NULL;
	}

	__lws_ssl_remove_wsi_from_buffered_list(wsi);

	return 0;
}

enum lws_ssl_capable_status
lws_tls_server_accept(struct lws *wsi)
{
	int n;

#if defined(LWS_WITH_LATENCY)
	lws_usec_t _g_ssl_acc_start = lws_now_usecs();
#endif

	n = gnutls_handshake((gnutls_session_t)wsi->tls.ssl);
	lwsl_debug("%s: gnutls_handshake returned %d\n", __func__, n);

#if defined(LWS_WITH_LATENCY)
	{
		unsigned int ms = (unsigned int)((lws_now_usecs() - _g_ssl_acc_start) / 1000);
		if (ms > 2 && !wsi->tls.ssl_accept_in_bg)
			lws_latency_note(&wsi->a.context->pt[(int)wsi->tsi], _g_ssl_acc_start, 2000, "ssl_accept:%dms", ms);
	}
#endif

	if (n == GNUTLS_E_SUCCESS)
		return LWS_SSL_CAPABLE_DONE;

	if (n == GNUTLS_E_AGAIN || n == GNUTLS_E_INTERRUPTED) {
		if (gnutls_record_get_direction((gnutls_session_t)wsi->tls.ssl) == 0) {
			if (!wsi->tls.ssl_accept_in_bg && lws_change_pollfd(wsi, LWS_POLLOUT, LWS_POLLIN))
				lwsl_notice("%s: lws_change_pollfd failed\n", __func__);

			return LWS_SSL_CAPABLE_MORE_SERVICE_READ;
		} else {
			if (!wsi->tls.ssl_accept_in_bg && lws_change_pollfd(wsi, LWS_POLLIN, LWS_POLLOUT))
				lwsl_notice("%s: lws_change_pollfd failed\n", __func__);

			return LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;
		}
	}

	lwsl_info("gnutls_handshake (server) failed: %s (%d)\n", gnutls_strerror(n), n);

	return LWS_SSL_CAPABLE_ERROR;
}

enum lws_ssl_capable_status
lws_tls_client_connect(struct lws *wsi, char *errbuf, size_t len)
{
	int n;

	n = gnutls_handshake((gnutls_session_t)wsi->tls.ssl);
	if (n == GNUTLS_E_SUCCESS)
		return LWS_SSL_CAPABLE_DONE;

	if (n == GNUTLS_E_AGAIN || n == GNUTLS_E_INTERRUPTED) {
		if (gnutls_record_get_direction((gnutls_session_t)wsi->tls.ssl) == 0) {
			if (lws_change_pollfd(wsi, LWS_POLLOUT, LWS_POLLIN))
				lwsl_notice("%s: lws_change_pollfd failed\n", __func__);
		} else {
			if (lws_change_pollfd(wsi, LWS_POLLIN, LWS_POLLOUT))
				lwsl_notice("%s: lws_change_pollfd failed\n", __func__);
		}

		return LWS_SSL_CAPABLE_MORE_SERVICE;
	}

	lwsl_info("gnutls_handshake (client) failed: %s (%d)\n", gnutls_strerror(n), n);

	if (errbuf)
		snprintf(errbuf, len, "GnuTLS handshake failed: %s", gnutls_strerror(n));

	return LWS_SSL_CAPABLE_ERROR;
}

int
lws_ssl_get_error(struct lws *wsi, int n)
{
	if (n == GNUTLS_E_AGAIN || n == GNUTLS_E_INTERRUPTED) {
		if (gnutls_record_get_direction((gnutls_session_t)wsi->tls.ssl) == 0)
			return 2; /* SSL_ERROR_WANT_READ */

		return 3; /* SSL_ERROR_WANT_WRITE */
	}

	return n;
}

enum lws_ssl_capable_status
__lws_tls_shutdown(struct lws *wsi)
{
	int n;

	n = gnutls_bye((gnutls_session_t)wsi->tls.ssl, GNUTLS_SHUT_WR);
	if (n == GNUTLS_E_SUCCESS)
		return LWS_SSL_CAPABLE_DONE;

	if (n == GNUTLS_E_AGAIN || n == GNUTLS_E_INTERRUPTED)
		return LWS_SSL_CAPABLE_MORE_SERVICE;

	return LWS_SSL_CAPABLE_ERROR;
}

enum lws_ssl_capable_status
lws_tls_server_abort_connection(struct lws *wsi)
{
	__lws_tls_shutdown(wsi);
	return LWS_SSL_CAPABLE_DONE;
}

int
lws_tls_client_confirm_peer_cert(struct lws *wsi, char *ebuf, size_t ebuf_len)
{
	/* TODO: Implement peer cert verification for GnuTLS */
	return 0;
}

static int
tops_fake_POLLIN_for_buffered_gnutls(struct lws_context_per_thread *pt)
{
	return lws_tls_fake_POLLIN_for_buffered(pt);
}

const struct lws_tls_ops tls_ops_gnutls = {
	/* fake_POLLIN_for_buffered */	tops_fake_POLLIN_for_buffered_gnutls,
};
