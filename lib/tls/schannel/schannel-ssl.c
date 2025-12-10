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
#include "private-lib-tls.h"

int
lws_ssl_capable_read(struct lws *wsi, unsigned char *buf, size_t len)
{
	/* stub */
	return -1;
}

int
lws_ssl_capable_write(struct lws *wsi, unsigned char *buf, size_t len)
{
	/* stub */
	return -1;
}

int
lws_ssl_pending(struct lws *wsi)
{
	/* stub */
	return 0;
}

int
lws_server_socket_service_ssl(struct lws *new_wsi, lws_sockfd_type accept_fd,
			      char is_pollin)
{
	/* stub */
	return 0;
}

int
lws_ssl_close(struct lws *wsi)
{
	/* stub */
	return 0;
}

int
lws_ssl_client_bio_create(struct lws *wsi)
{
	/* stub */
	return 0;
}

int
lws_ssl_client_connect2(struct lws *wsi, char *errbuf, size_t len)
{
	/* stub */
	return 0;
}

void
lws_ssl_bind_passphrase(lws_tls_ctx *ssl_ctx, int is_client,
			const struct lws_context_creation_info *info)
{
	/* stub */
}

int
lws_tls_server_new_nonblocking(struct lws *wsi, lws_sockfd_type accept_fd)
{
	/* stub */
	return 0;
}

enum lws_ssl_capable_status
lws_tls_server_accept(struct lws *wsi)
{
	/* stub */
	return LWS_SSL_CAPABLE_ERROR;
}

enum lws_ssl_capable_status
lws_tls_server_abort_connection(struct lws *wsi)
{
	/* stub */
	return LWS_SSL_CAPABLE_ERROR;
}

enum lws_ssl_capable_status
__lws_tls_shutdown(struct lws *wsi)
{
	/* stub */
	return LWS_SSL_CAPABLE_ERROR;
}

enum lws_ssl_capable_status
lws_tls_client_connect(struct lws *wsi, char *errbuf, size_t len)
{
	/* stub */
	return LWS_SSL_CAPABLE_ERROR;
}

int
lws_tls_client_confirm_peer_cert(struct lws *wsi, char *ebuf, size_t ebuf_len)
{
	/* stub */
	return 0;
}

int
lws_ssl_get_error(struct lws *wsi, int n)
{
	/* stub */
	return 0;
}

static int
tops_fake_POLLIN_for_buffered_schannel(struct lws_context_per_thread *pt)
{
	return lws_tls_fake_POLLIN_for_buffered(pt);
}

const struct lws_tls_ops tls_ops_schannel = {
	/* fake_POLLIN_for_buffered */	tops_fake_POLLIN_for_buffered_schannel,
};
