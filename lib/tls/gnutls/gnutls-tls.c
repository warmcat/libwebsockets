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
lws_context_init_ssl_library(struct lws_context *context,
			     const struct lws_context_creation_info *info)
{
	gnutls_global_init();
	return 0;
}

void
lws_context_deinit_ssl_library(struct lws_context *context)
{
	gnutls_global_deinit();
}

int
lws_tls_server_vhost_backend_init(const struct lws_context_creation_info *info,
				  struct lws_vhost *vhost, struct lws *wsi)
{
	vhost->tls.ssl_ctx = lws_zalloc(sizeof(*vhost->tls.ssl_ctx), "gnutls_ctx");
	if (!vhost->tls.ssl_ctx)
		return 1;

	if (gnutls_certificate_allocate_credentials(&vhost->tls.ssl_ctx->creds) < 0) {
		lws_free(vhost->tls.ssl_ctx);
		vhost->tls.ssl_ctx = NULL;
		return 1;
	}

	gnutls_priority_init(&vhost->tls.ssl_ctx->priority, "NORMAL", NULL);

	if (!vhost->tls.use_ssl ||
	    (!info->ssl_cert_filepath && !info->server_ssl_cert_mem))
		return 0;

	return lws_tls_server_certs_load(vhost, wsi, info->ssl_cert_filepath,
					 info->ssl_private_key_filepath,
					 info->server_ssl_cert_mem,
					 info->server_ssl_cert_mem_len,
					 info->server_ssl_private_key_mem,
					 info->server_ssl_private_key_mem_len);
}

int
lws_tls_client_create_vhost_context(struct lws_vhost *vh,
				    const struct lws_context_creation_info *info,
				    const char *cipher_list,
				    const char *ca_filepath,
				    const void *ca_mem,
				    unsigned int ca_mem_len,
				    const char *cert_filepath,
				    const void *cert_mem,
				    unsigned int cert_mem_len,
				    const char *private_key_filepath,
				    const void *key_mem,
				    unsigned int key_mem_len)
{
	vh->tls.ssl_client_ctx = lws_zalloc(sizeof(*vh->tls.ssl_client_ctx), "gnutls_client_ctx");
	if (!vh->tls.ssl_client_ctx)
		return 1;

	if (gnutls_certificate_allocate_credentials(&vh->tls.ssl_client_ctx->creds) < 0) {
		lws_free(vh->tls.ssl_client_ctx);
		vh->tls.ssl_client_ctx = NULL;
		return 1;
	}

	if (ca_filepath) {
		gnutls_certificate_set_x509_trust_file(vh->tls.ssl_client_ctx->creds,
						      ca_filepath, GNUTLS_X509_FMT_PEM);
	} else {
		gnutls_certificate_set_x509_system_trust(vh->tls.ssl_client_ctx->creds);
	}

	gnutls_priority_init(&vh->tls.ssl_client_ctx->priority, "NORMAL", NULL);

	return 0;
}

int
lws_tls_server_new_nonblocking(struct lws *wsi, lws_sockfd_type accept_fd)
{
	gnutls_session_t session;

	if (gnutls_init(&session, GNUTLS_SERVER) < 0)
		return 1;

	wsi->tls.ssl = (lws_tls_conn *)session;

	gnutls_priority_set(session, wsi->a.vhost->tls.ssl_ctx->priority);
	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, wsi->a.vhost->tls.ssl_ctx->creds);
	gnutls_transport_set_int((gnutls_session_t)wsi->tls.ssl, (int)accept_fd);

	if (wsi->a.vhost->tls.alpn_ctx.len) {
		gnutls_datum_t alpn[4];
		unsigned int i = 0, p = 0;
		while (p < wsi->a.vhost->tls.alpn_ctx.len && i < 4) {
			alpn[i].data = &wsi->a.vhost->tls.alpn_ctx.data[p + 1];
			alpn[i].size = wsi->a.vhost->tls.alpn_ctx.data[p];
			p += alpn[i].size + 1;
			i++;
		}
		gnutls_alpn_set_protocols(session, alpn, i, 0);
	}

	return 0;
}

int
lws_ssl_client_bio_create(struct lws *wsi)
{
	char hostname[128], *p;
	gnutls_session_t session;

	if (wsi->stash) {
		lws_strncpy(hostname, wsi->stash->cis[CIS_HOST], sizeof(hostname));
	} else {
#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
		if (lws_hdr_copy(wsi, hostname, sizeof(hostname),
				 _WSI_TOKEN_CLIENT_HOST) <= 0)
#endif
		{
			lwsl_err("%s: Unable to get hostname\n", __func__);

			return -1;
		}
	}

	/*
	 * remove any :port part on the hostname... necessary for network
	 * connection but typical certificates do not contain it
	 */
	p = hostname;
	while (*p) {
		if (*p == ':') {
			*p = '\0';
			break;
		}
		p++;
	}

	if (gnutls_init(&session, GNUTLS_CLIENT) < 0)
		return 1;

	wsi->tls.ssl = (lws_tls_conn *)session;

	gnutls_priority_set(session, wsi->a.vhost->tls.ssl_client_ctx->priority);
	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, wsi->a.vhost->tls.ssl_client_ctx->creds);
	gnutls_transport_set_int(session, (int)wsi->desc.sockfd);

	gnutls_server_name_set(session, GNUTLS_NAME_DNS, hostname, strlen(hostname));

	if (wsi->a.vhost->tls.alpn_ctx.len) {
		gnutls_datum_t alpn[4];
		unsigned int i = 0, p = 0;
		while (p < wsi->a.vhost->tls.alpn_ctx.len && i < 4) {
			alpn[i].data = &wsi->a.vhost->tls.alpn_ctx.data[p + 1];
			alpn[i].size = wsi->a.vhost->tls.alpn_ctx.data[p];
			p += alpn[i].size + 1;
			i++;
		}
		gnutls_alpn_set_protocols(session, alpn, i, 0);
	}

	return 0;
}

void
lws_ssl_SSL_CTX_destroy(struct lws_vhost *vhost)
{
	if (vhost->tls.ssl_ctx) {
		gnutls_certificate_free_credentials(vhost->tls.ssl_ctx->creds);
		gnutls_priority_deinit(vhost->tls.ssl_ctx->priority);
		lws_free(vhost->tls.ssl_ctx);
		vhost->tls.ssl_ctx = NULL;
	}
	if (vhost->tls.ssl_client_ctx) {
		gnutls_certificate_free_credentials(vhost->tls.ssl_client_ctx->creds);
		gnutls_priority_deinit(vhost->tls.ssl_client_ctx->priority);
		lws_free(vhost->tls.ssl_client_ctx);
		vhost->tls.ssl_client_ctx = NULL;
	}
}

lws_tls_ctx *
lws_tls_ctx_from_wsi(struct lws *wsi)
{
	if (!wsi || !wsi->a.vhost)
		return NULL;

	return wsi->a.vhost->tls.ssl_ctx;
}

void
lws_ssl_context_destroy(struct lws_context *context)
{
	/* Global init already handled by global_deinit */
}

void
lws_tls_session_vh_destroy(struct lws_vhost *vh)
{
	/* TODO: Implement session cache destruction for GnuTLS */
}

int
lws_tls_client_vhost_extra_cert_mem(struct lws_vhost *vh, const uint8_t *der, size_t len)
{
	/* TODO: Implement extra cert loading for GnuTLS */
	return 0;
}

int
lws_tls_vhost_cert_info(struct lws_vhost *vhost, enum lws_tls_cert_info type,
		       union lws_tls_cert_info_results *buf, size_t len)
{
	/* TODO: Implement cert info retrieval for GnuTLS */
	return -1;
}

int
lws_tls_server_certs_load(struct lws_vhost *vhost, struct lws *wsi,
			  const char *cert, const char *private_key,
			  const char *mem_cert, size_t len_mem_cert,
			  const char *mem_privkey, size_t mem_privkey_len)
{
	int n;

	if (mem_cert && mem_privkey) {
		gnutls_datum_t c, k;

		c.data = (uint8_t *)mem_cert;
		c.size = (unsigned int)len_mem_cert;
		k.data = (uint8_t *)mem_privkey;
		k.size = (unsigned int)mem_privkey_len;

		n = gnutls_certificate_set_x509_key_mem(vhost->tls.ssl_ctx->creds,
						       &c, &k, GNUTLS_X509_FMT_PEM);
	} else if (cert && private_key) {
		lwsl_notice("%s: loading cert %s, key %s\n", __func__, cert, private_key);
		n = gnutls_certificate_set_x509_key_file(vhost->tls.ssl_ctx->creds,
							cert, private_key,
							GNUTLS_X509_FMT_PEM);
	} else {
		return 1;
	}

	if (n < 0) {
		lwsl_err("Failed to load server certs: %s\n", gnutls_strerror(n));
		return 1;
	}

	return 0;
}

int
lws_tls_server_client_cert_verify_config(struct lws_vhost *vh)
{
	/* TODO: Implement client cert verify config for GnuTLS */
	return 0;
}

int
lws_tls_peer_cert_info(struct lws *wsi, enum lws_tls_cert_info type,
		       union lws_tls_cert_info_results *buf, size_t len)
{
	/* TODO: Implement peer cert info retrieval for GnuTLS */
	return -1;
}

int
lws_tls_session_is_reused(struct lws *wsi)
{
	return (int)gnutls_session_is_resumed((gnutls_session_t)wsi->tls.ssl);
}

int
lws_tls_session_dump_save(struct lws_vhost *vh, const char *host, uint16_t port,
			   int (*cb)(struct lws_context *, struct lws_tls_session_dump *), void *user)
{
	return -1;
}

int
lws_tls_session_dump_load(struct lws_vhost *vh, const char *host, uint16_t port,
			   int (*cb)(struct lws_context *, struct lws_tls_session_dump *), void *user)
{
	return -1;
}
