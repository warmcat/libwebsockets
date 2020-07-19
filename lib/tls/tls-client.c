/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2019 Andy Green <andy@warmcat.com>
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

int
lws_ssl_client_connect1(struct lws *wsi, char *errbuf, int len)
{
	int n;

	n = lws_tls_client_connect(wsi, errbuf, len);
	switch (n) {
	case LWS_SSL_CAPABLE_ERROR:
		return -1;
	case LWS_SSL_CAPABLE_DONE:
		return 1; /* connected */
	case LWS_SSL_CAPABLE_MORE_SERVICE_WRITE:
		lws_callback_on_writable(wsi);
		/* fallthru */
	case LWS_SSL_CAPABLE_MORE_SERVICE:
	case LWS_SSL_CAPABLE_MORE_SERVICE_READ:
		lwsi_set_state(wsi, LRS_WAITING_SSL);
		break;
	}

	return 0; /* retry */
}

int
lws_ssl_client_connect2(struct lws *wsi, char *errbuf, int len)
{
	int n;

	if (lwsi_state(wsi) == LRS_WAITING_SSL) {
		n = lws_tls_client_connect(wsi, errbuf, len);
		lwsl_debug("%s: SSL_connect says %d\n", __func__, n);

		switch (n) {
		case LWS_SSL_CAPABLE_ERROR:
			// lws_snprintf(errbuf, len, "client connect failed");
			return -1;
		case LWS_SSL_CAPABLE_DONE:
			break; /* connected */
		case LWS_SSL_CAPABLE_MORE_SERVICE_WRITE:
			lws_callback_on_writable(wsi);
			/* fallthru */
		case LWS_SSL_CAPABLE_MORE_SERVICE_READ:
			lwsi_set_state(wsi, LRS_WAITING_SSL);
			/* fallthru */
		case LWS_SSL_CAPABLE_MORE_SERVICE:
			return 0;
		}
	}

	if (lws_tls_client_confirm_peer_cert(wsi, errbuf, len))
		return -1;

	return 1;
}


int lws_context_init_client_ssl(const struct lws_context_creation_info *info,
				struct lws_vhost *vhost)
{
	const char *private_key_filepath = info->ssl_private_key_filepath;
	const char *cert_filepath = info->ssl_cert_filepath;
	const char *ca_filepath = info->ssl_ca_filepath;
	const char *cipher_list = info->ssl_cipher_list;
	lws_fakewsi_def_plwsa(&vhost->context->pt[0]);

	lws_fakewsi_prep_plwsa_ctx(vhost->context);

	if (vhost->options & LWS_SERVER_OPTION_ADOPT_APPLY_LISTEN_ACCEPT_CONFIG)
		return 0;

	if (vhost->tls.ssl_ctx) {
		cert_filepath = NULL;
		private_key_filepath = NULL;
		ca_filepath = NULL;
	}

	/*
	 *  for backwards-compatibility default to using ssl_... members, but
	 * if the newer client-specific ones are given, use those
	 */
	if (info->client_ssl_cipher_list)
		cipher_list = info->client_ssl_cipher_list;
	if (info->client_ssl_cert_filepath)
		cert_filepath = info->client_ssl_cert_filepath;
	if (info->client_ssl_private_key_filepath)
		private_key_filepath = info->client_ssl_private_key_filepath;

	if (info->client_ssl_ca_filepath)
		ca_filepath = info->client_ssl_ca_filepath;

	if (!lws_check_opt(info->options, LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT))
		return 0;

	if (vhost->tls.ssl_client_ctx)
		return 0;

#if !defined(LWS_WITH_MBEDTLS)
	if (info->provided_client_ssl_ctx) {
		/* use the provided OpenSSL context if given one */
		vhost->tls.ssl_client_ctx = info->provided_client_ssl_ctx;
		/* nothing for lib to delete */
		vhost->tls.user_supplied_ssl_ctx = 1;

		return 0;
	}
#endif

	if (lws_tls_client_create_vhost_context(vhost, info, cipher_list,
						ca_filepath,
						info->client_ssl_ca_mem,
						info->client_ssl_ca_mem_len,
						cert_filepath,
						info->client_ssl_cert_mem,
						info->client_ssl_cert_mem_len,
						private_key_filepath,
						info->client_ssl_key_mem,
						info->client_ssl_key_mem_len
						))
		return 1;

	lwsl_info("created client ssl context for %s\n", vhost->name);

	/*
	 * give him a fake wsi with context set, so he can use
	 * lws_get_context() in the callback
	 */

	plwsa->vhost = vhost; /* not a real bound wsi */

	vhost->protocols[0].callback((struct lws *)plwsa,
			LWS_CALLBACK_OPENSSL_LOAD_EXTRA_CLIENT_VERIFY_CERTS,
				     vhost->tls.ssl_client_ctx, NULL, 0);

	return 0;
}

