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
#include "private-lib-tls-openssl.h"

/*
 * Care: many openssl apis return 1 for success.  These are translated to the
 * lws convention of 0 for success.
 */

int lws_openssl_describe_cipher(struct lws *wsi);

extern int openssl_websocket_private_data_index,
    openssl_SSL_CTX_private_data_index;

#if !defined(USE_WOLFSSL)

static int
OpenSSL_client_verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
	SSL *ssl;
	int n;
	struct lws *wsi;

	/* keep old behaviour accepting self-signed server certs */
	if (!preverify_ok) {
		int err = X509_STORE_CTX_get_error(x509_ctx);

		if (err != X509_V_OK) {
			ssl = X509_STORE_CTX_get_ex_data(x509_ctx,
					SSL_get_ex_data_X509_STORE_CTX_idx());
			wsi = SSL_get_ex_data(ssl,
					openssl_websocket_private_data_index);
			if (!wsi) {
				lwsl_err("%s: can't get wsi from ssl privdata\n",
					 __func__);

				return 0;
			}

			if ((err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT ||
			     err == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN) &&
			     wsi->tls.use_ssl & LCCSCF_ALLOW_SELFSIGNED) {
				lwsl_notice("accepting self-signed "
					    "certificate (verify_callback)\n");
				X509_STORE_CTX_set_error(x509_ctx, X509_V_OK);
				return 1;	// ok
		} else if ((err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY ||
			    err == X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE) &&
			    wsi->tls.use_ssl & LCCSCF_ALLOW_INSECURE) {
				lwsl_notice("accepting non-trusted certificate\n");
				X509_STORE_CTX_set_error(x509_ctx, X509_V_OK);
				return 1;  /* ok */
			} else if ((err == X509_V_ERR_CERT_NOT_YET_VALID ||
				    err == X509_V_ERR_CERT_HAS_EXPIRED) &&
				    wsi->tls.use_ssl & LCCSCF_ALLOW_EXPIRED) {
				if (err == X509_V_ERR_CERT_NOT_YET_VALID)
					lwsl_notice("accepting not yet valid "
						    "certificate (verify_"
						    "callback)\n");
				else if (err == X509_V_ERR_CERT_HAS_EXPIRED)
					lwsl_notice("accepting expired "
						    "certificate (verify_"
						    "callback)\n");
				X509_STORE_CTX_set_error(x509_ctx, X509_V_OK);
				return 1;	// ok
			}
		}
	}

	ssl = X509_STORE_CTX_get_ex_data(x509_ctx,
					 SSL_get_ex_data_X509_STORE_CTX_idx());
	wsi = SSL_get_ex_data(ssl, openssl_websocket_private_data_index);
	if (!wsi) {
		lwsl_err("%s: can't get wsi from ssl privdata\n",  __func__);

		return 0;
	}

	n = lws_get_context_protocol(wsi->context, 0).callback(wsi,
			LWS_CALLBACK_OPENSSL_PERFORM_SERVER_CERT_VERIFICATION,
			x509_ctx, ssl, preverify_ok);

	/* keep old behaviour if something wrong with server certs */
	/* if ssl error is overruled in callback and cert is ok,
	 * X509_STORE_CTX_set_error(x509_ctx, X509_V_OK); must be set and
	 * return value is 0 from callback */
	if (!preverify_ok) {
		int err = X509_STORE_CTX_get_error(x509_ctx);

		if (err != X509_V_OK) {
			/* cert validation error was not handled in callback */
			int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
			const char *msg = X509_verify_cert_error_string(err);

			lwsl_err("SSL error: %s (preverify_ok=%d;err=%d;"
				 "depth=%d)\n", msg, preverify_ok, err, depth);

			return preverify_ok;	// not ok
		}
	}
	/*
	 * convert callback return code from 0 = OK to verify callback
	 * return value 1 = OK
	 */
	return !n;
}
#endif


int
lws_ssl_client_bio_create(struct lws *wsi)
{
	char hostname[128], *p;
#if defined(LWS_HAVE_SSL_set_alpn_protos) && \
    defined(LWS_HAVE_SSL_get0_alpn_selected)
	uint8_t openssl_alpn[40];
	const char *alpn_comma = wsi->context->tls.alpn_default;
	int n;
#endif

	if (wsi->stash) {
		lws_strncpy(hostname, wsi->stash->cis[CIS_HOST], sizeof(hostname));
#if defined(LWS_HAVE_SSL_set_alpn_protos) && \
    defined(LWS_HAVE_SSL_get0_alpn_selected)
		alpn_comma = wsi->stash->cis[CIS_ALPN];
#endif
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

	wsi->tls.ssl = SSL_new(wsi->vhost->tls.ssl_client_ctx);
	if (!wsi->tls.ssl) {
		lwsl_err("SSL_new failed: %s\n",
		         ERR_error_string(lws_ssl_get_error(wsi, 0), NULL));
		lws_tls_err_describe_clear();
		return -1;
	}

#if defined (LWS_HAVE_SSL_SET_INFO_CALLBACK)
	if (wsi->vhost->tls.ssl_info_event_mask)
		SSL_set_info_callback(wsi->tls.ssl, lws_ssl_info_callback);
#endif

#if defined LWS_HAVE_X509_VERIFY_PARAM_set1_host
	if (!(wsi->tls.use_ssl & LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK)) {
		X509_VERIFY_PARAM *param = SSL_get0_param(wsi->tls.ssl);

		/* Enable automatic hostname checks */
		X509_VERIFY_PARAM_set_hostflags(param,
					X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
		// Handle the case where the hostname is an IP address.
		if (!X509_VERIFY_PARAM_set1_ip_asc(param, hostname))
			X509_VERIFY_PARAM_set1_host(param, hostname, 0);
	}
#else
	if (!(wsi->tls.use_ssl & LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK)) {
		lwsl_err("%s: your tls lib is too old to have "
			 "X509_VERIFY_PARAM_set1_host, failing all client tls\n",
			 __func__);
		return -1;
	}
#endif

#if !defined(USE_WOLFSSL)
#ifndef USE_OLD_CYASSL
	/* OpenSSL_client_verify_callback will be called @ SSL_connect() */
	SSL_set_verify(wsi->tls.ssl, SSL_VERIFY_PEER,
		       OpenSSL_client_verify_callback);
#endif
#endif

#if !defined(USE_WOLFSSL)
	SSL_set_mode(wsi->tls.ssl,  SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
#endif
	/*
	 * use server name indication (SNI), if supported,
	 * when establishing connection
	 */
#ifdef USE_WOLFSSL
#ifdef USE_OLD_CYASSL
#ifdef CYASSL_SNI_HOST_NAME
	CyaSSL_UseSNI(wsi->tls.ssl, CYASSL_SNI_HOST_NAME, hostname,
		      strlen(hostname));
#endif
#else
#ifdef WOLFSSL_SNI_HOST_NAME
	wolfSSL_UseSNI(wsi->tls.ssl, WOLFSSL_SNI_HOST_NAME, hostname,
		       strlen(hostname));
#endif
#endif
#else
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
	SSL_set_tlsext_host_name(wsi->tls.ssl, hostname);
#endif
#endif

#ifdef USE_WOLFSSL
	/*
	 * wolfSSL/CyaSSL does certificate verification differently
	 * from OpenSSL.
	 * If we should ignore the certificate, we need to set
	 * this before SSL_new and SSL_connect is called.
	 * Otherwise the connect will simply fail with error code -155
	 */
#ifdef USE_OLD_CYASSL
	if (wsi->tls.use_ssl == 2)
		CyaSSL_set_verify(wsi->tls.ssl, SSL_VERIFY_NONE, NULL);
#else
	if (wsi->tls.use_ssl == 2)
		wolfSSL_set_verify(wsi->tls.ssl, SSL_VERIFY_NONE, NULL);
#endif
#endif /* USE_WOLFSSL */

	wsi->tls.client_bio = BIO_new_socket((int)(long long)wsi->desc.sockfd,
					     BIO_NOCLOSE);
	SSL_set_bio(wsi->tls.ssl, wsi->tls.client_bio, wsi->tls.client_bio);

#ifdef USE_WOLFSSL
#ifdef USE_OLD_CYASSL
	CyaSSL_set_using_nonblock(wsi->tls.ssl, 1);
#else
	wolfSSL_set_using_nonblock(wsi->tls.ssl, 1);
#endif
#else
	BIO_set_nbio(wsi->tls.client_bio, 1); /* nonblocking */
#endif

#if defined(LWS_HAVE_SSL_set_alpn_protos) && \
    defined(LWS_HAVE_SSL_get0_alpn_selected)
	if (wsi->vhost->tls.alpn)
		alpn_comma = wsi->vhost->tls.alpn;
	if (wsi->stash)
		alpn_comma = wsi->stash->cis[CIS_ALPN];
#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
	if (lws_hdr_copy(wsi, hostname, sizeof(hostname),
			 _WSI_TOKEN_CLIENT_ALPN) > 0)
		alpn_comma = hostname;
#endif

	lwsl_info("%s client conn using alpn list '%s'\n", wsi->role_ops->name, alpn_comma);

	n = lws_alpn_comma_to_openssl(alpn_comma, openssl_alpn,
				      sizeof(openssl_alpn) - 1);

	SSL_set_alpn_protos(wsi->tls.ssl, openssl_alpn, n);
#endif

	SSL_set_ex_data(wsi->tls.ssl, openssl_websocket_private_data_index,
			wsi);

	if (wsi->sys_tls_client_cert) {
		lws_system_blob_t *b = lws_system_get_blob(wsi->context,
					LWS_SYSBLOB_TYPE_CLIENT_CERT_DER,
					wsi->sys_tls_client_cert - 1);
		const uint8_t *data;
		size_t size;

		if (!b)
			goto no_client_cert;

		/*
		 * Set up the per-connection client cert
		 */

		size = lws_system_blob_get_size(b);
		if (!size)
			goto no_client_cert;

		if (lws_system_blob_get_single_ptr(b, &data))
			goto no_client_cert;

		if (SSL_use_certificate_ASN1(wsi->tls.ssl, data, (int)size) != 1) {
			lwsl_err("%s: use_certificate failed\n", __func__);
			lws_tls_err_describe_clear();
			goto no_client_cert;
		}

		b = lws_system_get_blob(wsi->context,
					LWS_SYSBLOB_TYPE_CLIENT_KEY_DER,
					wsi->sys_tls_client_cert - 1);
		if (!b)
			goto no_client_cert;

		size = lws_system_blob_get_size(b);
		if (!size)
			goto no_client_cert;

		if (lws_system_blob_get_single_ptr(b, &data))
			goto no_client_cert;

		if (SSL_use_PrivateKey_ASN1(EVP_PKEY_RSA, wsi->tls.ssl,
					    data, (int)size) != 1 &&
		    SSL_use_PrivateKey_ASN1(EVP_PKEY_EC, wsi->tls.ssl,
					    data, (int)size) != 1) {
			lwsl_err("%s: use_privkey failed\n", __func__);
			lws_tls_err_describe_clear();
			goto no_client_cert;
		}

		if (SSL_check_private_key(wsi->tls.ssl) != 1) {
			lwsl_err("Private SSL key doesn't match cert\n");
			lws_tls_err_describe_clear();
			return 1;
		}

		lwsl_notice("%s: set system client cert %u\n", __func__,
				wsi->sys_tls_client_cert - 1);
	}

	return 0;

no_client_cert:
	lwsl_err("%s: unable to set up system client cert %d\n", __func__,
			wsi->sys_tls_client_cert - 1);

	return 1;
}

enum lws_ssl_capable_status
lws_tls_client_connect(struct lws *wsi)
{
#if defined(LWS_HAVE_SSL_set_alpn_protos) && \
    defined(LWS_HAVE_SSL_get0_alpn_selected)
	const unsigned char *prot;
	char a[32];
	unsigned int len;
#endif
	int m, n;

	errno = 0;
	ERR_clear_error();
	n = SSL_connect(wsi->tls.ssl);
	if (n == 1) {
#if defined(LWS_HAVE_SSL_set_alpn_protos) && \
    defined(LWS_HAVE_SSL_get0_alpn_selected)
		SSL_get0_alpn_selected(wsi->tls.ssl, &prot, &len);

		if (len >= sizeof(a))
			len = sizeof(a) - 1;
		memcpy(a, (const char *)prot, len);
		a[len] = '\0';

		lws_role_call_alpn_negotiated(wsi, (const char *)a);
#endif
		lwsl_info("client connect OK\n");
		lws_openssl_describe_cipher(wsi);
		return LWS_SSL_CAPABLE_DONE;
	}

	m = lws_ssl_get_error(wsi, n);

	if (m == SSL_ERROR_SYSCALL || m == SSL_ERROR_SSL)
		return LWS_SSL_CAPABLE_ERROR;

	if (m == SSL_ERROR_WANT_READ || SSL_want_read(wsi->tls.ssl))
		return LWS_SSL_CAPABLE_MORE_SERVICE_READ;

	if (m == SSL_ERROR_WANT_WRITE || SSL_want_write(wsi->tls.ssl))
		return LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;

	if (!n) /* we don't know what he wants, but he says to retry */
		return LWS_SSL_CAPABLE_MORE_SERVICE;

	return LWS_SSL_CAPABLE_ERROR;
}

int
lws_tls_client_confirm_peer_cert(struct lws *wsi, char *ebuf, int ebuf_len)
{
#if !defined(USE_WOLFSSL)
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];
	char *p = (char *)&pt->serv_buf[0];
	char *sb = p;
	int n;

	errno = 0;
	ERR_clear_error();
	n = SSL_get_verify_result(wsi->tls.ssl);

	lwsl_debug("get_verify says %d\n", n);

	if (n == X509_V_OK)
		return 0;

	if ((n == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT ||
	     n == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN) &&
	     (wsi->tls.use_ssl & LCCSCF_ALLOW_SELFSIGNED)) {
		lwsl_info("accepting self-signed certificate\n");

		return 0;
	}
	if ((n == X509_V_ERR_CERT_NOT_YET_VALID ||
	     n == X509_V_ERR_CERT_HAS_EXPIRED) &&
	     (wsi->tls.use_ssl & LCCSCF_ALLOW_EXPIRED)) {
		lwsl_info("accepting expired certificate\n");
		return 0;
	}
	if (n == X509_V_ERR_CERT_NOT_YET_VALID) {
		lwsl_info("Cert is from the future... "
			    "probably our clock... accepting...\n");
		return 0;
	}
	lws_snprintf(ebuf, ebuf_len,
		"server's cert didn't look good, X509_V_ERR = %d: %s\n",
		 n, ERR_error_string(n, sb));
	lwsl_info("%s\n", ebuf);
	lws_tls_err_describe_clear();

	return -1;

#else /* USE_WOLFSSL */
	return 0;
#endif
}

int
lws_tls_client_vhost_extra_cert_mem(struct lws_vhost *vh,
                const uint8_t *der, size_t der_len)
{
	X509_STORE *st;
	X509 *x  = d2i_X509(NULL, &der, (long)der_len);
	int n;

	if (!x) {
		lwsl_err("%s: Failed to load DER\n", __func__);
		lws_tls_err_describe_clear();
		return 1;
	}

	st = SSL_CTX_get_cert_store(vh->tls.ssl_client_ctx);
	if (!st) {
		lwsl_err("%s: failed to get cert store\n", __func__);
		X509_free(x);
		return 1;
	}

	n = X509_STORE_add_cert(st, x);
	if (n != 1)
		lwsl_err("%s: failed to add cert\n", __func__);

	X509_free(x);

	return n != 1;
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
				    const char *private_key_filepath)
{
	struct lws_tls_client_reuse *tcr;
	X509_STORE *x509_store;
	unsigned long error;
	SSL_METHOD *method;
	EVP_MD_CTX *mdctx;
	unsigned int len;
	uint8_t hash[32];
	X509 *client_CA;
	char c;
	int n;

	/* basic openssl init already happened in context init */

	/* choose the most recent spin of the api */
#if defined(LWS_HAVE_TLS_CLIENT_METHOD)
	method = (SSL_METHOD *)TLS_client_method();
#elif defined(LWS_HAVE_TLSV1_2_CLIENT_METHOD)
	method = (SSL_METHOD *)TLSv1_2_client_method();
#else
	method = (SSL_METHOD *)SSLv23_client_method();
#endif

	if (!method) {
		error = ERR_get_error();
		lwsl_err("problem creating ssl method %lu: %s\n",
			error, ERR_error_string(error,
				      (char *)vh->context->pt[0].serv_buf));
		return 1;
	}

	/*
	 * OpenSSL client contexts are quite expensive, because they bring in
	 * the system certificate bundle for each one.  So if you have multiple
	 * vhosts, each with a client context, it can add up to several
	 * megabytes of heap.  In the case the client contexts are configured
	 * identically, they could perfectly well have shared just the one.
	 *
	 * For that reason, use a hash to fingerprint the context configuration
	 * and prefer to reuse an existing one with the same fingerprint if
	 * possible.
	 */

	 mdctx = EVP_MD_CTX_create();
	 if (!mdctx)
		 return 1;

	if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
		EVP_MD_CTX_destroy(mdctx);

		return 1;
	}

	if (info->ssl_client_options_set)
		EVP_DigestUpdate(mdctx, &info->ssl_client_options_set,
				 sizeof(info->ssl_client_options_set));

#if (OPENSSL_VERSION_NUMBER >= 0x009080df) && !defined(USE_WOLFSSL)
	if (info->ssl_client_options_clear)
		EVP_DigestUpdate(mdctx, &info->ssl_client_options_clear,
				 sizeof(info->ssl_client_options_clear));
#endif

	if (cipher_list)
		EVP_DigestUpdate(mdctx, cipher_list, strlen(cipher_list));

#if defined(LWS_HAVE_SSL_CTX_set_ciphersuites)
	if (info->client_tls_1_3_plus_cipher_list)
		EVP_DigestUpdate(mdctx, info->client_tls_1_3_plus_cipher_list,
				 strlen(info->client_tls_1_3_plus_cipher_list));
#endif

	if (!lws_check_opt(vh->options, LWS_SERVER_OPTION_DISABLE_OS_CA_CERTS)) {
		c = 1;
		EVP_DigestUpdate(mdctx, &c, 1);
	}

	if (ca_filepath)
		EVP_DigestUpdate(mdctx, ca_filepath, strlen(ca_filepath));

	if (cert_filepath)
		EVP_DigestUpdate(mdctx, cert_filepath, strlen(cert_filepath));

	if (private_key_filepath)
		EVP_DigestUpdate(mdctx, private_key_filepath,
				 strlen(private_key_filepath));
	if (ca_mem && ca_mem_len)
		EVP_DigestUpdate(mdctx, ca_mem, ca_mem_len);

	if (cert_mem && cert_mem_len)
		EVP_DigestUpdate(mdctx, cert_mem, cert_mem_len);

	len = sizeof(hash);
	EVP_DigestFinal_ex(mdctx, hash, &len);
	EVP_MD_CTX_destroy(mdctx);

	/* look for existing client context with same config already */

	lws_start_foreach_dll_safe(struct lws_dll2 *, p, tp,
			 lws_dll2_get_head(&vh->context->tls.cc_owner)) {
		tcr = lws_container_of(p, struct lws_tls_client_reuse, cc_list);

		if (!memcmp(hash, tcr->hash, len)) {

			/* it's a match */

			tcr->refcount++;
			vh->tls.ssl_client_ctx = tcr->ssl_client_ctx;

			lwsl_info("%s: vh %s: reusing client ctx %d: use %d\n",
				   __func__, vh->name, tcr->index,
				   tcr->refcount);

			return 0;
		}
	} lws_end_foreach_dll_safe(p, tp);

	/* no existing one the same... create new client SSL_CTX */

	errno = 0;
	ERR_clear_error();
	vh->tls.ssl_client_ctx = SSL_CTX_new(method);
	if (!vh->tls.ssl_client_ctx) {
		error = ERR_get_error();
		lwsl_err("problem creating ssl context %lu: %s\n",
			error, ERR_error_string(error,
				      (char *)vh->context->pt[0].serv_buf));
		return 1;
	}

	tcr = lws_zalloc(sizeof(*tcr), "client ctx tcr");
	if (!tcr) {
		SSL_CTX_free(vh->tls.ssl_client_ctx);
		return 1;
	}

	tcr->ssl_client_ctx = vh->tls.ssl_client_ctx;
	tcr->refcount = 1;
	memcpy(tcr->hash, hash, len);
	tcr->index = vh->context->tls.count_client_contexts++;
	lws_dll2_add_head(&tcr->cc_list, &vh->context->tls.cc_owner);

	lwsl_info("%s: vh %s: created new client ctx %d\n", __func__,
			vh->name, tcr->index);

	/* bind the tcr to the client context */

	SSL_CTX_set_ex_data(vh->tls.ssl_client_ctx,
			    openssl_SSL_CTX_private_data_index,
			    (char *)tcr);

#ifdef SSL_OP_NO_COMPRESSION
	SSL_CTX_set_options(vh->tls.ssl_client_ctx, SSL_OP_NO_COMPRESSION);
#endif

	SSL_CTX_set_options(vh->tls.ssl_client_ctx,
			    SSL_OP_CIPHER_SERVER_PREFERENCE);

	SSL_CTX_set_mode(vh->tls.ssl_client_ctx,
			 SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER |
			 SSL_MODE_RELEASE_BUFFERS);

	if (info->ssl_client_options_set)
		SSL_CTX_set_options(vh->tls.ssl_client_ctx,
				    info->ssl_client_options_set);

	/* SSL_clear_options introduced in 0.9.8m */
#if (OPENSSL_VERSION_NUMBER >= 0x009080df) && !defined(USE_WOLFSSL)
	if (info->ssl_client_options_clear)
		SSL_CTX_clear_options(vh->tls.ssl_client_ctx,
				      info->ssl_client_options_clear);
#endif

	if (cipher_list)
		SSL_CTX_set_cipher_list(vh->tls.ssl_client_ctx, cipher_list);

#if defined(LWS_HAVE_SSL_CTX_set_ciphersuites)
	if (info->client_tls_1_3_plus_cipher_list)
		SSL_CTX_set_ciphersuites(vh->tls.ssl_client_ctx,
					 info->client_tls_1_3_plus_cipher_list);
#endif

#ifdef LWS_SSL_CLIENT_USE_OS_CA_CERTS
	if (!lws_check_opt(vh->options, LWS_SERVER_OPTION_DISABLE_OS_CA_CERTS))
		/* loads OS default CA certs */
		SSL_CTX_set_default_verify_paths(vh->tls.ssl_client_ctx);
#endif

	/* openssl init for cert verification (for client sockets) */
	if (!ca_filepath && (!ca_mem || !ca_mem_len)) {
		if (!SSL_CTX_load_verify_locations(
			vh->tls.ssl_client_ctx, NULL, LWS_OPENSSL_CLIENT_CERTS))
			lwsl_err("Unable to load SSL Client certs from %s "
			    "(set by LWS_OPENSSL_CLIENT_CERTS) -- "
			    "client ssl isn't going to work\n",
			    LWS_OPENSSL_CLIENT_CERTS);
	} else if (ca_filepath) {
		if (!SSL_CTX_load_verify_locations(
			vh->tls.ssl_client_ctx, ca_filepath, NULL)) {
			lwsl_err(
				"Unable to load SSL Client certs "
				"file from %s -- client ssl isn't "
				"going to work\n", ca_filepath);
			lws_tls_err_describe_clear();
		}
		else
			lwsl_info("loaded ssl_ca_filepath\n");
	} else {

		lws_filepos_t amount = 0;
		uint8_t *up1;
		const uint8_t *up;

		if (lws_tls_alloc_pem_to_der_file(vh->context, NULL, ca_mem,
						  ca_mem_len, &up1,
						  &amount)) {
			lwsl_err("%s: Unable to decode x.509 mem\n", __func__);
			lwsl_hexdump_notice(ca_mem, ca_mem_len);
			return 1;
		}

		up = up1;
		client_CA = d2i_X509(NULL, &up, (long)amount);
		if (!client_CA) {
			lwsl_err("%s: d2i_X509 failed\n", __func__);
			lwsl_hexdump_notice(up1, (size_t)amount);
			lws_tls_err_describe_clear();
		} else {
			x509_store = X509_STORE_new();
			if (!X509_STORE_add_cert(x509_store, client_CA)) {
				X509_STORE_free(x509_store);
				lwsl_err("Unable to load SSL Client certs from "
					 "ssl_ca_mem -- client ssl isn't going to "
					 "work\n");
				lws_tls_err_describe_clear();
			} else {
				/* it doesn't increment x509_store ref counter */
				SSL_CTX_set_cert_store(vh->tls.ssl_client_ctx,
						       x509_store);
				lwsl_info("loaded ssl_ca_mem\n");
			}
		}
		if (client_CA)
			X509_free(client_CA);
		lws_free(up1);
	//	lws_tls_client_vhost_extra_cert_mem(vh, ca_mem, ca_mem_len);
	}

	/*
	 * callback allowing user code to load extra verification certs
	 * helping the client to verify server identity
	 */

	/* support for client-side certificate authentication */
	if (cert_filepath) {
		if (lws_tls_use_any_upgrade_check_extant(cert_filepath) !=
				LWS_TLS_EXTANT_YES &&
		    (info->options & LWS_SERVER_OPTION_IGNORE_MISSING_CERT))
			return 0;

		lwsl_notice("%s: doing cert filepath %s\n", __func__,
				cert_filepath);
		n = SSL_CTX_use_certificate_chain_file(vh->tls.ssl_client_ctx,
						       cert_filepath);
		if (n < 1) {
			lwsl_err("problem %d getting cert '%s'\n", n,
				 cert_filepath);
			lws_tls_err_describe_clear();
			return 1;
		}
		lwsl_notice("Loaded client cert %s\n", cert_filepath);
	} else if (cert_mem && cert_mem_len) {
		n = SSL_CTX_use_certificate_ASN1(vh->tls.ssl_client_ctx,
						 cert_mem_len, cert_mem);
		if (n < 1) {
			lwsl_err("%s: problem interpreting client cert\n",
				 __func__);
			lws_tls_err_describe_clear();
			return 1;
		}
	}
	if (private_key_filepath) {
		lwsl_notice("%s: doing private key filepath\n", __func__);
		lws_ssl_bind_passphrase(vh->tls.ssl_client_ctx, 1, info);
		/* set the private key from KeyFile */
		if (SSL_CTX_use_PrivateKey_file(vh->tls.ssl_client_ctx,
		    private_key_filepath, SSL_FILETYPE_PEM) != 1) {
			lwsl_err("use_PrivateKey_file '%s'\n",
				 private_key_filepath);
			lws_tls_err_describe_clear();
			return 1;
		}
		lwsl_notice("Loaded client cert private key %s\n",
			    private_key_filepath);

		/* verify private key */
		if (!SSL_CTX_check_private_key(vh->tls.ssl_client_ctx)) {
			lwsl_err("Private SSL key doesn't match cert\n");
			return 1;
		}
	}

	return 0;
}


