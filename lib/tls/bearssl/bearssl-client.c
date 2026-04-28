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
#include "private-lib-tls-bearssl.h"

enum lws_ssl_capable_status
lws_tls_client_connect(struct lws *wsi, char *errbuf, size_t elen)
{
	struct lws_tls_conn *conn = (struct lws_tls_conn *)wsi->tls.ssl;
	struct lws_tls_ctx *ctx = wsi->a.vhost->tls.ssl_client_ctx;
	unsigned st;
	int err;

	if (!conn->initialized) {
		br_x509_trust_anchor *tas = ctx ? ctx->trust_anchors : NULL;
		size_t num_tas = ctx ? ctx->num_trust_anchors : 0;

		/* We enforce strict validation if trust anchors are provided */
		br_x509_minimal_init(&conn->x509_ctx, &br_sha256_vtable,
			tas, num_tas);

		/* Basic init */
		br_ssl_client_init_full(&conn->u.client, &conn->x509_ctx, tas, num_tas);

		conn->tls_use_ssl = wsi->tls.use_ssl;
		lws_bearssl_x509_wrap_conn(conn);

#if defined(LWS_WITH_TLS_JIT_TRUST)
		conn->wsi = wsi;
#endif
		br_ssl_engine_set_buffer(&conn->u.client.eng, conn->iobuf_in, sizeof(conn->iobuf_in), 1);
		br_ssl_engine_set_buffer(&conn->u.client.eng, conn->iobuf_out, sizeof(conn->iobuf_out), 0);

		/* Extract hostname for SNI */
		if (wsi->stash) {
			conn->client_hostname = lws_strdup(wsi->stash->cis[CIS_HOST]);
		} else {
			char temp_host[128];
			if (lws_hdr_copy(wsi, temp_host, sizeof(temp_host), _WSI_TOKEN_CLIENT_HOST) > 0)
				conn->client_hostname = lws_strdup(temp_host);
		}

		if (conn->client_hostname) {
			char *p = strchr(conn->client_hostname, ':');
			if (p)
				*p = '\0';
		}

		int resume = 0;
#if defined(LWS_WITH_TLS_SESSIONS)
		if (!(wsi->a.vhost->options & LWS_SERVER_OPTION_DISABLE_TLS_SESSION_CACHE))
			resume = lws_tls_reuse_session(wsi);
#endif
		int skip = (wsi->tls.use_ssl & LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK);
		br_ssl_client_reset(&conn->u.client, skip ? NULL : conn->client_hostname, resume);
		conn->initialized = 1;
	}

	st = br_ssl_engine_current_state(&conn->u.client.eng);
	if (st == BR_SSL_CLOSED) {
		err = br_ssl_engine_last_error(&conn->u.client.eng);
#if defined(LWS_WITH_TLS_JIT_TRUST)
		if (err == BR_ERR_X509_NOT_TRUSTED)
			lws_tls_jit_trust_sort_kids(wsi, &wsi->tls.kid_chain);
#endif
		lws_snprintf(errbuf, elen, "BearSSL handshake failed: %d", err);
		return LWS_SSL_CAPABLE_ERROR;
	}

	if (lws_bearssl_pump(wsi) < 0) {
		lws_snprintf(errbuf, elen, "BearSSL pump failed");
		return LWS_SSL_CAPABLE_ERROR;
	}

	st = br_ssl_engine_current_state(&conn->u.client.eng);
	if (st == BR_SSL_CLOSED) {
		err = br_ssl_engine_last_error(&conn->u.client.eng);
#if defined(LWS_WITH_TLS_JIT_TRUST)
		if (err == BR_ERR_X509_NOT_TRUSTED)
			lws_tls_jit_trust_sort_kids(wsi, &wsi->tls.kid_chain);
#endif
		lws_snprintf(errbuf, elen, "BearSSL handshake failed: %d", err);
		return LWS_SSL_CAPABLE_ERROR;
	}

	if (st & BR_SSL_SENDREC)
		return LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;

	if (st & (BR_SSL_SENDAPP | BR_SSL_RECVAPP)) {
		lwsl_info("%s: client connect OK\n", __func__);

		if (lws_ssl_pending(wsi)) {
			struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];
			if (lws_dll2_is_detached(&wsi->tls.dll_pending_tls))
				lws_dll2_add_head(&wsi->tls.dll_pending_tls,
						  &pt->tls.dll_pending_tls_owner);
		}

#if defined(LWS_WITH_TLS_SESSIONS)
		lws_tls_session_new_bearssl(wsi);
#endif
		return LWS_SSL_CAPABLE_DONE;
	}

	return LWS_SSL_CAPABLE_MORE_SERVICE_READ;
}

int
lws_tls_client_confirm_peer_cert(struct lws *wsi, char *ebuf, size_t ebuf_len)
{
	return 0;
}

static int
lws_tls_bearssl_load_pem_certs(struct lws_vhost *vh, const char *filepath)
{
	struct lws_b64state b64;
	uint8_t chunk[1024];
	char line[256];
	uint8_t *der = NULL;
	size_t der_size = 0, der_len = 0;
	int inside = 0, ret = 0, fd, pos = 0;
	ssize_t n, i;

	fd = lws_open(filepath, LWS_O_RDONLY);
	if (fd < 0) {
		lwsl_err("%s: failed to open %s\n", __func__, filepath);
		return 1;
	}

	while ((n = read(fd, chunk, sizeof(chunk))) > 0) {
		for (i = 0; i < n; i++) {
			char c = (char)chunk[i];

			if (c != '\n' && c != '\r' && pos < (int)sizeof(line) - 1) {
				line[pos++] = c;
				continue;
			}
			if (pos == 0)
				continue;

			line[pos] = '\0';
			pos = 0;

			if (!strncmp(line, "-----BEGIN", 10)) {
				inside = 1;
				der_size = 2048;
				der = lws_malloc(der_size, "pem");
				if (!der) {
					ret = 1;
					goto done;
				}
				der_len = 0;
				lws_b64_decode_state_init(&b64);
				continue;
			}

			if (!strncmp(line, "-----END", 8)) {
				size_t in_len = 0, out_size = der_size - der_len;
				inside = 0;
				if (!der)
					continue;
				if (lws_b64_decode_stateful(&b64, "", &in_len, der + der_len, &out_size, 1) < 0) {
					lwsl_notice("%s: failed to decode b64 cert, skipping\n", __func__);
					lws_free(der);
					der = NULL;
					continue;
				}
				der_len += out_size;
				if (der_len && lws_tls_client_vhost_extra_cert_mem(vh, der, der_len))
					lwsl_notice("%s: ignoring unparseable cert\n", __func__);
				lws_free(der);
				der = NULL;
				continue;
			}

			if (inside) {
				size_t in_len = strlen(line);
				size_t out_size = der_size - der_len;

				if (out_size < in_len) {
					uint8_t *new_der;

					der_size += 2048 + in_len;
					new_der = lws_realloc(der, der_size, "pem");
					if (!new_der) {
						ret = 1;
						goto done;
					}
					der = new_der;
					out_size = der_size - der_len;
				}

				if (lws_b64_decode_stateful(&b64, line, &in_len, der + der_len, &out_size, 0) < 0) {
					lwsl_notice("%s: b64 decode err, skipping cert\n", __func__);
					inside = 0;
					lws_free(der);
					der = NULL;
					continue;
				}
				der_len += out_size;
			}
		}
	}

done:
	if (der)
		lws_free(der);
	close(fd);

	return ret;
}

static int
lws_tls_bearssl_load_certs_dir_cb(const char *dirpath, void *user,
				  struct lws_dir_entry *lde)
{
	struct lws_vhost *vh = (struct lws_vhost *)user;
	char path[256];

	if (lde->type != LDOT_FILE && lde->type != LDOT_LINK)
		return 0;

	lws_snprintf(path, sizeof(path), "%s/%s", dirpath, lde->name);

	/* we don't care about individual file errors here, load whatever we can */
	lws_tls_bearssl_load_pem_certs(vh, path);

	return 0;
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
	struct lws_tls_ctx *ctx;

#if defined(LWS_WITH_TLS_SESSIONS)
	vh->tls_session_cache_max = info->tls_session_cache_max ?
				    info->tls_session_cache_max : 10;
	lws_tls_session_cache(vh, info->tls_session_timeout);
#endif

	ctx = lws_zalloc(sizeof(*ctx), "bearssl client ctx");
	if (!ctx)
		return 1;

	vh->tls.ssl_client_ctx = ctx;

	if (!ca_filepath && (!ca_mem || !ca_mem_len)) {
		ca_filepath = getenv("SSL_CERT_FILE");
		if (!ca_filepath)
			ca_filepath = getenv("SSL_CERT_DIR");

		if (!ca_filepath) {
			if (access("/etc/ssl/certs/ca-certificates.crt", R_OK) == 0)
				ca_filepath = "/etc/ssl/certs/ca-certificates.crt";
			else if (access("/etc/pki/tls/certs/ca-bundle.crt", R_OK) == 0)
				ca_filepath = "/etc/pki/tls/certs/ca-bundle.crt";
		}
#if defined(LWS_OPENSSL_CLIENT_CERTS)
		if (!ca_filepath)
			ca_filepath = LWS_OPENSSL_CLIENT_CERTS;
#endif
	}

	if (ca_filepath) {
#if !defined(LWS_PLAT_OPTEE)
		struct stat s;
		if (!stat(ca_filepath, &s) && (s.st_mode & S_IFMT) == S_IFDIR) {
			lws_dir(ca_filepath, vh, lws_tls_bearssl_load_certs_dir_cb);
		} else {
			if (lws_tls_bearssl_load_pem_certs(vh, ca_filepath)) {
				lwsl_err("%s: failed to load CA %s\n", __func__, ca_filepath);
				return 1;
			}
		}
#endif
	} else if (ca_mem && ca_mem_len) {
		if (lws_tls_client_vhost_extra_cert_mem(vh, ca_mem, ca_mem_len))
			return 1;
	}

	return 0;
}

int
lws_ssl_client_bio_create(struct lws *wsi)
{
	struct lws_tls_conn *conn;

	conn = lws_zalloc(sizeof(*conn), "bearssl conn");
	if (!conn)
		return -1;

	wsi->tls.ssl = (lws_tls_conn *)conn;
	conn->is_client = 1;
	conn->ctx = wsi->a.vhost->tls.ssl_client_ctx;

	return 0;
}
