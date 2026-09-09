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
#include "private.h"

/* Helper to manage SChannel buffers */
	static int
lws_tls_schannel_realloc_buffer(struct lws_tls_schannel_conn *conn, size_t new_size)
{
	if (new_size <= conn->rx_alloc)
		return 0;

	uint8_t *new_buf = lws_realloc(conn->rx_buf, new_size, "schannel_rx");
	if (!new_buf)
		return 1;

	conn->rx_buf = new_buf;
	conn->rx_alloc = new_size;
	return 0;
}

int
lws_ssl_client_bio_create(struct lws *wsi)
{
	struct lws_tls_schannel_conn *conn;
	char hostname[128];

	conn = lws_zalloc(sizeof(*conn), "schannel_conn");
	if (!conn) return -1;

	wsi->tls.ssl = conn;

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

	/* Handle port stripping */
	lws_tls_client_strip_port(hostname);

	lws_strncpy(conn->hostname, hostname, sizeof(conn->hostname));

	/* ALPN */
#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
	if (wsi->alpn[0])
		lws_strncpy(conn->alpn, wsi->alpn, sizeof(conn->alpn));
	else if (wsi->a.vhost->tls.alpn)
		lws_strncpy(conn->alpn, wsi->a.vhost->tls.alpn, sizeof(conn->alpn));
#endif

	conn->relax = wsi->tls.use_ssl & (unsigned int)
			(LCCSCF_ALLOW_SELFSIGNED | LCCSCF_ALLOW_EXPIRED |
			 LCCSCF_ALLOW_INSECURE |
			 LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK);

	return 0;
}

/*
 * How many times a single service may go round the "SSPI wants more of this
 * record" loop before we hand back to the event loop.  A peer that dribbles
 * one handshake record out in tiny TCP segments must not be able to keep us
 * in here (it used to recurse once per recv(), one stack frame at a time)
 */

#define LWS_SCH_HS_LOOP_BUDGET 8

/* the same, for records that decrypt to no application data at all */

#define LWS_SCH_RX_LOOP_BUDGET 16

#if defined(LWS_WITH_TCP_TLS)
	enum lws_ssl_capable_status
lws_tls_client_connect(struct lws *wsi, char *errbuf, size_t len)
{
	struct lws_tls_schannel_conn *conn = wsi->tls.ssl;
	struct lws_tls_schannel_ctx *ctx = wsi->a.vhost->tls.ssl_client_ctx;
	SecBufferDesc out_desc, in_desc;
       SecBuffer out_buf[1], in_buf[3];
	ULONG req_attrs, ret_attrs;
	SECURITY_STATUS status = SEC_E_INTERNAL_ERROR;
	int budget = LWS_SCH_HS_LOOP_BUDGET;
	ssize_t n;

	if (!ctx || !conn)
		return LWS_SSL_CAPABLE_ERROR;

	req_attrs = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
		    ISC_REQ_CONFIDENTIALITY | ISC_REQ_STREAM |
		    ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_MANUAL_CRED_VALIDATION |
		    ISC_REQ_USE_SUPPLIED_CREDS;

	/* If we have pending output from previous step, try to send it */
	if (conn->tx_buf && conn->tx_pos < conn->tx_len) {
		n = send(wsi->desc.sockfd, (char *)conn->tx_buf + conn->tx_pos, (int)(conn->tx_len - conn->tx_pos), 0);
		if (n < 0) {
			if (LWS_ERRNO == LWS_EAGAIN || LWS_ERRNO == LWS_EWOULDBLOCK)
				return LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;
			return LWS_SSL_CAPABLE_ERROR;
		}
		conn->tx_pos += n;
		if (conn->tx_pos < conn->tx_len)
			return LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;

		lws_free_set_NULL(conn->tx_buf);
		conn->tx_len = 0;
		conn->tx_pos = 0;
	}

       if (conn->f_handshake_finished)
               return LWS_SSL_CAPABLE_DONE;


       uint8_t alpn_buf[256];
       size_t alpn_len = 0;

       /* ALPN */
       if (conn->alpn[0]) {
               uint32_t proto_lists_size = 0;
               uint32_t proto_id_type = 2; /* SecApplicationProtocolNegotiationExt_ALPN */
               uint16_t list_size = 0;

               uint8_t *pData = alpn_buf + 10; /* Skip 10 bytes header */
               char temp[64];
               lws_strncpy(temp, conn->alpn, sizeof(temp));
               const char *p = temp;
               const char *end = p + strlen(p);

               while (p < end) {
                       const char *comma = strchr(p, ',');
                       size_t item_len;
                       if (comma) item_len = lws_ptr_diff_size_t(comma, p);
                       else item_len = strlen(p);

                       if (item_len > 0 && item_len < 256) {
                               if (pData + 1 + item_len > alpn_buf + sizeof(alpn_buf)) break;
                               *pData++ = (uint8_t)item_len;
                               memcpy(pData, p, item_len);
                               pData += item_len;
                       }

                       if (comma) p = comma + 1;
                       else break;
               }

               list_size = (uint16_t)(pData - (alpn_buf + 10));
               proto_lists_size = 6 + list_size;

               memcpy(alpn_buf, &proto_lists_size, 4);
               memcpy(alpn_buf + 4, &proto_id_type, 4);
               memcpy(alpn_buf + 8, &list_size, 2);
               alpn_len = (size_t)(pData - alpn_buf);
       }

	while (budget--) {

	/*
	 * in_buf[] is consulted below for SECBUFFER_EXTRA whichever branch we
	 * took, but the initial branch hands SSPI its own in_bufs[]... so it
	 * has to start out defined every time round
	 */

	memset(in_buf, 0, sizeof(in_buf));

	if (!conn->f_context_init) {
		/* Initial call */
		SecBuffer in_bufs[1];
		SecBufferDesc in_desc_initial;

               in_bufs[0].BufferType = SECBUFFER_EMPTY;
               in_bufs[0].pvBuffer = NULL;
               in_bufs[0].cbBuffer = 0;
		in_desc_initial.cBuffers = 0;
               in_desc_initial.pBuffers = in_bufs;
		in_desc_initial.ulVersion = SECBUFFER_VERSION;

               if (alpn_len > 0) {
			in_bufs[0].BufferType = SECBUFFER_APPLICATION_PROTOCOLS;
			in_bufs[0].pvBuffer = alpn_buf;
                       in_bufs[0].cbBuffer = (unsigned long)alpn_len;
			in_desc_initial.cBuffers = 1;
		}

               out_buf[0].BufferType = SECBUFFER_TOKEN;
               out_buf[0].cbBuffer = 0;
               out_buf[0].pvBuffer = NULL;
               out_desc.cBuffers = 1;
               out_desc.pBuffers = out_buf;
               out_desc.ulVersion = SECBUFFER_VERSION;

		status = InitializeSecurityContextA(&ctx->cred, NULL, conn->hostname, req_attrs, 0, 0,
				(in_desc_initial.cBuffers > 0) ? &in_desc_initial : NULL,
				0, &conn->ctxt, &out_desc, &ret_attrs, NULL);
               lwsl_notice("%s: InitSecCtx (initial) returned 0x%x\n", __func__, (int)status);

		conn->f_context_init = 1;
	} else {
		/* Continuation */
		if (conn->rx_len == 0) {
			if (conn->rx_alloc < 4096) lws_tls_schannel_realloc_buffer(conn, 4096);

			n = recv(wsi->desc.sockfd, (char *)conn->rx_buf, (int)conn->rx_alloc, 0);
			if (n < 0) {
				if (LWS_ERRNO == LWS_EAGAIN || LWS_ERRNO == LWS_EWOULDBLOCK)
					return LWS_SSL_CAPABLE_MORE_SERVICE_READ;
				return LWS_SSL_CAPABLE_ERROR;
			} else if (n == 0) {
				return LWS_SSL_CAPABLE_ERROR;
			}
			conn->rx_len = n;
		}

		in_buf[0].BufferType = SECBUFFER_TOKEN;
		in_buf[0].pvBuffer = conn->rx_buf;
		in_buf[0].cbBuffer = (unsigned long)conn->rx_len;
		in_buf[1].BufferType = SECBUFFER_EMPTY;
		in_buf[1].pvBuffer = NULL;
		in_buf[1].cbBuffer = 0;
		in_desc.cBuffers = 2;

               if (alpn_len > 0) {
                       in_buf[2].BufferType = SECBUFFER_APPLICATION_PROTOCOLS;
                       in_buf[2].pvBuffer = alpn_buf;
                       in_buf[2].cbBuffer = (unsigned long)alpn_len;
                       in_desc.cBuffers = 3;
               }

		in_desc.pBuffers = in_buf;
		in_desc.ulVersion = SECBUFFER_VERSION;

		out_buf[0].BufferType = SECBUFFER_TOKEN;
		out_buf[0].cbBuffer = 0;
		out_buf[0].pvBuffer = NULL;
		out_desc.cBuffers = 1;
		out_desc.pBuffers = out_buf;
		out_desc.ulVersion = SECBUFFER_VERSION;

		status = InitializeSecurityContextA(&ctx->cred, &conn->ctxt, conn->hostname, req_attrs, 0, 0,
				&in_desc, 0, NULL, &out_desc, &ret_attrs, NULL);
               lwsl_notice("%s: InitSecCtx (cont) returned 0x%x\n", __func__, (int)status);
	}

	if (status == SEC_E_INCOMPLETE_MESSAGE) {
		if (conn->rx_len == conn->rx_alloc) {
			if (lws_tls_schannel_realloc_buffer(conn, conn->rx_alloc + 2048))
				return LWS_SSL_CAPABLE_ERROR;
		}

		n = recv(wsi->desc.sockfd, (char *)conn->rx_buf + conn->rx_len, (int)(conn->rx_alloc - conn->rx_len), 0);
		if (n < 0) {
			if (LWS_ERRNO == LWS_EAGAIN || LWS_ERRNO == LWS_EWOULDBLOCK)
				return LWS_SSL_CAPABLE_MORE_SERVICE_READ;
			return LWS_SSL_CAPABLE_ERROR;
		} else if (n == 0) {
			return LWS_SSL_CAPABLE_ERROR;
		}
		conn->rx_len += n;

		continue;
	}

	break;

	} /* while (budget--) */

	if (status == SEC_E_INCOMPLETE_MESSAGE)
		/* still short of a whole record, come back when there's more */
		return LWS_SSL_CAPABLE_MORE_SERVICE_READ;

	if (status == SEC_I_CONTINUE_NEEDED || status == SEC_E_OK) {
		if (out_buf[0].cbBuffer > 0 && out_buf[0].pvBuffer) {
			conn->tx_buf = lws_malloc(out_buf[0].cbBuffer, "schannel_tx");
			if (!conn->tx_buf) {
				FreeContextBuffer(out_buf[0].pvBuffer);
				return LWS_SSL_CAPABLE_ERROR;
			}
			memcpy(conn->tx_buf, out_buf[0].pvBuffer, out_buf[0].cbBuffer);
			conn->tx_len = out_buf[0].cbBuffer;
			conn->tx_pos = 0;
			FreeContextBuffer(out_buf[0].pvBuffer);
		}

		if (in_buf[1].BufferType == SECBUFFER_EXTRA &&
		    in_buf[1].cbBuffer > 0 && conn->rx_buf &&
		    conn->rx_len >= in_buf[1].cbBuffer) {
			memmove(conn->rx_buf, (uint8_t*)conn->rx_buf + (conn->rx_len - in_buf[1].cbBuffer), in_buf[1].cbBuffer);
			conn->rx_len = in_buf[1].cbBuffer;
		} else {
			conn->rx_len = 0;
		}

		if (status == SEC_E_OK) {
			conn->f_handshake_finished = 1;
			if (QueryContextAttributes(&conn->ctxt,
						   SECPKG_ATTR_STREAM_SIZES,
						   &conn->stream_sizes) !=
								SEC_E_OK ||
			    !conn->stream_sizes.cbMaximumMessage) {
				lwsl_wsi_err(wsi, "no stream sizes");

				return LWS_SSL_CAPABLE_ERROR;
			}

			/*
			 * Handle the negotiated ALPN through the shared
			 * helper, so (for client connections) the negotiated
			 * ALPN is also recorded in the client alpn cache like
			 * the other TLS backends do
			 */
			lws_tls_schannel_server_conn_alpn(wsi);
               }

               if (conn->tx_buf) {
                       n = send(wsi->desc.sockfd, (char *)conn->tx_buf, (int)conn->tx_len, 0);
                       if (n < 0) {
                               if (LWS_ERRNO == LWS_EAGAIN || LWS_ERRNO == LWS_EWOULDBLOCK)
                                       return LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;
                       } else {
                               conn->tx_pos += n;
                               if (conn->tx_pos == conn->tx_len) {
                                       lws_free_set_NULL(conn->tx_buf);
                                       conn->tx_len = 0;
                               } else {
                                       return LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;
                               }
                       }
		}

               if (status == SEC_E_OK) {
                       return LWS_SSL_CAPABLE_DONE;
               }

		return LWS_SSL_CAPABLE_MORE_SERVICE_READ;
	}

	lwsl_err("%s: InitializeSecurityContext failed 0x%x\n", __func__, (int)status);
	if (errbuf && len)
		lws_snprintf(errbuf, len, "InitializeSecurityContext: 0x%x",
			     (unsigned int)status);

	return LWS_SSL_CAPABLE_ERROR;
}

	int
lws_tls_server_new_nonblocking(struct lws *wsi, lws_sockfd_type accept_fd)
{
	struct lws_tls_schannel_conn *conn;
	conn = lws_zalloc(sizeof(*conn), "schannel_conn_srv");
	if (!conn) return 1;
	wsi->tls.ssl = conn;

	wsi->tls.ctx_ref = lws_tls_ctx_ref_get(wsi->a.vhost);

	return 0;
}
#endif

enum lws_ssl_capable_status
lws_tls_server_accept(struct lws *wsi)
{
	struct lws_tls_schannel_conn *conn = wsi->tls.ssl;
	struct lws_tls_schannel_ctx *ctx = wsi->tls.ctx_ref ? wsi->tls.ctx_ref->ctx : wsi->a.vhost->tls.ssl_ctx;
	SecBufferDesc out_desc, in_desc;
       SecBuffer out_buf[1], in_buf[3];
	ULONG req_attrs, ret_attrs;
	SECURITY_STATUS status = SEC_E_INTERNAL_ERROR;
	int budget = LWS_SCH_HS_LOOP_BUDGET;
	ssize_t n;

    if (!ctx || !conn) {
        lwsl_wsi_err(wsi, "ctx %p (vhost %s) conn %p missing\n", ctx, wsi->a.vhost->name, conn);
        return LWS_SSL_CAPABLE_ERROR;
    }

	if (conn->f_handshake_finished)
		return LWS_SSL_CAPABLE_DONE;

	if (conn->tx_buf && conn->tx_pos < conn->tx_len) {
		n = send(wsi->desc.sockfd, (char *)conn->tx_buf + conn->tx_pos, (int)(conn->tx_len - conn->tx_pos), 0);
		if (n < 0) {
			if (LWS_ERRNO == LWS_EAGAIN || LWS_ERRNO == LWS_EWOULDBLOCK)
				return LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;
			return LWS_SSL_CAPABLE_ERROR;
		}
		conn->tx_pos += n;
		if (conn->tx_pos < conn->tx_len)
			return LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;
		lws_free_set_NULL(conn->tx_buf);
		conn->tx_len = 0;
	}

	req_attrs = ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT |
		ASC_REQ_CONFIDENTIALITY | ASC_REQ_STREAM |
		ASC_REQ_ALLOCATE_MEMORY;

	/*
	 * If the vhost cares about client certificates at all, we have to ask
	 * for one: without ASC_REQ_MUTUAL_AUTH Schannel never sends a
	 * CertificateRequest and there is simply nothing to check afterwards
	 */

	if (lws_check_opt(wsi->a.vhost->options,
			  LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT) ||
	    lws_check_opt(wsi->a.vhost->options,
		LWS_SERVER_OPTION_MBEDTLS_VERIFY_CLIENT_CERT_POST_HANDSHAKE)) {
		req_attrs |= ASC_REQ_MUTUAL_AUTH;
		conn->f_want_client_cert = 1;
	}

	if (conn->rx_len == 0) {
		if (conn->rx_alloc < 4096) lws_tls_schannel_realloc_buffer(conn, 4096);
		n = recv(wsi->desc.sockfd, (char *)conn->rx_buf, (int)conn->rx_alloc, 0);
		if (n < 0) {
			if (LWS_ERRNO == LWS_EAGAIN || LWS_ERRNO == LWS_EWOULDBLOCK)
				return LWS_SSL_CAPABLE_MORE_SERVICE_READ;
             lwsl_err("%s: recv failed %d\n", __func__, LWS_ERRNO);
			return LWS_SSL_CAPABLE_ERROR;
		} else if (n == 0) {
            lwsl_err("%s: recv 0 (EOF)\n", __func__);
			return LWS_SSL_CAPABLE_ERROR;
		}
		conn->rx_len = n;
        lwsl_info("%s: recv %d bytes client hello\n", __func__, (int)n);
	}

       uint8_t alpn_buf[256];
       size_t alpn_len = 0;

       if (wsi->a.vhost->tls.alpn) {
               uint8_t *pData = alpn_buf + 10;
               uint32_t ext_type = 2, total_list_size; /* 2 = SecApplicationProtocolNegotiationExt_ALPN */
               uint16_t list_size;
               const char *p = wsi->a.vhost->tls.alpn;

               while (p && *p) {
                       const char *comma = strchr(p, ',');
                       size_t item_len = comma ? lws_ptr_diff_size_t(comma, p) : strlen(p);
                       if (item_len > 255 || (pData + item_len + 1 - alpn_buf) > 256) break;
                       *pData++ = (uint8_t)item_len;
                       memcpy(pData, p, item_len);
                       pData += item_len;
                       if (comma) p = comma + 1;
                       else break;
               }

               list_size = (uint16_t)(pData - (alpn_buf + 10));
               total_list_size = 6 + list_size;
               memcpy(alpn_buf, &total_list_size, 4);
               memcpy(alpn_buf + 4, &ext_type, 4);
               memcpy(alpn_buf + 8, &list_size, 2);
               alpn_len = (size_t)(pData - alpn_buf);
       }

	while (budget--) {

	memset(in_buf, 0, sizeof(in_buf));
	in_buf[0].BufferType = SECBUFFER_TOKEN;
	in_buf[0].pvBuffer = conn->rx_buf;
	in_buf[0].cbBuffer = (unsigned long)conn->rx_len;
	in_buf[1].BufferType = SECBUFFER_EMPTY;
	in_buf[1].pvBuffer = NULL;
	in_buf[1].cbBuffer = 0;
	in_desc.cBuffers = 2;

       if (alpn_len > 0) {
               in_buf[2].BufferType = SECBUFFER_APPLICATION_PROTOCOLS;
               in_buf[2].pvBuffer = alpn_buf;
               in_buf[2].cbBuffer = (unsigned long)alpn_len;
               in_desc.cBuffers = 3;
       }

	in_desc.pBuffers = in_buf;
	in_desc.ulVersion = SECBUFFER_VERSION;

	out_buf[0].BufferType = SECBUFFER_TOKEN;
	out_buf[0].cbBuffer = 0;
	out_buf[0].pvBuffer = NULL;
	out_desc.cBuffers = 1;
	out_desc.pBuffers = out_buf;
	out_desc.ulVersion = SECBUFFER_VERSION;

#if defined(LWS_WITH_LATENCY)
	lws_usec_t _sch_ssl_acc_start = lws_now_usecs();
#endif

	status = AcceptSecurityContext(&ctx->cred, conn->f_context_init ? &conn->ctxt : NULL,
			&in_desc, req_attrs, 0, &conn->ctxt,
			&out_desc, &ret_attrs, NULL);

#if defined(LWS_WITH_LATENCY)
	{
		unsigned int ms = (unsigned int)((lws_now_usecs() - _sch_ssl_acc_start) / 1000);
		if (ms > 2 && !wsi->tls.ssl_accept_in_bg)
			lws_latency_note(&wsi->a.context->pt[(int)wsi->tsi], _sch_ssl_acc_start, 2000, "ssl_accept:%dms", ms);
	}
#endif

	conn->f_context_init = 1;

    lwsl_info("%s: AcceptSecurityContext status 0x%x\n", __func__, (int)status);

	if (status == SEC_E_INCOMPLETE_MESSAGE) {
		if (conn->rx_len == conn->rx_alloc) {
			if (lws_tls_schannel_realloc_buffer(conn, conn->rx_alloc + 2048))
				return LWS_SSL_CAPABLE_ERROR;
		}
		n = recv(wsi->desc.sockfd, (char *)conn->rx_buf + conn->rx_len, (int)(conn->rx_alloc - conn->rx_len), 0);
		if (n < 0) {
			if (LWS_ERRNO == LWS_EAGAIN || LWS_ERRNO == LWS_EWOULDBLOCK)
				return LWS_SSL_CAPABLE_MORE_SERVICE_READ;
			return LWS_SSL_CAPABLE_ERROR;
		} else if (n == 0) {
			return LWS_SSL_CAPABLE_ERROR;
		}
		conn->rx_len += n;

		continue;
	}

	break;

	} /* while (budget--) */

	if (status == SEC_E_INCOMPLETE_MESSAGE)
		/* still short of a whole record, come back when there's more */
		return LWS_SSL_CAPABLE_MORE_SERVICE_READ;

	if (status == SEC_I_CONTINUE_NEEDED || status == SEC_E_OK) {
		if (out_buf[0].cbBuffer > 0 && out_buf[0].pvBuffer) {
			conn->tx_buf = lws_malloc(out_buf[0].cbBuffer, "schannel_tx_srv");
			if (!conn->tx_buf) {
				FreeContextBuffer(out_buf[0].pvBuffer);

				return LWS_SSL_CAPABLE_ERROR;
			}
			memcpy(conn->tx_buf, out_buf[0].pvBuffer, out_buf[0].cbBuffer);
			conn->tx_len = out_buf[0].cbBuffer;
			conn->tx_pos = 0;
			FreeContextBuffer(out_buf[0].pvBuffer);

			n = send(wsi->desc.sockfd, (char *)conn->tx_buf, (int)conn->tx_len, 0);
			if (n < 0) {
				if (LWS_ERRNO == LWS_EAGAIN || LWS_ERRNO == LWS_EWOULDBLOCK)
					return LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;
			} else {
				conn->tx_pos += n;
				if (conn->tx_pos == conn->tx_len) {
					lws_free_set_NULL(conn->tx_buf);
					conn->tx_len = 0;
				}
			}
		}

		if (in_buf[1].BufferType == SECBUFFER_EXTRA &&
		    in_buf[1].cbBuffer > 0 && conn->rx_buf &&
		    conn->rx_len >= in_buf[1].cbBuffer) {
			memmove(conn->rx_buf, (uint8_t*)conn->rx_buf + (conn->rx_len - in_buf[1].cbBuffer), in_buf[1].cbBuffer);
			conn->rx_len = in_buf[1].cbBuffer;
		} else {
			conn->rx_len = 0;
		}

		if (status == SEC_E_OK) {
			conn->f_handshake_finished = 1;
			if (QueryContextAttributes(&conn->ctxt,
						   SECPKG_ATTR_STREAM_SIZES,
						   &conn->stream_sizes) !=
								SEC_E_OK ||
			    !conn->stream_sizes.cbMaximumMessage) {
				lwsl_wsi_err(wsi, "no stream sizes");

				return LWS_SSL_CAPABLE_ERROR;
			}

			if (conn->f_want_client_cert &&
			    lws_tls_schannel_server_client_cert(wsi))
				return LWS_SSL_CAPABLE_ERROR;

                       if (lws_ssl_pending(wsi) &&
                           lws_dll2_is_detached(&wsi->tls.dll_pending_tls)) {
                               struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];
                               lws_pt_lock(pt, __func__);
                               lws_dll2_add_head(&wsi->tls.dll_pending_tls,
                                                 &pt->tls.dll_pending_tls_owner);
                               lws_pt_unlock(pt);
                       }

			return LWS_SSL_CAPABLE_DONE;
		}

		if (conn->tx_buf) return LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;
		return LWS_SSL_CAPABLE_MORE_SERVICE_READ;
	}

	lwsl_err("%s: AcceptSecurityContext failed 0x%x\n", __func__, (int)status);
	return LWS_SSL_CAPABLE_ERROR;
}

int
lws_tls_schannel_server_conn_alpn(struct lws *wsi)
{
       struct lws_tls_schannel_conn *conn = wsi->tls.ssl;
       SecPkgContext_ApplicationProtocol alpn_result;
       SECURITY_STATUS alpn_stat;

       if (!conn || !conn->f_handshake_finished)
               return 0;

       alpn_stat = QueryContextAttributes(&conn->ctxt, SECPKG_ATTR_APPLICATION_PROTOCOL, &alpn_result);
       if (alpn_stat == SEC_E_OK && alpn_result.ProtoNegoStatus == SecApplicationProtocolNegotiationStatus_Success) {
               char cstr[64];
               if (alpn_result.ProtocolIdSize < sizeof(cstr)) {
                       memcpy(cstr, alpn_result.ProtocolId, alpn_result.ProtocolIdSize);
                       cstr[alpn_result.ProtocolIdSize] = 0;
                       lwsl_notice("%s: ALPN negotiated %s\n", __func__, cstr);

#if defined(LWS_WITH_CLIENT)
		       /*
			* record the successful ALPN in the cache, the same
			* as the generic helper does for the other backends
			*/
		       if (lwsi_role_client(wsi) && wsi->cli_hostname_copy &&
		           wsi->a.context->alpn_cache && wsi->c_port) {
			       char key[256];
			       void *p;
			       lws_snprintf(key, sizeof(key), "alpn_%s_%u",
					    wsi->cli_hostname_copy,
					    wsi->c_port);
			       lws_cache_write_through(wsi->a.context->alpn_cache,
						       key,
						       (const uint8_t *)cstr,
						       strlen(cstr) + 1,
						       lws_now_usecs() +
						       (lws_usec_t)(3600ULL * 1000000ULL),
						       &p);
			       lwsl_wsi_notice(wsi, "wrote ALPN %s to cache for %s",
					       cstr, key);
		       }
#endif

                       return lws_role_call_alpn_negotiated(wsi, cstr);
               }
       }
       return 0;
}

	int
lws_ssl_capable_read(struct lws *wsi, unsigned char *buf, size_t len)
{
	struct lws_tls_schannel_conn *conn = wsi->tls.ssl;
	SecBufferDesc msg_desc;
	SecBuffer msg_buf[4];
	SECURITY_STATUS status;
	int budget = LWS_SCH_RX_LOOP_BUDGET;
	size_t pending_len;
	ssize_t n;

    if (!wsi->tls.ssl)
        return lws_ssl_capable_read_no_ssl(wsi, buf, len);

	if (!conn || !conn->f_handshake_finished) return LWS_SSL_CAPABLE_ERROR;

	/* Check if we have decrypted data pending in buflist */
	pending_len = lws_buflist_next_segment_len(&conn->decrypted_list, NULL);
	if (pending_len > 0) {
		size_t copy_len = pending_len > len ? len : pending_len;
		lws_buflist_linear_use(&conn->decrypted_list, buf, copy_len);
		lwsl_wsi_debug(wsi, "buflist pending %d, copied %d", (int)pending_len, (int)copy_len);
		n = (int)copy_len;
		goto check_pending;
	}

	/*
	 * Records that decrypt to no application data at all (post-handshake
	 * handshake messages, empty records) used to recurse into ourselves
	 * once per record with no bound at all; go round a bounded loop in
	 * this frame instead and let the event loop have us back after that
	 */

	while (budget--) {

	if (!conn->rx_len) {
		if (!conn->rx_alloc &&
		    lws_tls_schannel_realloc_buffer(conn, 4096))
			return LWS_SSL_CAPABLE_ERROR;
		n = recv(wsi->desc.sockfd, (char *)conn->rx_buf, (int)conn->rx_alloc, 0);
		if (n < 0) {
			if (LWS_ERRNO == LWS_EAGAIN ||
					LWS_ERRNO == LWS_EWOULDBLOCK)
				goto want_read;

			return LWS_SSL_CAPABLE_ERROR;
		}
		if (n == 0)
			return LWS_SSL_CAPABLE_ERROR;

		conn->rx_len = n;
		lwsl_wsi_debug(wsi, "recv %d bytes", (int)n);
	}

	/* Decrypt */
	msg_buf[0].BufferType = SECBUFFER_DATA;
	msg_buf[0].pvBuffer = conn->rx_buf;
	msg_buf[0].cbBuffer = (unsigned long)conn->rx_len;
	msg_buf[1].BufferType = SECBUFFER_EMPTY;
	msg_buf[2].BufferType = SECBUFFER_EMPTY;
	msg_buf[3].BufferType = SECBUFFER_EMPTY;

	msg_desc.cBuffers = 4;
	msg_desc.pBuffers = msg_buf;
	msg_desc.ulVersion = SECBUFFER_VERSION;

	status = DecryptMessage(&conn->ctxt, &msg_desc, 0, NULL);

	if (status == SEC_E_INCOMPLETE_MESSAGE) {
		if (conn->rx_len == conn->rx_alloc &&
		    lws_tls_schannel_realloc_buffer(conn, conn->rx_alloc + 2048))
			return LWS_SSL_CAPABLE_ERROR;

		n = recv(wsi->desc.sockfd, (char *)conn->rx_buf + conn->rx_len, (int)(conn->rx_alloc - conn->rx_len), 0);
		if (n < 0) {
			if (LWS_ERRNO == LWS_EAGAIN || LWS_ERRNO == LWS_EWOULDBLOCK)
				goto want_read;

			return LWS_SSL_CAPABLE_ERROR;
		} else if (n == 0) {
			return LWS_SSL_CAPABLE_ERROR;
		}
		conn->rx_len += n;

		continue;
	}

       if (status != SEC_E_OK && status != SEC_I_RENEGOTIATE && status != SEC_I_CONTEXT_EXPIRED && status != SEC_E_CONTEXT_EXPIRED) {
		lwsl_err("%s: DecryptMessage failed 0x%x\n", __func__, (int)status);
		return LWS_SSL_CAPABLE_ERROR;
	}

	if (status == SEC_E_OK || status == SEC_I_RENEGOTIATE ||
           status == SEC_I_CONTEXT_EXPIRED || status == SEC_E_CONTEXT_EXPIRED) {
		int i;
		uint8_t *dec_data = NULL;
		size_t dec_len = 0;

		/* First locate the data pointer/length before any memmove happens */
		for (i = 0; i < 4; i++) {
			if (msg_buf[i].BufferType == SECBUFFER_DATA) {
				dec_data = msg_buf[i].pvBuffer;
				dec_len = msg_buf[i].cbBuffer;
				break;
			}
		}

		/* Process decrypted data immediately */
		if (dec_len > 0) {
			size_t copy_len = dec_len > len ? len : dec_len;
			memcpy(buf, dec_data, copy_len);

			if (dec_len > copy_len) {
				if (lws_buflist_append_segment(&conn->decrypted_list, dec_data + copy_len, dec_len - copy_len) < 0) {
					lwsl_err("OOM appending to buflist\n");
					return LWS_SSL_CAPABLE_ERROR;
				}
			}
			n = (int)copy_len; /* Return value */
			lwsl_wsi_debug(wsi, "decrypted %d bytes, copied %d to user\n", (int)dec_len, (int)n);
		} else {
                       if (status == SEC_I_CONTEXT_EXPIRED || status == SEC_E_CONTEXT_EXPIRED)
                               return LWS_SSL_CAPABLE_ERROR;

			/*
			 * Renegotiation is refused.  Re-running the handshake
			 * here does not re-run the peer certificate
			 * confirmation (that only happens in
			 * lws_ssl_client_connect2()), so the peer could swap
			 * to any certificate it liked and we would carry on
			 * as if it were the one we verified.  TLS 1.3, which
			 * is what this backend asks for, has no renegotiation
			 * at all
			 */

			if (status == SEC_I_RENEGOTIATE) {
				lwsl_wsi_notice(wsi, "refusing renegotiation");

				return LWS_SSL_CAPABLE_ERROR;
			}

			/* Handshake message or empty record: go round again */
			/* But first move extra data */
			for (i = 0; i < 4; i++)
				if (msg_buf[i].BufferType == SECBUFFER_EXTRA) {
					memmove(conn->rx_buf, msg_buf[i].pvBuffer, msg_buf[i].cbBuffer);
					conn->rx_len = msg_buf[i].cbBuffer;
					break;
				}

			if (i == 4)
				conn->rx_len = 0;

			continue;
		}

		/* Now handle extra data buffering */
		for (i = 0; i < 4; i++) {
			if (msg_buf[i].BufferType == SECBUFFER_EXTRA) {
				memmove(conn->rx_buf, msg_buf[i].pvBuffer, msg_buf[i].cbBuffer);
				conn->rx_len = msg_buf[i].cbBuffer;
				goto check_pending;
			}
		}
		conn->rx_len = 0;

		goto check_pending;
	}

	return LWS_SSL_CAPABLE_ERROR;

	} /* while (budget--) */

want_read:
	/*
	 * We have nothing for the caller this time.  Fall through the pending
	 * bookkeeping rather than returning directly: if there is no complete
	 * record waiting we must come off the fake-POLLIN list, or the event
	 * loop spins on us at 100% CPU for as long as the peer stays quiet
	 */

	n = LWS_SSL_CAPABLE_MORE_SERVICE_READ;

check_pending:
	{
		struct lws_context_per_thread *pt =
				&wsi->a.context->pt[(int)wsi->tsi];

		lws_pt_lock(pt, __func__);
		if (lws_ssl_pending(wsi)) {
			if (lws_dll2_is_detached(&wsi->tls.dll_pending_tls))
				lws_dll2_add_head(&wsi->tls.dll_pending_tls,
						  &pt->tls.dll_pending_tls_owner);
		} else
			__lws_ssl_remove_wsi_from_buffered_list(wsi);
		lws_pt_unlock(pt);
	}

	return (int)n;
}

	int
lws_ssl_capable_write(struct lws *wsi, unsigned char *buf, size_t len)
{
	struct lws_tls_schannel_conn *conn = wsi->tls.ssl;
	SecBufferDesc msg_desc;
	SecBuffer msg_buf[4];
	SECURITY_STATUS status;
	uint8_t *alloc_buf;
	size_t alloc_len;
	ssize_t n;

    if (!wsi->tls.ssl)
        return lws_ssl_capable_write_no_ssl(wsi, buf, len);

	if (!conn || !conn->f_handshake_finished) return LWS_SSL_CAPABLE_ERROR;

	/* Flush existing ciphertext */
	if (conn->tx_buf) {
		n = send(wsi->desc.sockfd, (char *)conn->tx_buf + conn->tx_pos, (int)(conn->tx_len - conn->tx_pos), 0);
		if (n < 0) {
			if (LWS_ERRNO == LWS_EAGAIN || LWS_ERRNO == LWS_EWOULDBLOCK)
				return LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;
			return LWS_SSL_CAPABLE_ERROR;
		}
		conn->tx_pos += n;
		if (conn->tx_pos < conn->tx_len)
			return LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;

		lws_free_set_NULL(conn->tx_buf);
		conn->tx_len = 0;
		conn->tx_pos = 0;

		/* Consumed old data, but what about new data?
		   The caller called us to write 'buf'.
		   We just flushed OLD data.
		   We should now process the new data if possible, or return 0?
		   If we return 0, LWS might think we wrote nothing.
		   Actually, we should proceed to encrypt 'buf' now that we are clear.
		   */
	}

	/*
	 * EncryptMessage() will not accept more plaintext than
	 * cbMaximumMessage in one record; hand back a short write for the
	 * rest rather than failing the whole connection
	 */

	if (!conn->stream_sizes.cbMaximumMessage)
		return LWS_SSL_CAPABLE_ERROR;

	if (len > conn->stream_sizes.cbMaximumMessage)
		len = conn->stream_sizes.cbMaximumMessage;

	alloc_len = conn->stream_sizes.cbHeader + len + conn->stream_sizes.cbTrailer;
	alloc_buf = lws_malloc(alloc_len, "schannel_write");
	if (!alloc_buf) return LWS_SSL_CAPABLE_ERROR;

	msg_buf[0].BufferType = SECBUFFER_STREAM_HEADER;
	msg_buf[0].pvBuffer = alloc_buf;
	msg_buf[0].cbBuffer = conn->stream_sizes.cbHeader;

	msg_buf[1].BufferType = SECBUFFER_DATA;
	msg_buf[1].pvBuffer = alloc_buf + conn->stream_sizes.cbHeader;
	msg_buf[1].cbBuffer = (unsigned long)len;
	memcpy(msg_buf[1].pvBuffer, buf, len);

	msg_buf[2].BufferType = SECBUFFER_STREAM_TRAILER;
	msg_buf[2].pvBuffer = alloc_buf + conn->stream_sizes.cbHeader + len;
	msg_buf[2].cbBuffer = conn->stream_sizes.cbTrailer;

	msg_buf[3].BufferType = SECBUFFER_EMPTY;
	msg_buf[3].cbBuffer = 0;

	msg_desc.cBuffers = 4;
	msg_desc.pBuffers = msg_buf;
	msg_desc.ulVersion = SECBUFFER_VERSION;

	status = EncryptMessage(&conn->ctxt, 0, &msg_desc, 0);
	if (status != SEC_E_OK) {
		lwsl_err("%s: EncryptMessage failed 0x%x\n", __func__, (int)status);
		lws_free(alloc_buf);
		return LWS_SSL_CAPABLE_ERROR;
	}

	size_t total_len = msg_buf[0].cbBuffer + msg_buf[1].cbBuffer + msg_buf[2].cbBuffer;

	n = send(wsi->desc.sockfd, (char *)alloc_buf, (int)total_len, 0);

	if (n < 0) {
		if (LWS_ERRNO == LWS_EAGAIN || LWS_ERRNO == LWS_EWOULDBLOCK) {
			/* Blocked immediately. Buffer EVERYTHING. */
			conn->tx_buf = alloc_buf;
			conn->tx_len = total_len;
			conn->tx_pos = 0;
			return (int)len; /* Valid write of plaintext, but buffered ciphertext */
		}
		lws_free(alloc_buf);
		return LWS_SSL_CAPABLE_ERROR;
	}

	if ((size_t)n < total_len) {
		/* Partial write. Buffer remainder. */
		conn->tx_buf = alloc_buf;
		conn->tx_len = total_len;
		conn->tx_pos = n;
		/* We return 'len' because we accepted the whole plaintext frame and encrypted it. */
		return (int)len;
	}

	lws_free(alloc_buf);
	return (int)len;
}

	int
lws_ssl_pending(struct lws *wsi)
{
	struct lws_tls_schannel_conn *conn = wsi->tls.ssl;

	/*
	 * "Pending" has to mean "another call will make progress without the
	 * socket becoming readable", ie, decrypted data we have not handed
	 * over yet, or a whole undecrypted record sitting in rx_buf.  Any
	 * lesser test (such as "rx_len is nonzero") leaves a peer that sent a
	 * few bytes of a record and then went quiet permanently on the
	 * fake-POLLIN list, which the event loop then services with a zero
	 * timeout for ever
	 */

	if (conn && lws_buflist_next_segment_len(&conn->decrypted_list, NULL) > 0) {
		lwsl_wsi_debug(wsi, "pending buflist");
		return 1;
	}

	if (conn && conn->rx_len >= 5) {
		size_t record_len = (((size_t)conn->rx_buf[3]) << 8) | conn->rx_buf[4];
		if (conn->rx_len >= 5 + record_len) {
			lwsl_wsi_debug(wsi, "pending rx_buf complete record %d", (int)record_len);
			return 1;
		}
	}

	return 0;
}

	int
lws_ssl_close(struct lws *wsi)
{
	struct lws_tls_schannel_conn *conn = wsi->tls.ssl;
	if (conn) {
		DeleteSecurityContext(&conn->ctxt);
		/* rx_buf / tx_buf hold plaintext, and conn holds key-ish
		 * material for QUIC; do not leave it in the freed heap */
		if (conn->rx_buf)
			lws_explicit_bzero(conn->rx_buf, conn->rx_alloc);
		if (conn->tx_buf)
			lws_explicit_bzero(conn->tx_buf, conn->tx_len);
		lws_free_set_NULL(conn->rx_buf);
		lws_free_set_NULL(conn->tx_buf);
		lws_buflist_destroy_all_segments(&conn->decrypted_list);
		lws_explicit_bzero(conn, sizeof(*conn));
		lws_free_set_NULL(conn);
		wsi->tls.ssl = NULL;
	}

	if (wsi->tls.ctx_ref) {
		lws_tls_ctx_ref_unref(wsi->tls.ctx_ref);
		wsi->tls.ctx_ref = NULL;
	}

	if (wsi->tls.quic_tp_recv) {
		lws_free((void *)wsi->tls.quic_tp_recv);
		wsi->tls.quic_tp_recv = NULL;
	}
	if (wsi->tls.quic_tp_send) {
		lws_free((void *)wsi->tls.quic_tp_send);
		wsi->tls.quic_tp_send = NULL;
	}

	return 0;
}

	void
lws_ssl_bind_passphrase(lws_tls_ctx *ssl_ctx, int is_client,
		const struct lws_context_creation_info *info)
{
}

	enum lws_ssl_capable_status
lws_tls_server_abort_connection(struct lws *wsi)
{
	lws_ssl_close(wsi);
	return LWS_SSL_CAPABLE_DONE;
}

	enum lws_ssl_capable_status
__lws_tls_shutdown(struct lws *wsi)
{
	lws_ssl_close(wsi);
	return LWS_SSL_CAPABLE_DONE;
}

/*
 * Chain trust bits that are never a reason to refuse here: we do not ask
 * CertGetCertificateChain() for revocation checking, so "unknown" is the
 * expected answer rather than a finding
 */

#define LWS_SCH_TRUST_DONT_CARE (CERT_TRUST_REVOCATION_STATUS_UNKNOWN | \
				 CERT_TRUST_IS_OFFLINE_REVOCATION)

static DWORD
lws_tls_schannel_policy(PCCERT_CHAIN_CONTEXT chain, DWORD auth_type,
			WCHAR *wname, DWORD ignore)
{
	CERT_CHAIN_POLICY_STATUS ps;
	HTTPSPolicyCallbackData ph;
	CERT_CHAIN_POLICY_PARA pp;

	memset(&ph, 0, sizeof(ph));
	ph.cbStruct = sizeof(ph);
	ph.dwAuthType = auth_type;
	ph.pwszServerName = wname;

	memset(&pp, 0, sizeof(pp));
	pp.cbSize = sizeof(pp);
	pp.dwFlags = ignore;
	pp.pvExtraPolicyPara = &ph;

	memset(&ps, 0, sizeof(ps));
	ps.cbSize = sizeof(ps);

	if (!CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, chain,
					      &pp, &ps))
		return (DWORD)CERT_E_UNTRUSTEDROOT;

	return ps.dwError;
}

/*
 * The single place this backend decides whether a peer certificate is
 * acceptable.
 *
 * The chain is built against ctx's exclusive trust root if the app pinned a
 * CA, else against the OS ROOT store.  It is then judged twice: once with
 * nothing forgiven, which is what LWS_TLS_CERT_INFO_VERIFIED reports, and
 * (only if that failed and the connection asked for it) once with exactly
 * the relaxations the LCCSCF_ALLOW_... flags describe.
 *
 * Deciding it this way is what keeps the openssl semantics: the name check
 * lives in the SSL chain policy and is only skipped for
 * LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK, so an untrusted root can never
 * hide a name mismatch behind itself, and the chain error bits are examined
 * separately so a passing name cannot hide a chain problem either.
 */

int
lws_tls_schannel_confirm_cert(struct lws_tls_schannel_ctx *ctx,
			      struct lws_tls_schannel_conn *conn,
			      PCCERT_CONTEXT pCert, const char *hostname,
			      char *ebuf, size_t ebuf_len)
{
	LPSTR usage = hostname ? (LPSTR)szOID_PKIX_KP_SERVER_AUTH :
				 (LPSTR)szOID_PKIX_KP_CLIENT_AUTH;
	PCCERT_CHAIN_CONTEXT chain = NULL;
	DWORD auth_type = hostname ? AUTHTYPE_SERVER : AUTHTYPE_CLIENT;
	WCHAR wname[128], *pwname = NULL;
	DWORD err, ignore = 0, allowed = LWS_SCH_TRUST_DONT_CARE;
	HCERTCHAINENGINE engine;
	CERT_CHAIN_PARA cp;
	int ret = -1;

	if (!conn || !pCert)
		return -1;

	engine = lws_tls_schannel_chain_engine(ctx);
	if (ctx && ctx->ca_store && !engine) {
		/*
		 * The app pinned a CA but we could not make it the exclusive
		 * trust root; going ahead on the default engine would trust
		 * the whole OS root store instead, so refuse
		 */
		lws_snprintf(ebuf, ebuf_len, "cannot honour the pinned CA");

		return -1;
	}

	conn->f_peer_cert_checked = 1;
	conn->f_peer_cert_verified = 0;

	if (hostname) {
		/*
		 * If the hostname is not valid UTF-8 (or does not fit), we
		 * must fail closed: leaving pwszServerName NULL makes the SSL
		 * chain policy skip name matching entirely (F-047)
		 */
		if (!MultiByteToWideChar(CP_UTF8, 0, hostname, -1, wname,
					 (int)LWS_ARRAY_SIZE(wname))) {
			lws_snprintf(ebuf, ebuf_len, "hostname not valid "
				     "UTF-8, refusing to skip peer name check");

			return -1;
		}
		pwname = wname;
	}

	memset(&cp, 0, sizeof(cp));
	cp.cbSize = sizeof(cp);
	cp.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
	cp.RequestedUsage.Usage.cUsageIdentifier = 1;
	cp.RequestedUsage.Usage.rgpszUsageIdentifier = &usage;

	if (!CertGetCertificateChain(engine, pCert, NULL,
				     ctx ? ctx->store : NULL, &cp, 0,
				     NULL, &chain) || !chain) {
		lws_snprintf(ebuf, ebuf_len, "cannot build peer cert chain");

		return -1;
	}

	err = lws_tls_schannel_policy(chain, auth_type, pwname, 0);
	if (err == ERROR_SUCCESS &&
	    !(chain->TrustStatus.dwErrorStatus & ~LWS_SCH_TRUST_DONT_CARE)) {
		conn->f_peer_cert_verified = 1;
		ret = 0;
		goto bail;
	}

	if (!conn->relax) {
		lws_snprintf(ebuf, ebuf_len, "Certificate validation failed: "
			     "0x%x (chain 0x%x)", (unsigned int)err,
			     (unsigned int)chain->TrustStatus.dwErrorStatus);
		goto bail;
	}

	if (conn->relax & (LCCSCF_ALLOW_SELFSIGNED | LCCSCF_ALLOW_INSECURE)) {
		ignore |= CERT_CHAIN_POLICY_ALLOW_UNKNOWN_CA_FLAG;
		allowed |= CERT_TRUST_IS_UNTRUSTED_ROOT |
			   CERT_TRUST_IS_PARTIAL_CHAIN;
	}

	if (conn->relax & (LCCSCF_ALLOW_EXPIRED | LCCSCF_ALLOW_INSECURE)) {
		ignore |= CERT_CHAIN_POLICY_IGNORE_ALL_NOT_TIME_VALID_FLAGS;
		allowed |= CERT_TRUST_IS_NOT_TIME_VALID |
			   CERT_TRUST_CTL_IS_NOT_TIME_VALID |
			   CERT_TRUST_IS_NOT_TIME_NESTED;
	}

	if (conn->relax & LCCSCF_ALLOW_INSECURE) {
		ignore |= CERT_CHAIN_POLICY_IGNORE_WRONG_USAGE_FLAG |
			  CERT_CHAIN_POLICY_IGNORE_INVALID_POLICY_FLAG |
			  CERT_CHAIN_POLICY_IGNORE_INVALID_BASIC_CONSTRAINTS_FLAG;
		allowed |= CERT_TRUST_IS_NOT_VALID_FOR_USAGE |
			   CERT_TRUST_INVALID_BASIC_CONSTRAINTS |
			   CERT_TRUST_INVALID_POLICY_CONSTRAINTS |
			   CERT_TRUST_INVALID_NAME_CONSTRAINTS;
	}

	/*
	 * Note that no flag here forgives a name mismatch except
	 * LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK, exactly as on openssl
	 */

	if (conn->relax & LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK)
		ignore |= CERT_CHAIN_POLICY_IGNORE_INVALID_NAME_FLAG;

	err = lws_tls_schannel_policy(chain, auth_type, pwname, ignore);
	if (err == ERROR_SUCCESS &&
	    !(chain->TrustStatus.dwErrorStatus & ~allowed)) {
		lwsl_info("%s: allowing anyway\n", __func__);
		ret = 0;
		goto bail;
	}

	lws_snprintf(ebuf, ebuf_len, "Certificate validation failed: 0x%x "
		     "(chain 0x%x)", (unsigned int)err,
		     (unsigned int)chain->TrustStatus.dwErrorStatus);

bail:
	CertFreeCertificateChain(chain);

	return ret;
}

	int
lws_tls_client_confirm_peer_cert(struct lws *wsi, char *ebuf, size_t ebuf_len)
{
	struct lws_tls_schannel_conn *conn = wsi->tls.ssl;
	struct lws_tls_schannel_ctx *ctx = wsi->a.vhost->tls.ssl_client_ctx;
	PCCERT_CONTEXT pCert = NULL;
	int ret;

	if (!conn)
		return -1;

	if (QueryContextAttributes(&conn->ctxt,
				   SECPKG_ATTR_REMOTE_CERT_CONTEXT,
				   &pCert) != SEC_E_OK || !pCert) {
		lws_snprintf(ebuf, ebuf_len, "no peer certificate");

		return -1;
	}

	ret = lws_tls_schannel_confirm_cert(ctx, conn, pCert, conn->hostname,
					    ebuf, ebuf_len);

	CertFreeCertificateContext(pCert);

	return ret;
}

int
lws_tls_schannel_server_client_cert(struct lws *wsi)
{
	struct lws_tls_schannel_conn *conn = wsi->tls.ssl;
	struct lws_tls_schannel_ctx *ctx = wsi->tls.ctx_ref ?
			wsi->tls.ctx_ref->ctx : wsi->a.vhost->tls.ssl_ctx;
	int required = lws_check_opt(wsi->a.vhost->options,
		LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT) &&
		       !lws_check_opt(wsi->a.vhost->options,
		LWS_SERVER_OPTION_PEER_CERT_NOT_REQUIRED);
	PCCERT_CONTEXT pCert = NULL;
	char ebuf[128];

	if (!conn)
		return 1;

	if (QueryContextAttributes(&conn->ctxt,
				   SECPKG_ATTR_REMOTE_CERT_CONTEXT,
				   &pCert) != SEC_E_OK || !pCert) {
		conn->f_peer_cert_checked = 1;
		conn->f_peer_cert_verified = 0;

		if (!required)
			return 0;

		lwsl_wsi_notice(wsi, "vh %s requires a client cert and the "
				"peer sent none", wsi->a.vhost->name);

		return 1;
	}

	ebuf[0] = '\0';
	if (lws_tls_schannel_confirm_cert(ctx, conn, pCert, NULL, ebuf,
					  sizeof(ebuf))) {
		CertFreeCertificateContext(pCert);

		lwsl_wsi_notice(wsi, "vh %s: client cert rejected: %s",
				wsi->a.vhost->name, ebuf);

		return required;
	}

	CertFreeCertificateContext(pCert);

	return 0;
}

	int
lws_ssl_get_error(struct lws *wsi, int n)
{
	return n;
}

	static int
tops_fake_POLLIN_for_buffered_schannel(struct lws_context_per_thread *pt)
{
	int ret = lws_tls_fake_POLLIN_for_buffered(pt);
	if (ret) lwsl_info("%s: triggered %d\n", __func__, ret);
	return ret;
}

const struct lws_tls_ops tls_ops_schannel = {
	.fake_POLLIN_for_buffered = tops_fake_POLLIN_for_buffered_schannel,
};
