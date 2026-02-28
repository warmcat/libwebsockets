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
	char hostname[128], *p;

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
	p = hostname;
	while (*p) {
		if (*p == ':') {
			*p = '\0';
			break;
		}
		p++;
	}

	lws_strncpy(conn->hostname, hostname, sizeof(conn->hostname));

	/* ALPN */
#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
	if (wsi->a.vhost->tls.alpn)
		lws_strncpy(conn->alpn, wsi->a.vhost->tls.alpn, sizeof(conn->alpn));
#endif

	if (wsi->tls.use_ssl & LCCSCF_ALLOW_SELFSIGNED)
		conn->f_allow_self_signed = 1;

	return 0;
}

	enum lws_ssl_capable_status
lws_tls_client_connect(struct lws *wsi, char *errbuf, size_t len)
{
	struct lws_tls_schannel_conn *conn = wsi->tls.ssl;
	struct lws_tls_schannel_ctx *ctx = wsi->a.vhost->tls.ssl_client_ctx;
	SecBufferDesc out_desc, in_desc;
	SecBuffer out_buf[1], in_buf[2];
	ULONG req_attrs, ret_attrs;
	SECURITY_STATUS status;
	ssize_t n;

	if (!ctx || !conn)
		return LWS_SSL_CAPABLE_ERROR;

	req_attrs = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
		    ISC_REQ_CONFIDENTIALITY | ISC_REQ_STREAM |
		    ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_MANUAL_CRED_VALIDATION |
		    ISC_REQ_USE_SUPPLIED_CREDS;

	if (conn->f_handshake_finished)
		return LWS_SSL_CAPABLE_DONE;

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

	if (!conn->f_context_init) {
		/* Initial call */
		SecBuffer in_bufs[1];
		SecBufferDesc in_desc_initial;
		uint8_t alpn_buf[256];

		out_buf[0].BufferType = SECBUFFER_TOKEN;
		out_buf[0].cbBuffer = 0;
		out_buf[0].pvBuffer = NULL;
		out_desc.cBuffers = 1;
		out_desc.pBuffers = out_buf;
		out_desc.ulVersion = SECBUFFER_VERSION;

		in_desc_initial.cBuffers = 0;
		in_desc_initial.pBuffers = NULL;
		in_desc_initial.ulVersion = SECBUFFER_VERSION;

		/* ALPN */
		if (conn->alpn[0]) {
			/* Construct APPLICATION_PROTOCOLS buffer */
			/* Structure: SecApplicationProtocolNegotiationExt_ALPN */
			/* unsigned long Status;
			   unsigned long ProtoIdType;
			   unsigned long ProtocolListSize;
			   unsigned char ProtocolList[ANYSIZE_ARRAY];
			   */

			uint32_t status = 0;
			uint32_t proto_id_type = 1; /* ALPN */
			uint32_t list_size = 0;

			uint8_t *pData = alpn_buf + 12; /* Skip 12 bytes header */

			/* Parse comma separated list */
			char temp[64];
			lws_strncpy(temp, conn->alpn, sizeof(temp));
			char *p = temp;
			char *end = p + strlen(p);

			while (p < end) {
				char *comma = strchr(p, ',');
				size_t item_len;
				if (comma) item_len = comma - p;
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

			list_size = (uint32_t)(pData - (alpn_buf + 12));

			memcpy(alpn_buf, &status, 4);
			memcpy(alpn_buf + 4, &proto_id_type, 4);
			memcpy(alpn_buf + 8, &list_size, 4);

			in_bufs[0].BufferType = SECBUFFER_APPLICATION_PROTOCOLS;
			in_bufs[0].pvBuffer = alpn_buf;
			in_bufs[0].cbBuffer = (unsigned long)(pData - alpn_buf);

			in_desc_initial.cBuffers = 1;
			in_desc_initial.pBuffers = in_bufs;
		}

		status = InitializeSecurityContextA(&ctx->cred, NULL, conn->hostname, req_attrs, 0, 0,
				(in_desc_initial.cBuffers > 0) ? &in_desc_initial : NULL,
				0, &conn->ctxt, &out_desc, &ret_attrs, NULL);

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
		return lws_tls_client_connect(wsi, errbuf, len);
	}

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

		if (in_buf[1].BufferType == SECBUFFER_EXTRA && in_buf[1].cbBuffer > 0) {
			memmove(conn->rx_buf, (uint8_t*)conn->rx_buf + (conn->rx_len - in_buf[1].cbBuffer), in_buf[1].cbBuffer);
			conn->rx_len = in_buf[1].cbBuffer;
		} else {
			conn->rx_len = 0;
		}

		if (status == SEC_E_OK) {
			conn->f_handshake_finished = 1;
			QueryContextAttributes(&conn->ctxt, SECPKG_ATTR_STREAM_SIZES, &conn->stream_sizes);

			/* Check ALPN Negotiation Result */
			SecPkgContext_ApplicationProtocol alpn_result;
			if (QueryContextAttributes(&conn->ctxt, SECPKG_ATTR_APPLICATION_PROTOCOL, &alpn_result) == SEC_E_OK) {
				if (alpn_result.ProtoNegoStatus == SecApplicationProtocolNegotiationStatus_Success) {
					/* Inform LWS about negotiated protocol */
					char negotiated[64];
					if (alpn_result.ProtocolIdSize < sizeof(negotiated)) {
						memcpy(negotiated, alpn_result.ProtocolId, alpn_result.ProtocolIdSize);
						negotiated[alpn_result.ProtocolIdSize] = 0;
						lws_role_call_alpn_negotiated(wsi, negotiated);
					}
				}
			}

			return LWS_SSL_CAPABLE_DONE;
		}

		if (conn->tx_buf)
			return LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;

		return LWS_SSL_CAPABLE_MORE_SERVICE_READ;
	}

	lwsl_err("%s: InitializeSecurityContext failed 0x%x\n", __func__, (int)status);
	return LWS_SSL_CAPABLE_ERROR;
}

	int
lws_tls_server_new_nonblocking(struct lws *wsi, lws_sockfd_type accept_fd)
{
	struct lws_tls_schannel_conn *conn;
	conn = lws_zalloc(sizeof(*conn), "schannel_conn_srv");
	if (!conn) return 1;
	wsi->tls.ssl = conn;
	return 0;
}

enum lws_ssl_capable_status
lws_tls_server_accept(struct lws *wsi)
{
	struct lws_tls_schannel_conn *conn = wsi->tls.ssl;
	struct lws_tls_schannel_ctx *ctx = wsi->a.vhost->tls.ssl_ctx;
	SecBufferDesc out_desc, in_desc;
	SecBuffer out_buf[1], in_buf[2];
	ULONG req_attrs, ret_attrs;
	SECURITY_STATUS status;
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

	req_attrs = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
		ISC_REQ_CONFIDENTIALITY | ISC_REQ_STREAM |
		ISC_REQ_ALLOCATE_MEMORY;

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

	in_buf[0].BufferType = SECBUFFER_TOKEN;
	in_buf[0].pvBuffer = conn->rx_buf;
	in_buf[0].cbBuffer = (unsigned long)conn->rx_len;
	in_buf[1].BufferType = SECBUFFER_EMPTY;
	in_buf[1].pvBuffer = NULL;
	in_buf[1].cbBuffer = 0;
	in_desc.cBuffers = 2;
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
		return lws_tls_server_accept(wsi);
	}

	if (status == SEC_I_CONTINUE_NEEDED || status == SEC_E_OK) {
		if (out_buf[0].cbBuffer > 0 && out_buf[0].pvBuffer) {
			conn->tx_buf = lws_malloc(out_buf[0].cbBuffer, "schannel_tx_srv");
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

		if (in_buf[1].BufferType == SECBUFFER_EXTRA && in_buf[1].cbBuffer > 0) {
			memmove(conn->rx_buf, (uint8_t*)conn->rx_buf + (conn->rx_len - in_buf[1].cbBuffer), in_buf[1].cbBuffer);
			conn->rx_len = in_buf[1].cbBuffer;
		} else {
			conn->rx_len = 0;
		}

		if (status == SEC_E_OK) {
			conn->f_handshake_finished = 1;
			QueryContextAttributes(&conn->ctxt, SECPKG_ATTR_STREAM_SIZES, &conn->stream_sizes);
			return LWS_SSL_CAPABLE_DONE;
		}

		if (conn->tx_buf) return LWS_SSL_CAPABLE_MORE_SERVICE_WRITE;
		return LWS_SSL_CAPABLE_MORE_SERVICE_READ;
	}

	lwsl_err("%s: AcceptSecurityContext failed 0x%x\n", __func__, (int)status);
	return LWS_SSL_CAPABLE_ERROR;
}

	int
lws_ssl_capable_read(struct lws *wsi, unsigned char *buf, size_t len)
{
	struct lws_tls_schannel_conn *conn = wsi->tls.ssl;
	SecBufferDesc msg_desc;
	SecBuffer msg_buf[4];
	SECURITY_STATUS status;
	ssize_t n;

    if (!wsi->tls.ssl)
        return lws_ssl_capable_read_no_ssl(wsi, buf, len);

	if (!conn || !conn->f_handshake_finished) return LWS_SSL_CAPABLE_ERROR;

	conn->f_socket_is_blocking = 0;

	/* Check if we have decrypted data pending in buflist */
	size_t pending_len = lws_buflist_next_segment_len(&conn->decrypted_list, NULL);
	if (pending_len > 0) {
		size_t copy_len = pending_len > len ? len : pending_len;
		lws_buflist_linear_use(&conn->decrypted_list, buf, copy_len);
		lwsl_wsi_debug(wsi, "buflist pending %d, copied %d", (int)pending_len, (int)copy_len);
		n = (int)copy_len;
		goto check_pending;
	}

	if (!conn->rx_len) {
		if (!conn->rx_alloc)
			lws_tls_schannel_realloc_buffer(conn, 4096);
		n = recv(wsi->desc.sockfd, (char *)conn->rx_buf, (int)conn->rx_alloc, 0);
		if (n < 0) {
			if (LWS_ERRNO == LWS_EAGAIN ||
					LWS_ERRNO == LWS_EWOULDBLOCK) {
				conn->f_socket_is_blocking = 1;
				return LWS_SSL_CAPABLE_MORE_SERVICE_READ;
			}
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
		if (conn->rx_len == conn->rx_alloc)
			lws_tls_schannel_realloc_buffer(conn, conn->rx_alloc + 2048);

		n = recv(wsi->desc.sockfd, (char *)conn->rx_buf + conn->rx_len, (int)(conn->rx_alloc - conn->rx_len), 0);
		if (n < 0) {
			if (LWS_ERRNO == LWS_EAGAIN || LWS_ERRNO == LWS_EWOULDBLOCK) {
				conn->f_socket_is_blocking = 1;
				return LWS_SSL_CAPABLE_MORE_SERVICE_READ;
			}
			return LWS_SSL_CAPABLE_ERROR;
		} else if (n == 0) {
			return LWS_SSL_CAPABLE_ERROR;
		}
		conn->rx_len += n;
		return lws_ssl_capable_read(wsi, buf, len);
	}

	if (status == SEC_E_OK || status == SEC_I_RENEGOTIATE) {
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
			/* Handshake message or empty record. Recurse to read next record. */
			/* But first move extra data */
			for (i = 0; i < 4; i++) {
				if (msg_buf[i].BufferType == SECBUFFER_EXTRA) {
					memmove(conn->rx_buf, msg_buf[i].pvBuffer, msg_buf[i].cbBuffer);
					conn->rx_len = msg_buf[i].cbBuffer;
					return lws_ssl_capable_read(wsi, buf, len);
				}
			}
			conn->rx_len = 0;
			return lws_ssl_capable_read(wsi, buf, len);
		}

		/* Now handle extra data buffering */
		for (i = 0; i < 4; i++) {
			if (msg_buf[i].BufferType == SECBUFFER_EXTRA) {
				memmove(conn->rx_buf, msg_buf[i].pvBuffer, msg_buf[i].cbBuffer);
				conn->rx_len = msg_buf[i].cbBuffer;
				goto done;
			}
		}
		conn->rx_len = 0;

done:
		goto check_pending;
	}

	return LWS_SSL_CAPABLE_ERROR;

check_pending:
	if (n != (ssize_t)len) {
		lws_ssl_remove_wsi_from_buffered_list(wsi);
		return (int)n;
	}

	if (lws_ssl_pending(wsi)) {
		struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];
		if (lws_dll2_is_detached(&wsi->tls.dll_pending_tls))
			lws_dll2_add_head(&wsi->tls.dll_pending_tls, &pt->tls.dll_pending_tls_owner);
	} else {
		lws_ssl_remove_wsi_from_buffered_list(wsi);
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

	if (conn && lws_buflist_next_segment_len(&conn->decrypted_list, NULL) > 0) {
		lwsl_wsi_debug(wsi, "pending buflist");
		return 1;
	}

	if (conn && conn->rx_len > 0 && !conn->f_socket_is_blocking) {
		lwsl_wsi_debug(wsi, "pending rx_len %d", (int)conn->rx_len);
		return 1;
	}

	return 0;
}

	int
lws_ssl_close(struct lws *wsi)
{
	struct lws_tls_schannel_conn *conn = wsi->tls.ssl;
	if (conn) {
		DeleteSecurityContext(&conn->ctxt);
		lws_free_set_NULL(conn->rx_buf);
		lws_free_set_NULL(conn->tx_buf);
		lws_buflist_destroy_all_segments(&conn->decrypted_list);
		lws_free_set_NULL(conn);
		wsi->tls.ssl = NULL;
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

	int
lws_tls_client_confirm_peer_cert(struct lws *wsi, char *ebuf, size_t ebuf_len)
{
	struct lws_tls_schannel_conn *conn = wsi->tls.ssl;
	PCCERT_CONTEXT pCert = NULL;
	SECURITY_STATUS status;
	int ret = -1;

	if (!conn) return -1;

	status = QueryContextAttributes(&conn->ctxt, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &pCert);
	if (status != SEC_E_OK || !pCert) {
		/* No remote cert */
		return -1;
	}

	CERT_CHAIN_PARA ChainPara;
	PCCERT_CHAIN_CONTEXT pChainContext = NULL;

	memset(&ChainPara, 0, sizeof(ChainPara));
	ChainPara.cbSize = sizeof(ChainPara);

	if (CertGetCertificateChain(NULL, pCert, NULL, NULL, &ChainPara, 0, NULL, &pChainContext)) {

		HTTPSPolicyCallbackData polHttps;
		memset(&polHttps, 0, sizeof(HTTPSPolicyCallbackData));
		polHttps.cbStruct = sizeof(HTTPSPolicyCallbackData);
		polHttps.dwAuthType = AUTHTYPE_SERVER;

		/* Convert stored hostname to WCHAR for validation */
		WCHAR wszServerName[128];
		if (MultiByteToWideChar(CP_UTF8, 0, conn->hostname, -1, wszServerName, LWS_ARRAY_SIZE(wszServerName))) {
			polHttps.pwszServerName = wszServerName;
		}

		CERT_CHAIN_POLICY_PARA PolicyPara;
		memset(&PolicyPara, 0, sizeof(PolicyPara));
		PolicyPara.cbSize = sizeof(PolicyPara);
		PolicyPara.pvExtraPolicyPara = &polHttps;

		CERT_CHAIN_POLICY_STATUS PolicyStatus;
		memset(&PolicyStatus, 0, sizeof(PolicyStatus));
		PolicyStatus.cbSize = sizeof(PolicyStatus);

		if (CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, pChainContext, &PolicyPara, &PolicyStatus)) {
			if (PolicyStatus.dwError == ERROR_SUCCESS) {
				ret = 0;
			} else {
				/* Check if we allow self signed */
				if (conn->f_allow_self_signed) {
					/* Check if the error is only related to untrusted root or partial chain */
					if (PolicyStatus.dwError == CERT_E_UNTRUSTEDROOT ||
							PolicyStatus.dwError == CERT_E_CHAINING) {
						ret = 0;
					}
				}

				if (ret != 0) {
					lws_snprintf(ebuf, ebuf_len, "Certificate validation failed: 0x%x", (unsigned int)PolicyStatus.dwError);
				}
			}
		}

		CertFreeCertificateChain(pChainContext);
	}

	CertFreeCertificateContext(pCert);
	return ret;
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
	/* fake_POLLIN_for_buffered */	tops_fake_POLLIN_for_buffered_schannel,
};
