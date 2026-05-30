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
#include "private.h"

#define LWS_SCH_QUIC_TP_EXT_TYPE                        57
#define LWS_SCH_QUIC_TP_HS_TYPE_CLIENT_HELLO            1
#define LWS_SCH_QUIC_TP_HS_TYPE_ENCRYPTED_EXT           8
#define LWS_SCH_QUIC_TP_PARAM_ID_INITIAL_SCID           0x0f
#define LWS_SCH_QUIC_TP_PARAM_ID_INITIAL_MAX_DATA       0x04
#define LWS_SCH_MAX_TRAFFIC_SECRET_SIZE                 512

int
lws_tls_quic_vhost_init(lws_tls_ctx *ctx)
{
	/* No context-wide init needed for QUIC under Schannel */
	return 0;
}

int
lws_tls_quic_init(struct lws *wsi, lws_tls_quic_secret_cb cb)
{
	if (!wsi || !wsi->tls.ssl)
		return -1;

	wsi->tls.quic_secret_cb = cb;

	/* Schannel handles its own buffers, but we might set up a custom bio if needed */
	return 0;
}

int
lws_tls_quic_set_transport_parameters(struct lws *wsi, const uint8_t *tp, size_t tp_len)
{
#if defined(SECPKG_ATTR_APPLICATION_PROTOCOL) || defined(SECPKG_ATTR_APP_DATA)
	/*
	 * Transport parameter exchange on Windows using Schannel for QUIC
	 * typically requires MsQuic or newer Windows 11 / Server 2022 APIs.
	 */
	wsi->tls.quic_tp_send = tp;
	wsi->tls.quic_tp_send_len = tp_len;
	return 0;
#else
	return -1;
#endif
}

int
lws_tls_quic_get_transport_parameters(struct lws *wsi, const uint8_t **tp, size_t *tp_len)
{
	if (!wsi->tls.quic_tp_recv) {
		if (tp_len)
			*tp_len = 0;
		return -1;
	}

	*tp = wsi->tls.quic_tp_recv;
	if (tp_len)
		*tp_len = wsi->tls.quic_tp_recv_len;

	return 0;
}

int
lws_tls_quic_advance_handshake(struct lws *wsi, int level,
			       const uint8_t *in, size_t in_len,
			       uint8_t *out, size_t *out_len)
{
        struct lws_tls_schannel_conn *conn = (struct lws_tls_schannel_conn *)wsi->tls.ssl;
	DWORD flags = 0, req_flags = ISC_REQ_SEQUENCE_DETECT |
				     ISC_REQ_CONFIDENTIALITY |
                                     ISC_REQ_EXTENDED_ERROR |
                                     ISC_REQ_STREAM;
        unsigned long long in_sec_flags = ISC_REQ_MESSAGES;
        SecBuffer in_bufs[8], out_bufs[8];
        SecBufferDesc in_desc, out_desc;
        SECURITY_STATUS status;
        int num_in_bufs = 0;
        union {
          uint8_t buf[256];
          uint64_t align64;
        } alpn_u;
        union {
          uint8_t buf[4096];
          uint64_t align64;
        } tp_u;
        union {
          uint8_t buf[256];
          uint64_t align64;
        } sub_u;
        union {
          uint8_t buf[4096];
          uint64_t align64;
        } peer_tp_u;
        union {
          uint8_t buf[16384];
          uint64_t align64;
        } token_u;
        union {
          uint8_t buf[8]; /* ALERTS are 2 bytes, but ensure 8-byte union size */
          uint64_t align64;
        } alert_u;

        if (!conn)
		return -1;

	/* In Schannel, QUIC handshake uses InitializeSecurityContext/AcceptSecurityContext */
	if (in && in_len) {
		if (!conn->rx_buf || conn->rx_alloc < conn->rx_len + in_len) {
			size_t na = conn->rx_len + in_len + 4096;
			uint8_t *nb = lws_realloc(conn->rx_buf, na, "schannel quic rx");
			if (!nb) return -1;
			conn->rx_buf = nb;
			conn->rx_alloc = na;
		}
		memcpy(conn->rx_buf + conn->rx_len, in, in_len);
		conn->rx_len += in_len;
	}

	memset(&alpn_u, 0, sizeof(alpn_u));
	memset(&tp_u, 0, sizeof(tp_u));
	memset(&sub_u, 0, sizeof(sub_u));
	memset(&peer_tp_u, 0, sizeof(peer_tp_u));
	memset(&token_u, 0, sizeof(token_u));
	memset(&alert_u, 0, sizeof(alert_u));

	if (conn->rx_len == 0 && lwsi_role_client(wsi)) {
		uint8_t *pData = alpn_u.buf + 10;
		uint32_t ext_type = 2, total_list_size; /* 2 = SecApplicationProtocolNegotiationExt_ALPN */
		uint16_t list_size;
		const char *p = wsi->alpn ? wsi->alpn : (wsi->a.vhost->tls.alpn ? wsi->a.vhost->tls.alpn : "h3");

		while (p && *p) {
			const char *comma = strchr(p, ',');
			size_t item_len = comma ? (size_t)(comma - p) : strlen(p);
			if (item_len > 255 || (pData + item_len + 1 - alpn_u.buf) > 256) break;
			*pData++ = (uint8_t)item_len;
			memcpy(pData, p, item_len);
			pData += item_len;
			if (comma) p = comma + 1;
			else break;
		}

		list_size = (uint16_t)(pData - (alpn_u.buf + 10));
		total_list_size = 6 + list_size;
		memcpy(alpn_u.buf, &total_list_size, 4);
		memcpy(alpn_u.buf + 4, &ext_type, 4);
		memcpy(alpn_u.buf + 8, &list_size, 2);

		in_bufs[num_in_bufs].BufferType = SECBUFFER_APPLICATION_PROTOCOLS;
		in_bufs[num_in_bufs].pvBuffer = alpn_u.buf;
		in_bufs[num_in_bufs].cbBuffer = (unsigned long)(pData - alpn_u.buf);
		num_in_bufs++;
	} else if (conn->rx_len > 0) {
		in_bufs[num_in_bufs].BufferType = SECBUFFER_TOKEN;
		in_bufs[num_in_bufs].cbBuffer = (unsigned long)conn->rx_len;
		in_bufs[num_in_bufs].pvBuffer = (void *)conn->rx_buf;
		num_in_bufs++;
	}

	in_bufs[num_in_bufs].BufferType = SECBUFFER_EMPTY;
	in_bufs[num_in_bufs].cbBuffer = 0;
	in_bufs[num_in_bufs].pvBuffer = NULL;
	num_in_bufs++;

	in_bufs[num_in_bufs].BufferType = SECBUFFER_EMPTY;
	in_bufs[num_in_bufs].cbBuffer = 0;
	in_bufs[num_in_bufs].pvBuffer = NULL;
	num_in_bufs++;

	if (conn->rx_len > 0 && !lwsi_role_client(wsi) && !conn->f_context_init && wsi->a.vhost->tls.alpn) {
		uint8_t *pData = alpn_u.buf + 10;
		uint32_t ext_type = 2, total_list_size; /* 2 = SecApplicationProtocolNegotiationExt_ALPN */
		uint16_t list_size;
		const char *p = wsi->a.vhost->tls.alpn;

		while (p && *p) {
			const char *comma = strchr(p, ',');
			size_t item_len = comma ? (size_t)(comma - p) : strlen(p);
			if (item_len > 255 || (pData + item_len + 1 - alpn_u.buf) > 256) break;
			*pData++ = (uint8_t)item_len;
			memcpy(pData, p, item_len);
			pData += item_len;
			if (comma) p = comma + 1;
			else break;
		}

		list_size = (uint16_t)(pData - (alpn_u.buf + 10));
		total_list_size = 6 + list_size;
		memcpy(alpn_u.buf, &total_list_size, 4);
		memcpy(alpn_u.buf + 4, &ext_type, 4);
		memcpy(alpn_u.buf + 8, &list_size, 2);

		in_bufs[num_in_bufs].BufferType = SECBUFFER_APPLICATION_PROTOCOLS;
		in_bufs[num_in_bufs].pvBuffer = alpn_u.buf;
		in_bufs[num_in_bufs].cbBuffer = (unsigned long)(pData - alpn_u.buf);
		num_in_bufs++;
	}

#if defined(ISC_REQ_MESSAGES)
	in_bufs[num_in_bufs].BufferType = SECBUFFER_FLAGS;
	in_bufs[num_in_bufs].cbBuffer = sizeof(in_sec_flags);
	in_bufs[num_in_bufs].pvBuffer = &in_sec_flags;
	num_in_bufs++;
#endif

	if (!conn->f_context_init) {
		SEND_GENERIC_TLS_EXTENSION *ext = (SEND_GENERIC_TLS_EXTENSION *)tp_u.buf;
		ext->ExtensionType = LWS_SCH_QUIC_TP_EXT_TYPE;
		ext->HandshakeType = lwsi_role_client(wsi) ? LWS_SCH_QUIC_TP_HS_TYPE_CLIENT_HELLO : LWS_SCH_QUIC_TP_HS_TYPE_ENCRYPTED_EXT;
		ext->Flags = 0;
		if (wsi->tls.quic_tp_send && wsi->tls.quic_tp_send_len) {
			ext->BufferSize = (WORD)wsi->tls.quic_tp_send_len;
			memcpy(ext->Buffer, wsi->tls.quic_tp_send, ext->BufferSize);
		} else {
			/* SChannel requires valid QUIC Transport Parameters. initial_source_connection_id is mandatory! */
			ext->BufferSize = 16;
			ext->Buffer[0] = LWS_SCH_QUIC_TP_PARAM_ID_INITIAL_SCID;
			ext->Buffer[1] = 0x08; /* length = 8 */
			memset(&ext->Buffer[2], 0x42, 8); /* 8-byte dummy SCID */
			ext->Buffer[10] = LWS_SCH_QUIC_TP_PARAM_ID_INITIAL_MAX_DATA;
			ext->Buffer[11] = 0x04; /* length = 4 */
			memset(&ext->Buffer[12], 0x00, 4);
		}

		if (ext->BufferSize > 0) {
			in_bufs[num_in_bufs].BufferType = SECBUFFER_SEND_GENERIC_TLS_EXTENSION;
			in_bufs[num_in_bufs].cbBuffer = (unsigned long)(offsetof(SEND_GENERIC_TLS_EXTENSION, Buffer) + ext->BufferSize);
			in_bufs[num_in_bufs].pvBuffer = tp_u.buf;
			num_in_bufs++;
		}
	}

	if (conn->rx_len > 0 && lwsi_role_client(wsi) && !wsi->tls.quic_tp_recv) {
		SUBSCRIBE_GENERIC_TLS_EXTENSION *sub = (SUBSCRIBE_GENERIC_TLS_EXTENSION *)sub_u.buf;
		sub->Flags = 0;
		sub->SubscriptionsCount = 1;
		sub->Subscriptions[0].ExtensionType = LWS_SCH_QUIC_TP_EXT_TYPE;
		sub->Subscriptions[0].HandshakeType = LWS_SCH_QUIC_TP_HS_TYPE_ENCRYPTED_EXT;

		in_bufs[num_in_bufs].BufferType = SECBUFFER_SUBSCRIBE_GENERIC_TLS_EXTENSION;
		in_bufs[num_in_bufs].cbBuffer = (unsigned long)(offsetof(SUBSCRIBE_GENERIC_TLS_EXTENSION, Subscriptions) + sizeof(sub->Subscriptions[0]));
		in_bufs[num_in_bufs].pvBuffer = sub;
		num_in_bufs++;
	}

	if (num_in_bufs > 0) {
		in_desc.ulVersion = SECBUFFER_VERSION;
		in_desc.cBuffers = num_in_bufs;
		in_desc.pBuffers = in_bufs;
	}

	out_bufs[0].BufferType = SECBUFFER_TOKEN;
	out_bufs[0].cbBuffer = sizeof(token_u.buf);
	out_bufs[0].pvBuffer = token_u.buf;
	out_desc.cBuffers = 1;

	out_bufs[1].BufferType = SECBUFFER_ALERT;
	out_bufs[1].cbBuffer = 2; /* MSQUIC uses 2 bytes for AlertBufferRaw */
	out_bufs[1].pvBuffer = alert_u.buf;
	out_desc.cBuffers++;

	if (conn->rx_len > 0 && lwsi_role_client(wsi) && !wsi->tls.quic_tp_recv) {
		out_bufs[out_desc.cBuffers].BufferType = SECBUFFER_SUBSCRIBE_GENERIC_TLS_EXTENSION;
		out_bufs[out_desc.cBuffers].cbBuffer = 0;
		out_bufs[out_desc.cBuffers].pvBuffer = NULL;
		out_desc.cBuffers++;
	}

	uint8_t sec_traf_buf[4][LWS_SCH_MAX_TRAFFIC_SECRET_SIZE];
	memset(sec_traf_buf, 0, sizeof(sec_traf_buf));
	for (int i = 0; i < 4; i++) {
		out_bufs[out_desc.cBuffers].BufferType = SECBUFFER_TRAFFIC_SECRETS;
		out_bufs[out_desc.cBuffers].cbBuffer = sizeof(sec_traf_buf[i]);
		out_bufs[out_desc.cBuffers].pvBuffer = sec_traf_buf[i];
		out_desc.cBuffers++;
	}
	out_desc.ulVersion = SECBUFFER_VERSION;
	out_desc.pBuffers = out_bufs;

	if (lwsi_role_client(wsi) || !wsi->a.vhost->listen_port) {
		char *target_name = conn->hostname;
		if (target_name && target_name[0] >= '0' && target_name[0] <= '9') {
			/* SChannel strictly rejects IP addresses for SNI. Pass "localhost" for local tests. */
			target_name = "localhost";
		}

		WCHAR wTargetName[256];
		WCHAR *pwTargetName = NULL;
		if (target_name) {
			if (MultiByteToWideChar(CP_UTF8, 0, target_name, -1, wTargetName, 256) > 0) {
				pwTargetName = wTargetName;
			}
		}

#ifndef SECURITY_NATIVE_DREP
#define SECURITY_NATIVE_DREP 16
#endif
		status = InitializeSecurityContextW(
			&wsi->a.vhost->tls.ssl_client_ctx->cred,
			conn->f_context_init ? &conn->ctxt : NULL,
			pwTargetName,
			req_flags,
			0, SECURITY_NATIVE_DREP, /* Reserved1 = 0, TargetDataRep */
			(num_in_bufs > 0) ? &in_desc : NULL,
			0,
			&conn->ctxt,
			&out_desc,
			&flags,
			NULL);
		conn->f_context_init = 1;
	} else {
		struct lws_tls_schannel_ctx *ctx = wsi->tls.ctx_ref ?
			(struct lws_tls_schannel_ctx *)wsi->tls.ctx_ref->ctx : wsi->a.vhost->tls.ssl_ctx;
		status = AcceptSecurityContext(
			&ctx->cred,
			conn->f_context_init ? &conn->ctxt : NULL,
			(num_in_bufs > 0) ? &in_desc : NULL,
			req_flags,
			SECURITY_NATIVE_DREP,
			&conn->ctxt,
			&out_desc,
			&flags,
			NULL);
		conn->f_context_init = 1;
	}

	if (status == SEC_E_OK ||
            status == SEC_I_CONTINUE_NEEDED ||
            status == SEC_I_CONTINUE_NEEDED_MESSAGE_OK)
		for (unsigned int j = 0; j < out_desc.cBuffers; j++)
			if (out_bufs[j].BufferType == SECBUFFER_SUBSCRIBE_GENERIC_TLS_EXTENSION &&
			    out_bufs[j].pvBuffer && !wsi->tls.quic_tp_recv) {
				
				size_t ext_len = out_bufs[j].cbBuffer;
				uint8_t *ext_data = (uint8_t *)out_bufs[j].pvBuffer;
				
				lwsl_notice("SChannel returned ext_len %zu", ext_len);
				lwsl_hexdump_notice(ext_data, ext_len < 32 ? ext_len : 32);
				
				if (ext_len > 4) {
					ext_len -= 4;
					ext_data += 4;
					
					wsi->tls.quic_tp_recv = lws_malloc(ext_len, "quic_tp_recv");
					if (wsi->tls.quic_tp_recv) {
						memcpy((void *)wsi->tls.quic_tp_recv, ext_data, ext_len);
						wsi->tls.quic_tp_recv_len = ext_len;
					}
				}
				FreeContextBuffer(out_bufs[j].pvBuffer);
			}

	if (status != SEC_E_OK &&
            status != SEC_I_CONTINUE_NEEDED &&
            status != SEC_I_CONTINUE_NEEDED_MESSAGE_OK)
		out_bufs[0].cbBuffer = 0;

	size_t split_offset = 0;

	if (out_bufs[0].cbBuffer && out_bufs[0].pvBuffer) {
		if (out && out_len && *out_len >= out_bufs[0].cbBuffer) {
			memcpy(out, out_bufs[0].pvBuffer, out_bufs[0].cbBuffer);
			*out_len = out_bufs[0].cbBuffer;
		} else if (out && out_len) {
			*out_len = 0; /* buffer too small to copy */
		}
	} else {
		if (out_len)
			*out_len = 0;
	}

#if defined(SECBUFFER_TRAFFIC_SECRETS)
	/*
	 * Extract secrets if available. SChannel populates traffic secrets
	 * dynamically during the handshake steps for QUIC TLS 1.3
	 * in the output SecBuffers we provided.
	 */

	if (wsi->tls.quic_secret_cb && (status == SEC_E_OK || status == SEC_I_CONTINUE_NEEDED || status == SEC_I_CONTINUE_NEEDED_MESSAGE_OK)) {
		for (unsigned int j = 0; j < out_desc.cBuffers; j++) {
			if (out_bufs[j].BufferType == SECBUFFER_TRAFFIC_SECRETS && out_bufs[j].pvBuffer) {
				SEC_TRAFFIC_SECRETS *secrets = (SEC_TRAFFIC_SECRETS *)out_bufs[j].pvBuffer;
				if (secrets->TrafficSecretType != 0) {
					uint8_t type = secrets->TrafficSecretType;
					struct lws_tls_schannel_conn *conn = (struct lws_tls_schannel_conn *)wsi->tls.ssl;

					/* SChannel outputs `1` and `2` for BOTH Handshake and Application secrets. */
					if (type == 1 && conn->quic_secret_type_count[1] >= 1) {
						type = 3; /* Map to Client Application */
					} else if (type == 2 && conn->quic_secret_type_count[2] >= 1) {
						type = 4; /* Map to Server Application */
					}

					if (type <= 4) {
						conn->quic_secret_type_count[secrets->TrafficSecretType]++;
					}

					enum lws_tls_quic_secret_type mapped_type;
					switch (type) {
					case 1: mapped_type = LWS_TLS_QUIC_SECRET_CLIENT_HANDSHAKE; break;
					case 2: mapped_type = LWS_TLS_QUIC_SECRET_SERVER_HANDSHAKE; break;
					case 3: mapped_type = LWS_TLS_QUIC_SECRET_CLIENT_APPLICATION; break;
					case 4: mapped_type = LWS_TLS_QUIC_SECRET_SERVER_APPLICATION; break;
					default:
						mapped_type = (enum lws_tls_quic_secret_type)-1;
						break;
					}

					if ((int)mapped_type != -1) {
						if (secrets->MsgSequenceStart > 0 && secrets->MsgSequenceStart < out_bufs[0].cbBuffer) {
							if (split_offset == 0 || secrets->MsgSequenceStart < split_offset)
								split_offset = secrets->MsgSequenceStart;
						}

						if (wsi->tls.quic_secret_cb(wsi, mapped_type, secrets->TrafficSecret, secrets->TrafficSecretSize) < 0) {
							lwsl_err("%s: quic_secret_cb failed for type %d\n", __func__, mapped_type);
							return -1;
						}
					}
				}
			}
		}
	}

	if (split_offset > 0 && split_offset < *out_len) {
		size_t remainder = *out_len - split_offset;

		/*
		 * We return the Initial bytes back to the caller in `out`, but we must
		 * instantly push the Handshake bytes into the QUIC layer at Level 2,
		 * because the caller does not loop to pull them!
		 */
		lws_tls_quic_tx_crypto_cb(wsi, 2 /* LWS_QUIC_LEVEL_HANDSHAKE */, out + split_offset, remainder);

		*out_len = split_offset;
	}

#else
	lwsl_err("%s: SECBUFFER_TRAFFIC_SECRETS missing from SDK (Compiled against Windows SDK version 0x%08X)\n", __func__, NTDDI_VERSION);
#endif

	if (status == SEC_I_CONTINUE_NEEDED || status == SEC_I_CONTINUE_NEEDED_MESSAGE_OK || status == SEC_E_OK) {
		if (conn->rx_len > 0) {
			size_t extra = 0;
			for (int j = 0; j < num_in_bufs; j++) {
				if (in_bufs[j].BufferType == SECBUFFER_EXTRA) {
					extra = in_bufs[j].cbBuffer;
					break;
				}
			}
			if (extra > 0) {
				memmove(conn->rx_buf, conn->rx_buf + (conn->rx_len - extra), extra);
				conn->rx_len = extra;
			} else {
				conn->rx_len = 0;
			}
		}

		if (status == SEC_E_OK) {
			conn->f_handshake_finished = 1;
			return 0;
		}
		return 1;
	}

	if (status == SEC_E_INCOMPLETE_MESSAGE) {
		/* Keep the buffer and wait for more data */
		if (out_len) *out_len = 0;
		return 1;
	}

	if (status == SEC_E_OK || status == SEC_I_CONTINUE_NEEDED || status == SEC_I_CONTINUE_NEEDED_MESSAGE_OK) {
		return 1;
	}

	lwsl_err("%s: Schannel handshake error: 0x%lx\n", __func__, (unsigned long)status);
	return -1;
}

int
lws_tls_quic_api_test(void)
{
#if !defined(SECPKG_ATTR_TLS_TRAFFIC_SECRETS)
	lwsl_notice("%s: SDK too old for SChannel TLS 1.3 QUIC secrets\n", __func__);
	return 0;
#else
	PCCERT_CONTEXT pCertCtx = NULL;
	LWS_SCH_CREDENTIALS srv_cred = { 0 }, cli_cred = { 0 };
	CredHandle hSrvCred, hCliCred;
	CtxtHandle hSrvCtxt, hCliCtxt;
	TimeStamp ts;
	SECURITY_STATUS st;
	BYTE subject_name[] = { 0x30, 0x15, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0A, 0x6C, 0x6F, 0x63, 0x61, 0x6C, 0x68, 0x6F, 0x73, 0x74 };
	CERT_NAME_BLOB subject = { sizeof(subject_name), subject_name };
	int srv_init = 0, cli_init = 0, i;
	int secrets_found = 0;
	uint8_t c2s[4096];
	uint8_t s2c[4096];
	ULONG c2s_len = 0, s2c_len = 0;
	ULONG req_flags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY | ISC_REQ_ALLOCATE_MEMORY;
	ULONG ret_flags;

	pCertCtx = CertCreateSelfSignCertificate(NULL, &subject, 0, NULL, NULL, NULL, NULL, NULL);
	if (!pCertCtx) {
		lwsl_err("%s: Failed to create self signed cert\n", __func__);
		return 1;
	}

	srv_cred.dwVersion = SCH_CREDENTIALS_VERSION;
	srv_cred.cCreds = 1;
	srv_cred.paCred = &pCertCtx;
	srv_cred.dwFlags = SCH_CRED_NO_DEFAULT_CREDS;
	st = AcquireCredentialsHandleA(NULL, UNISP_NAME_A, SECPKG_CRED_INBOUND, NULL, &srv_cred, NULL, NULL, &hSrvCred, &ts);
	if (st == SEC_E_UNKNOWN_CREDENTIALS || st == SEC_E_INVALID_PARAMETER) {
		SCHANNEL_CRED old_cred = { 0 };
		old_cred.dwVersion = SCHANNEL_CRED_VERSION;
		old_cred.cCreds = 1;
		old_cred.paCred = &pCertCtx;
		old_cred.dwFlags = SCH_CRED_NO_DEFAULT_CREDS;
		st = AcquireCredentialsHandleA(NULL, UNISP_NAME_A, SECPKG_CRED_INBOUND, NULL, &old_cred, NULL, NULL, &hSrvCred, &ts);
	}
	if (st != SEC_E_OK) { CertFreeCertificateContext(pCertCtx); return 1; }

	cli_cred.dwVersion = SCH_CREDENTIALS_VERSION;
	cli_cred.dwFlags = SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_MANUAL_CRED_VALIDATION;
	st = AcquireCredentialsHandleA(NULL, UNISP_NAME_A, SECPKG_CRED_OUTBOUND, NULL, &cli_cred, NULL, NULL, &hCliCred, &ts);
	if (st == SEC_E_UNKNOWN_CREDENTIALS || st == SEC_E_INVALID_PARAMETER) {
		SCHANNEL_CRED old_cred = { 0 };
		old_cred.dwVersion = SCHANNEL_CRED_VERSION;
		old_cred.dwFlags = SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_MANUAL_CRED_VALIDATION;
		st = AcquireCredentialsHandleA(NULL, UNISP_NAME_A, SECPKG_CRED_OUTBOUND, NULL, &old_cred, NULL, NULL, &hCliCred, &ts);
	}
	if (st != SEC_E_OK) { FreeCredentialsHandle(&hSrvCred); CertFreeCertificateContext(pCertCtx); return 1; }

	for (i = 0; i < 10; i++) {
		SecBufferDesc in_desc = { SECBUFFER_VERSION, 0, NULL }, out_desc = { SECBUFFER_VERSION, 0, NULL };
		SecBuffer in_bufs[2] = { 0 }, out_bufs[1] = { 0 };

		/* Client side */
		if (s2c_len > 0 || !cli_init) {
			if (s2c_len > 0) {
				in_bufs[0].BufferType = SECBUFFER_TOKEN;
				in_bufs[0].pvBuffer = s2c;
				in_bufs[0].cbBuffer = s2c_len;
				in_desc.cBuffers = 1;
				in_desc.pBuffers = in_bufs;
			}
			out_bufs[0].BufferType = SECBUFFER_TOKEN;
			out_desc.cBuffers = 1;
			out_desc.pBuffers = out_bufs;

			st = InitializeSecurityContextA(&hCliCred, cli_init ? &hCliCtxt : NULL, (SEC_CHAR *)"localhost", req_flags, 0, 0,
				s2c_len ? &in_desc : NULL, 0, cli_init ? NULL : &hCliCtxt, &out_desc, &ret_flags, NULL);

			cli_init = 1;
			s2c_len = 0;

			if (st == SEC_E_OK || st == SEC_I_CONTINUE_NEEDED) {
				SEC_TRAFFIC_SECRETS *secrets = NULL;
				if (QueryContextAttributes(&hCliCtxt, SECPKG_ATTR_TLS_TRAFFIC_SECRETS, &secrets) == SEC_E_OK && secrets != NULL) {
					secrets_found++;
					FreeContextBuffer(secrets);
				}
				if (out_bufs[0].cbBuffer && out_bufs[0].pvBuffer) {
					memcpy(c2s, out_bufs[0].pvBuffer, out_bufs[0].cbBuffer);
					c2s_len = out_bufs[0].cbBuffer;
					FreeContextBuffer(out_bufs[0].pvBuffer);
				}
			} else {
				break;
			}
		}

		/* Server side */
		if (c2s_len > 0) {
			in_bufs[0].BufferType = SECBUFFER_TOKEN;
			in_bufs[0].pvBuffer = c2s;
			in_bufs[0].cbBuffer = c2s_len;
			in_desc.cBuffers = 1;
			in_desc.pBuffers = in_bufs;

			out_bufs[0].BufferType = SECBUFFER_TOKEN;
			out_bufs[0].cbBuffer = 0;
			out_bufs[0].pvBuffer = NULL;
			out_desc.cBuffers = 1;
			out_desc.pBuffers = out_bufs;

			st = AcceptSecurityContext(&hSrvCred, srv_init ? &hSrvCtxt : NULL, &in_desc, req_flags, 0,
				srv_init ? NULL : &hSrvCtxt, &out_desc, &ret_flags, NULL);

			srv_init = 1;
			c2s_len = 0;

			if (st == SEC_E_OK || st == SEC_I_CONTINUE_NEEDED) {
				SEC_TRAFFIC_SECRETS *secrets = NULL;
				if (QueryContextAttributes(&hSrvCtxt, SECPKG_ATTR_TLS_TRAFFIC_SECRETS, &secrets) == SEC_E_OK && secrets != NULL) {
					secrets_found++;
					FreeContextBuffer(secrets);
				}
				if (out_bufs[0].cbBuffer && out_bufs[0].pvBuffer) {
					memcpy(s2c, out_bufs[0].pvBuffer, out_bufs[0].cbBuffer);
					s2c_len = out_bufs[0].cbBuffer;
					FreeContextBuffer(out_bufs[0].pvBuffer);
				}
			} else {
				break;
			}
		}

		if (st == SEC_E_OK && c2s_len == 0 && s2c_len == 0)
			break;
	}

	if (cli_init) DeleteSecurityContext(&hCliCtxt);
	if (srv_init) DeleteSecurityContext(&hSrvCtxt);
	FreeCredentialsHandle(&hCliCred);
	FreeCredentialsHandle(&hSrvCred);
	CertFreeCertificateContext(pCertCtx);

	lwsl_notice("%s: API test completed, secrets extracted: %d\n", __func__, secrets_found);
	return secrets_found > 0 ? 0 : 1;
#endif
}

int
lws_tls_quic_migrate_wsi(struct lws *old_wsi, struct lws *new_wsi)
{
	(void)old_wsi;
	(void)new_wsi;
	return 0;
}
