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

#ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#endif
#include "private-lib-core.h"

#if defined(LWS_WITH_MBEDTLS)
#if defined(LWS_HAVE_MBEDTLS_NET_SOCKETS)
#include "mbedtls/net_sockets.h"
#else
#include "mbedtls/net.h"
#endif
#endif

#ifdef LWS_SSL_CLIENT_USE_OS_CA_CERTS
BOOL imported_native_ca = FALSE;
#endif

int
lws_send_pipe_choked(struct lws *wsi)
{	struct lws *wsi_eff;

#if defined(LWS_WITH_HTTP2)
	wsi_eff = lws_get_network_wsi(wsi);
#else
	wsi_eff = wsi;
#endif
	/* the fact we checked implies we avoided back-to-back writes */
	wsi_eff->could_have_pending = 0;

	/* treat the fact we got a truncated send pending as if we're choked */
	if (lws_has_buffered_out(wsi_eff)
#if defined(LWS_WITH_HTTP_STREAM_COMPRESSION)
	    ||wsi->http.comp_ctx.buflist_comp ||
	      wsi->http.comp_ctx.may_have_more
#endif
	)
		return 1;

	return (int)wsi_eff->sock_send_blocking;
}

int
lws_poll_listen_fd(struct lws_pollfd *fd)
{
	fd_set readfds;
	struct timeval tv = { 0, 0 };

	assert((fd->events & LWS_POLLIN) == LWS_POLLIN);

	FD_ZERO(&readfds);
	FD_SET(fd->fd, &readfds);

	return select(((int)fd->fd) + 1, &readfds, NULL, NULL, &tv);
}

int
lws_plat_set_nonblocking(lws_sockfd_type fd)
{
	u_long optl = 1;
	int result = !!ioctlsocket(fd, FIONBIO, &optl);
	if (result)
	{
		int error = LWS_ERRNO;
		lwsl_err("ioctlsocket FIONBIO 1 failed with error %d\n", error);
	}
	return result;
}

int
lws_plat_set_socket_options(struct lws_vhost *vhost, lws_sockfd_type fd,
			    int unix_skt)
{
	int optval = 1;
	int optlen = sizeof(optval);
	DWORD dwBytesRet;
	struct tcp_keepalive alive;
	int protonbr;
#ifndef _WIN32_WCE
	struct protoent *tcp_proto;
#endif

	if (vhost->ka_time) {
		/* enable keepalive on this socket */
		optval = 1;
		if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE,
			       (const char *)&optval, optlen) < 0) {
			int error = LWS_ERRNO;
			lwsl_err("setsockopt SO_KEEPALIVE 1 failed with error %d\n", error);
			return 1;
		}

		alive.onoff = TRUE;
		alive.keepalivetime = vhost->ka_time * 1000;
		alive.keepaliveinterval = vhost->ka_interval * 1000;

		if (WSAIoctl(fd, SIO_KEEPALIVE_VALS, &alive, sizeof(alive),
			     NULL, 0, &dwBytesRet, NULL, NULL)) {
			int error = LWS_ERRNO;
			lwsl_err("WSAIoctl SIO_KEEPALIVE_VALS 1 %lu %lu failed with error %d\n", alive.keepalivetime, alive.keepaliveinterval, error);
			return 1;
		}
	}

	/* Disable Nagle */
	optval = 1;
#ifndef _WIN32_WCE
	tcp_proto = getprotobyname("TCP");
	if (!tcp_proto) {
		int error = LWS_ERRNO;
		lwsl_warn("getprotobyname(\"TCP\") failed with error, falling back to 6 %d\n", error);
		protonbr = 6;  /* IPPROTO_TCP */
	} else
		protonbr = tcp_proto->p_proto;
#else
	protonbr = 6;
#endif

	if (setsockopt(fd, protonbr, TCP_NODELAY, (const char *)&optval, optlen) ) {
		int error = LWS_ERRNO;
		lwsl_warn("setsockopt TCP_NODELAY 1 failed with error %d\n", error);
	}

#ifdef LWS_SSL_CLIENT_USE_OS_CA_CERTS
	/* only import certs once*/
	if (!lws_check_opt(vhost->options, LWS_SERVER_OPTION_DISABLE_OS_CA_CERTS) && !imported_native_ca) {
		/* adapted from curl openssl.c*/
		/* Import certificates from the Windows root certificate store if requested.
		https://stackoverflow.com/questions/9507184/
		https://github.com/d3x0r/SACK/blob/master/src/netlib/ssl_layer.c#L1037
		https://tools.ietf.org/html/rfc5280 */

		X509_STORE* store = SSL_CTX_get_cert_store(vhost->tls.ssl_client_ctx);
		HCERTSTORE hStore = CertOpenSystemStore((HCRYPTPROV_LEGACY)NULL,
			TEXT("ROOT"));

		if (hStore) {
			PCCERT_CONTEXT pContext = NULL;
			/* The array of enhanced key usage OIDs will vary per certificate and is
				declared outside of the loop so that rather than malloc/free each
				iteration we can grow it with realloc, when necessary. */
			CERT_ENHKEY_USAGE* enhkey_usage = NULL;
			DWORD enhkey_usage_size = 0;

			/* This loop makes a best effort to import all valid certificates from
				the MS root store. If a certificate cannot be imported it is skipped.
				'result' is used to store only hard-fail conditions (such as out of
				memory) that cause an early break. */
			for (;;) {
				X509* x509;
				FILETIME now;
				BYTE key_usage[2];
				DWORD req_size = 0;
				const unsigned char* encoded_cert;
				char cert_name[256];

				pContext = CertEnumCertificatesInStore(hStore, pContext);
				if (!pContext)
					break;

				if (!CertGetNameStringA(pContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0,
					NULL, cert_name, sizeof(cert_name))) {
					strcpy(cert_name, "Unknown");
				}
				lwsl_info("%s: Checking cert \"%s\"\n", __func__, cert_name);

				encoded_cert = (const unsigned char*)pContext->pbCertEncoded;
				if (!encoded_cert)
					continue;

				GetSystemTimeAsFileTime(&now);
				if (CompareFileTime(&pContext->pCertInfo->NotBefore, &now) > 0 || CompareFileTime(&now, &pContext->pCertInfo->NotAfter) > 0)
					continue;

				/* If key usage exists check for signing attribute */
				if (CertGetIntendedKeyUsage(pContext->dwCertEncodingType,
					pContext->pCertInfo,
					key_usage, sizeof(key_usage))) {
					if (!(key_usage[0] & CERT_KEY_CERT_SIGN_KEY_USAGE))
						continue;
				}
				else if (GetLastError())
					continue;

				/* If enhanced key usage exists check for server auth attribute.
				*
				* Note "In a Microsoft environment, a certificate might also have EKU
				* extended properties that specify valid uses for the certificate."
				* The call below checks both, and behavior varies depending on what is
				* found. For more details see CertGetEnhancedKeyUsage doc.
				*/
				if (CertGetEnhancedKeyUsage(pContext, 0, NULL, &req_size)) {
					if (req_size && req_size > enhkey_usage_size) {
						void* tmp = lws_realloc(enhkey_usage, req_size, __func__);

						if (!tmp) {
							lwsl_err("%s: Out of memory allocating for OID list", __func__);
							break;
						}

						enhkey_usage = (CERT_ENHKEY_USAGE*)tmp;
						enhkey_usage_size = req_size;
					}

					if (CertGetEnhancedKeyUsage(pContext, 0, enhkey_usage, &req_size)) {
						if (!enhkey_usage || (enhkey_usage && !enhkey_usage->cUsageIdentifier)) {
							/* "If GetLastError returns CRYPT_E_NOT_FOUND, the certificate is
								good for all uses. If it returns zero, the certificate has no
								valid uses." */
							if ((HRESULT)GetLastError() != CRYPT_E_NOT_FOUND)
								continue;
						}
						else if (enhkey_usage) {
							DWORD i;
							BOOL found = FALSE;

							for (i = 0; i < enhkey_usage->cUsageIdentifier; ++i) {
								if (!strcmp("1.3.6.1.5.5.7.3.1" /* OID server auth */,
									enhkey_usage->rgpszUsageIdentifier[i])) {
									found = TRUE;
									break;
								}
							}

							if (!found)
								continue;
						}
					}
					else
						continue;
				}
				else
					continue;

				x509 = d2i_X509(NULL, &encoded_cert, pContext->cbCertEncoded);
				if (!x509)
					continue;

				/* Try to import the certificate. This may fail for legitimate reasons
				such as duplicate certificate, which is allowed by MS but not
				OpenSSL. */
				if (X509_STORE_add_cert(store, x509) == 1) {
					lwsl_info("%s: Imported cert \"%s\"\n", __func__, cert_name);
					imported_native_ca = TRUE;
				}
				X509_free(x509);
			}

			free(enhkey_usage);
			CertFreeCertificateContext(pContext);
			CertCloseStore(hStore, 0);

			if (imported_native_ca)
				lwsl_info("%s: successfully imported windows ca store\n", __func__);
			else
				lwsl_info("%s: error importing windows ca store, continuing anyway\n", __func__);
		}
#endif

	}
	return lws_plat_set_nonblocking(fd);
}

int
lws_plat_set_socket_options_ip(lws_sockfd_type fd, uint8_t pri, int lws_flags)
{
	/*
	 * Seems to require "differeniated services" but no docs
	 *
	 * https://docs.microsoft.com/en-us/windows/win32/winsock/ipproto-ip-socket-options
	 * https://docs.microsoft.com/en-us/previous-versions/windows/desktop/qos/differentiated-services
	 */
	lwsl_warn("%s: not implemented on windows platform\n", __func__);

	return 0;
}

int
lws_interface_to_sa(int ipv6,
		const char *ifname, struct sockaddr_in *addr, size_t addrlen)
{
	long long address;
#ifdef LWS_WITH_IPV6
	struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;

	if (ipv6) {
		if (lws_plat_inet_pton(AF_INET6, ifname, &addr6->sin6_addr) == 1) {
			return LWS_ITOSA_USABLE;
		}
	}
#endif

	address = inet_addr(ifname);

	if (address == INADDR_NONE) {
		struct hostent *entry = gethostbyname(ifname);
		if (entry)
			address = ((struct in_addr *)entry->h_addr_list[0])->s_addr;
	}

	if (address == INADDR_NONE)
		return LWS_ITOSA_NOT_EXIST;

	addr->sin_addr.s_addr = (unsigned long)(lws_intptr_t)address;

	return LWS_ITOSA_USABLE;
}

void
lws_plat_insert_socket_into_fds(struct lws_context *context, struct lws *wsi)
{
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];

#if defined(LWS_WITH_UDP)
	if (wsi->udp) {
		lwsl_info("%s: UDP\n", __func__);
		pt->fds[pt->fds_count].events |= LWS_POLLIN;
	}
#endif

	pt->fds[pt->fds_count++].revents = 0;

	lws_plat_change_pollfd(context, wsi, &pt->fds[pt->fds_count - 1]);
}

void
lws_plat_delete_socket_from_fds(struct lws_context *context,
						struct lws *wsi, int m)
{
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];

	pt->fds_count--;
}


int
lws_plat_check_connection_error(struct lws *wsi)
{
	int optVal;
	int optLen = sizeof(int);

	if (getsockopt(wsi->desc.sockfd, SOL_SOCKET, SO_ERROR,
			   (char*)&optVal, &optLen) != SOCKET_ERROR && optVal &&
		optVal != LWS_EALREADY && optVal != LWS_EINPROGRESS &&
		optVal != LWS_EWOULDBLOCK && optVal != WSAEINVAL) {
		   lwsl_debug("Connect failed SO_ERROR=%d\n", optVal);
		   return 1;
	}

	return 0;
}

int
lws_plat_change_pollfd(struct lws_context *context, struct lws *wsi,
		       struct lws_pollfd *pfd)
{
	//struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];

	return 0;
}

const char *
lws_plat_inet_ntop(int af, const void *src, char *dst, socklen_t cnt)
{
	WCHAR *buffer;
	size_t bufferlen = (size_t)cnt;
	BOOL ok = FALSE;

	buffer = lws_malloc(bufferlen * 2, "inet_ntop");
	if (!buffer) {
		lwsl_err("Out of memory\n");
		return NULL;
	}

	if (af == AF_INET) {
		struct sockaddr_in srcaddr;
		memset(&srcaddr, 0, sizeof(srcaddr));
		srcaddr.sin_family = AF_INET;
		memcpy(&(srcaddr.sin_addr), src, sizeof(srcaddr.sin_addr));

		if (!WSAAddressToStringW((struct sockaddr*)&srcaddr,
					sizeof(srcaddr), 0, buffer,
					(LPDWORD)&bufferlen))
			ok = TRUE;
#ifdef LWS_WITH_IPV6
	} else if (af == AF_INET6) {
		struct sockaddr_in6 srcaddr;
		memset(&srcaddr, 0, sizeof(srcaddr));
		srcaddr.sin6_family = AF_INET6;
		memcpy(&(srcaddr.sin6_addr), src, sizeof(srcaddr.sin6_addr));

		if (!WSAAddressToStringW((struct sockaddr*)&srcaddr,
					 sizeof(srcaddr), 0, buffer,
					 (LPDWORD)&bufferlen))
			ok = TRUE;
#endif
	} else
		lwsl_err("Unsupported type\n");

	if (!ok) {
		int rv = WSAGetLastError();
		lwsl_err("WSAAddressToString() : %d\n", rv);
	} else {
		if (WideCharToMultiByte(CP_ACP, 0, buffer, (int)bufferlen, dst,
					cnt, 0, NULL) <= 0)
			ok = FALSE;
	}

	lws_free(buffer);
	return ok ? dst : NULL;
}

int
lws_plat_inet_pton(int af, const char *src, void *dst)
{
	WCHAR *buffer;
	size_t bufferlen = strlen(src) + 1;
	BOOL ok = FALSE;

	buffer = lws_malloc(bufferlen * 2, "inet_pton");
	if (!buffer) {
		lwsl_err("Out of memory\n");
		return -1;
	}

	if (MultiByteToWideChar(CP_ACP, 0, src, (int)bufferlen, buffer,
				(int)bufferlen) <= 0) {
		lwsl_err("Failed to convert multi byte to wide char\n");
		lws_free(buffer);
		return -1;
	}

	if (af == AF_INET) {
		struct sockaddr_in dstaddr;
		int dstaddrlen = sizeof(dstaddr);

		memset(&dstaddr, 0, sizeof(dstaddr));
		dstaddr.sin_family = AF_INET;

		if (!WSAStringToAddressW(buffer, af, 0, (struct sockaddr *) &dstaddr, &dstaddrlen)) {
			ok = TRUE;
			memcpy(dst, &dstaddr.sin_addr, sizeof(dstaddr.sin_addr));
		}
#ifdef LWS_WITH_IPV6
	} else if (af == AF_INET6) {
		struct sockaddr_in6 dstaddr;
		int dstaddrlen = sizeof(dstaddr);

		memset(&dstaddr, 0, sizeof(dstaddr));
		dstaddr.sin6_family = AF_INET6;

		if (!WSAStringToAddressW(buffer, af, 0, (struct sockaddr *) &dstaddr, &dstaddrlen)) {
			ok = TRUE;
			memcpy(dst, &dstaddr.sin6_addr, sizeof(dstaddr.sin6_addr));
		}
#endif
	} else
		lwsl_err("Unsupported type\n");

	if (!ok) {
		int rv = WSAGetLastError();
		lwsl_err("WSAAddressToString() : %d\n", rv);
	}

	lws_free(buffer);
	return ok ? 1 : -1;
}

int
lws_plat_ifname_to_hwaddr(int fd, const char *ifname, uint8_t *hwaddr, int len)
{
	lwsl_err("%s: UNIMPLEMENTED on this platform\n", __func__);

	return -1;
}

int
lws_plat_rawudp_broadcast(uint8_t *p, const uint8_t *canned, size_t canned_len,
			  size_t n, int fd, const char *iface)
{
	lwsl_err("%s: UNIMPLEMENTED on this platform\n", __func__);

	return -1;
}

int
lws_plat_if_up(const char *ifname, int fd, int up)
{
	lwsl_err("%s: UNIMPLEMENTED on this platform\n", __func__);

	return -1;
}

int
lws_plat_BINDTODEVICE(lws_sockfd_type fd, const char *ifname)
{
	lwsl_err("%s: UNIMPLEMENTED on this platform\n", __func__);

	return -1;
}

int
lws_plat_ifconfig(int fd, uint8_t *ip, lws_dhcpc_ifstate_t *is)
{
	lwsl_err("%s: UNIMPLEMENTED on this platform\n", __func__);

	return -1;
}

#if defined(LWS_WITH_MBEDTLS)
int
lws_plat_mbedtls_net_send(void *ctx, const uint8_t *buf, size_t len)
{
	int fd = ((mbedtls_net_context *) ctx)->fd;
	int ret;

	if (fd < 0)
		return MBEDTLS_ERR_NET_INVALID_CONTEXT;

	ret = write(fd, buf, (unsigned int)len);
	if (ret >= 0)
		return ret;

	if (errno == EAGAIN || errno == EWOULDBLOCK)
		return MBEDTLS_ERR_SSL_WANT_WRITE;

        if (WSAGetLastError() == WSAECONNRESET )
            return( MBEDTLS_ERR_NET_CONN_RESET );

	return MBEDTLS_ERR_NET_SEND_FAILED;
}

int
lws_plat_mbedtls_net_recv(void *ctx, unsigned char *buf, size_t len)
{
	int fd = ((mbedtls_net_context *) ctx)->fd;
	int ret;

	if (fd < 0)
		return MBEDTLS_ERR_NET_INVALID_CONTEXT;

	ret = (int)read(fd, buf, (unsigned int)len);
	if (ret >= 0)
		return ret;

	if (errno == EAGAIN || errno == EWOULDBLOCK)
		return MBEDTLS_ERR_SSL_WANT_READ;

        if (WSAGetLastError() == WSAECONNRESET)
            return MBEDTLS_ERR_NET_CONN_RESET;

	return MBEDTLS_ERR_NET_RECV_FAILED;
}
#endif

