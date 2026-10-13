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

/** \defgroup proxyv2 PROXY protocol version 2
 * ##PROXY protocol version 2
 *
 * A proxy that forwards a connection without terminating it, eg, a TLS
 * passthrough, can't add an X-Forwarded-For to what it can't read.  Instead,
 * before the client's bytes, it sends the server it connects onward to one
 * binary PROXY v2 header saying who the client is, as haproxy defined it and
 * many servers understand.
 *
 * Anybody can send one, so a server must only believe one at the very start
 * of a connection from a proxy it trusts, and at most one per connection:
 * anything later is just the client's data.  These helpers only render and
 * parse the header; that policy is the caller's.
 *
 * We render and accept TCP or UDP over IPv4 or IPv6, and LOCAL (the proxy's
 * own connection, eg, a health check, which carries no addresses).  Of the
 * TLVs, we render and report PP2_TYPE_ALPN and PP2_TYPE_AUTHORITY (the name
 * the client asked for, eg, its TLS SNI), verify PP2_TYPE_CRC32C if it is
 * present, and skip the others.
 */
///@{

/* the most of a header we accept: addresses and a few small TLVs */
#define LWS_PROXY_V2_MAX		(16 + 512)

typedef struct lws_proxy_v2 {
	lws_sockaddr46		src;	/**< the client, as the proxy saw it */
	lws_sockaddr46		dst;	/**< what the client connected to */
	char			authority[256];
	/**< PP2_TYPE_AUTHORITY, eg, the client's TLS SNI name, or "" */
	char			alpn[64]; /**< PP2_TYPE_ALPN, or "" */
	uint8_t			local;	/**< LOCAL: no addresses, the proxy's
					 * own connection */
	uint8_t			dgram;	/**< the client's connection is UDP */
} lws_proxy_v2_t;

/**
 * lws_proxy_v2_header_len() - how long the PROXY v2 header at buf is
 *
 * \param buf: the first bytes of the connection
 * \param len: how many of them there are
 *
 * Returns the length of the whole header if \p buf starts with the PROXY v2
 * signature and enough of a header to say how long it is, 0 if more bytes
 * are needed to know, or -1 if it is not a PROXY v2 header, or one longer
 * than LWS_PROXY_V2_MAX.
 */
LWS_VISIBLE LWS_EXTERN int
lws_proxy_v2_header_len(const uint8_t *buf, size_t len);

/**
 * lws_proxy_v2_parse() - parse one whole PROXY v2 header
 *
 * \param buf: the header
 * \param len: its length, as lws_proxy_v2_header_len() gave it
 * \param pv: filled in with what the header says
 *
 * Everything in the header is untrusted until the caller has decided to
 * trust where it came from, and is checked as such: the version, command and
 * address family must be ones we accept, the address block and every TLV
 * must fit exactly, an authority or alpn must be printable and fit, neither
 * may appear twice, and a CRC32C TLV must match.
 *
 * Returns 0 if the header is valid, else -1.
 */
LWS_VISIBLE LWS_EXTERN int
lws_proxy_v2_parse(const uint8_t *buf, size_t len, lws_proxy_v2_t *pv);

/**
 * lws_proxy_v2_render() - render a PROXY v2 header
 *
 * \param pv: what the header should say.  src and dst must be of the same
 *	      family, unless local is set; IPv4-mapped IPv6 addresses count as
 *	      IPv4, so a pair of them, or one with an AF_INET address, is
 *	      rendered as TCP4 / UDP4.  Empty authority or alpn are left out.
 * \param buf: where to render it
 * \param len: the space at \p buf
 *
 * Returns the length of the header rendered, or -1 if it did not fit or
 * \p pv can't be rendered.
 */
LWS_VISIBLE LWS_EXTERN int
lws_proxy_v2_render(const lws_proxy_v2_t *pv, uint8_t *buf, size_t len);

///@}
