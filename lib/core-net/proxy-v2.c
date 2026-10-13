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
 *
 * PROXY protocol version 2, as haproxy's proxy-protocol.txt defines it: the
 * binary header a proxy sends before a client's bytes, saying who the client
 * is.  See lws-proxy-v2.h for the policy a caller must apply.
 */

#include "private-lib-core.h"

static const uint8_t pp2_sig[12] = {
	0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a
};

#define PP2_VERSION		0x20
#define PP2_CMD_LOCAL		0x00
#define PP2_CMD_PROXY		0x01

#define PP2_AF_UNSPEC		0x00
#define PP2_AF_INET		0x10
#define PP2_AF_INET6		0x20
#define PP2_PROTO_UNSPEC	0x00
#define PP2_PROTO_STREAM	0x01
#define PP2_PROTO_DGRAM		0x02

#define PP2_TYPE_ALPN		0x01
#define PP2_TYPE_AUTHORITY	0x02
#define PP2_TYPE_CRC32C		0x03

/* CRC-32C (Castagnoli), as the CRC32C TLV uses */

static uint32_t
pp2_crc32c(const uint8_t *p, size_t len)
{
	uint32_t c = 0xffffffffu;
	int n;

	while (len--) {
		c ^= *p++;
		for (n = 0; n < 8; n++)
			c = (c >> 1) ^ (0x82f63b78u & (0u - (c & 1u)));
	}

	return c ^ 0xffffffffu;
}

int
lws_proxy_v2_header_len(const uint8_t *buf, size_t len)
{
	size_t n = len < sizeof(pp2_sig) ? len : sizeof(pp2_sig), hl;

	/* as much of the signature as is here must match */
	if (memcmp(buf, pp2_sig, n))
		return -1;

	if (len < 16)
		return 0;

	hl = 16 + (((size_t)buf[14] << 8) | buf[15]);
	if (hl > LWS_PROXY_V2_MAX)
		return -1;

	return (int)hl;
}

/* a TLV string: printable, NUL-free and with room for its NUL */

static int
pp2_tlv_str(char *dest, size_t dest_len, const uint8_t *v, size_t vl)
{
	size_t n;

	if (*dest || !vl || vl >= dest_len)
		/* a second one, or nothing, or too big */
		return -1;

	for (n = 0; n < vl; n++)
		if (v[n] <= ' ' || v[n] > '~')
			return -1;

	memcpy(dest, v, vl);
	dest[vl] = '\0';

	return 0;
}

int
lws_proxy_v2_parse(const uint8_t *buf, size_t len, lws_proxy_v2_t *pv)
{
	size_t pos = 16, ab, tl;
	int hl = lws_proxy_v2_header_len(buf, len), crc_at = -1;
	uint8_t fam, proto;

	memset(pv, 0, sizeof(*pv));

	if (hl <= 0 || (size_t)hl != len)
		return -1;

	if ((buf[12] & 0xf0) != PP2_VERSION)
		return -1;

	fam = buf[13] & 0xf0;
	proto = buf[13] & 0x0f;

	switch (buf[12] & 0x0f) {
	case PP2_CMD_LOCAL:
		/*
		 * The proxy's own connection: whatever address block it sent
		 * is to be ignored, but the TLVs after it still have to fit
		 */
		pv->local = 1;
		break;
	case PP2_CMD_PROXY:
		break;
	default:
		return -1;
	}

	switch (fam) {
	case PP2_AF_INET:
		ab = 12;
		break;
	case PP2_AF_INET6:
		ab = 36;
		break;
	case PP2_AF_UNSPEC:
		if (!pv->local)
			/* a proxied client with no address is no use to us */
			return -1;
		ab = 0;
		break;
	default:
		/* AF_UNIX, or anything else */
		return -1;
	}

	if (!pv->local) {
		if (proto != PP2_PROTO_STREAM && proto != PP2_PROTO_DGRAM)
			return -1;
		pv->dgram = proto == PP2_PROTO_DGRAM;
	}

	if (len - pos < ab)
		return -1;

	if (!pv->local && fam == PP2_AF_INET) {
		pv->src.sa4.sin_family = AF_INET;
		memcpy(&pv->src.sa4.sin_addr, buf + pos, 4);
		memcpy(&pv->src.sa4.sin_port, buf + pos + 8, 2);
		pv->dst.sa4.sin_family = AF_INET;
		memcpy(&pv->dst.sa4.sin_addr, buf + pos + 4, 4);
		memcpy(&pv->dst.sa4.sin_port, buf + pos + 10, 2);
	}
#if defined(LWS_WITH_IPV6)
	if (!pv->local && fam == PP2_AF_INET6) {
		pv->src.sa6.sin6_family = AF_INET6;
		memcpy(&pv->src.sa6.sin6_addr, buf + pos, 16);
		memcpy(&pv->src.sa6.sin6_port, buf + pos + 32, 2);
		pv->dst.sa6.sin6_family = AF_INET6;
		memcpy(&pv->dst.sa6.sin6_addr, buf + pos + 16, 16);
		memcpy(&pv->dst.sa6.sin6_port, buf + pos + 34, 2);
	}
#else
	if (!pv->local && fam == PP2_AF_INET6)
		/* a client we have no way to represent */
		return -1;
#endif
	pos += ab;

	/* the TLVs must exactly fill the rest */

	while (pos < len) {
		if (len - pos < 3)
			return -1;
		tl = ((size_t)buf[pos + 1] << 8) | buf[pos + 2];
		if (tl > len - pos - 3)
			return -1;

		switch (buf[pos]) {
		case PP2_TYPE_ALPN:
			if (pp2_tlv_str(pv->alpn, sizeof(pv->alpn),
					buf + pos + 3, tl))
				return -1;
			break;
		case PP2_TYPE_AUTHORITY:
			if (pp2_tlv_str(pv->authority, sizeof(pv->authority),
					buf + pos + 3, tl))
				return -1;
			break;
		case PP2_TYPE_CRC32C:
			if (tl != 4 || crc_at >= 0)
				return -1;
			crc_at = (int)pos + 3;
			break;
		default:
			/* the others are nothing we act on */
			break;
		}

		pos += 3 + tl;
	}

	if (crc_at >= 0) {
		/* the CRC is over the whole header, with its own field zeroed */
		uint8_t tmp[LWS_PROXY_V2_MAX];
		uint32_t want = ((uint32_t)buf[crc_at] << 24) |
				((uint32_t)buf[crc_at + 1] << 16) |
				((uint32_t)buf[crc_at + 2] << 8) |
				(uint32_t)buf[crc_at + 3];

		memcpy(tmp, buf, len);
		memset(tmp + crc_at, 0, 4);
		if (pp2_crc32c(tmp, len) != want)
			return -1;
	}

	return 0;
}

static int
pp2_tlv(uint8_t *buf, size_t len, size_t *pos, uint8_t type, const char *s)
{
	size_t n = strlen(s);

	if (!n)
		return 0;
	if (len - *pos < 3 + n || n > 0xffff)
		return -1;

	buf[(*pos)++] = type;
	buf[(*pos)++] = (uint8_t)(n >> 8);
	buf[(*pos)++] = (uint8_t)n;
	memcpy(buf + *pos, s, n);
	*pos += n;

	return 0;
}

int
lws_proxy_v2_render(const lws_proxy_v2_t *pv, uint8_t *buf, size_t len)
{
	size_t pos = 16;

	if (len < 16)
		return -1;

	memcpy(buf, pp2_sig, sizeof(pp2_sig));

	if (pv->local) {
		buf[12] = PP2_VERSION | PP2_CMD_LOCAL;
		buf[13] = PP2_AF_UNSPEC | PP2_PROTO_UNSPEC;
	} else {
		uint8_t proto = pv->dgram ? PP2_PROTO_DGRAM : PP2_PROTO_STREAM;

		buf[12] = PP2_VERSION | PP2_CMD_PROXY;

		if (pv->src.sa4.sin_family == AF_INET &&
		    pv->dst.sa4.sin_family == AF_INET) {
			if (len - pos < 12)
				return -1;
			buf[13] = PP2_AF_INET | proto;
			memcpy(buf + pos, &pv->src.sa4.sin_addr, 4);
			memcpy(buf + pos + 4, &pv->dst.sa4.sin_addr, 4);
			memcpy(buf + pos + 8, &pv->src.sa4.sin_port, 2);
			memcpy(buf + pos + 10, &pv->dst.sa4.sin_port, 2);
			pos += 12;
		}
#if defined(LWS_WITH_IPV6)
		else if (pv->src.sa6.sin6_family == AF_INET6 &&
			 pv->dst.sa6.sin6_family == AF_INET6) {
			if (len - pos < 36)
				return -1;
			buf[13] = PP2_AF_INET6 | proto;
			memcpy(buf + pos, &pv->src.sa6.sin6_addr, 16);
			memcpy(buf + pos + 16, &pv->dst.sa6.sin6_addr, 16);
			memcpy(buf + pos + 32, &pv->src.sa6.sin6_port, 2);
			memcpy(buf + pos + 34, &pv->dst.sa6.sin6_port, 2);
			pos += 36;
		}
#endif
		else
			/* no addresses, or of different families */
			return -1;
	}

	if (pp2_tlv(buf, len, &pos, PP2_TYPE_ALPN, pv->alpn) ||
	    pp2_tlv(buf, len, &pos, PP2_TYPE_AUTHORITY, pv->authority))
		return -1;

	if (pos > LWS_PROXY_V2_MAX)
		return -1;

	buf[14] = (uint8_t)((pos - 16) >> 8);
	buf[15] = (uint8_t)(pos - 16);

	return (int)pos;
}
