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
 * address.c: network addresses as text and as data: parsing and writing
 * numeric v4 / v6 addresses and macs, the lws_sockaddr46 comparisons and
 * conversions, cidr and lan / local tests.  Neither half's (see
 * READMEs/README.sans-io-split.md): they name no socket, and both halves use
 * them.
 */

#include "private-lib-core.h"

/*
 * https://en.wikipedia.org/wiki/IPv6_address
 *
 * An IPv6 address is represented as eight groups of four hexadecimal digits,
 * each group representing 16 bits (two octets, a group sometimes also called a
 * hextet[6][7]). The groups are separated by colons (:). An example of an IPv6
 * address is:
 *
 *    2001:0db8:85a3:0000:0000:8a2e:0370:7334
 *
 * The hexadecimal digits are case-insensitive, but IETF recommendations suggest
 * the use of lower case letters. The full representation of eight 4-digit
 * groups may be simplified by several techniques, eliminating parts of the
 * representation.
 *
 * Leading zeroes in a group may be omitted, but each group must retain at least
 * one hexadecimal digit.[1] Thus, the example address may be written as:
 *
 *    2001:db8:85a3:0:0:8a2e:370:7334
 *
 * One or more consecutive groups containing zeros only may be replaced with a
 * single empty group, using two consecutive colons (::).[1] The substitution
 * may only be applied once in the address, however, because multiple
 * occurrences would create an ambiguous representation. Thus, the example
 * address can be further simplified:
 *
 *    2001:db8:85a3::8a2e:370:7334
 *
 * The localhost (loopback) address, 0:0:0:0:0:0:0:1, and the IPv6 unspecified
 * address, 0:0:0:0:0:0:0:0, are reduced to ::1 and ::, respectively.
 *
 * During the transition of the Internet from IPv4 to IPv6, it is typical to
 * operate in a mixed addressing environment. For such use cases, a special
 * notation has been introduced, which expresses IPv4-mapped and IPv4-compatible
 * IPv6 addresses by writing the least-significant 32 bits of an address in the
 * familiar IPv4 dot-decimal notation, whereas the other 96 (most significant)
 * bits are written in IPv6 format. For example, the IPv4-mapped IPv6 address
 * ::ffff:c000:0280 is written as ::ffff:192.0.2.128, thus expressing clearly
 * the original IPv4 address that was mapped to IPv6.
 */

int
lws_parse_numeric_address(const char *ads, uint8_t *result, size_t max_len)
{
	struct lws_tokenize ts;
	uint8_t *orig = result, temp[16];
	int sects = 0, ipv6 = !!(char *)strchr(ads, ':'), skip_point = -1, dm = 0;
	char t[5];
	size_t n;
	long u;

	lws_tokenize_init(&ts, ads, LWS_TOKENIZE_F_NO_INTEGERS |
				    LWS_TOKENIZE_F_MINUS_NONTERM);
	ts.len = strlen(ads);
	if (!ipv6 && ts.len < 7)
		return -1;

	if (ipv6 && ts.len < 2)
		return -2;

	if (!ipv6 && max_len < 4)
		return -3;

	if (ipv6 && max_len < 16)
		return -4;

	/*
	 * We can only ever produce 4 (v4) or 16 (v6) bytes... a caller with a
	 * bigger buffer must not let us accept an overlong literal, since the
	 * "::" reassembly at ENDED below is written around a 16-byte result
	 * (and it is the ipv6 entry check above that guarantees 16 are there).
	 */

	if (max_len > 16)
		max_len = 16;

	if (ipv6)
		memset(result, 0, max_len);

	do {
		ts.e = (int8_t)lws_tokenize(&ts);
		switch (ts.e) {
		case LWS_TOKZE_TOKEN:
			dm = 0;
			if (ipv6) {
				if (ts.token_len > 4)
					return -1;
				memcpy(t, ts.token, ts.token_len);
				t[ts.token_len] = '\0';
				for (n = 0; n < ts.token_len; n++)
					if (t[n] < '0' || t[n] > 'f' ||
					    (t[n] > '9' && t[n] < 'A') ||
					    (t[n] > 'F' && t[n] < 'a'))
						return -1;
				u = strtol(t, NULL, 16);
				if (u > 0xffff)
					return -5;
			} else {
				if (ts.token_len > 3)
					return -1;
				memcpy(t, ts.token, ts.token_len);
				t[ts.token_len] = '\0';
				for (n = 0; n < ts.token_len; n++)
					if (t[n] < '0' || t[n] > '9')
						return -1;
				u = strtol(t, NULL, 10);
				if (u > 0xff)
					return -6;
			}
			if (u < 0)
				return -7;
			/*
			 * The whole group must fit in what's left of the
			 * result buffer (2 bytes for an ipv6 group, 1 for
			 * an ipv4 octet) before we write any of it, else
			 * overlong literals like a 9-group ipv6 or a
			 * 5-octet ipv4 write past the end of the caller's
			 * buffer before the group count check at ENDED
			 * rejects them
			 */
			if (result - orig + (ipv6 ? 2 : 1) > (int)max_len)
				return -15;
			if (ipv6)
				*result++ = (uint8_t)(u >> 8);
			*result++ = (uint8_t)u;
			sects++;
			break;

		case LWS_TOKZE_DELIMITER:
			if (dm++) {
				if (dm > 2)
					return -8;
				if (*ts.token != ':')
					return -9;
				/*
				 * back to back :
				 *
				 * RFC4291 4.2: "::" may only appear once in an
				 * address, since more than one occurrence
				 * cannot be resolved unambiguously.  We would
				 * otherwise accept it and silently normalize
				 * to something other than a conformant parser
				 * (eg, the OS resolver, or a peer or proxy)
				 * would, which is an ACL bypass primitive.
				 */
				if (skip_point != -1)
					return -16;
				if (result - orig + 2 > (int)max_len)
					return -15;
				*result++ = 0;
				*result++ = 0;
				skip_point = lws_ptr_diff(result, orig);
				break;
			}
			if (ipv6 && orig[2] == 0xff && orig[3] == 0xff &&
			    skip_point == 2) {
				/* ipv4 backwards compatible format */
				ipv6 = 0;
				memset(orig, 0, max_len);
				orig[10] = 0xff;
				orig[11] = 0xff;
				skip_point = -1;
				result = &orig[12];
				sects = 0;
				break;
			}
			if (ipv6 && *ts.token != ':')
				return -10;
			if (!ipv6 && *ts.token != '.')
				return -11;
			break;

		case LWS_TOKZE_ENDED:
			if (!ipv6 && sects == 4)
				return lws_ptr_diff(result, orig);
			if (ipv6 && sects == 8)
				return lws_ptr_diff(result, orig);
			if (skip_point != -1) {
				int ow = lws_ptr_diff(result, orig);
				/*
				 * contains ...::...
				 */
				if (ow == 16)
					return 16;
				memcpy(temp, &orig[skip_point], (unsigned int)(ow - skip_point));
				memset(&orig[skip_point], 0, (unsigned int)(16 - skip_point));
				memcpy(&orig[16 - (ow - skip_point)], temp,
						   (unsigned int)(ow - skip_point));

				return 16;
			}
			return -12;

		default: /* includes ENDED */
			lwsl_err("%s: malformed ip address\n",
				 __func__);

			return -13;
		}
	} while (ts.e > 0 && result - orig <= (int)max_len);

	lwsl_err("%s: ended on e %d\n", __func__, ts.e);

	return -14;
}

int
lws_sa46_parse_numeric_address(const char *ads, lws_sockaddr46 *sa46)
{
	uint8_t a[16];
	int n;

	memset(sa46, 0, sizeof(*sa46));

	n = lws_parse_numeric_address(ads, a, sizeof(a));
	if (n < 0)
		return -1;

#if defined(LWS_WITH_IPV6)
	if (n == 16) {
		sa46->sa6.sin6_family = AF_INET6;
		memcpy(sa46->sa6.sin6_addr.s6_addr, a,
		       sizeof(sa46->sa6.sin6_addr.s6_addr));

		return 0;
	}
#endif

	if (n != 4)
		return -1;

#if defined(LWS_WITH_IPV4)
	sa46->sa4.sin_family = AF_INET;
	memcpy(&sa46->sa4.sin_addr.s_addr, a,
	       sizeof(sa46->sa4.sin_addr.s_addr));

	return 0;
#elif defined(LWS_WITH_IPV6)
	/*
	 * IPv4 literal in a build with IPv4 compiled out: represent it as an
	 * IPv4-mapped IPv6 address (::ffff:a.b.c.d) so it can be stored in an
	 * AF_INET6 sockaddr and, on a dual-stack host (or behind NAT64),
	 * actually reached.  On a host with no IPv4 route this connect will
	 * simply fail cleanly at the socket layer; the alternative ("refuse
	 * the literal") makes DNS-server discovery and similar config unusable
	 * on otherwise-capable dual-stack hosts for no benefit.
	 */
	{
		static uint8_t did_notice;

		sa46->sa6.sin6_family = AF_INET6;
		memset(sa46->sa6.sin6_addr.s6_addr, 0, 10);
		sa46->sa6.sin6_addr.s6_addr[10] = 0xff;
		sa46->sa6.sin6_addr.s6_addr[11] = 0xff;
		memcpy(&sa46->sa6.sin6_addr.s6_addr[12], a, 4);

		if (!did_notice) {
			did_notice = 1;
			lwsl_notice("IPv4 literal '%s' mapped to ::ffff: in this "
				    "IPv6-only build; reachable only on dual-stack "
				    "or via NAT64\n", ads);
		}

		return 0;
	}
#else
	return -1;
#endif
}

int
lws_sa46_is_ipv4_mapped(const lws_sockaddr46 *sa46)
{
#if defined(LWS_WITH_IPV6)
	if (sa46 && sa46->sa4.sin_family == AF_INET6) {
		const uint8_t *a = sa46->sa6.sin6_addr.s6_addr;

		return !a[0] && !a[1] && !a[2] && !a[3] && !a[4] && !a[5] &&
		       !a[6] && !a[7] && !a[8] && !a[9] &&
			a[10] == 0xff && a[11] == 0xff;
	}
#else
	(void)sa46;
#endif

	return 0;
}

int
lws_write_numeric_address(const uint8_t *ads, int size, char *buf, size_t len)
{
	char c, elided = 0, soe = 0, zb = (char)-1, n, ipv4 = 0;
	const char *e = buf + len;
	char *obuf = buf;
	int q = 0;

	if (size == 4)
		return lws_snprintf(buf, len, "%u.%u.%u.%u",
				    ads[0], ads[1], ads[2], ads[3]);

	if (size != 16)
		goto bail;

	for (c = 0; c < (char)size / 2; c++) {
		uint16_t v = (uint16_t)((ads[q] << 8) | ads[q + 1]);

		if (buf + 8 > e)
			goto bail;

		q += 2;
		if (soe) {
			if (v)
				*buf++ = ':';
				/* fall thru to print hex value */
		} else
			if (!elided && !soe && !v) {
				elided = soe = 1;
				zb = c;
				continue;
			}

		if (ipv4) {
			n = (char)lws_snprintf(buf, lws_ptr_diff_size_t(e, buf), "%u.%u",
					ads[q - 2], ads[q - 1]);
			buf += n;
			if (c == 6)
				*buf++ = '.';
		} else {
			if (soe && !v)
				continue;
			if (c)
				*buf++ = ':';

			buf += lws_snprintf(buf, lws_ptr_diff_size_t(e, buf), "%x", v);

			if (soe && v) {
				soe = 0;
				if (c == 5 && v == 0xffff && !zb) {
					ipv4 = 1;
					*buf++ = ':';
				}
			}
		}
	}
	if (buf + 3 > e)
		goto bail;

	if (soe) { /* as is the case for all zeros */
		*buf++ = ':';
		*buf++ = ':';
		*buf = '\0';
	}

	return lws_ptr_diff(buf, obuf);

bail:
	/*
	 * We're failing: the buffer may hold a partial address, and the
	 * ipv4-tail path deliberately overwrites the NUL lws_snprintf() left,
	 * so we can be leaving an unterminated "string" behind.  Hand back a
	 * valid, empty one instead.
	 */

	if (len)
		*obuf = '\0';

	return -1;
}

int
lws_sa46_write_numeric_address(lws_sockaddr46 *sa46, char *buf, size_t len)
{
	*buf = '\0';
#if defined(LWS_WITH_IPV6)
	if (sa46->sa4.sin_family == AF_INET6)
		return lws_write_numeric_address(
				(uint8_t *)&sa46->sa6.sin6_addr, 16, buf, len);
#endif
	/*
	 * Not under LWS_WITH_IPV4: an IPv6-only build can still be handed an
	 * AF_INET sockaddr by the platform (macOS reports a v4 peer on an
	 * AF_INET6 socket that way), and refusing to render it is exactly
	 * when you most want to see what the address was
	 */
	if (sa46->sa4.sin_family == AF_INET)
		return lws_write_numeric_address(
				(uint8_t *)&sa46->sa4.sin_addr, 4, buf, len);

#if defined(LWS_WITH_UNIX_SOCK)
	if (sa46->sa4.sin_family == AF_UNIX)
		return lws_snprintf(buf, len, "(unix skt)");
#endif

	if (!sa46->sa4.sin_family)
		return lws_snprintf(buf, len, "(unset)");

	if (sa46->sa4.sin_family == AF_INET6)
		return lws_snprintf(buf, len, "(ipv6 unsupp)");

	lws_snprintf(buf, len, "(AF%d unsupp)", (int)sa46->sa4.sin_family);

	return -1;
}

int
lws_sa46_compare_ads(const lws_sockaddr46 *sa46a, const lws_sockaddr46 *sa46b)
{
#if defined(LWS_WITH_IPV4)
	uint8_t norm1[16], norm2[16];
#endif
	const uint8_t *p1, *p2;

#if defined(LWS_WITH_IPV4)
	if (sa46a->sa4.sin_family == AF_INET) {
		p1 = norm1;
		lws_4to6(norm1, (const uint8_t *)&sa46a->sa4.sin_addr);
	} else
#endif
#if defined(LWS_WITH_IPV6)
	if (sa46a->sa4.sin_family == AF_INET6) {
		p1 = (const uint8_t *)&sa46a->sa6.sin6_addr;
	} else
#endif
		return 1;

#if defined(LWS_WITH_IPV4)
	if (sa46b->sa4.sin_family == AF_INET) {
		p2 = norm2;
		lws_4to6(norm2, (const uint8_t *)&sa46b->sa4.sin_addr);
	} else
#endif
#if defined(LWS_WITH_IPV6)
	if (sa46b->sa4.sin_family == AF_INET6) {
		p2 = (const uint8_t *)&sa46b->sa6.sin6_addr;
	} else
#endif
		return 1;

	return memcmp(p1, p2, 16);
}

void
lws_4to6(uint8_t *v6addr, const uint8_t *v4addr)
{
	v6addr[12] = v4addr[0];
	v6addr[13] = v4addr[1];
	v6addr[14] = v4addr[2];
	v6addr[15] = v4addr[3];

	memset(v6addr, 0, 10);

	v6addr[10] = v6addr[11] = 0xff;
}

#if defined(LWS_WITH_IPV6)
void
lws_sa46_4to6(lws_sockaddr46 *sa46, const uint8_t *v4addr, uint16_t port)
{
	sa46->sa4.sin_family = AF_INET6;

	lws_4to6((uint8_t *)&sa46->sa6.sin6_addr.s6_addr[0], v4addr);

	sa46->sa6.sin6_port = htons(port);
}
#endif

int
lws_sa46_on_net(const lws_sockaddr46 *sa46a, const lws_sockaddr46 *sa46_net,
		int net_len)
{
#if defined(LWS_WITH_IPV4)
	uint8_t norm[2][16];
#endif
	const uint8_t *p1, *p2;
	uint8_t mask = 0xff;

	/*
	 * Bring the two addresses into a common, comparable 16-byte form, so
	 * IPv4 addresses are compared as IPv4-mapped IPv6 addresses whether
	 * they arrived as AF_INET, or already normalized to v4-mapped AF_INET6
	 * (as happens in an IPv6-only build).
	 *
	 * The prefix length is expressed in the address family space of
	 * sa46_net, so when the net is (or is stored as) IPv4, the prefix
	 * length is bumped by the 96 bits of v4-mapped prefix.
	 */

#if defined(LWS_WITH_IPV4)
	if (sa46a->sa4.sin_family == AF_INET) {
		/* ip is v4, compare it as v4-mapped v6 */

		lws_4to6(norm[0], (const uint8_t *)&sa46a->sa4.sin_addr);
		p1 = norm[0];
	} else
#endif
#if defined(LWS_WITH_IPV6)
	if (sa46a->sa4.sin_family == AF_INET6) {
		p1 = (const uint8_t *)&sa46a->sa6.sin6_addr;
	} else
#endif
		return 1;

#if defined(LWS_WITH_IPV4)
	if (sa46_net->sa4.sin_family == AF_INET) {
		/* net is v4, compare it as v4-mapped v6 */

		lws_4to6(norm[1], (const uint8_t *)&sa46_net->sa4.sin_addr);
		p2 = norm[1];
		/* because the mask length is for net v4 address */
		net_len += 12 * 8;
	} else
#endif
#if defined(LWS_WITH_IPV6)
	if (sa46_net->sa4.sin_family == AF_INET6) {
		p2 = (const uint8_t *)&sa46_net->sa6.sin6_addr;
		if (net_len <= 32 && lws_sa46_is_ipv4_mapped(sa46_net))
			/*
			 * The net is stored as v4-mapped (IPv6-only build),
			 * so the prefix length is in v4 space
			 */
			net_len += 12 * 8;
	} else
#endif
		return 1;

	/*
	 * Both operands are exactly 16 bytes wide from here on: whatever the
	 * caller believed the prefix length was, we can only ever compare 128
	 * bits of it, and walking further would read off the end of the
	 * normalization buffers and of the caller's lws_sockaddr46.
	 */

	if (net_len > 128)
		net_len = 128;
	if (net_len < 0)
		net_len = 0;

	while (net_len > 0) {
		if (net_len < 8)
			mask = (uint8_t)(mask << (8 - net_len));

		if (((*p1++) & mask) != ((*p2++) & mask))
			return 1;

		net_len -= 8;
	}

	return 0;
}

void
lws_sa46_copy_address(lws_sockaddr46 *sa46a, const void *in, int af)
{
	sa46a->sa4.sin_family = (sa_family_t)af;

	if (af == AF_INET) {
#if defined(LWS_WITH_IPV4)
		memcpy(&sa46a->sa4.sin_addr, in, 4);
#elif defined(LWS_WITH_IPV6)
		/*
		 * IPv6-only build: there is a single internal address family,
		 * AF_INET6.  IPv4 addresses from any source (eg, netlink route
		 * information) are normalized to IPv4-mapped IPv6 form, the
		 * same as IPv4 literals in
		 * lws_sa46_parse_numeric_address(), so they can coexist and
		 * compare with native IPv6 addresses consistently.
		 */
		lws_4to6(sa46a->sa6.sin6_addr.s6_addr, in);
		sa46a->sa4.sin_family = AF_INET6;
#endif
		return;
	}

#if defined(LWS_WITH_IPV6)
	if (af == AF_INET6)
		memcpy(&sa46a->sa6.sin6_addr, in, sizeof(sa46a->sa6.sin6_addr));
#endif
}


int
lws_parse_mac(const char *ads, uint8_t *result_6_bytes)
{
	uint8_t *p = result_6_bytes;
	struct lws_tokenize ts;
	char t[3];
	size_t n;
	long u;

	lws_tokenize_init(&ts, ads, LWS_TOKENIZE_F_NO_INTEGERS |
				    LWS_TOKENIZE_F_MINUS_NONTERM);
	ts.len = strlen(ads);

	do {
		ts.e = (int8_t)lws_tokenize(&ts);
		switch (ts.e) {
		case LWS_TOKZE_TOKEN:
			if (ts.token_len != 2)
				return -1;
			if (p - result_6_bytes == 6)
				return -2;
			t[0] = ts.token[0];
			t[1] = ts.token[1];
			t[2] = '\0';
			for (n = 0; n < 2; n++)
				if (t[n] < '0' || t[n] > 'f' ||
				    (t[n] > '9' && t[n] < 'A') ||
				    (t[n] > 'F' && t[n] < 'a'))
					return -1;
			u = strtol(t, NULL, 16);
			if (u > 0xff)
				return -5;
			*p++ = (uint8_t)u;
			break;

		case LWS_TOKZE_DELIMITER:
			if (*ts.token != ':')
				return -10;
			if (p - result_6_bytes > 5)
				return -11;
			break;

		case LWS_TOKZE_ENDED:
			if (p - result_6_bytes != 6)
				return -12;
			return 0;

		default:
			lwsl_err("%s: malformed mac\n", __func__);

			return -13;
		}
	} while (ts.e > 0);

	lwsl_err("%s: ended on e %d\n", __func__, ts.e);

	return -14;
}

int
lws_is_lan_address(const char *ads)
{
	lws_sockaddr46 sa46;

	if (!ads)
		return 0;

	if (lws_sa46_parse_numeric_address(ads, &sa46) < 0)
		return 0;

#if defined(LWS_WITH_IPV4)
	if (sa46.sa4.sin_family == AF_INET) {
		uint8_t *p = (uint8_t *)&sa46.sa4.sin_addr.s_addr;

		/* 10.0.0.0/8 */
		if (p[0] == 10)
			return 1;
		/* 172.16.0.0/12 */
		if (p[0] == 172 && p[1] >= 16 && p[1] <= 31)
			return 1;
		/* 192.168.0.0/16 */
		if (p[0] == 192 && p[1] == 168)
			return 1;
		/* 127.0.0.0/8 */
		if (p[0] == 127)
			return 1;
	} else
#endif
	if (sa46.sa4.sin_family == AF_INET6) {
#if defined(LWS_WITH_IPV6)
		uint8_t *p = (uint8_t *)&sa46.sa6.sin6_addr.s6_addr;

		/*
		 * An IPv4-mapped address (::ffff:a.b.c.d) is evaluated by its
		 * embedded IPv4 address, so "is this LAN" agrees whether the
		 * address is stored as AF_INET or as a mapped AF_INET6 (as
		 * happens in an IPv6-only build).
		 */
		if (lws_sa46_is_ipv4_mapped(&sa46)) {
			uint8_t *q = &p[12];

			if (q[0] == 10)
				return 1;
			if (q[0] == 172 && q[1] >= 16 && q[1] <= 31)
				return 1;
			if (q[0] == 192 && q[1] == 168)
				return 1;
			if (q[0] == 127)
				return 1;

			return 0;
		}

		/* fc00::/7 */
		if ((p[0] & 0xfe) == 0xfc)
			return 1;
		/* fe80::/10 */
		if (p[0] == 0xfe && (p[1] & 0xc0) == 0x80)
			return 1;
		/* ::1 */
		if (p[0] == 0 && p[1] == 0 && p[2] == 0 && p[3] == 0 &&
		    p[4] == 0 && p[5] == 0 && p[6] == 0 && p[7] == 0 &&
		    p[8] == 0 && p[9] == 0 && p[10] == 0 && p[11] == 0 &&
		    p[12] == 0 && p[13] == 0 && p[14] == 0 && p[15] == 1)
			return 1;
#endif
	}

	return 0;
}

int
lws_parse_cidr(const char *cidr, lws_sockaddr46 *sa46, int *len)
{
	char buf[64], *p;
	int n;

	lws_strncpy(buf, cidr, sizeof(buf));
	p = (char *)strchr(buf, '/');

	if (!p) {
		*len = -1; /* no mask */
	} else {
		const char *q;

		*p++ = '\0';

		/*
		 * It must be a plain decimal prefix length... "/" alone, or
		 * anything nonnumeric, would otherwise atoi() to 0, ie, a
		 * prefix that silently matches every address
		 */

		if (!*p || strlen(p) > 3)
			return -1;

		for (q = p; *q; q++)
			if (*q < '0' || *q > '9')
				return -1;

		*len = atoi(p);
	}

	n = lws_sa46_parse_numeric_address(buf, sa46);
	if (n)
		return n;

	if (*len == -1) {
		*len = sa46->sa4.sin_family == AF_INET6 ? 128 : 32;

		return 0;
	}

	/*
	 * The prefix length is in the address family space of the net address
	 * (an IPv6-only build stores v4 nets as v4-mapped AF_INET6, with the
	 * prefix length still in v4 space, so accept up to 128 for AF_INET6);
	 * refuse anything wider, so consumers like lws_sa46_on_net() can never
	 * be handed a prefix wider than the addresses they compare.
	 */

	if (*len > (sa46->sa4.sin_family == AF_INET6 ? 128 : 32))
		return -1;

	return 0;
}

int
lws_is_local_address(const char *ads)
{
	if (!ads)
		return 0;

	if (!strcmp(ads, "127.0.0.1") ||
	    !strcmp(ads, "::1") ||
	    !strcmp(ads, "localhost") ||
	    !strcmp(ads, "localhost4") ||
	    !strcmp(ads, "localhost6"))
		return 1;

	return 0;
}
