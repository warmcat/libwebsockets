/*
 * lws-api-test-proxy-v2
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The PROXY v2 header helpers: what lws_proxy_v2_render() emits, byte for
 * byte, against the layout in haproxy's proxy-protocol.txt; that
 * lws_proxy_v2_parse() gives back what was rendered; and that it refuses
 * every malformed header we can think of, since a header is attacker-chosen
 * bytes until the caller decides it trusts where it came from.
 */

#include <libwebsockets.h>
#include <string.h>

static int tests, fail;

static void
expect(const char *what, int ok)
{
	tests++;
	if (!ok) {
		fail++;
		lwsl_err("  FAIL: %s\n", what);
	} else
		lwsl_user("  PASS: %s\n", what);
}

static const uint8_t sig[12] = {
	0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a
};

/*
 * TCP over IPv4, 192.0.2.1:56324 to 198.51.100.2:443, laid out as
 * proxy-protocol.txt section 2.2 says: signature, version and command,
 * family and protocol, length, then source and destination addresses, then
 * source and destination ports, all in network order
 */
static const uint8_t v4_hdr[] = {
	0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
	0x21, 0x11, 0x00, 0x0c,
	192, 0, 2, 1,
	198, 51, 100, 2,
	0xdc, 0x04,
	0x01, 0xbb
};

/* an independent CRC-32C, to make a CRC32C TLV with */

static uint32_t
ref_crc32c(const uint8_t *p, size_t len)
{
	uint32_t c = ~0u;
	int n;

	while (len--) {
		c ^= *p++;
		for (n = 0; n < 8; n++)
			c = (c & 1) ? (c >> 1) ^ 0x82f63b78u : c >> 1;
	}

	return ~c;
}

static void
set_addr(lws_sockaddr46 *sa, const char *ads, int port)
{
	memset(sa, 0, sizeof(*sa));
	if (lws_sa46_parse_numeric_address(ads, sa))
		lwsl_err("%s: can't parse %s\n", __func__, ads);
	sa46_sockport(sa, htons((uint16_t)port));
}

/* a copy of h with byte at idx replaced, parsed */

static int
parse_with(const uint8_t *h, size_t len, size_t idx, uint8_t v)
{
	uint8_t b[LWS_PROXY_V2_MAX];
	lws_proxy_v2_t pv;

	memcpy(b, h, len);
	b[idx] = v;

	return lws_proxy_v2_parse(b, len, &pv);
}

/*
 * A TCP4 header with the TLV bytes t appended (the length field set to
 * cover them), into b.  Returns its length.
 */

static size_t
v4_with_tlvs(uint8_t *b, const uint8_t *t, size_t tl)
{
	size_t n = sizeof(v4_hdr);

	memcpy(b, v4_hdr, n);
	memcpy(b + n, t, tl);
	b[14] = (uint8_t)((12 + tl) >> 8);
	b[15] = (uint8_t)(12 + tl);

	return n + tl;
}

int
main(int argc, const char **argv)
{
	uint8_t b[LWS_PROXY_V2_MAX], b2[LWS_PROXY_V2_MAX];
	lws_proxy_v2_t pv, pv2;
	char a1[64], a2[64];
	size_t l;
	int n;

	lws_set_log_level(LLL_USER | LLL_ERR, NULL);
	(void)argc;
	(void)argv;

	lwsl_user("LWS API selftest: PROXY v2 header\n");

	/* rendering matches the documented layout exactly */

	memset(&pv, 0, sizeof(pv));
	set_addr(&pv.src, "192.0.2.1", 56324);
	set_addr(&pv.dst, "198.51.100.2", 443);
	n = lws_proxy_v2_render(&pv, b, sizeof(b));
	expect("TCP4 renders as the spec lays it out",
	       n == (int)sizeof(v4_hdr) && !memcmp(b, v4_hdr, sizeof(v4_hdr)));

#if defined(LWS_WITH_IPV6)
	/*
	 * An IPv4 client on a dual-stack listener, or any IPv4 address in an
	 * IPv6-only build, is IPv4-mapped: it is still an IPv4 client
	 */

	memset(&pv, 0, sizeof(pv));
	set_addr(&pv.src, "::ffff:192.0.2.1", 56324);
	set_addr(&pv.dst, "::ffff:198.51.100.2", 443);
	n = lws_proxy_v2_render(&pv, b, sizeof(b));
	expect("IPv4-mapped renders as TCP4",
	       n == (int)sizeof(v4_hdr) && !memcmp(b, v4_hdr, sizeof(v4_hdr)));
#endif

	/* and parses back */

	expect("TCP4 header length known from its first 16 bytes",
	       lws_proxy_v2_header_len(v4_hdr, 16) == (int)sizeof(v4_hdr));
	expect("TCP4 needs 16 bytes to know its length",
	       !lws_proxy_v2_header_len(v4_hdr, 15) &&
	       !lws_proxy_v2_header_len(v4_hdr, 3));
	n = lws_proxy_v2_parse(v4_hdr, sizeof(v4_hdr), &pv2);
	lws_sa46_write_numeric_address(&pv2.src, a1, sizeof(a1));
	lws_sa46_write_numeric_address(&pv2.dst, a2, sizeof(a2));
	expect("TCP4 parses to its addresses and ports",
	       !n && !pv2.local && !pv2.dgram && !strcmp(a1, "192.0.2.1") &&
	       !strcmp(a2, "198.51.100.2") &&
	       ntohs(pv2.src.sa4.sin_port) == 56324 &&
	       ntohs(pv2.dst.sa4.sin_port) == 443 && !pv2.authority[0]);

	/* the TLVs we use round trip */

	lws_strncpy(pv.authority, "auth.example.com", sizeof(pv.authority));
	lws_strncpy(pv.alpn, "h2", sizeof(pv.alpn));
	n = lws_proxy_v2_render(&pv, b, sizeof(b));
	expect("TCP4 with authority and alpn renders",
	       n > 0 && lws_proxy_v2_header_len(b, (size_t)n) == n);
	expect("TCP4 with authority and alpn round trips",
	       n > 0 && !lws_proxy_v2_parse(b, (size_t)n, &pv2) &&
	       !strcmp(pv2.authority, "auth.example.com") &&
	       !strcmp(pv2.alpn, "h2"));

#if defined(LWS_WITH_IPV6)
	memset(&pv, 0, sizeof(pv));
	set_addr(&pv.src, "2001:db8::1", 40000);
	set_addr(&pv.dst, "2001:db8::2", 443);
	pv.dgram = 1;
	lws_strncpy(pv.authority, "auth.example.com", sizeof(pv.authority));
	n = lws_proxy_v2_render(&pv, b, sizeof(b));
	expect("UDP6 renders with the AF_INET6 / DGRAM byte",
	       n == 16 + 36 + 3 + 16 && b[13] == 0x22);
	memset(&pv2, 0, sizeof(pv2));
	if (n > 0)
		n = lws_proxy_v2_parse(b, (size_t)n, &pv2);
	lws_sa46_write_numeric_address(&pv2.src, a1, sizeof(a1));
	expect("UDP6 round trips",
	       !n && pv2.dgram && !strcmp(a1, "2001:db8::1") &&
	       ntohs(pv2.src.sa6.sin6_port) == 40000 &&
	       !strcmp(pv2.authority, "auth.example.com"));
#endif

	/* LOCAL carries no addresses */

	memset(&pv, 0, sizeof(pv));
	pv.local = 1;
	n = lws_proxy_v2_render(&pv, b, sizeof(b));
	expect("LOCAL renders as an empty UNSPEC header",
	       n == 16 && b[12] == 0x20 && !b[13] && !b[14] && !b[15]);
	expect("LOCAL parses", n == 16 && !lws_proxy_v2_parse(b, 16, &pv2) &&
			       pv2.local);

	/* rendering refuses what it can't say */

	memset(&pv, 0, sizeof(pv));
	expect("render refuses a proxied client with no addresses",
	       lws_proxy_v2_render(&pv, b, sizeof(b)) < 0);
	set_addr(&pv.src, "192.0.2.1", 1);
	set_addr(&pv.dst, "198.51.100.2", 2);
	expect("render refuses a buffer too small",
	       lws_proxy_v2_render(&pv, b, 20) < 0);

	/* a CRC32C TLV is checked */

	expect("the reference CRC-32C is the standard one",
	       ref_crc32c((const uint8_t *)"123456789", 9) == 0xe3069283u);
	{
		static const uint8_t crc_tlv[] = { 0x03, 0x00, 0x04, 0, 0, 0, 0 };
		uint32_t c;

		l = v4_with_tlvs(b, crc_tlv, sizeof(crc_tlv));
		c = ref_crc32c(b, l);
		b[l - 4] = (uint8_t)(c >> 24);
		b[l - 3] = (uint8_t)(c >> 16);
		b[l - 2] = (uint8_t)(c >> 8);
		b[l - 1] = (uint8_t)c;
		expect("a header with the right CRC32C parses",
		       !lws_proxy_v2_parse(b, l, &pv2));
		expect("a header with the wrong CRC32C is refused",
		       parse_with(b, l, 16, 193) < 0);
	}

	/* unknown TLVs are skipped */

	{
		static const uint8_t t[] = { 0xe0, 0x00, 0x02, 'x', 'y',
					     0x04, 0x00, 0x00 };

		l = v4_with_tlvs(b, t, sizeof(t));
		expect("unknown and NOOP TLVs are skipped",
		       !lws_proxy_v2_parse(b, l, &pv2));
	}

	/* and everything malformed is refused */

	expect("not the signature",
	       lws_proxy_v2_header_len((const uint8_t *)"GET / HTTP/1.1\r\n",
				       16) < 0);
	expect("a v1 text header is not a v2 one",
	       lws_proxy_v2_header_len((const uint8_t *)
			"PROXY TCP4 192.0.2.1 198.51.100.2 1 2\r\n", 39) < 0);
	expect("a wrong byte early in the signature is noticed at once",
	       lws_proxy_v2_header_len((const uint8_t *)"\r\n\r\nX", 5) < 0);
	expect("version 1 in the binary header",
	       parse_with(v4_hdr, sizeof(v4_hdr), 12, 0x11) < 0);
	expect("an undefined command", parse_with(v4_hdr, sizeof(v4_hdr), 12,
						  0x22) < 0);
	expect("AF_UNIX", parse_with(v4_hdr, sizeof(v4_hdr), 13, 0x31) < 0);
	expect("PROXY with AF_UNSPEC",
	       parse_with(v4_hdr, sizeof(v4_hdr), 13, 0x01) < 0);
	expect("PROXY with an UNSPEC transport",
	       parse_with(v4_hdr, sizeof(v4_hdr), 13, 0x10) < 0);
	expect("an IPv6 family with an IPv4 sized address block",
	       parse_with(v4_hdr, sizeof(v4_hdr), 13, 0x21) < 0);
	expect("a length different from what was given",
	       lws_proxy_v2_parse(v4_hdr, sizeof(v4_hdr) - 1, &pv2) < 0);

	memcpy(b2, sig, sizeof(sig));
	b2[12] = 0x21;
	b2[13] = 0x11;
	b2[14] = 0xff;
	b2[15] = 0xff;
	expect("a header longer than we accept",
	       lws_proxy_v2_header_len(b2, 16) < 0);

	{
		/* a TLV claiming more than is left */
		static const uint8_t t1[] = { 0x02, 0x00, 0x09, 'a', 'b' };
		/* two bytes left over after the TLVs */
		static const uint8_t t2[] = { 0x02, 0x00, 0x01, 'a', 0x00, 0x00 };
		/* the authority twice */
		static const uint8_t t3[] = { 0x02, 0x00, 0x01, 'a',
					      0x02, 0x00, 0x01, 'b' };
		/* an authority that isn't printable */
		static const uint8_t t4[] = { 0x02, 0x00, 0x03, 'a', '\n', 'b' };
		static const uint8_t t5[] = { 0x02, 0x00, 0x03, 'a', ' ', 'b' };
		static const uint8_t t6[] = { 0x02, 0x00, 0x03, 'a', 0, 'b' };
		/* an empty authority */
		static const uint8_t t7[] = { 0x02, 0x00, 0x00 };
		/* a CRC32C of the wrong size */
		static const uint8_t t8[] = { 0x03, 0x00, 0x02, 0, 0 };
		uint8_t t9[3 + 256];

		l = v4_with_tlvs(b, t1, sizeof(t1));
		expect("a TLV longer than what is left",
		       lws_proxy_v2_parse(b, l, &pv2) < 0);
		l = v4_with_tlvs(b, t2, sizeof(t2));
		expect("bytes left over after the TLVs",
		       lws_proxy_v2_parse(b, l, &pv2) < 0);
		l = v4_with_tlvs(b, t3, sizeof(t3));
		expect("the authority twice",
		       lws_proxy_v2_parse(b, l, &pv2) < 0);
		l = v4_with_tlvs(b, t4, sizeof(t4));
		expect("an authority with a control character",
		       lws_proxy_v2_parse(b, l, &pv2) < 0);
		l = v4_with_tlvs(b, t5, sizeof(t5));
		expect("an authority with a space",
		       lws_proxy_v2_parse(b, l, &pv2) < 0);
		l = v4_with_tlvs(b, t6, sizeof(t6));
		expect("an authority with a NUL",
		       lws_proxy_v2_parse(b, l, &pv2) < 0);
		l = v4_with_tlvs(b, t7, sizeof(t7));
		expect("an empty authority",
		       lws_proxy_v2_parse(b, l, &pv2) < 0);
		l = v4_with_tlvs(b, t8, sizeof(t8));
		expect("a CRC32C of the wrong size",
		       lws_proxy_v2_parse(b, l, &pv2) < 0);

		t9[0] = 0x02;
		t9[1] = 0x01;
		t9[2] = 0x00;
		memset(t9 + 3, 'a', 256);
		l = v4_with_tlvs(b, t9, sizeof(t9));
		expect("an authority too long to hold",
		       lws_proxy_v2_parse(b, l, &pv2) < 0);
	}

	lwsl_user("Completed: %s (tests=%d fail=%d)\n",
		  fail ? "FAIL" : "PASS", tests, fail);

	return !!fail;
}
