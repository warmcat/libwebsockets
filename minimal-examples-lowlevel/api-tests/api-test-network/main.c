#include <libwebsockets.h>
#include <string.h>

int main(void)
{
	lws_sockaddr46 sa46;
	int e = 0;

	lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE, NULL);

	lwsl_user("LWS network api tests\n");

	if (!lws_is_lan_address("10.1.2.3")) { lwsl_err("10.x failed\n"); e++; }
	if (!lws_is_lan_address("192.168.1.5")) { lwsl_err("192.168.x failed\n"); e++; }
	if (!lws_is_lan_address("172.16.0.1")) { lwsl_err("172.16.x failed\n"); e++; }
	if (lws_is_lan_address("8.8.8.8")) { lwsl_err("8.8.8.8 failed\n"); e++; }

	if (!lws_is_local_address("127.0.0.1") && !lws_is_local_address("::1")) {
		lwsl_err("local address check failed\n");
		e++;
	}

	/*
	 * An IPv4 literal must parse in every build.  In a dual-stack build it
	 * stays AF_INET; in an IPv6-only build (LWS_WITH_IPV4 off) it is mapped
	 * to ::ffff:a.b.c.d as AF_INET6 so DNS-server discovery and similar
	 * config still works on dual-stack hosts.
	 */
	memset(&sa46, 0, sizeof(sa46));
	if (lws_sa46_parse_numeric_address("192.168.1.1", &sa46) < 0) { // NOSONAR
		lwsl_err("sa46 parse '192.168.1.1' failed\n");
		e++;
	} else {
#if defined(LWS_WITH_IPV4)
		if (sa46.sa4.sin_family != AF_INET) {
			lwsl_err("sa46 family %d != AF_INET\n",
				 sa46.sa4.sin_family);
			e++;
		}
#elif defined(LWS_WITH_IPV6)
		if (sa46.sa4.sin_family != AF_INET6 ||
		    !lws_sa46_is_ipv4_mapped(&sa46)) {
			lwsl_err("sa46 IPv6-only mapping failed (family %d)\n",
				 sa46.sa4.sin_family);
			e++;
		}
		/* a native IPv6 literal is not mapped */
		memset(&sa46, 0, sizeof(sa46));
		if (lws_sa46_parse_numeric_address("2001:db8::1", &sa46) < 0 ||
		    lws_sa46_is_ipv4_mapped(&sa46)) {
			lwsl_err("sa46 native IPv6 mapped wrongly\n");
			e++;
		}
#endif
	}

	/*
	 * F-017 regression: overlong literals must be rejected without
	 * writing past the end of the 16-byte buffer the sa46 parser uses
	 * internally.  These are peer-reachable via client redirect targets.
	 */
	{
		static const char * const overlong[] = {
			"1:2:3:4:5:6:7:8:9",	/* 9th ipv6 group     */
			"1:2:3:4:5:6:7:8::",	/* :: after 8 groups  */
			"::ffff:1.2.3.4.5",	/* 5th mapped octet   */
			"1.2.3.4.5",		/* 5th ipv4 octet     */
		};
		size_t n;

		for (n = 0; n < LWS_ARRAY_SIZE(overlong); n++)
			if (!lws_sa46_parse_numeric_address(overlong[n],
							    &sa46)) {
				lwsl_err("sa46 accepted overlong '%s'\n",
					 overlong[n]);
				e++;
			}
	}

	/*
	 * G-197: the parser must be as strict as inet_pton(), so it can never
	 * read an address differently from libc's resolver.  A leading zero
	 * makes an octet octal to libc ("012.0.0.1" is 10.0.0.1 to it), and
	 * stray separators or whitespace are accepted by nothing else.
	 */
	{
		static const char * const refused[] = {
			"012.0.0.1",
			"010.0.0.1",
			"1.2.3.04",
			"00.1.2.3",
			"::ffff:012.0.0.1",
			":1:2:3:4:5:6:7:8",
			"1:2:3:4:5:6:7:8:",
			":1::",
			"1::2:",
			" 1 .2. 3.4",
			"1.2.3.4 ",
			"\t1.2.3.4",
			".1.2.3.4",
			"1.2.3.4.",
			"::ffff:1.2.3.4.",
			"1.2.3.4\n",
			"[::1]",
			"::1%lo",
		};
		static const struct {
			const char	*ads;
			int		len;
			uint8_t		b[4];
		} accepted[] = {
			{ "0.0.0.0",		4, { 0, 0, 0, 0 } },
			{ "10.0.0.1",		4, { 10, 0, 0, 1 } },
			{ "100.200.0.255",	4, { 100, 200, 0, 255 } },
			{ "::",			16, { 0, 0, 0, 0 } },
			{ "::1",		16, { 0, 0, 0, 0 } },
			{ "1::",		16, { 0, 1, 0, 0 } },
			{ "::ffff:10.0.0.1",	16, { 0, 0, 0, 0 } },
		};
		uint8_t q[16];
		size_t n;

		for (n = 0; n < LWS_ARRAY_SIZE(refused); n++)
			if (lws_parse_numeric_address(refused[n], q,
						      sizeof(q)) >= 0) {
				lwsl_err("accepted non-strict '%s'\n",
					 refused[n]);
				e++;
			}

		for (n = 0; n < LWS_ARRAY_SIZE(accepted); n++)
			if (lws_parse_numeric_address(accepted[n].ads, q,
						      sizeof(q)) !=
							accepted[n].len ||
			    memcmp(q, accepted[n].b, 4)) {
				lwsl_err("refused or misread '%s'\n",
					 accepted[n].ads);
				e++;
			}
	}

	/*
	 * ... and what libc would still take as ipv4 (and lws therefore
	 * refuses to resolve for a connection) is recognized as ambiguous
	 */
	{
		static const struct {
			const char	*host;
			int		amb;
		} hosts[] = {
			{ "012.0.0.1",		1 },
			{ "10.1",		1 },
			{ "167772161",		1 },
			{ "0xa.0.0.1",		1 },
			{ "0x0a000001",		1 },
			{ "1.2.3.0x4",		1 },
			{ "1.2.3.4.",		1 },
			{ "example.com.1",	1 },
			{ "1.2.3.4",		0 },
			{ "::1",		0 },
			{ "example.com",	0 },
			{ "example.com.",	0 },
			{ "1.example",		0 },
			{ "0xg",		0 },
			{ "",			0 },
			{ ".",			0 },
		};
		size_t n;

		for (n = 0; n < LWS_ARRAY_SIZE(hosts); n++)
			if (lws_host_is_ambiguous_numeric(hosts[n].host) !=
							hosts[n].amb) {
				lwsl_err("ambiguous numeric '%s' != %d\n",
					 hosts[n].host, hosts[n].amb);
				e++;
			}
	}

	/* ... names lws resolves to loopback itself (RFC 6761 6.3) */
	{
		static const struct {
			const char	*host;
			int		lh;
		} hosts[] = {
			{ "localhost",		1 },
			{ "localhost.",		1 },
			{ "LocalHost",		1 },
			{ "other.localhost",	1 },
			{ "a.b.localhost.",	1 },
			{ ".localhost",		1 },
			{ "notlocalhost",	0 },
			{ "localhost.example",	0 },
			{ "localhost..",	0 },
			{ "localhos",		0 },
			{ "127.0.0.1",		0 },
			{ "",			0 },
			{ ".",			0 },
		};
		size_t n;

		for (n = 0; n < LWS_ARRAY_SIZE(hosts); n++)
			if (lws_host_is_localhost(hosts[n].host) !=
							hosts[n].lh) {
				lwsl_err("localhost '%s' != %d\n",
					 hosts[n].host, hosts[n].lh);
				e++;
			}
	}

	/*
	 * ... and the same for the raw parser with an exact-size ipv4 result
	 * buffer, where the extra octet goes 1 byte past the end
	 */
	{
		uint8_t q[4] = { 0xff, 0xff, 0xff, 0xff };

		if (lws_parse_numeric_address("1.2.3.4", q, sizeof(q)) != 4 ||
		    q[0] != 1 || q[1] != 2 || q[2] != 3 || q[3] != 4) {
			lwsl_err("exact-size ipv4 buffer parse broken\n");
			e++;
		}
		if (lws_parse_numeric_address("1.2.3.4.5", q, sizeof(q)) >= 0) {
			lwsl_err("5-octet ipv4 accepted, 4-byte buffer\n");
			e++;
		}
	}

	/*
	 * G-198: a cidr's prefix is bounded by the family it is written in,
	 * in every build.  An IPv6-only build stores a v4 net v4-mapped, and
	 * used to accept a v4 prefix up to 128 there, where 33..96 match every
	 * IPv4 address.
	 */
	{
		static const struct {
			const char	*cidr;
			int		len; /* -1 = refused */
		} cidrs[] = {
			{ "10.0.0.0/8",		8 },
			{ "10.0.0.0/32",	32 },
			{ "10.0.0.1",		32 },
			{ "10.0.0.0/33",	-1 },
			{ "10.0.0.0/64",	-1 },
			{ "10.0.0.0/96",	-1 },
			{ "10.0.0.0/104",	-1 },
			{ "010.0.0.0/8",	-1 },
			{ "10.0.0.0/",		-1 },
#if defined(LWS_WITH_IPV6)
			{ "2001:db8::/32",	32 },
			{ "2001:db8::/128",	128 },
			{ "2001:db8::1",	128 },
			{ "::ffff:10.0.0.0/104", 104 },
			{ "2001:db8::/129",	-1 },
#endif
		};
		lws_sockaddr46 net, a;
		size_t n;
		int len;

		for (n = 0; n < LWS_ARRAY_SIZE(cidrs); n++) {
			len = -1;
			if (lws_parse_cidr(cidrs[n].cidr, &net, &len))
				len = -1;
			if (len != cidrs[n].len) {
				lwsl_err("cidr '%s': len %d, expected %d\n",
					 cidrs[n].cidr, len, cidrs[n].len);
				e++;
			}
		}

		if (lws_parse_cidr("10.0.0.0/8", &net, &len) ||
		    lws_sa46_parse_numeric_address("10.1.2.3", &a) ||
		    lws_sa46_on_net(&a, &net, len) ||
		    lws_sa46_parse_numeric_address("11.0.0.1", &a) ||
		    !lws_sa46_on_net(&a, &net, len)) {
			lwsl_err("10.0.0.0/8 cidr membership wrong\n");
			e++;
		}
	}

	/*
	 * lws_sa46_on_net() has to give the same answers however the v4
	 * addresses are represented: natively as AF_INET in dual builds, or
	 * normalized to v4-mapped AF_INET6 in an IPv6-only build (the prefix
	 * length is in v4 space in both cases)
	 */
	{
		lws_sockaddr46 net;

		if (lws_sa46_parse_numeric_address("192.168.1.1", &sa46) ||
		    lws_sa46_parse_numeric_address("192.168.1.0", &net)) {
			lwsl_err("on_net setup failed\n");
			e++;
		} else {
			if (lws_sa46_on_net(&sa46, &net, 24)) {
				lwsl_err("192.168.1.1 not on 192.168.1.0/24\n");
				e++;
			}
			if (lws_sa46_on_net(&sa46, &net, 25)) {
				lwsl_err("192.168.1.1 not on 192.168.1.0/25\n");
				e++;
			}
			if (!lws_sa46_parse_numeric_address("192.168.1.129",
							    &sa46) &&
			    !lws_sa46_on_net(&sa46, &net, 25)) {
				lwsl_err("192.168.1.129 wrongly on 192.168.1.0/25\n");
				e++;
			}
		}
	}

#if defined(LWS_WITH_IPV6)
	{
		lws_sockaddr46 d6, n6;

		if (lws_sa46_parse_numeric_address("2001:db8::1", &d6) ||
		    lws_sa46_parse_numeric_address("2001:db8::", &n6)) {
			lwsl_err("on_net v6 setup failed\n");
			e++;
		} else {
			if (lws_sa46_on_net(&d6, &n6, 32)) {
				lwsl_err("2001:db8::1 not on 2001:db8::/32\n");
				e++;
			}
			if (!lws_sa46_parse_numeric_address("2001:db9::1", &d6) &&
			    !lws_sa46_on_net(&d6, &n6, 32)) {
				lwsl_err("2001:db9::1 wrongly on 2001:db8::/32\n");
				e++;
			}
		}

		/*
		 * a v4 address (v4-mapped in IPv6-only builds) is not on a
		 * native v6 net
		 */
		if (!lws_sa46_parse_numeric_address("192.168.1.1", &sa46) &&
		    !lws_sa46_on_net(&sa46, &n6, 32)) {
			lwsl_err("v4 address wrongly on native v6 net\n");
			e++;
		}

		/*
		 * comparison has to bridge the representations: a v4 address
		 * and its v4-mapped form are the same address
		 */
		if (!lws_sa46_parse_numeric_address("192.168.1.1", &sa46) &&
		    !lws_sa46_parse_numeric_address("::ffff:192.168.1.1", &d6) &&
		    lws_sa46_compare_ads(&sa46, &d6)) {
			lwsl_err("v4 and v4-mapped compare unequal\n");
			e++;
		}

		/*
		 * ... in every build, IPv6-only ones too: the platform can
		 * still hand those an AF_INET sockaddr, eg, macOS gives the
		 * source of a datagram from a v4 peer on an AF_INET6 socket
		 * like that.  When an IPv6-only build couldn't compare it,
		 * every answer from an IPv4 nameserver was taken as coming
		 * from somewhere else, and nothing resolved.
		 */
		memset(&sa46, 0, sizeof(sa46));
		sa46.sa4.sin_family = AF_INET;
		sa46.sa4.sin_addr.s_addr = htonl(0xc0a80101); /* 192.168.1.1 */
		if (lws_sa46_parse_numeric_address("::ffff:192.168.1.1", &d6) ||
		    lws_sa46_compare_ads(&sa46, &d6) ||
		    lws_sa46_compare_ads(&d6, &sa46)) {
			lwsl_err("platform AF_INET and v4-mapped compare "
				 "unequal\n");
			e++;
		}
	}
#endif

	/*
	 * Host keys: one host is one key, an IPv4 address or an IPv6 /64, and
	 * anything that isn't an IP address shares the one "unknown" key
	 */
	{
		static const struct {
			const char	*ads;
			const char	*key;
		} hk[] = {
			{ "192.0.2.1",			"192.0.2.1" },
			{ "203.0.113.255",		"203.0.113.255" },
#if defined(LWS_WITH_IPV6)
			{ "::ffff:192.0.2.1",		"192.0.2.1" },
			{ "2001:db8:1:2::1",		"2001:db8:1:2::/64" },
			{ "2001:db8:1:2:ffff:ffff:ffff:ffff",
							"2001:db8:1:2::/64" },
			{ "2001:db8:1:3::1",		"2001:db8:1:3::/64" },
			{ "::1",			"0:0:0:0::/64" },
			{ "ffff:ffff:ffff:ffff::",	"ffff:ffff:ffff:ffff::/64" },
#endif
		};
		char key[LWS_HOST_KEY_LEN];
		size_t n;

		for (n = 0; n < LWS_ARRAY_SIZE(hk); n++) {
			key[0] = '\0';
			if (lws_sa46_parse_numeric_address(hk[n].ads, &sa46) ||
			    lws_sa46_host_key(&sa46, key, sizeof(key)) ||
			    strcmp(key, hk[n].key)) {
				lwsl_err("host key of %s: '%s', expected "
					 "'%s'\n", hk[n].ads, key, hk[n].key);
				e++;
			}
		}

		/* not an address: the shared bucket, not "never the same" */
		memset(&sa46, 0, sizeof(sa46));
		if (lws_sa46_host_key(&sa46, key, sizeof(key)) != 1 ||
		    strcmp(key, LWS_HOST_KEY_UNKNOWN)) {
			lwsl_err("host key of an unset sa46: '%s'\n", key);
			e++;
		}
	}

	lwsl_user("Completed: %d fails\n", e);

	return e;
}
