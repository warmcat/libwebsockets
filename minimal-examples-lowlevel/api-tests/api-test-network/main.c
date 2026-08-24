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
	}
#endif

	lwsl_user("Completed: %d fails\n", e);

	return e;
}
