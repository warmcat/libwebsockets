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

	lwsl_user("Completed: %d fails\n", e);

	return e;
}
