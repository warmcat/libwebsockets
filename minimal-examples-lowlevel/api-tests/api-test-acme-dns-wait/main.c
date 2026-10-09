/*
 * lws-api-test-acme-dns-wait
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Before the ACME dns-01 client tells the ACME server to look for the
 * challenge TXT, it asks the zone's name servers directly until they all
 * serve it (plugins/protocol_lws_acme_client/acme-dns-wait.c).  This checks
 *
 *  - the apex NS records are taken from the zone, with any A / AAAA glue
 *    the zone has for them, and an NS that is not a host name is skipped
 *  - the value is matched against each string of a TXT RDATA
 *  - against the auth dns plugin on loopback: a name server serving the
 *    value is ready at once, one serving another value never is and the
 *    wait fails naming it, and one with a silent address and a serving one
 *    is ready, since an address that doesn't answer says nothing
 *  - a name server that refuses, as it doesn't serve the zone, is named as
 *    not authoritative when the wait fails
 */

#include <libwebsockets.h>

#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "private-acme-client.h"

#define ZDIR		"acme-dns-wait-zones"
#define ORIGIN		"wait.example"
#define ZFILE		ORIGIN "_2000000000_2000000000_1.zone"
#define VALUE		"Zm9vYmFyLWNoYWxsZW5nZS12YWx1ZQ"

extern const struct lws_protocols lws_auth_dns_protocols[];

static struct lws_context *context;
static lws_sorted_usec_list_t sul_start, sul_deadline;
static lws_sockaddr46 sa_srv, sa_silent;
static int fails, outstanding;

static const char zone[] =
	"$ORIGIN " ORIGIN ".\n"
	"$TTL 3600\n"
	"@	IN	SOA	ns1." ORIGIN ". hostmaster." ORIGIN ". (\n"
	"			2026100501 ; serial\n"
	"			3600 1800 604800 60 )\n"
	"@	IN	NS	ns1." ORIGIN ".\n"
	"@	IN	NS	ns8.warmcat.com.\n"
	"ns1	IN	A	127.0.0.1\n"
	"ns1	IN	AAAA	::1\n"
	"www	IN	A	127.0.0.77\n"
	"_acme-challenge	IN	TXT	\"" VALUE "\"\n";

static int
expect(int cond, const char *what)
{
	if (cond) {
		lwsl_user("%s: ok: %s\n", __func__, what);
		return 0;
	}

	lwsl_err("%s: FAILED: %s\n", __func__, what);
	fails++;

	return 1;
}

static void
unit_checks(void)
{
	static const char bad_ns[] =
		"$ORIGIN bad.example.\n"
		"$TTL 3600\n"
		"@	IN	SOA	ns.bad.example. h.bad.example. (\n"
		"			1 3600 1800 604800 60 )\n"
		"@	IN	NS	ns.bad.example.\n"
		"sub	IN	NS	ns.elsewhere.example.\n";
	static const uint8_t txt_two[] = "\x03one\x05value";
	static const uint8_t txt_trunc[] = "\x09value";
	struct acme_dns_ns ns[ACME_DNS_MAX_NS];
	int n;

	n = acme_dns_zone_ns(zone, sizeof(zone) - 1, ORIGIN, ns,
			     (int)LWS_ARRAY_SIZE(ns));
	expect(n == 2, "two apex NS");
	if (n == 2) {
		expect(!strcmp(ns[0].host, "ns1." ORIGIN) &&
		       ns[0].glue_count ==
#if defined(LWS_WITH_IPV6)
				2,
#else
				1,
#endif
		       "in-zone NS has its glue");
		expect(!strcmp(ns[1].host, "ns8.warmcat.com") &&
		       !ns[1].glue_count, "out of zone NS has none");
	}

	n = acme_dns_zone_ns(bad_ns, sizeof(bad_ns) - 1, "bad.example", ns,
			     (int)LWS_ARRAY_SIZE(ns));
	expect(n == 1 && !strcmp(ns[0].host, "ns.bad.example"),
	       "a delegation's NS is not the apex's");

	n = acme_dns_zone_ns(zone, sizeof(zone) - 1, ORIGIN, ns, 1);
	expect(n == 1, "no more NS than room for");

	expect(acme_dns_txt_has(txt_two, sizeof(txt_two) - 1, "value"),
	       "second TXT string matches");
	expect(!acme_dns_txt_has(txt_two, sizeof(txt_two) - 1, "valu"),
	       "a prefix doesn't");
	expect(!acme_dns_txt_has(txt_trunc, sizeof(txt_trunc) - 1, "value"),
	       "a string running off the end doesn't");
}

struct wcase {
	const char	*what;
	const char	*qname;
	const char	*value;
	const char	*why;		/* what a failure must say */
	int		silent;		/* also give it a silent address */
	int		ok;
	int		done;
};

static struct wcase cases[] = {
	{ "serving name server is ready", "_acme-challenge." ORIGIN, VALUE,
	  NULL, 0, 1, 0 },
	{ "silent address doesn't stop it", "_acme-challenge." ORIGIN, VALUE,
	  NULL, 1, 1, 0 },
	{ "name server without it times out", "_acme-challenge." ORIGIN,
	  "not-the-value", "ns1." ORIGIN " didn't", 0, 0, 0 },
	{ "name server not serving the zone", "_acme-challenge.other.example",
	  VALUE, "ns1." ORIGIN " (not authoritative for the zone)", 0, 0, 0 },
};

static void
wait_cb(void *opaque, int ok, const char *why)
{
	struct wcase *c = (struct wcase *)opaque;

	c->done = 1;
	expect(ok == c->ok && (ok || (why && strstr(why, c->why))), c->what);
	if (why)
		lwsl_user("%s:   (%s)\n", __func__, why);

	if (!--outstanding)
		lws_default_loop_exit(context);
}

static void
start_cb(lws_sorted_usec_list_t *sul)
{
	struct acme_dns_server s[2];
	size_t n;

	for (n = 0; n < LWS_ARRAY_SIZE(cases); n++) {
		memset(s, 0, sizeof(s));
		lws_strncpy(s[0].ns, "ns1." ORIGIN, sizeof(s[0].ns));
		s[0].sa46 = cases[n].silent ? sa_silent : sa_srv;
		lws_strncpy(s[1].ns, "ns1." ORIGIN, sizeof(s[1].ns));
		s[1].sa46 = sa_srv;

		if (!acme_dns_wait_start(context, cases[n].qname,
					 cases[n].value, s,
					 cases[n].silent ? 2 : 1,
					 4 * LWS_US_PER_SEC,
					 500 * LWS_US_PER_MS, wait_cb,
					 &cases[n])) {
			expect(0, cases[n].what);
			continue;
		}
		outstanding++;
	}

	if (!outstanding)
		lws_default_loop_exit(context);
}

static void
deadline_cb(lws_sorted_usec_list_t *sul)
{
	expect(0, "every wait called back");
	lws_default_loop_exit(context);
}

static int
write_zone(void)
{
	int fd;

	/* auth_dns refuses zones others can write: keep them owner-only */
	if ((mkdir(ZDIR, 0700) && errno != EEXIST) || chmod(ZDIR, 0700))
		return 1;

	fd = open(ZDIR "/" ZFILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		return 1;
	if (write(fd, zone, sizeof(zone) - 1) != (ssize_t)(sizeof(zone) - 1)) {
		close(fd);
		return 1;
	}
	close(fd);

	return chmod(ZDIR "/" ZFILE, 0600);
}

static int
port_arg(int argc, const char **argv, const char *sw)
{
	const char *p = lws_cmdline_option(argc, argv, sw);
	int n = p ? atoi(p) : 0;

	return n > 0 && n < 65536 ? n : 0;
}

int
main(int argc, const char **argv)
{
	const struct lws_protocols my_protocols[] = {
		lws_auth_dns_protocols[0],
		LWS_PROTOCOL_LIST_TERM
	};
	struct lws_protocol_vhost_options pvo_zonedir = {
		NULL, NULL, "zone-dir", ZDIR
	};
	struct lws_protocol_vhost_options pvo = {
		NULL, &pvo_zonedir, "protocol-lws-auth-dns", ""
	};
	struct lws_context_creation_info info;
	int port = port_arg(argc, argv, "-p"),
	    port_silent = port_arg(argc, argv, "--port-silent"), sink = -1,
	    r = 1;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	lwsl_user("LWS API selftest: acme dns-01 wait for name servers\n");

	if (!port || !port_silent) {
		lwsl_err("%s: -p and --port-silent <port> are required\n",
			 __func__);
		return 1;
	}

	unit_checks();

	if (write_zone()) {
		lwsl_err("%s: unable to write the zone\n", __func__);
		return 1;
	}

	memset(&sa_srv, 0, sizeof(sa_srv));
	sa_srv.sa4.sin_family = AF_INET;
	sa_srv.sa4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sa_srv.sa4.sin_port = htons((uint16_t)port);
	sa_silent = sa_srv;
	sa_silent.sa4.sin_port = htons((uint16_t)port_silent);

	/* an address that takes the questions and never answers them */
	sink = socket(AF_INET, SOCK_DGRAM, 0);
	if (sink < 0 || bind(sink, (struct sockaddr *)&sa_silent.sa4,
			     sizeof(sa_silent.sa4))) {
		lwsl_err("%s: unable to bind the silent address\n", __func__);
		goto bail;
	}

	/* a server: size the fds tables to the process limit */
	info.fd_limit_per_thread = 0;
	info.port = port;
	info.options = LWS_SERVER_OPTION_ADOPT_APPLY_LISTEN_ACCEPT_CONFIG;
	info.listen_accept_role = "raw-skt";
	info.listen_accept_protocol = "protocol-lws-auth-dns";
	info.protocols = my_protocols;
	info.pvo = &pvo;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("%s: lws init failed\n", __func__);
		goto bail;
	}

	lws_sul_schedule(context, 0, &sul_start, start_cb, 200 * LWS_US_PER_MS);
	lws_sul_schedule(context, 0, &sul_deadline, deadline_cb,
			 20 * LWS_US_PER_SEC);

	while (lws_service(context, 0) >= 0)
		;

	lws_sul_cancel(&sul_start);
	lws_sul_cancel(&sul_deadline);
	lws_context_destroy(context);

	lwsl_user("Completed: %s\n", fails ? "FAIL" : "PASS");
	r = !!fails;

bail:
	if (sink >= 0)
		close(sink);

	return r;
}
