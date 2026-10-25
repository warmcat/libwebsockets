/*
 * lws-api-test-extip-arbitrate
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Several sources may report our external address: the DHT, an extip
 * server, and the router.  The context keeps each source's view, and its
 * best address per family is the one from the strongest source that has
 * one (ROUTER > EXTIP > DHT).
 *
 * This feeds a sequence of reports to lws_extip_report() and checks after
 * each one what lws_extip_get_best() says, then that an `ext-ips` SMD
 * message went out for exactly the changes of the best address, with the
 * last one describing the final state.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

#if defined(WIN32) || defined(_WIN32)
#else
#include <sys/socket.h>
#endif

struct step {
	const char		*what;
	int			src;		/* lws_extip_src_t */
	int			af;		/* af given to lws_extip_report */
	const char		*ads;		/* NULL = offline */
	int			expect_af;	/* family to check after */
	const char		*expect;	/* expected best, NULL = none */
	int			changes;	/* best changed: an SMD went out */
};

static const struct step steps[] = {
	{ "dht detects v4",
	  LWS_EXTIP_SRC_DHT, AF_INET, "198.51.100.1",
	  AF_INET, "198.51.100.1", 1 },
	{ "extip outranks dht",
	  LWS_EXTIP_SRC_EXTIP, AF_INET, "203.0.113.2",
	  AF_INET, "203.0.113.2", 1 },
	{ "dht change is shadowed by extip",
	  LWS_EXTIP_SRC_DHT, AF_INET, "198.51.100.3",
	  AF_INET, "203.0.113.2", 0 },
	{ "router outranks extip",
	  LWS_EXTIP_SRC_ROUTER, AF_INET, "192.0.2.4",
	  AF_INET, "192.0.2.4", 1 },
	{ "extip offline is shadowed by router",
	  LWS_EXTIP_SRC_EXTIP, AF_INET, NULL,
	  AF_INET, "192.0.2.4", 0 },
	{ "router offline falls back to dht",
	  LWS_EXTIP_SRC_ROUTER, AF_INET, NULL,
	  AF_INET, "198.51.100.3", 1 },
	{ "out of range source is ignored",
	  LWS_EXTIP_SRC_COUNT, AF_INET, "192.0.2.9",
	  AF_INET, "198.51.100.3", 0 },
#if defined(LWS_WITH_IPV6)
	{ "router reports v6",
	  LWS_EXTIP_SRC_ROUTER, AF_INET6, "2001:db8:1::5",
	  AF_INET6, "2001:db8:1::5", 1 },
	{ "dht v6 is shadowed by router",
	  LWS_EXTIP_SRC_DHT, AF_INET6, "2001:db8:2::6",
	  AF_INET6, "2001:db8:1::5", 0 },
	{ "v6 address reported as v4 is ignored",
	  LWS_EXTIP_SRC_ROUTER, AF_INET, "2001:db8:3::7",
	  AF_INET, "198.51.100.3", 0 },
	{ "v4 is untouched by v6 reports",
	  LWS_EXTIP_SRC_DHT, AF_INET6, "2001:db8:2::8",
	  AF_INET, "198.51.100.3", 0 },
#endif
};

#if defined(LWS_WITH_IPV6)
static const char *final_smd = "{\"ext-ips\": [\"198.51.100.3\", \"2001:db8:1::5\"]}";
#else
static const char *final_smd = "{\"ext-ips\": [\"198.51.100.3\"]}";
#endif

static struct lws_context *context;
static lws_sorted_usec_list_t sul_check;
static int bad = 1, smd_count;
static char last_smd[128];

static int
smd_cb(void *opaque, lws_smd_class_t c, lws_usec_t ts, void *buf, size_t len)
{
	if (!(c & LWSSMDCL_NETWORK) || !buf ||
	    !strstr((const char *)buf, "\"ext-ips\""))
		return 0;

	lwsl_user("SMD: %.*s\n", (int)len, (const char *)buf);
	smd_count++;
	lws_strnncpy(last_smd, (const char *)buf, len, sizeof(last_smd));

	return 0;
}

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(context);
}

static int
run_steps(void)
{
	lws_sockaddr46 sa46, best;
	char got[64];
	size_t n;
	int e = 0;

	for (n = 0; n < LWS_ARRAY_SIZE(steps); n++) {
		const struct step *s = &steps[n];

		memset(&sa46, 0, sizeof(sa46));
		if (s->ads && lws_sa46_parse_numeric_address(s->ads, &sa46)) {
			lwsl_err("%s: bad test address %s\n", __func__, s->ads);
			return 1;
		}

		lws_extip_report(context, (lws_extip_src_t)s->src, s->ads ?
				 &sa46 : NULL, s->af, s->ads ?
				 LWS_EXTIP_STATUS_CHANGED :
				 LWS_EXTIP_STATUS_OFFLINE, NULL, 0);

		got[0] = '\0';
		if (!lws_extip_get_best(context, s->expect_af, &best))
			lws_sa46_write_numeric_address(&best, got, sizeof(got));

		if (strcmp(got, s->expect ? s->expect : "")) {
			lwsl_err("FAIL: step %d (%s): best '%s', expected '%s'\n",
				 (int)n, s->what, got, s->expect ? s->expect : "");
			e = 1;
		} else
			lwsl_user("step %d (%s): best '%s'\n", (int)n, s->what,
				  got);
	}

	return e;
}

static void
check_cb(lws_sorted_usec_list_t *sul)
{
	int changes = 0;
	size_t n;

	for (n = 0; n < LWS_ARRAY_SIZE(steps); n++)
		changes += steps[n].changes;

	if (smd_count != changes)
		lwsl_err("FAIL: %d ext-ips SMD, expected %d\n", smd_count,
			 changes);
	else if (strcmp(last_smd, final_smd))
		lwsl_err("FAIL: last SMD '%s', expected '%s'\n", last_smd,
			 final_smd);
	else
		bad = 0;

	lws_default_loop_exit(context);
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;

	signal(SIGINT, sigint_handler);

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	lwsl_user("LWS API selftest: extip source arbitration\n");

	info.port			= CONTEXT_PORT_NO_LISTEN;
	info.early_smd_cb		= smd_cb;
	info.early_smd_class_filter	= LWSSMDCL_NETWORK;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	if (!run_steps())
		/* let the SMD messages queued by the steps be delivered */
		lws_sul_schedule(context, 0, &sul_check, check_cb,
				 250 * LWS_US_PER_MS);
	else
		lws_default_loop_exit(context);

	while (lws_service(context, 0) >= 0)
		;

	lws_context_destroy(context);

	lwsl_user("Completed: %s\n", bad ? "FAIL" : "PASS");

	return lws_cmdline_passfail(argc, argv, bad);
}
