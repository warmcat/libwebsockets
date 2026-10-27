/*
 * lws-api-test-extip-router
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Runs both ends of the lws-extip-router plugin in one context:
 *
 *  - a "router" vhost, serving signed replies listing the addresses on the
 *    loopback interface, as if it were the router's outward interface
 *
 *  - a "host" vhost, asking the router every second with a fresh nonce
 *
 * Normally the host must take the router's reply and report 127.0.0.1 (and,
 * if the loopback interface has ::1, that too, it's in the router's ::1/128
 * "prefix") as the external address from LWS_EXTIP_SRC_ROUTER.
 *
 * With --wrong-key, the host is given the public half of a different key
 * than the router signs with: it must refuse every reply, and nothing may be
 * reported.
 *
 * The test generates the keys itself and writes them into the current dir.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ifaddrs.h>

#define LWS_PLUGIN_STATIC
#include "../../../plugins/protocol_lws_extip_router/protocol_lws_extip_router.c"

enum {
	LWS_SW_PORT,
	LWS_SW_WRONG_KEY,
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_PORT]		= { "-p",		"Router listen port" },
	[LWS_SW_WRONG_KEY]	= { "--wrong-key",	"Give the host a key the router doesn't sign with: expect nothing reported" },
	[LWS_SW_HELP]		= { "--help",		"Show this help information" },
};

/* named for the port, so ctest -j runs of both modes don't collide */
static char key_priv[64], key_pub[64], key_other[64];

static const struct lws_protocols protocols[] = {
	{ "http", lws_callback_http_dummy, 0, 0, 0, NULL, 0 },
	LWS_PLUGIN_PROTOCOL_EXTIP_ROUTER,
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_http_mount mount = {
	.mountpoint		= "/extip",
	.mountpoint_len		= 6,
	.origin			= "lws-extip-router",
	.origin_protocol	= LWSMPRO_CALLBACK,
};

static struct lws_context *context;
static lws_sorted_usec_list_t sul_end;
static int bad = 1, wrong_key, want_v6, got_v4, got_v6, smds;
static char lo_iface[32];

static int
smd_cb(void *opaque, lws_smd_class_t c, lws_usec_t ts, void *buf, size_t len)
{
	const char *s = (const char *)buf;

	if (!(c & LWSSMDCL_NETWORK) || !buf || !strstr(s, "\"ext-ips\""))
		return 0;

	lwsl_user("SMD: %.*s\n", (int)len, s);
	smds++;

	got_v4 = !!strstr(s, "\"127.0.0.1\"");
	got_v6 = !!strstr(s, "\"::1\"");

	if (!wrong_key && got_v4 && (!want_v6 || got_v6)) {
		bad = 0;
		lws_default_loop_exit(context);
	}

	return 0;
}

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(context);
}

static void
end_cb(lws_sorted_usec_list_t *sul)
{
	lws_sockaddr46 sa46;

	if (wrong_key) {
		/* several polls went by: all of them must have been refused */
		if (smds || !lws_extip_get_best(context, AF_INET, &sa46))
			lwsl_err("FAIL: a reply signed by another key was "
				 "taken\n");
		else
			bad = 0;
	} else
		lwsl_err("FAIL: timed out: v4 %d, v6 %d (wanted %d)\n",
			 got_v4, got_v6, want_v6);

	lws_default_loop_exit(context);
}

/* the name of the interface with 127.0.0.1 on it, and if it has ::1 */

static int
find_loopback(void)
{
	struct ifaddrs *ifa, *i;

	if (getifaddrs(&ifa))
		return 1;

	for (i = ifa; i; i = i->ifa_next) {
		if (!i->ifa_addr || !i->ifa_name)
			continue;
		if (i->ifa_addr->sa_family == AF_INET &&
		    ((const struct sockaddr_in *)i->ifa_addr)->sin_addr.s_addr ==
							htonl(INADDR_LOOPBACK))
			lws_strncpy(lo_iface, i->ifa_name, sizeof(lo_iface));
	}

#if defined(LWS_WITH_IPV6)
	for (i = ifa; i && lo_iface[0]; i = i->ifa_next)
		if (i->ifa_addr && i->ifa_name &&
		    i->ifa_addr->sa_family == AF_INET6 &&
		    !strcmp(i->ifa_name, lo_iface) &&
		    !memcmp(((const struct sockaddr_in6 *)
					i->ifa_addr)->sin6_addr.s6_addr,
			    in6addr_loopback.s6_addr,
			    sizeof(in6addr_loopback.s6_addr)))
			want_v6 = 1;
#endif

	freeifaddrs(ifa);

	return !lo_iface[0];
}

static int
write_key(struct lws_jwk *jwk, int flags, const char *path)
{
	char buf[1024];
	int len = sizeof(buf), n, fd;

	n = lws_jwk_export(jwk, flags, buf, &len);
	if (n < 0)
		return 1;

	fd = lws_open(path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
	if (fd < 0)
		return 1;

	if (write(fd, buf, (size_t)n) != (ssize_t)n) {
		close(fd);
		return 1;
	}

	close(fd);

	return 0;
}

static int
make_keys(void)
{
	struct lws_jwk router, other;
	int r = 1;

	memset(&router, 0, sizeof(router));
	memset(&other, 0, sizeof(other));

	if (lws_jwk_generate(context, &router, LWS_GENCRYPTO_KTY_EC, 0,
			     "P-256") ||
	    lws_jwk_generate(context, &other, LWS_GENCRYPTO_KTY_EC, 0,
			     "P-256"))
		goto bail;

	if (write_key(&router, LWSJWKF_EXPORT_PRIVATE, key_priv) ||
	    write_key(&router, 0, key_pub) ||
	    write_key(&other, 0, key_other))
		goto bail;

	r = 0;

bail:
	lws_jwk_destroy(&router);
	lws_jwk_destroy(&other);

	return r;
}

int
main(int argc, const char **argv)
{
	struct lws_protocol_vhost_options rpvo[3], rp, hpvo[3], hp;
	struct lws_context_creation_info info;
	char url[128];
	const char *p;
	int port = 7681;

	signal(SIGINT, sigint_handler);

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches,
					LWS_ARRAY_SIZE(switches));
		return 0;
	}

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_PORT].sw)))
		port = atoi(p);
	wrong_key = !!lws_cmdline_option(argc, argv,
					 switches[LWS_SW_WRONG_KEY].sw);

	lws_snprintf(key_priv, sizeof(key_priv), "extip-router-%d-priv.jwk",
		     port);
	lws_snprintf(key_pub, sizeof(key_pub), "extip-router-%d-pub.jwk", port);
	lws_snprintf(key_other, sizeof(key_other),
		     "extip-router-%d-other-pub.jwk", port);

	lwsl_user("LWS API selftest: extip router%s\n",
		  wrong_key ? " (wrong key)" : "");

	if (find_loopback()) {
		lwsl_err("can't find the loopback interface\n");
		return 1;
	}

	info.options			|= LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
	info.early_smd_cb		= smd_cb;
	info.early_smd_class_filter	= LWSSMDCL_NETWORK;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	if (make_keys()) {
		lwsl_err("key generation failed\n");
		goto bail;
	}

	/* the router: signs what's on the loopback interface */

	memset(rpvo, 0, sizeof(rpvo));
	rpvo[0].name	= "jwk-private";
	rpvo[0].value	= key_priv;
	rpvo[0].next	= &rpvo[1];
	rpvo[1].name	= "v4-iface";
	rpvo[1].value	= lo_iface;
	rpvo[1].next	= &rpvo[2];
	rpvo[2].name	= "v6-iface";
	rpvo[2].value	= lo_iface;

	memset(&rp, 0, sizeof(rp));
	rp.name		= "lws-extip-router";
	rp.value	= "";
	rp.options	= rpvo;

	info.vhost_name		= "router";
	info.port		= port;
	info.protocols		= protocols;
	info.mounts		= &mount;
	info.pvo		= &rp;

	if (!lws_create_vhost(context, &info)) {
		lwsl_err("router vhost failed\n");
		goto bail;
	}

	/* the host: asks the router */

	lws_snprintf(url, sizeof(url), "http://127.0.0.1:%d/extip", port);

	memset(hpvo, 0, sizeof(hpvo));
	hpvo[0].name	= "router-url";
	hpvo[0].value	= url;
	hpvo[0].next	= &hpvo[1];
	hpvo[1].name	= "jwk-public";
	hpvo[1].value	= wrong_key ? key_other : key_pub;
	hpvo[1].next	= &hpvo[2];
	hpvo[2].name	= "interval-secs";
	hpvo[2].value	= "1";

	memset(&hp, 0, sizeof(hp));
	hp.name		= "lws-extip-router";
	hp.value	= "";
	hp.options	= hpvo;

	info.vhost_name		= "host";
	info.port		= CONTEXT_PORT_NO_LISTEN;
	info.mounts		= NULL;
	info.pvo		= &hp;

	if (!lws_create_vhost(context, &info)) {
		lwsl_err("host vhost failed\n");
		goto bail;
	}

	/*
	 * The host polls at once, then every second: in the wrong-key case,
	 * give it a few refusals; otherwise this is only the backstop
	 */

	lws_sul_schedule(context, 0, &sul_end, end_cb, (wrong_key ? 4 : 10) *
							LWS_US_PER_SEC);

	while (lws_service(context, 0) >= 0)
		;

bail:
	lws_sul_cancel(&sul_end);
	lws_context_destroy(context);

	lwsl_user("Completed: %s\n", bad ? "FAIL" : "PASS");

	return lws_cmdline_passfail(argc, argv, bad);
}
