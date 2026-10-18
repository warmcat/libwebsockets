/*
 * lws-api-test-dnssec-monitor-geo-dl
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 * Note: CC0 1.0 Universal Public Domain Dedication
 *
 * Fences G-043 in the dnssec-monitor plugin's geo CSV downloader
 * (monitor-geo.c): inv_geo_dl_create() hands its download state to
 * lws_client_connect_via_info() as the opaque, and the plugin's
 * CLIENT_CONNECTION_ERROR handler destroys it with inv_geo_dl_fail().  But
 * the connect can fail synchronously, eg, on an NXDOMAIN the async dns
 * cache already holds, delivering that CCE before it returns NULL; the
 * downloader then destroyed the state a second time on its own error path
 * (double free, and a close() of an fd number that was already closed).
 *
 * A fake nameserver on loopback, adopted into the event loop, answers every
 * query NXDOMAIN.  The test drives the downloader the way the plugin does,
 * with a protocol whose client callbacks do what the plugin's do for the
 * downloader's opaque, and runs GEODL_TRIES downloads one after the other.
 * Each must end exactly one of two ways:
 *
 *  - the CCE came inside the connect call: the create reports failure, and
 *    the state was destroyed exactly once (ASan sees a second destroy);
 *
 *  - the connect returned with the lookup pending: the create returns the
 *    download, and the asynchronous CCE that follows destroys it;
 *
 * and neither leaves its temp file behind.  The first lookup always goes to
 * the wire.  Later ones are answered inside the connect when the resolver
 * serves the NXDOMAIN from its cache; at the time of writing lws' async dns
 * caches the NXDOMAIN but does not serve A / AAAA lookups from a negative
 * entry, so they go to the wire too and the test reports which path each
 * took.  The plugin is only built with async dns, so the blocking
 * resolver's synchronous NXDOMAIN CCE does not apply to it.
 *
 * The test runs under ctest, which gives the fake nameserver's port in
 * LWS_ASYNCDNS_PORT, the port the resolver asks its nameservers on.  To run
 * it by hand, set that to any free udp port.
 */

#include <libwebsockets.h>

#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

#include "private.h"

#define GEODL_BASE_DIR		"./geo-dl-base"
#define GEODL_WATCHDOG_S	10
#define GEODL_TRIES		3

static struct lws_context *cx;
static lws_sorted_usec_list_t sul_watchdog, sul_step;
static struct vhd vhd;
static int fails, queries, cces, cces_in_call, in_call, step;

static void
step_cb(lws_sorted_usec_list_t *sul);

static int
expect(int cond, const char *what)
{
	if (cond) {
		lwsl_user("  ok: %s\n", what);
		return 0;
	}

	lwsl_err("FAIL: %s\n", what);

	return 1;
}

/*
 * The fake nameserver: whatever the question, the name does not exist
 */

static int
callback_fake_ns(struct lws *wsi, enum lws_callback_reasons reason,
		 void *user, void *in, size_t len)
{
	const uint8_t *q = (const uint8_t *)in;
	uint8_t resp[512];
	lws_sockfd_type fd;
	size_t o = 12;
	ssize_t n;

	if (reason != LWS_CALLBACK_RAW_RX)
		return 0;

	/* walk the query's qname, which has no compression pointers */

	if (len < 12 || len > sizeof(resp))
		return 0;
	while (o < len && q[o]) {
		if (q[o] > 63)
			return 0;
		o += (size_t)q[o] + 1;
	}
	if (o + 5 > len)
		return 0;
	o += 5; /* the question section ends after QTYPE + QCLASS */

	memcpy(resp, q, o);
	resp[2] = 0x81;			/* QR + RD */
	resp[3] = 0x83;			/* RA, rcode NXDOMAIN */
	resp[6] = 0; resp[7] = 0;	/* ANCOUNT */
	resp[8] = 0; resp[9] = 0;	/* NSCOUNT */
	resp[10] = 0; resp[11] = 0;	/* ARCOUNT */

	queries++;

	fd = lws_get_socket_fd(wsi);
	if (fd == LWS_SOCK_INVALID) {
		lwsl_err("%s: no socket to answer on\n", __func__);
		return 0;
	}
	n = sendto(fd,
#if defined(WIN32)
		   (const char *)
#endif
		   resp,
#if defined(WIN32)
		   (int)
#endif
		   o, 0, sa46_sockaddr(&lws_get_udp(wsi)->sa46),
		   sa46_socklen(&lws_get_udp(wsi)->sa46));
	if (n < (ssize_t)o)
		lwsl_err("%s: answer send failed\n", __func__);

	return 0;
}

/*
 * What the monitor plugin's callback does with the downloader's opaque on
 * the ways a client connection can end before it has a response
 */

static int
callback_monitor(struct lws *wsi, enum lws_callback_reasons reason,
		 void *user, void *in, size_t len)
{
	struct inv_geo_dl *g = (struct inv_geo_dl *)lws_get_opaque_user_data(wsi);

	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		if (!g || g->magic != INV_GEO_DL_MAGIC)
			break;
		lwsl_user("%s: CCE (%s): %s\n", __func__,
			  in_call ? "inside the connect" : "async",
			  in ? (const char *)in : "?");
		cces++;
		if (in_call)
			cces_in_call++;
		inv_geo_dl_fail(g);
		lws_set_opaque_user_data(wsi, NULL);
		lws_sul_schedule(cx, 0, &sul_step, step_cb, 1);
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		if (!g || g->magic != INV_GEO_DL_MAGIC)
			break;
		inv_geo_dl_fail(g);
		lws_set_opaque_user_data(wsi, NULL);
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols[] = {
	{ "fake-ns", callback_fake_ns, 0, 0, 0, NULL, 0 },
	{ "lws-dht-dnssec-monitor", callback_monitor, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static int
tmp_file_exists(int is_v6)
{
	char path[512];
	struct stat st;

	lws_snprintf(path, sizeof(path), GEODL_BASE_DIR "/geo/%s.tmp",
		     is_v6 ? "dbip-country-ipv6-cidr.csv" :
			     "dbip-country-ipv4-cidr.csv");

	return !stat(path, &st);
}

/*
 * One download per step.  A download whose CCE came inside the connect is
 * over when the create returns; one whose connect is pending is over when
 * its CCE schedules the next step.
 */

static void
step_cb(lws_sorted_usec_list_t *sul)
{
	int in_call_before;

	(void)sul;

	if (step) {
		/* the previous download is over, however it went */
		fails += expect(cces == step && !vhd.geo.dl4,
				"download failed and was destroyed");
		fails += expect(!tmp_file_exists(0), "no temp file left");
	}

	if (step == GEODL_TRIES || fails) {
		step = GEODL_TRIES + 1;
		lws_default_loop_exit(cx);
		return;
	}

	lwsl_user("%s: download %d\n", __func__, step + 1);
	step++;

	in_call_before = cces_in_call;
	in_call = 1;
	vhd.geo.dl4 = inv_geo_dl_create(&vhd, 0);
	in_call = 0;

	if (cces_in_call != in_call_before) {
		lwsl_user("%s: CCE came inside the connect\n", __func__);
		fails += expect(!vhd.geo.dl4,
				"CCE inside the connect: create failed");
		/* the CCE already scheduled the next step */
		return;
	}

	fails += expect(!!vhd.geo.dl4, "connect pending: create returned it");
	if (!vhd.geo.dl4)
		lws_default_loop_exit(cx);
	/* its CCE schedules the next step */
}

static void
sul_watchdog_cb(lws_sorted_usec_list_t *sul)
{
	(void)sul;
	lwsl_err("%s: timed out\n", __func__);
	fails++;
	lws_default_loop_exit(cx);
}

static void
sigint_handler(int sig)
{
	(void)sig;
	lws_default_loop_exit(cx);
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p = getenv("LWS_ASYNCDNS_PORT");
	lws_sockaddr46 sa46;
	int ns_port, n;

	signal(SIGINT, sigint_handler);

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	lwsl_user("LWS API selftest: dnssec-monitor geo download, "
		  "synchronous connect failure\n");

	ns_port = p ? atoi(p) : 0;
	if (ns_port <= 0 || ns_port > 65535) {
		lwsl_err("Set LWS_ASYNCDNS_PORT to a free udp port\n");

		return 1;
	}

	lws_dir(GEODL_BASE_DIR, NULL, lws_dir_rm_rf_cb);
	rmdir(GEODL_BASE_DIR);
	if (mkdir(GEODL_BASE_DIR, 0700)) {
		lwsl_err("Unable to create " GEODL_BASE_DIR ": %d\n", errno);

		return 1;
	}

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");

		return 1;
	}

	/* only our fake nameserver may be asked */

	n = 0;
	while (!lws_plat_asyncdns_get_server(cx, n++, &sa46))
		lws_async_dns_server_remove(cx, &sa46);
	memset(&sa46, 0, sizeof(sa46));
	if (lws_sa46_parse_numeric_address("127.0.0.1", &sa46) ||
	    !lws_async_dns_server_add(cx, &sa46)) {
		lwsl_err("Unable to pin the fake nameserver\n");
		fails++;
		goto bail;
	}

	info.protocols = protocols;
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.vhost_name = "geo-dl";
	vhd.vhost = lws_create_vhost(cx, &info);
	if (!vhd.vhost) {
		lwsl_err("Failed to create vhost\n");
		fails++;
		goto bail;
	}

	if (!lws_create_adopt_udp(vhd.vhost, "127.0.0.1", ns_port,
				  LWS_CAUDP_BIND, "fake-ns", NULL, NULL, NULL,
				  NULL, "fake-ns")) {
		lwsl_err("Unable to bind the fake nameserver on %d\n",
			 ns_port);
		fails++;
		goto bail;
	}

	vhd.context = cx;
	vhd.base_dir = GEODL_BASE_DIR;

	lws_sul_schedule(cx, 0, &sul_watchdog, sul_watchdog_cb,
			 GEODL_WATCHDOG_S * LWS_US_PER_SEC);
	lws_sul_schedule(cx, 0, &sul_step, step_cb, 1);

	while (lws_service(cx, 0) >= 0 && step <= GEODL_TRIES && !fails)
		;

	lws_sul_cancel(&sul_watchdog);
	lws_sul_cancel(&sul_step);

	fails += expect(step == GEODL_TRIES + 1, "every download was tried");
	lwsl_user("%d of %d CCEs came inside the connect\n", cces_in_call,
		  cces);
	fails += expect(queries > 0, "the fake nameserver was asked");

bail:
	lws_context_destroy(cx);

	lws_dir(GEODL_BASE_DIR, NULL, lws_dir_rm_rf_cb);
	rmdir(GEODL_BASE_DIR);

	lwsl_user("Completed: %s\n", fails ? "FAIL" : "PASS");

	return !!fails;
}
