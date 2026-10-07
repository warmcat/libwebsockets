/*
 * lws-api-test-adns-direct
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * lws_async_dns_query_direct() asks one particular server, here the auth
 * dns plugin serving a small zone on loopback in the same context, and
 * reports exactly what it said:
 *
 *  - a TXT record that exists comes back with its RDATA and the AA bit
 *  - a name with two TXT records gives both
 *  - a name that exists without the asked type is found, with no records
 *  - a name that doesn't exist is NXDOMAIN
 *  - an A record comes back as its four address bytes
 *  - a server that never answers times out
 *  - a port with nothing on it fails at once, as the ICMP refusal arrives
 *  - a cancelled query never calls back
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

#define ZDIR		"adns-direct-zones"
#define ORIGIN		"direct.example"
/* decorated filename fields: far-future ttl / sig expiry, serial 1 */
#define ZFILE		ORIGIN "_2000000000_2000000000_1.zone"

extern const struct lws_protocols lws_auth_dns_protocols[];

static struct lws_context *context;
static lws_sorted_usec_list_t sul_start, sul_deadline;
static lws_sockaddr46 sa_srv, sa_dead, sa_refused;
static struct lws_adns_direct *cancelled;
static int fails, outstanding;

struct dq {
	const char		*what;
	const char		*name;
	adns_query_type_t	qtype;
	int			dead;	/* 1: a port that never answers,
					 * 2: a port nothing is bound to */
	lws_async_dns_retcode_t	ret;
	int			count;
	const char		*rdata;	/* NULL: don't check */
	size_t			rdata_len;
	int			done;
};

static struct dq qs[] = {
	{ "TXT that exists", "_acme-challenge." ORIGIN, LWS_ADNS_RECORD_TXT,
	  0, LADNS_RET_FOUND, 1, "\x0chello-direct", 13, 0 },
	{ "two TXT", "two." ORIGIN, LWS_ADNS_RECORD_TXT,
	  0, LADNS_RET_FOUND, 2, NULL, 0, 0 },
	{ "no TXT at that name", "www." ORIGIN, LWS_ADNS_RECORD_TXT,
	  0, LADNS_RET_FOUND, 0, NULL, 0, 0 },
	{ "no such name", "nope." ORIGIN, LWS_ADNS_RECORD_TXT,
	  0, LADNS_RET_NXDOMAIN, 0, NULL, 0, 0 },
	{ "A record", "www." ORIGIN, LWS_ADNS_RECORD_A,
	  0, LADNS_RET_FOUND, 1, "\x7f\x00\x00\x4d", 4, 0 },
	{ "nobody answers", "_acme-challenge." ORIGIN, LWS_ADNS_RECORD_TXT,
	  1, LADNS_RET_TIMEDOUT, 0, NULL, 0, 0 },
	{ "port refused", "_acme-challenge." ORIGIN, LWS_ADNS_RECORD_TXT,
	  2, LADNS_RET_FAILED, 0, NULL, 0, 0 },
};

static void
direct_cb(void *opaque, const lws_adns_direct_result_t *r)
{
	struct dq *q = (struct dq *)opaque;
	int ok = 1;

	if (q == NULL) {
		lwsl_err("%s: FAILED: the cancelled query called back\n",
			 __func__);
		fails++;
		return;
	}

	q->done = 1;
	outstanding--;

	if (r->ret != q->ret || r->count != q->count)
		ok = 0;
	if (ok && r->ret != LADNS_RET_TIMEDOUT && r->ret != LADNS_RET_FAILED &&
	    !r->authoritative)
		ok = 0;
	if (ok && q->rdata && (r->rrs[0].type != (uint16_t)q->qtype ||
			       r->rrs[0].len != q->rdata_len ||
			       memcmp(r->rrs[0].rdata, q->rdata, q->rdata_len)))
		ok = 0;

	if (ok)
		lwsl_user("%s: ok: %s\n", __func__, q->what);
	else {
		lwsl_err("%s: FAILED: %s (ret %d rcode %d aa %d count %d)\n",
			 __func__, q->what, r->ret, r->rcode, r->authoritative,
			 r->count);
		fails++;
	}

	if (!outstanding)
		lws_default_loop_exit(context);
}

static void
start_cb(lws_sorted_usec_list_t *sul)
{
	size_t n;

	for (n = 0; n < LWS_ARRAY_SIZE(qs); n++) {
		if (!lws_async_dns_query_direct(context,
				qs[n].dead == 1 ? &sa_dead :
				(qs[n].dead == 2 ? &sa_refused : &sa_srv),
				qs[n].name,
				qs[n].qtype, direct_cb, &qs[n])) {
			lwsl_err("%s: FAILED: couldn't start %s\n", __func__,
				 qs[n].what);
			fails++;
			continue;
		}
		outstanding++;
	}

	/* its callback would see a NULL opaque */
	cancelled = lws_async_dns_query_direct(context, &sa_srv,
				"_acme-challenge." ORIGIN, LWS_ADNS_RECORD_TXT,
				direct_cb, NULL);
	if (!cancelled) {
		lwsl_err("%s: FAILED: couldn't start the one to cancel\n",
			 __func__);
		fails++;
	}
	lws_async_dns_query_direct_cancel(&cancelled);
	if (cancelled) {
		lwsl_err("%s: FAILED: cancel left the handle\n", __func__);
		fails++;
	}

	if (!outstanding)
		lws_default_loop_exit(context);
}

static void
deadline_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("%s: FAILED: not every query called back\n", __func__);
	fails++;
	lws_default_loop_exit(context);
}

static int
write_zone(void)
{
	static const char z[] =
		"$ORIGIN " ORIGIN ".\n"
		"$TTL 3600\n"
		"@	IN	SOA	ns1." ORIGIN ". hostmaster." ORIGIN ". (\n"
		"			2026100501 ; serial\n"
		"			3600 1800 604800 60 )\n"
		"@	IN	NS	ns1." ORIGIN ".\n"
		"ns1	IN	A	127.0.0.77\n"
		"www	IN	A	127.0.0.77\n"
		"_acme-challenge	IN	TXT	\"hello-direct\"\n"
		"two	IN	TXT	\"one\"\n"
		"two	IN	TXT	\"two\"\n";
	int fd;

	/* auth_dns refuses zones others can write: keep them owner-only */
	if ((mkdir(ZDIR, 0700) && errno != EEXIST) || chmod(ZDIR, 0700))
		return 1;

	fd = open(ZDIR "/" ZFILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		return 1;
	if (write(fd, z, sizeof(z) - 1) != (ssize_t)(sizeof(z) - 1)) {
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
	    port_dead = port_arg(argc, argv, "--port-dead"),
	    port_refused = port_arg(argc, argv, "--port-refused"), sink, r = 1;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	lwsl_user("LWS API selftest: async dns direct queries\n");

	if (!port || !port_dead || !port_refused) {
		lwsl_err("%s: -p, --port-dead and --port-refused <port> are "
			 "required\n", __func__);
		return 1;
	}

	if (write_zone()) {
		lwsl_err("%s: unable to write the zone\n", __func__);
		return 1;
	}

	memset(&sa_srv, 0, sizeof(sa_srv));
	sa_srv.sa4.sin_family = AF_INET;
	sa_srv.sa4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sa_srv.sa4.sin_port = htons((uint16_t)port);
	sa_dead = sa_srv;
	sa_dead.sa4.sin_port = htons((uint16_t)port_dead);
	sa_refused = sa_srv;
	sa_refused.sa4.sin_port = htons((uint16_t)port_refused);

	/* a server that takes the questions and never answers them */
	sink = socket(AF_INET, SOCK_DGRAM, 0);
	if (sink < 0 || bind(sink, (struct sockaddr *)&sa_dead.sa4,
			     sizeof(sa_dead.sa4))) {
		lwsl_err("%s: unable to bind the silent server\n", __func__);
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

	/* give the server's listeners a moment */
	lws_sul_schedule(context, 0, &sul_start, start_cb,
			 200 * LWS_US_PER_MS);
	lws_sul_schedule(context, 0, &sul_deadline, deadline_cb,
			 25 * LWS_US_PER_SEC);

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
