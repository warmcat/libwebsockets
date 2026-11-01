/*
 * lws-api-test-async-dns-faults
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * How async dns copes with nameservers that misbehave: fake nameservers on
 * loopback, adopted into the event loop, answer each name in a different bad
 * way, and we check what the lookups, and a client connection, make of it.
 *
 * The first pass has the nameservers misbehave in what they answer:
 *
 *  - "ok.test": answered properly, but the first nameserver listed never
 *    answers anything (on Linux, where all of 127.0.0.0/8 is loopback and we
 *    can put a black hole at 127.0.0.2).  We know nothing about either server
 *    yet, so the question has to be raced to both and the second one's answer
 *    taken at once, not after the first one's retransmits ran out.
 *
 *  - "servfail-aaaa.test": A is answered, AAAA gets SERVFAIL, as some home
 *    routers and DNS64 setups do.  The A answer stands.
 *
 *  - "servfail-late-a.test": the same, but the SERVFAIL comes first and the A
 *    answer a little later.
 *
 *  - "drop-aaaa.test": A is answered, AAAA questions are silently dropped.
 *    The A answer stands once the AAAA retransmits run out.
 *
 *  - "servfail.test": both halves get SERVFAIL: the lookup fails, quickly.
 *
 *  - "dead.test", from an http client connection: nobody ever answers.  The
 *    connection has to fail when the query's retransmits run out, saying it
 *    timed out, not after asking again from the top several times over.
 *
 * Every other name (eg, a search list candidate) is NXDOMAIN.
 *
 * The second pass, on Linux, has the first nameservers listed be ones we
 * can't ask at all: 255.255.255.255, which a socket can't connect() to
 * without SO_BROADCAST, and 127.0.0.3, where nothing listens, so it refuses
 * what we send it.  "ok.test" still has to be answered at once by the one
 * that works, and so does "servfail-aaaa.test" asked once we have learned
 * that much.
 *
 * The test runs under ctest, which gives the fake nameservers' port in
 * LWS_ASYNCDNS_PORT, the port the resolver asks its nameservers on, and the
 * resolv.conf we write in LWS_ASYNCDNS_RESOLV_CONF, so the platform's own
 * nameservers are not asked.  To run it by hand, set the port to any free udp
 * port, and the resolv.conf to a scratch file name.
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#if !defined(WIN32)
#include <fcntl.h>
#include <unistd.h>
#endif

#define WATCHDOG_S		25

/* what the live nameserver does with each name */

enum {
	ANS_ANSWER,		/* answer it */
	ANS_SERVFAIL,		/* SERVFAIL at once */
	ANS_LATE,		/* answer it, after a while */
	ANS_DROP,		/* never answer */
};

static const struct fake_name {
	const char		*name;
	uint8_t			a, aaaa;	/* ANS_* for each type */
	uint8_t			v4[4];
} fake_names[] = {
	{ "ok.test",		  ANS_ANSWER,	ANS_ANSWER,   { 192, 0, 2, 1 } },
	{ "servfail-aaaa.test",	  ANS_ANSWER,	ANS_SERVFAIL, { 192, 0, 2, 2 } },
	{ "servfail-late-a.test", ANS_LATE,	ANS_SERVFAIL, { 192, 0, 2, 3 } },
	{ "drop-aaaa.test",	  ANS_ANSWER,	ANS_DROP,     { 192, 0, 2, 4 } },
	{ "servfail.test",	  ANS_SERVFAIL,	ANS_SERVFAIL, { 0, 0, 0, 0 } },
	{ "dead.test",		  ANS_DROP,	ANS_DROP,     { 0, 0, 0, 0 } },
};

static const uint8_t v6_ok[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
				   0, 0, 0, 0, 0, 0, 0, 1 };

/* what we expect of each lookup */

struct leg {
	const char		*name;
	int			fake;		/* index into fake_names */
	int			found;		/* expect it found, else failed */
	int			client;		/* by a client connection */
	int			wave;		/* asked when earlier waves end */
	int			within_ms;	/* it must be over by then */

	int			started;
	int			done;
	int			ret;
	lws_usec_t		t_start;
	lws_usec_t		took;
};

/* a nameserver, and for the ones we fake, its adopted udp socket */

enum {
	NS_LIVE,		/* answers as fake_names says */
	NS_DEAD,		/* takes everything and never answers */
	NS_UNREACH,		/* nothing of ours is there */
};

struct fake_ns {
	const char		*ads;
	int			kind;
	int			asked;
};

static struct leg legs_answers[] = {
	{ "dead first nameserver",	0, 1, 0, 0,  1500, 0, 0, 0, 0, 0 },
	{ "SERVFAIL on AAAA",		1, 1, 0, 0,  1500, 0, 0, 0, 0, 0 },
	{ "SERVFAIL on AAAA, A later",	2, 1, 0, 0,  1500, 0, 0, 0, 0, 0 },
	{ "AAAA dropped",		3, 1, 0, 0, 15000, 0, 0, 0, 0, 0 },
	{ "SERVFAIL on both",		4, 0, 0, 0,  3000, 0, 0, 0, 0, 0 },
	{ "nobody answers (client)",	5, 0, 1, 0, 15000, 0, 0, 0, 0, 0 },
};

static struct fake_ns nss_answers[] = {
#if defined(__linux__)
	{ "127.0.0.2",		NS_DEAD,	0 },
#endif
	{ "127.0.0.1",		NS_LIVE,	0 },
};

#if defined(__linux__)
static struct leg legs_unreach[] = {
	{ "unreachable first nameservers", 0, 1, 0, 0, 1500, 0, 0, 0, 0, 0 },
	{ "... and asked again",	1, 1, 0, 1, 1500, 0, 0, 0, 0, 0 },
};

static struct fake_ns nss_unreach[] = {
	{ "255.255.255.255",	NS_UNREACH,	0 },
	{ "127.0.0.3",		NS_UNREACH,	0 },
	{ "127.0.0.1",		NS_LIVE,	0 },
};
#endif

static const struct pass {
	const char		*name;
	struct leg		*legs;
	size_t			nlegs;
	struct fake_ns		*nss;
	size_t			nnss;
} passes[] = {
	{ "misbehaving answers", legs_answers, LWS_ARRAY_SIZE(legs_answers),
	  nss_answers, LWS_ARRAY_SIZE(nss_answers) },
#if defined(__linux__)
	{ "unreachable nameservers", legs_unreach, LWS_ARRAY_SIZE(legs_unreach),
	  nss_unreach, LWS_ARRAY_SIZE(nss_unreach) },
#endif
};

/* an answer held back for ANS_LATE */

static struct late {
	lws_sorted_usec_list_t	sul;
	struct lws		*wsi;
	lws_sockaddr46		peer;
	size_t			len;
	uint8_t			pkt[512];
} late;

static const struct pass *pass;
static struct lws_context *cx;
static struct lws_vhost *vh;
static lws_sorted_usec_list_t sul_watchdog;
static int fails;

static struct lws *
lookup_cb(struct lws *wsi, const char *ads, const struct addrinfo *result,
	  int n, void *opaque);

static void
leg_start(struct leg *leg)
{
	const char *name = fake_names[leg->fake].name;
	struct lws_client_connect_info i;

	lwsl_user("%s: looking up %s\n", leg->name, name);
	leg->started = 1;
	leg->t_start = lws_now_usecs();

	if (!leg->client) {
		if (lws_async_dns_query(cx, 0, name, LWS_ADNS_RECORD_A,
					lookup_cb, NULL, leg, NULL) ==
							LADNS_RET_FAILED) {
			lwsl_err("%s: query refused\n", leg->name);
			fails++;
			leg->done = 1;
		}

		return;
	}

	memset(&i, 0, sizeof(i));
	i.context		= cx;
	i.vhost			= vh;
	i.address		= name;
	i.host			= name;
	i.origin		= name;
	i.port			= 80;
	i.path			= "/";
	i.method		= "GET";
	i.protocol		= "cli";
	i.local_protocol_name	= "cli";
	i.opaque_user_data	= leg;

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("%s: refused\n", leg->name);
		fails++;
		leg->done = 1;
	}
}

/* start the next wave when the last one has ended, or end the pass */

static void
check_done(void)
{
	int wave = -1;
	size_t n;

	for (n = 0; n < pass->nlegs; n++)
		if (pass->legs[n].started && !pass->legs[n].done)
			return;

	for (n = 0; n < pass->nlegs; n++)
		if (!pass->legs[n].started &&
		    (wave < 0 || pass->legs[n].wave < wave))
			wave = pass->legs[n].wave;

	if (wave < 0) {
		lws_default_loop_exit(cx);
		return;
	}

	for (n = 0; n < pass->nlegs; n++)
		if (!pass->legs[n].started && pass->legs[n].wave == wave)
			leg_start(&pass->legs[n]);

	/* they may all have finished, or been refused, at once */
	check_done();
}

static void
leg_done(struct leg *leg, int ret)
{
	if (leg->done)
		return;

	leg->done = 1;
	leg->ret = ret;
	leg->took = lws_now_usecs() - leg->t_start;

	lwsl_user("%s: %s: ret %d after %dms\n", __func__, leg->name, ret,
		  (int)(leg->took / LWS_US_PER_MS));
	check_done();
}

static void
fake_send(struct lws *wsi, const lws_sockaddr46 *peer, const uint8_t *pkt,
	  size_t len)
{
	lws_sockfd_type fd = lws_get_socket_fd(wsi);
	ssize_t n;

	if (fd == LWS_SOCK_INVALID) {
		lwsl_err("%s: no socket to answer on\n", __func__);
		return;
	}

	n = sendto(fd,
#if defined(WIN32)
		   (const char *)
#endif
		   pkt,
#if defined(WIN32)
		   (int)
#endif
		   len, 0, sa46_sockaddr(peer), sa46_socklen(peer));
	if (n < (ssize_t)len)
		lwsl_err("%s: answer send failed\n", __func__);
}

static void
sul_late_cb(lws_sorted_usec_list_t *sul)
{
	(void)sul;
	fake_send(late.wsi, &late.peer, late.pkt, late.len);
}

/*
 * The fake nameservers: the dead one drops everything, the live one does
 * what fake_names says
 */

static int
callback_fake_ns(struct lws *wsi, enum lws_callback_reasons reason,
		 void *user, void *in, size_t len)
{
	struct fake_ns *ns = (struct fake_ns *)lws_get_opaque_user_data(wsi);
	const uint8_t *q = (const uint8_t *)in;
	const struct fake_name *fn = NULL;
	char name[64];
	uint8_t resp[512];
	size_t o = 12, nl = 0, n;
	uint16_t qtype;
	int how;

	if (reason != LWS_CALLBACK_RAW_RX || !ns)
		return 0;

	ns->asked++;
	if (ns->kind != NS_LIVE)
		return 0;

	/* walk the query's qname, which has no compression pointers */

	if (len < 12 || len > sizeof(resp) - 28)
		return 0;
	while (o < len && q[o]) {
		if (q[o] > 63 || o + 1 + q[o] >= len ||
		    nl + q[o] + 2 > sizeof(name))
			return 0;
		if (nl)
			name[nl++] = '.';
		memcpy(name + nl, q + o + 1, q[o]);
		nl += q[o];
		o += (size_t)q[o] + 1;
	}
	name[nl] = '\0';
	if (o + 5 > len)
		return 0;
	qtype = (uint16_t)((q[o + 1] << 8) | q[o + 2]);
	o += 5; /* the question section ends after QTYPE + QCLASS */

	for (n = 0; n < LWS_ARRAY_SIZE(fake_names); n++)
		if (!strcmp(name, fake_names[n].name))
			fn = &fake_names[n];

	memcpy(resp, q, o);
	resp[2] = 0x81;			/* QR + RD */
	resp[3] = 0x80;			/* RA, rcode NOERROR */
	memset(&resp[6], 0, 6);		/* no answer, authority, additional */

	if (!fn) {
		resp[3] = 0x83;		/* NXDOMAIN */
		fake_send(wsi, &lws_get_udp(wsi)->sa46, resp, o);

		return 0;
	}

	how = qtype == LWS_ADNS_RECORD_AAAA ? fn->aaaa : fn->a;

	switch (how) {
	case ANS_DROP:
		return 0;
	case ANS_SERVFAIL:
		resp[3] = 0x82;
		fake_send(wsi, &lws_get_udp(wsi)->sa46, resp, o);
		return 0;
	default:
		break;
	}

	/* one answer: a pointer to the qname, type, class, ttl, rdata */

	if (qtype != LWS_ADNS_RECORD_A && qtype != LWS_ADNS_RECORD_AAAA) {
		/* NODATA */
		fake_send(wsi, &lws_get_udp(wsi)->sa46, resp, o);
		return 0;
	}

	resp[7] = 1;
	resp[o++] = 0xc0;
	resp[o++] = 12;
	resp[o++] = 0;
	resp[o++] = (uint8_t)qtype;
	resp[o++] = 0;
	resp[o++] = 1;			/* IN */
	resp[o++] = 0;
	resp[o++] = 0;
	resp[o++] = 0;
	resp[o++] = 60;			/* ttl */
	resp[o++] = 0;
	if (qtype == LWS_ADNS_RECORD_A) {
		resp[o++] = 4;
		memcpy(&resp[o], fn->v4, 4);
		o += 4;
	} else {
		resp[o++] = 16;
		memcpy(&resp[o], v6_ok, 16);
		o += 16;
	}

	if (how == ANS_LATE) {
		/* after the other half's SERVFAIL, but before a retransmit */
		late.wsi = wsi;
		late.peer = lws_get_udp(wsi)->sa46;
		late.len = o;
		memcpy(late.pkt, resp, o);
		lws_sul_schedule(cx, 0, &late.sul, sul_late_cb,
				 150 * LWS_US_PER_MS);

		return 0;
	}

	fake_send(wsi, &lws_get_udp(wsi)->sa46, resp, o);

	return 0;
}

/* the lookups: found, with the address we gave it, or failed */

static struct lws *
lookup_cb(struct lws *wsi, const char *ads, const struct addrinfo *result,
	  int n, void *opaque)
{
	struct leg *leg = (struct leg *)opaque;
	const struct fake_name *fn = &fake_names[leg->fake];
	const struct addrinfo *ai;
	int seen = 0;

	(void)wsi;
	(void)ads;

	if (n >= 0)
		n &= ~LWS_ADNS_DNSSEC_VALID;

	for (ai = result; ai; ai = ai->ai_next)
		if (ai->ai_family == AF_INET &&
		    !memcmp(&((const struct sockaddr_in *)ai->ai_addr)->
						sin_addr, fn->v4, 4))
			seen = 1;

	if (n == LADNS_RET_FOUND && leg->found && !seen) {
		lwsl_err("%s: %s: found, but not %u.%u.%u.%u\n", __func__,
			 leg->name, fn->v4[0], fn->v4[1], fn->v4[2],
			 fn->v4[3]);
		fails++;
	}

	if (result)
		lws_async_dns_freeaddrinfo(&result);

	leg_done(leg, n);

	return NULL;
}

/* the client connection: it must fail, saying the lookup timed out */

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	struct leg *leg = (struct leg *)lws_get_opaque_user_data(wsi);

	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		if (!leg || leg->done)
			break;
		lwsl_user("%s: %s: %s\n", __func__, leg->name,
			  in ? (const char *)in : "(null)");
		if (!in || !strstr((const char *)in, "timed out")) {
			lwsl_err("%s: %s: not a dns timeout\n", __func__,
				 leg->name);
			fails++;
		}
		leg_done(leg, LADNS_RET_TIMEDOUT);
		break;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		if (!leg || leg->done)
			break;
		lwsl_err("%s: %s: connected\n", __func__, leg->name);
		fails++;
		leg_done(leg, LADNS_RET_FOUND);

		return -1;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols[] = {
	{ "fake-ns", callback_fake_ns, 0, 0, 0, NULL, 0 },
	{ "cli", callback_cli, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

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

#if !defined(WIN32)
/* the platform's nameservers are ours, so a reload doesn't ask others */
static int
write_resolv_conf(const char *path)
{
	char buf[256];
	size_t n, o = 0;
	int fd, r = 0;

	for (n = 0; n < pass->nnss; n++)
		o += (size_t)lws_snprintf(buf + o, sizeof(buf) - o,
					  "nameserver %s\n", pass->nss[n].ads);

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		return 1;
	if (write(fd, buf, o) != (ssize_t)o)
		r = 1;
	close(fd);

	return r;
}
#endif

static int
run_pass(int argc, const char **argv, int ns_port)
{
	struct lws_context_creation_info info;
	lws_sockaddr46 sa46;
	size_t n;
	int m;

	lwsl_user("*** pass: %s\n", pass->name);

#if !defined(WIN32)
	{
		const char *p = getenv("LWS_ASYNCDNS_RESOLV_CONF");

		if (!p || write_resolv_conf(p)) {
			lwsl_err("Set LWS_ASYNCDNS_RESOLV_CONF to a "
				 "writeable file\n");

			return 1;
		}
	}
#endif

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");

		return 1;
	}

	/* only our nameservers may be asked, in our order */

	m = 0;
	while (!lws_plat_asyncdns_get_server(cx, m++, &sa46))
		lws_async_dns_server_remove(cx, &sa46);
	for (n = 0; n < pass->nnss; n++) {
		memset(&sa46, 0, sizeof(sa46));
		if (lws_sa46_parse_numeric_address(pass->nss[n].ads, &sa46) ||
		    !lws_async_dns_server_add(cx, &sa46)) {
			lwsl_err("Unable to pin nameserver %s\n",
				 pass->nss[n].ads);
			goto bail;
		}
	}

	info.protocols = protocols;
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.vhost_name = "cli";
	vh = lws_create_vhost(cx, &info);
	if (!vh) {
		lwsl_err("Failed to create client vhost\n");
		goto bail;
	}

	for (n = 0; n < pass->nnss; n++)
		if (pass->nss[n].kind != NS_UNREACH &&
		    !lws_create_adopt_udp(vh, pass->nss[n].ads, ns_port,
					  LWS_CAUDP_BIND, "fake-ns", NULL,
					  NULL, &pass->nss[n], NULL,
					  "fake-ns")) {
			lwsl_err("Unable to bind nameserver %s:%d\n",
				 pass->nss[n].ads, ns_port);
			goto bail;
		}

	lws_sul_schedule(cx, 0, &sul_watchdog, sul_watchdog_cb,
			 WATCHDOG_S * LWS_US_PER_SEC);

	check_done();
	lws_context_default_loop_run_destroy(cx);
	cx = NULL;

	for (n = 0; n < pass->nlegs; n++) {
		struct leg *leg = &pass->legs[n];

		if (!leg->done) {
			lwsl_err("%s: never finished\n", leg->name);
			fails++;
			continue;
		}
		if (leg->found != (leg->ret == LADNS_RET_FOUND)) {
			lwsl_err("%s: %s, ret %d\n", leg->name,
				 leg->found ? "not found" : "found", leg->ret);
			fails++;
		}
		if (!leg->found && !leg->client &&
		    leg->ret == LADNS_RET_TIMEDOUT) {
			lwsl_err("%s: timed out, the server said why\n",
				 leg->name);
			fails++;
		}
		if (leg->took > (lws_usec_t)leg->within_ms * LWS_US_PER_MS) {
			lwsl_err("%s: took %dms, more than %dms\n", leg->name,
				 (int)(leg->took / LWS_US_PER_MS),
				 leg->within_ms);
			fails++;
		}
	}

	for (n = 0; n < pass->nnss; n++)
		if (pass->nss[n].kind != NS_UNREACH && !pass->nss[n].asked) {
			lwsl_err("Nameserver %s was never asked\n",
				 pass->nss[n].ads);
			fails++;
		}

	return 0;

bail:
	lws_context_destroy(cx);
	cx = NULL;

	return 1;
}

int main(int argc, const char **argv)
{
	const char *p = getenv("LWS_ASYNCDNS_PORT");
	int ns_port;
	size_t n;

	signal(SIGINT, sigint_handler);

	lwsl_user("LWS API selftest: async dns with misbehaving nameservers\n");

	ns_port = p ? atoi(p) : 0;
	if (ns_port <= 0 || ns_port > 65535) {
		lwsl_err("Set LWS_ASYNCDNS_PORT to a free udp port\n");

		return 1;
	}

	for (n = 0; n < LWS_ARRAY_SIZE(passes); n++) {
		pass = &passes[n];
		if (run_pass(argc, argv, ns_port))
			return 1;
	}

	lwsl_user("Completed: %s\n", fails ? "FAIL" : "PASS");

	return !!fails;
}
