/*
 * lws-api-test-auth-dns-dnsbl
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 * Note: CC0 1.0 Universal Public Domain
 *
 * F-054 fence: pending DNSBL query lifetimes in protocol-lws-auth-dns.
 *
 * The authoritative-DNS plugin suspends answers for served A records on
 * DNSBL lookups issued via the context async resolver, and frees the
 * suspended query after 5s regardless of the lookups' fate.  Two legs
 * exercise the lifetime hazards:
 *
 * Leg 1, late resolver response: the resolver is pinned to a local stub
 * that reads the DNSBL queries but only answers them after the plugin's
 * 5s timeout has already replayed the answer and freed the query.  With
 * the fix, the lookups were cancelled at free time so the late replies
 * are dropped as unknown tids; pre-fix they completed into
 * dnsbl_query_cb() on freed heap (ASAN red).
 *
 * Leg 2, client disconnect: a TCP client disconnects while its query is
 * suspended on DNSBL lookups.  With the fix the RAW_CLOSE sweep NULLs
 * q->wsi so the timeout skips the replay; pre-fix the timeout called
 * back into the destroyed client wsi (ASAN red).
 *
 * The test passes when the suspended UDP answer arrives (proving the
 * timeout path ran), the stub saw the DNSBL queries (proving the DNSBL
 * path engaged), the late replies were serviced, and the process is
 * still standing afterwards.
 */

#include <libwebsockets.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <dirent.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/*
 * timings... the plugin dnsbl timeout is 5s; the stub replies at 7s,
 * ie, after both legs' pending queries were already freed
 */

#define TICK_US			(100 * LWS_US_PER_MS)
#define STUB_LATE_US		(7 * LWS_US_PER_SEC)
#define TCP_CONNECT_US		(1 * LWS_US_PER_SEC)
#define TCP_CLOSE_US		(2 * LWS_US_PER_SEC)
#define END_US			(10 * LWS_US_PER_SEC)
#define DEADLINE_US		(13 * LWS_US_PER_SEC)

#define QID_UDP			0x1234
#define QID_TCP			0x4322

extern const struct lws_protocols lws_auth_dns_protocols[];

static struct lws_context *context;
static volatile int interrupted;

static int auth_port, bh_port;
static int stub_fd = -1, cli_udp_fd = -1, cli_tcp_fd = -1;
static struct sockaddr_in auth_sa;

static lws_usec_t t0;
static int udp_query_sent, got_answer, tcp_query_sent, tcp_closed;
static int stub_saw_queries;
static int test_ok = 1;

static lws_sorted_usec_list_t sul_drive;

/*
 * The stub captures every DNSBL query that reaches it, then answers them
 * all at t0 + STUB_LATE_US, ie, after the plugin already timed its
 * pending queries out and freed them.
 */

struct captured {
	struct captured		*next;
	struct sockaddr_storage	peer;
	socklen_t		peer_len;
	int			answered;
	uint8_t			pkt[512];
	size_t			len;
};

static struct captured *captured_head, *captured_tail;

/* build a DNS query for "name" into buf, returning the packet length */

static size_t
mk_query(uint8_t *buf, size_t bufsize, uint16_t id, const char *name,
	 uint16_t qtype)
{
	const char *p = name;
	size_t o = 12;

	memset(buf, 0, bufsize >= 12 ? 12 : bufsize);
	buf[0] = (uint8_t)(id >> 8);
	buf[1] = (uint8_t)(id & 0xff);
	buf[2] = 0x01;			/* RD */
	buf[5] = 1;			/* QDCOUNT = 1 */

	while (*p) {
		const char *dot = strchr(p, '.');
		size_t l = dot ? (size_t)(dot - p) : strlen(p);

		if (!l || l > 63 || o + 1 + l + 4 > bufsize)
			return 0;

		buf[o++] = (uint8_t)l;
		memcpy(&buf[o], p, l);
		o += l;

		p = dot ? dot + 1 : p + l;
	}
	buf[o++] = 0;			/* root */

	buf[o++] = (uint8_t)(qtype >> 8);
	buf[o++] = (uint8_t)(qtype & 0xff);
	buf[o++] = 0;			/* IN */
	buf[o++] = 1;

	return o;
}

/*
 * Turn a captured DNS query into a positive response of the same type
 * (A -> 127.0.0.2, AAAA -> ::ffff:127.0.0.2-ish), sent back to its source.
 */

static void
stub_answer_one(struct captured *cap)
{
	uint8_t resp[600];
	uint16_t qtype = (uint16_t)((cap->pkt[cap->len - 4] << 8) |
				     cap->pkt[cap->len - 3]);
	size_t o;

	if (cap->len + 2 + 10 + 16 > sizeof(resp))
		return;

	memcpy(resp, cap->pkt, cap->len);
	resp[2] = 0x81;			/* QR + RD */
	resp[3] = 0x80;			/* RA */
	resp[6] = 0; resp[7] = 1;	/* ANCOUNT = 1 */
	resp[10] = 0; resp[11] = 0;	/* ARCOUNT = 0 */

	o = cap->len;
	resp[o++] = 0xc0;		/* name: pointer to qname */
	resp[o++] = 0x0c;
	resp[o++] = (uint8_t)(qtype >> 8);
	resp[o++] = (uint8_t)(qtype & 0xff);
	resp[o++] = 0; resp[o++] = 1;	/* IN */
	resp[o++] = 0; resp[o++] = 0;	/* TTL hi */
	resp[o++] = 0; resp[o++] = 60;	/* TTL lo */

	if (qtype == LWS_ADNS_RECORD_AAAA) {
		resp[o++] = 0; resp[o++] = 16;
		memset(&resp[o], 0, 12);
		o += 12;
		resp[o++] = 0x7f; resp[o++] = 0; resp[o++] = 0; resp[o++] = 2;
	} else {
		resp[o++] = 0; resp[o++] = 4;
		resp[o++] = 0x7f; resp[o++] = 0; resp[o++] = 0; resp[o++] = 2;
	}

	if (sendto(stub_fd, resp, o, 0, (struct sockaddr *)&cap->peer,
		   cap->peer_len) < 0)
		lwsl_err("%s: late reply sendto failed: errno %d\n",
				__func__, errno);
	else
		lwsl_user("stub: sent late reply (%zu bytes, type %d)\n",
				o, qtype);
}

static void
stub_tick(lws_usec_t now)
{
	struct captured *cap;

	/* harvest any new DNSBL queries */

	do {
		struct sockaddr_storage peer;
		socklen_t plen = sizeof(peer);
		uint8_t buf[512];
		ssize_t n = recvfrom(stub_fd, buf, sizeof(buf), 0,
				     (struct sockaddr *)&peer, &plen);

		if (n < 12)
			break;

		cap = malloc(sizeof(*cap));
		if (!cap)
			break;
		memset(cap, 0, sizeof(*cap));
		memcpy(cap->pkt, buf, (size_t)n);
		cap->len = (size_t)n;
		cap->peer = peer;
		cap->peer_len = plen;

		if (captured_tail)
			captured_tail->next = cap;
		else
			captured_head = cap;
		captured_tail = cap;

		stub_saw_queries++;
		lwsl_user("stub: captured DNSBL query %d (type %d)\n",
				stub_saw_queries,
				(buf[n - 4] << 8) | buf[n - 3]);
	} while (1);

	/* answer everything captured once we are good and late */

	if (now - t0 < STUB_LATE_US)
		return;

	for (cap = captured_head; cap; cap = cap->next)
		if (!cap->answered) {
			cap->answered = 1;
			stub_answer_one(cap);
		}
}

static void
udp_client_tick(void)
{
	uint8_t buf[2048];
	ssize_t n;

	n = recv(cli_udp_fd, buf, sizeof(buf), 0);
	if (n < 12)
		return;

	/*
	 * The only way this answer can exist is the plugin's 5s dnsbl
	 * timeout replaying it: the resolver stub never answers in time.
	 */

	if (!((buf[0] << 8 | buf[1]) == QID_UDP && (buf[2] & 0x80))) {
		lwsl_err("%s: unexpected UDP packet id %02x%02x\n", __func__,
				buf[0], buf[1]);
		test_ok = 0;
		return;
	}

	lwsl_user("leg 1: suspended answer replayed by dnsbl timeout "
		  "(ancount %d)\n", (buf[6] << 8) | buf[7]);
	got_answer = 1;
}

static void
drive_cb(lws_sorted_usec_list_t *sul)
{
	lws_usec_t now = lws_now_usecs();

	(void)sul;

	stub_tick(now);
	udp_client_tick();

	/*
	 * The udp query goes out from the first drive tick, so vhost
	 * protocol init (and so the plugin's udp listener) has already
	 * happened in the first service pass.
	 */

	if (!udp_query_sent) {
		uint8_t q[64];
		size_t ql;

		udp_query_sent = 1;

		ql = mk_query(q, sizeof(q), QID_UDP, "www.example.com",
				LWS_ADNS_RECORD_A);
		if (!ql) {
			test_ok = 0;
			goto sched;
		}

		if (sendto(cli_udp_fd, q, ql, 0, (struct sockaddr *)&auth_sa,
			   sizeof(auth_sa)) < 0) {
			lwsl_err("%s: client query sendto failed errno %d\n",
					__func__, errno);
			test_ok = 0;
			goto sched;
		}

		lwsl_user("leg 1: udp query sent, awaiting 5s timeout replay\n");
	}

	if (!tcp_query_sent && now - t0 >= TCP_CONNECT_US) {
		struct sockaddr_in sa;
		uint8_t q[64], frame[66];
		size_t ql;

		tcp_query_sent = 1;

		cli_tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
		if (cli_tcp_fd < 0) {
			lwsl_err("%s: tcp socket failed\n", __func__);
			test_ok = 0;
			goto sched;
		}

		memset(&sa, 0, sizeof(sa));
		sa.sin_family = AF_INET;
		sa.sin_port = htons((uint16_t)auth_port);
		sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

		if (connect(cli_tcp_fd, (struct sockaddr *)&sa, sizeof(sa))) {
			lwsl_err("%s: tcp connect failed errno %d\n",
					__func__, errno);
			test_ok = 0;
			goto sched;
		}

		ql = mk_query(q, sizeof(q), QID_TCP, "tcp.example.com",
				LWS_ADNS_RECORD_A);
		if (!ql) {
			test_ok = 0;
			goto sched;
		}

		/* length-prefixed DNS-over-TCP framing */

		frame[0] = (uint8_t)(ql >> 8);
		frame[1] = (uint8_t)(ql & 0xff);
		memcpy(&frame[2], q, ql);

		if (send(cli_tcp_fd, frame, ql + 2, 0) < 0) {
			lwsl_err("%s: tcp send failed errno %d\n",
					__func__, errno);
			test_ok = 0;
			goto sched;
		}

		lwsl_user("leg 2: tcp query sent\n");
	}

	if (tcp_query_sent && !tcp_closed && now - t0 >= TCP_CLOSE_US) {
		tcp_closed = 1;
		if (cli_tcp_fd >= 0) {
			close(cli_tcp_fd);
			cli_tcp_fd = -1;
		}
		lwsl_user("leg 2: tcp client disconnected while dnsbl "
			  "lookups pending\n");
	}

sched:
	if (now - t0 >= DEADLINE_US) {
		lwsl_err("%s: deadline (answer %d, stub %d, tcp %d/%d)\n",
				__func__, got_answer, stub_saw_queries,
				tcp_query_sent, tcp_closed);
		test_ok = 0;
		interrupted = 1;
		lws_cancel_service(context);

		return;
	}

	if (got_answer && tcp_closed && stub_saw_queries &&
	    now - t0 >= END_US) {
		interrupted = 1;
		lws_cancel_service(context);

		return;
	}

	lws_sul_schedule(context, 0, &sul_drive, drive_cb, TICK_US);
}

static void
sigint_handler(int sig)
{
	(void)sig;

	interrupted = 1;
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	static const char *dns[] = { "127.0.0.1", NULL };
	const struct lws_protocols my_protocols[] = {
		lws_auth_dns_protocols[0],
		{ NULL, NULL, 0, 0, 0, NULL, 0 }
	};
	const char *zonedir = "zones-dnsbl";
	struct lws_protocol_vhost_options pvo_dnsbl = {
		NULL, NULL, "dnsbl", "one.blackhole.test,two.blackhole.test"
	};
	struct lws_protocol_vhost_options pvo_zonedir;
	struct lws_protocol_vhost_options pvo = {
		NULL, NULL, "protocol-lws-auth-dns", ""
	};
	struct sockaddr_in sa;
	const char *p;
	char portstr[16];
	int n = 0;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	if ((p = lws_cmdline_option(argc, argv, "-p"))) {
		auth_port = atoi(p);
		if (auth_port <= 0 || auth_port > 65535) {
			lwsl_err("Bad auth dns port %s\n", p);
			return 1;
		}
	}

	if ((p = lws_cmdline_option(argc, argv, "-b"))) {
		bh_port = atoi(p);
		if (bh_port <= 0 || bh_port > 65535) {
			lwsl_err("Bad dnsbl stub port %s\n", p);
			return 1;
		}
	}

	if ((p = lws_cmdline_option(argc, argv, "-z")))
		zonedir = p;

	/*
	 * The plugin only admits a service-owned, non-group/world-writable
	 * zone dir with like-mode zone files (F-055); a umask-002 checkout
	 * produces group-writable files, so normalize the fixture modes.
	 */
	{
		DIR *d = opendir(zonedir);
		struct dirent *de;

		if (chmod(zonedir, 0755))
			lwsl_err("%s: chmod %s failed\n", __func__, zonedir);
		if (d) {
			while ((de = readdir(d))) {
				size_t l = strlen(de->d_name);
				char path[1024];

				if (l < 6 || strcmp(de->d_name + l - 5, ".zone"))
					continue;
				lws_snprintf(path, sizeof(path), "%s/%s",
					     zonedir, de->d_name);
				chmod(path, 0644);
			}
			closedir(d);
		}
	}

	pvo_zonedir.next = &pvo_dnsbl;
	pvo_zonedir.options = NULL;
	pvo_zonedir.name = "zone-dir";
	pvo_zonedir.value = zonedir;
	pvo.options = &pvo_zonedir;

	if (!auth_port || !bh_port) {
		lwsl_err("usage: %s -p <auth dns port> -b <dnsbl stub port>"
			 " [-z <zone dir>]\n", argv[0]);
		return 1;
	}

	signal(SIGINT, sigint_handler);

	/*
	 * The whole context resolver is pinned to 127.0.0.1 on the stub
	 * port... this must be in place before the context creates its
	 * resolver wsis.
	 */

	lws_snprintf(portstr, sizeof(portstr), "%d", bh_port);
	setenv("LWS_ASYNCDNS_PORT", portstr, 1);

	/* the blackholed DNSBL resolver stub itself */

	stub_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (stub_fd < 0) {
		lwsl_err("stub socket failed\n");
		return 1;
	}
	fcntl(stub_fd, F_SETFL, O_NONBLOCK);

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons((uint16_t)bh_port);
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(stub_fd, (struct sockaddr *)&sa, sizeof(sa))) {
		lwsl_err("stub bind 127.0.0.1:%d failed errno %d\n",
				bh_port, errno);
		close(stub_fd);
		return 1;
	}

	/* the unauthenticated UDP client query that starts leg 1 */

	cli_udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (cli_udp_fd < 0) {
		lwsl_err("client socket failed\n");
		close(stub_fd);
		return 1;
	}
	fcntl(cli_udp_fd, F_SETFL, O_NONBLOCK);

	/*
	 * The auth dns vhost: UDP + TCP listeners on auth_port, serving
	 * zones from the local zone dir, with two DNSBLs configured so
	 * each suspended query fans out into several lookups.
	 *
	 * ADOPT_...: DNS-over-TCP is binary, it must never go near the http
	 * parser, all accepts bind straight to the raw protocol.
	 */

	info.port = auth_port;
	info.options = LWS_SERVER_OPTION_ADOPT_APPLY_LISTEN_ACCEPT_CONFIG;
	info.listen_accept_role = "raw-skt";
	info.listen_accept_protocol = "protocol-lws-auth-dns";
	info.protocols = my_protocols;
	info.async_dns_servers = dns;
	info.pvo = &pvo;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		close(cli_udp_fd);
		close(stub_fd);
		return 1;
	}

	/*
	 * Drop any platform-assigned resolver entries, so the pinned stub
	 * is the only possible resolver for the DNSBL lookups (the pin
	 * itself only stops further platform acquisition, not entries the
	 * watcher found before it existed).
	 */

	{
		lws_sockaddr46 sa46;
		lws_sockaddr46 pin;
		int index = 0;

		memset(&pin, 0, sizeof(pin));
		pin.sa4.sin_family = AF_INET;
		pin.sa4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

		while (!lws_plat_asyncdns_get_server(context, index++, &sa46)) {
			char buf[64];

			lws_sa46_write_numeric_address(&sa46, buf, sizeof(buf));

			if (!lws_sa46_compare_ads(&sa46, &pin)) {
				lwsl_user("keeping pinned stub resolver %s\n", buf);
				continue;
			}

			lwsl_user("removing platform resolver %s\n", buf);
			lws_async_dns_server_remove(context, &sa46);
		}
	}

	memset(&auth_sa, 0, sizeof(auth_sa));
	auth_sa.sin_family = AF_INET;
	auth_sa.sin_port = htons((uint16_t)auth_port);
	auth_sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	lwsl_user("LWS API selftest: auth dns DNSBL lifetimes (F-054)\n");

	t0 = lws_now_usecs();
	lws_sul_schedule(context, 0, &sul_drive, drive_cb, TICK_US);

	while (n >= 0 && !interrupted)
		n = lws_service(context, 0);

	/*
	 * Results... the blackhole stub must have seen the DNSBL lookups,
	 * the suspended answer must have been replayed by the 5s timeout,
	 * and both legs' late replies must have been serviced harmlessly
	 * on the way here.
	 */

	if (!stub_saw_queries) {
		lwsl_err("FAIL: stub saw no DNSBL queries (dnsbl path did "
			 "not engage)\n");
		test_ok = 0;
	}

	if (!udp_query_sent || !got_answer) {
		lwsl_err("FAIL: no timeout replay of suspended answer\n");
		test_ok = 0;
	}

	if (!tcp_query_sent || !tcp_closed) {
		lwsl_err("FAIL: tcp disconnect leg did not run\n");
		test_ok = 0;
	}

	{
		struct captured *cap = captured_head, *next;

		while (cap) {
			next = cap->next;
			free(cap);
			cap = next;
		}
	}

	lwsl_user("Completed: %s\n", test_ok ? "PASS" : "FAIL");

	lws_context_destroy(context);
	close(cli_udp_fd);
	close(stub_fd);

	return !test_ok;
}
