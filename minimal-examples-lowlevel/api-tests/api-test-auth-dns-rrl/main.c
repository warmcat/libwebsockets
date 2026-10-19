/*
 * lws-api-test-auth-dns-rrl
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 * Note: CC0 1.0 Universal Public Domain
 *
 * G-289 fence: what protocol-lws-auth-dns sends back over UDP is bounded, so
 * it is no use as a reflector towards a spoofed source.
 *
 *  1. A large answer (a 20-RR TXT RRset, ~2.3KB) asked for over UDP with an
 *     EDNS0 payload size of 4096 comes back in at most 1232 bytes, as the
 *     question alone with TC set and our OPT; asked without EDNS0, in at
 *     most 512 bytes, the same way.
 *  2. The same question over TCP is answered whole.
 *  3. A burst of queries from one source address is answered only up to
 *     its prefix's budget (rrl-burst); beyond that, every rrl-slip'th
 *     query gets an empty TC=1 answer and the rest none at all.
 *  4. Meanwhile a source in another prefix is answered as usual.
 *
 * The second source is ::1 when lws has IPv6, otherwise 127.0.1.1 (another
 * /24 of the loopback net, which Linux routes to lo); if neither can be
 * bound, step 4 is skipped with a notice.
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
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define TICK_US			(20 * LWS_US_PER_MS)
#define STEP_TIMEOUT_US		(3 * LWS_US_PER_SEC)
#define FLOOD_SETTLE_US		(700 * LWS_US_PER_MS)

#define BASE_DIR		"zones-rrl"
#define ZONE_FILE		"big.example_2000000000_2000000000_1.zone"

/* the budget the test configures, and as numbers */
#define RRL_RATE_S		"5"
#define RRL_BURST_S		"5"
#define RRL_SLIP_S		"2"
#define RRL_BURST		5
#define RRL_SLIP		2

#define TXT_RRS			20
#define FLOOD			40
#define OTHER			3

extern const struct lws_protocols lws_auth_dns_protocols[];

static struct lws_context *context;
static lws_sorted_usec_list_t sul_drive;
static int port, fd_a = -1, fd_b = -1, fd_tcp = -1, b_family;
static int test_ok = 1, done;
static char run_dir[256];

static enum {
	S_UDP_BIG,
	S_TCP_BIG,
	S_FLOOD,
	S_OTHER,
	S_DONE
} state;

static lws_usec_t t_step;
static int got_full, got_tc, got_big_edns, got_big_plain;
static uint8_t tcp_rx[8192], tcp_tx[512];
static size_t tcp_rx_len, tcp_tx_len;

static void
fail(const char *why)
{
	lwsl_err("FAIL: %s\n", why);
	test_ok = 0;
	done = 1;
}

/* a DNS query for name / qtype, with an OPT RR if edns_size */

static size_t
mk_query(uint8_t *buf, size_t bufsize, uint16_t id, const char *name,
	 uint16_t qtype, uint16_t edns_size)
{
	const char *p = name;
	size_t o = 12;

	if (bufsize < 12 + 256 + 4 + 11)
		return 0;

	memset(buf, 0, 12);
	lws_ser_wu16be(buf, id);
	buf[2] = 0x01;			/* RD */
	buf[5] = 1;			/* QDCOUNT */

	while (*p) {
		const char *dot = strchr(p, '.');
		size_t l = dot ? (size_t)(dot - p) : strlen(p);

		if (!l || l > 63 || o + 1 + l > 12 + 255)
			return 0;

		buf[o++] = (uint8_t)l;
		memcpy(&buf[o], p, l);
		o += l;
		p = dot ? dot + 1 : p + l;
	}
	buf[o++] = 0;

	lws_ser_wu16be(&buf[o], qtype);
	o += 2;
	lws_ser_wu16be(&buf[o], 1);	/* IN */
	o += 2;

	if (edns_size) {
		buf[11] = 1;		/* ARCOUNT */
		buf[o++] = 0;		/* root */
		lws_ser_wu16be(&buf[o], 41); /* OPT */
		o += 2;
		lws_ser_wu16be(&buf[o], edns_size);
		o += 2;
		memset(&buf[o], 0, 6);	/* ext rcode, version, flags, rdlen */
		o += 6;
	}

	return o;
}

static int
send_q(int fd, int family, uint16_t id, const char *name, uint16_t qtype,
       uint16_t edns_size)
{
	uint8_t buf[512];
	size_t ql = mk_query(buf, sizeof(buf), id, name, qtype, edns_size);
	struct sockaddr_in sa4;
#if defined(LWS_WITH_IPV6)
	struct sockaddr_in6 sa6;
#endif
	struct sockaddr *sa = (struct sockaddr *)&sa4;
	socklen_t sl = sizeof(sa4);

	memset(&sa4, 0, sizeof(sa4));
	sa4.sin_family = AF_INET;
	sa4.sin_port = htons((uint16_t)port);
	sa4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

#if defined(LWS_WITH_IPV6)
	if (family == AF_INET6) {
		memset(&sa6, 0, sizeof(sa6));
		sa6.sin6_family = AF_INET6;
		sa6.sin6_port = htons((uint16_t)port);
		sa6.sin6_addr = in6addr_loopback;
		sa = (struct sockaddr *)&sa6;
		sl = sizeof(sa6);
	}
#endif

	return !ql || sendto(fd, buf, ql, 0, sa, sl) != (ssize_t)ql;
}

/* a nonblocking UDP socket bound to the loopback address ads */

static int
udp_bind(int family, const char *ads)
{
	struct sockaddr_in sa4;
#if defined(LWS_WITH_IPV6)
	struct sockaddr_in6 sa6;
#endif
	struct sockaddr *sa = (struct sockaddr *)&sa4;
	socklen_t sl = sizeof(sa4);
	int fd = socket(family, SOCK_DGRAM, 0);

	if (fd < 0)
		return -1;

	memset(&sa4, 0, sizeof(sa4));
	sa4.sin_family = AF_INET;
	if (inet_pton(AF_INET, ads, &sa4.sin_addr) != 1 && family == AF_INET)
		goto bail;

#if defined(LWS_WITH_IPV6)
	if (family == AF_INET6) {
		memset(&sa6, 0, sizeof(sa6));
		sa6.sin6_family = AF_INET6;
		if (inet_pton(AF_INET6, ads, &sa6.sin6_addr) != 1)
			goto bail;
		sa = (struct sockaddr *)&sa6;
		sl = sizeof(sa6);
	}
#endif

	if (bind(fd, sa, sl) || fcntl(fd, F_SETFL, O_NONBLOCK) < 0)
		goto bail;

	return fd;

bail:
	close(fd);

	return -1;
}

static void
harvest(int fd, int is_flood)
{
	uint8_t buf[2048];
	ssize_t r;

	while ((r = recv(fd, buf, sizeof(buf), 0)) >= 12) {
		uint16_t id = lws_ser_ru16be(buf),
			 anc = lws_ser_ru16be(&buf[6]),
			 arc = lws_ser_ru16be(&buf[10]);
		int tc = !!(buf[2] & 0x02);

		if (!(buf[2] & 0x80)) {
			fail("a reply that is not a response");
			return;
		}

		switch (id) {
		case 0x0100: /* the big TXT RRset, EDNS0 4096 */
			lwsl_user("udp edns 4096: %d bytes, tc %d, anc %d, "
				  "arc %d\n", (int)r, tc, anc, arc);
			if (r > 1232 || !tc || anc || arc != 1) {
				fail("udp answer with edns 4096 not capped at "
				     "1232 as an empty TC=1 with OPT");
				return;
			}
			got_big_edns = 1;
			continue;
		case 0x0101: /* the big TXT RRset, no EDNS0 */
			lwsl_user("udp no edns: %d bytes, tc %d, anc %d, "
				  "arc %d\n", (int)r, tc, anc, arc);
			if (r > 512 || !tc || anc || arc) {
				fail("udp answer without edns not capped at "
				     "512 as an empty TC=1");
				return;
			}
			got_big_plain = 1;
			continue;
		}

		if (!is_flood && (id & 0xff00) != 0x0300) {
			fail("unexpected response id");
			return;
		}

		if (tc) {
			if (anc) {
				fail("a TC=1 answer with records in it");
				return;
			}
			got_tc++;
		} else if (anc == 1 && !(buf[3] & 0xf))
			got_full++;
		else {
			fail("a bad answer to www.big.example");
			return;
		}
	}
}

static int
tcp_start(void)
{
	struct sockaddr_in sa4;
	size_t ql;

	fd_tcp = socket(AF_INET, SOCK_STREAM, 0);
	if (fd_tcp < 0)
		return 1;

	memset(&sa4, 0, sizeof(sa4));
	sa4.sin_family = AF_INET;
	sa4.sin_port = htons((uint16_t)port);
	sa4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	if (fcntl(fd_tcp, F_SETFL, O_NONBLOCK) < 0)
		return 1;

	if (connect(fd_tcp, (struct sockaddr *)&sa4, sizeof(sa4)) &&
	    errno != EINPROGRESS)
		return 1;

	/* RFC 7766 framing: a 16-bit length, then the query */
	ql = mk_query(tcp_tx + 2, sizeof(tcp_tx) - 2, 0x0200,
		      "txt.big.example", 16, 4096);
	if (!ql)
		return 1;
	lws_ser_wu16be(tcp_tx, (uint16_t)ql);
	tcp_tx_len = ql + 2;
	tcp_rx_len = 0;

	return 0;
}

/* returns 1 when the whole TCP answer is in */

static int
tcp_service(void)
{
	ssize_t r;

	if (tcp_tx_len) {
		/* until the nonblocking connect completes, this fails */
		r = send(fd_tcp, tcp_tx, tcp_tx_len, 0);
		if (r > 0) {
			memmove(tcp_tx, tcp_tx + r, tcp_tx_len - (size_t)r);
			tcp_tx_len -= (size_t)r;
		}
		return 0;
	}

	r = recv(fd_tcp, tcp_rx + tcp_rx_len, sizeof(tcp_rx) - tcp_rx_len, 0);
	if (r > 0)
		tcp_rx_len += (size_t)r;

	if (tcp_rx_len < 2 + 12 ||
	    tcp_rx_len < 2 + (size_t)lws_ser_ru16be(tcp_rx))
		return 0;

	return 1;
}

static void
drive_cb(lws_sorted_usec_list_t *sul)
{
	lws_usec_t now = lws_now_usecs();
	int n;

	(void)sul;

	switch (state) {
	case S_UDP_BIG:
		if (!t_step) {
			t_step = now;
			if (send_q(fd_a, AF_INET, 0x0100, "txt.big.example",
				   16, 4096) ||
			    send_q(fd_a, AF_INET, 0x0101, "txt.big.example",
				   16, 0)) {
				fail("udp send");
				break;
			}
		}
		harvest(fd_a, 0);
		if (got_big_edns && got_big_plain) {
			state = S_TCP_BIG;
			t_step = 0;
			break;
		}
		if (now - t_step > STEP_TIMEOUT_US)
			fail("no udp answer to the big question");
		break;

	case S_TCP_BIG:
		if (!t_step) {
			t_step = now;
			if (tcp_start()) {
				fail("tcp connect");
				break;
			}
		}
		if (tcp_service()) {
			uint16_t anc = lws_ser_ru16be(tcp_rx + 2 + 6);
			int tc = !!(tcp_rx[2 + 2] & 0x02);

			lwsl_user("tcp: %d bytes, tc %d, anc %d\n",
				  (int)lws_ser_ru16be(tcp_rx), tc, anc);
			if (tc || anc != TXT_RRS ||
			    lws_ser_ru16be(tcp_rx) <= 1232) {
				fail("tcp answer not whole");
				break;
			}
			state = S_FLOOD;
			t_step = 0;
			break;
		}
		if (now - t_step > STEP_TIMEOUT_US)
			fail("no tcp answer");
		break;

	case S_FLOOD:
		if (!t_step) {
			t_step = now;
			got_full = got_tc = 0;
			for (n = 0; n < FLOOD; n++)
				if (send_q(fd_a, AF_INET, (uint16_t)(0x1000 + n),
					   "www.big.example", 1, 0)) {
					fail("flood send");
					break;
				}
		}
		harvest(fd_a, 1);
		if (now - t_step < FLOOD_SETTLE_US)
			break;

		lwsl_user("flood of %d: %d answered, %d TC=1, %d dropped\n",
			  FLOOD, got_full, got_tc, FLOOD - got_full - got_tc);
		/*
		 * the 2 udp queries before took 2 of the burst, and it
		 * refills at 5/s: a few more may have come back meanwhile
		 */
		if (got_full < 1 || got_full > RRL_BURST + 2 ||
		    got_tc < (FLOOD - RRL_BURST - 2) / RRL_SLIP - 1 ||
		    got_full + got_tc >= FLOOD) {
			fail("flood from one source not rate limited");
			break;
		}
		state = fd_b >= 0 ? S_OTHER : S_DONE;
		t_step = 0;
		break;

	case S_OTHER:
		if (!t_step) {
			t_step = now;
			got_full = got_tc = 0;
			for (n = 0; n < OTHER; n++)
				if (send_q(fd_b, b_family, (uint16_t)(0x0300 + n),
					   "www.big.example", 1, 0)) {
					fail("other source send");
					break;
				}
		}
		harvest(fd_b, 0);
		if (got_full == OTHER) {
			lwsl_user("other source: all %d answered\n", OTHER);
			state = S_DONE;
			break;
		}
		if (got_tc || now - t_step > STEP_TIMEOUT_US)
			fail("another source was limited too");
		break;

	case S_DONE:
		done = 1;
		break;
	}

	if (!done)
		lws_sul_schedule(context, 0, &sul_drive, drive_cb, TICK_US);
	else
		lws_cancel_service(context);
}


static int
write_zone(void)
{
	char text[8192], path[512];
	size_t o = 0;
	int fd, n, ok;

	o += (size_t)lws_snprintf(text + o, sizeof(text) - o,
			"$ORIGIN big.example.\n"
			"$TTL 86400\n"
			"@	IN	SOA	ns1.big.example. hostmaster.big.example. "
				"( 2026090101 3600 1800 604800 86400 )\n"
			"@	IN	NS	ns1.big.example.\n"
			"www	IN	A	127.0.0.77\n");

	for (n = 0; n < TXT_RRS; n++)
		o += (size_t)lws_snprintf(text + o, sizeof(text) - o,
			"txt	IN	TXT	t%02d-%s\n", n,
			"0123456789abcdef0123456789abcdef0123456789abcdef"
			"0123456789abcdef0123456789abcdef0123456789abcdef");

	if (mkdir(BASE_DIR, 0755) && errno != EEXIST)
		return 1;
	if (mkdir(run_dir, 0700) && errno != EEXIST)
		return 1;
	/* the zone dir must not be group / world writable whatever the umask */
	if (chmod(run_dir, 0700))
		return 1;

	lws_snprintf(path, sizeof(path), "%s/%s", run_dir, ZONE_FILE);
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		return 1;
	ok = write(fd, text, o) == (ssize_t)o;
	close(fd);

	return !ok || chmod(path, 0600);
}

static void
remove_zone(void)
{
	char path[512];

	lws_snprintf(path, sizeof(path), "%s/%s", run_dir, ZONE_FILE);
	unlink(path);
	rmdir(run_dir);
	/* only goes if no other run is using it */
	rmdir(BASE_DIR);
}

static void
sigint_handler(int sig)
{
	(void)sig;
	lws_default_loop_exit(context);
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const struct lws_protocols protocols[] = {
		lws_auth_dns_protocols[0],
		LWS_PROTOCOL_LIST_TERM
	};
	struct lws_protocol_vhost_options pvo_slip = {
		NULL, NULL, "rrl-slip", RRL_SLIP_S
	}, pvo_burst = {
		&pvo_slip, NULL, "rrl-burst", RRL_BURST_S
	}, pvo_rate = {
		&pvo_burst, NULL, "rrl-responses-per-second", RRL_RATE_S

	}, pvo_zonedir = {
		&pvo_rate, NULL, "zone-dir", run_dir
	}, pvo = {
		NULL, &pvo_zonedir, "protocol-lws-auth-dns", ""
	};
	const char *p;
	int n = 0;

	signal(SIGINT, sigint_handler);
	lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE, NULL);
	lwsl_user("LWS API selftest: auth dns UDP answer size and rate "
		  "limiting (G-289)\n");

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);
	if (port <= 0 || port > 65535) {
		lwsl_err("usage: %s -p <auth dns port>\n", argv[0]);
		return 1;
	}

	lws_snprintf(run_dir, sizeof(run_dir), "%s/%d", BASE_DIR, (int)getpid());
	if (write_zone()) {
		lwsl_err("unable to write the zone\n");
		remove_zone();
		return 1;
	}

	fd_a = udp_bind(AF_INET, "127.0.0.1");
#if defined(LWS_WITH_IPV6)
	b_family = AF_INET6;
	fd_b = udp_bind(AF_INET6, "::1");
#endif
	if (fd_b < 0) {
		b_family = AF_INET;
		fd_b = udp_bind(AF_INET, "127.0.1.1");
	}
	if (fd_b < 0)
		lwsl_notice("no second loopback source: other-source step "
			    "skipped\n");

	if (fd_a < 0) {
		lwsl_err("unable to bind the client socket\n");
		remove_zone();
		return 1;
	}

	lws_context_info_defaults(&info, NULL);
	info.fd_limit_per_thread = 0;
	info.port = port;
	info.options = LWS_SERVER_OPTION_ADOPT_APPLY_LISTEN_ACCEPT_CONFIG;
	info.listen_accept_role = "raw-skt";
	info.listen_accept_protocol = "protocol-lws-auth-dns";
	info.protocols = protocols;
	info.pvo = &pvo;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		test_ok = 0;
		goto bail;
	}

	lws_sul_schedule(context, 0, &sul_drive, drive_cb, TICK_US);

	while (n >= 0 && !done)
		n = lws_service(context, 0);

	if (n < 0)
		test_ok = 0;

	lws_context_destroy(context);

bail:
	if (fd_tcp >= 0)
		close(fd_tcp);
	if (fd_b >= 0)
		close(fd_b);
	close(fd_a);
	remove_zone();

	lwsl_user("Completed: %s\n", test_ok && state == S_DONE ? "PASS" :
								 "FAIL");

	return !(test_ok && state == S_DONE);
}
