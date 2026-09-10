/*
 * libwebsockets - libFuzzer target for the async-dns response parser
 *
 * Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * The DNS wire parser (lib/system/async-dns/async-dns-parse.c, and dnssec.c
 * when built) takes UDP payloads from anyone who can spoof the resolver's
 * address.  Each input is delivered as the response to a real pending query
 * for "fuzz.invalid", the same way the api-test injects canned responses:
 * the query is issued through the public api, its transaction id is patched
 * into the input, and the packet goes into lws_adns_parse_udp() with the
 * query's server.
 *
 * The context's only nameserver is 127.0.0.1 on a port we bound ourselves
 * (via LWS_ASYNCDNS_PORT), so the query lws sends when serviced lands in our
 * own sink socket and nothing leaves the process.  /etc/resolv.conf is
 * bypassed by pointing LWS_ASYNCDNS_RESOLV_CONF at a nonexistent file.
 *
 * Input layout:
 *
 *   [0]  bits 0-1: DNSSEC mode (off / tolerate / require), when built
 *        bits 2-3: query type: A, AAAA, DNSKEY, TXT
 *   [1..] the DNS response packet; its first two bytes (the tid) are
 *        overwritten with the pending query's tid
 *
 * The context is torn down and recreated every 256 inputs so anything a
 * response left pending (DNSSEC sub-lookups, TCP fallback wsi) is bounded.
 */

#include <libwebsockets.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>

static struct lws_context *cx;
static lws_sorted_usec_list_t sul;
static const char *servers[] = { "127.0.0.1", NULL };
static unsigned int iters;
static int sink_fd = -1, done, marker;

static const adns_query_type_t qtypes[] = {
	LWS_ADNS_RECORD_A, LWS_ADNS_RECORD_AAAA,
	LWS_ADNS_RECORD_DNSKEY, LWS_ADNS_RECORD_TXT
};

static void
sul_cb(lws_sorted_usec_list_t *s)
{
	(void)s;
}

static struct lws *
adns_cb(struct lws *wsi, const char *ads, const struct addrinfo *result,
	int n, void *opaque)
{
	(void)wsi;
	(void)ads;
	(void)n;
	(void)opaque;

	done = 1;

	if (result)
		lws_async_dns_freeaddrinfo(&result);

	return NULL;
}

/* one non-blocking pass through the event loop */

static void
service_once(void)
{
	lws_sul_schedule(cx, 0, &sul, sul_cb, 1);
	lws_service(cx, 0);
	lws_sul_cancel(&sul);
}

static void
drain_sink(void)
{
	uint8_t d[2048];

	while (recv(sink_fd, d, sizeof(d), MSG_DONTWAIT) > 0)
		;
}

static int
ctx_create(void)
{
	struct lws_context_creation_info info;

	memset(&info, 0, sizeof(info));
	info.port		= CONTEXT_PORT_NO_LISTEN;
	info.async_dns_servers	= servers;

	cx = lws_create_context(&info);

	return cx ? 0 : 1;
}

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	struct sockaddr_in sin;
	socklen_t sl = sizeof(sin);
	char port[8];

	(void)argc;
	(void)argv;

	signal(SIGPIPE, SIG_IGN);

	if (getenv("LWS_FUZZ_VERBOSE"))
		lws_set_log_level(0x7fff, NULL);
	else
		lws_set_log_level(0, NULL);

	/* our sink for the queries lws sends, on an ephemeral port */

	sink_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sink_fd < 0)
		return 1;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family		= AF_INET;
	sin.sin_addr.s_addr	= htonl(INADDR_LOOPBACK);

	if (bind(sink_fd, (struct sockaddr *)&sin, sizeof(sin)) ||
	    getsockname(sink_fd, (struct sockaddr *)&sin, &sl))
		return 1;

	lws_snprintf(port, sizeof(port), "%u", ntohs(sin.sin_port));
	setenv("LWS_ASYNCDNS_PORT", port, 1);
	setenv("LWS_ASYNCDNS_RESOLV_CONF", "/nonexistent/resolv.conf", 1);

	return ctx_create();
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct lws_async_dns_server *dsrv;
	struct lws_async_dns *dns;
	struct lws_adns_q *q = NULL;
	adns_query_type_t qtype;
	uint16_t tid;
	uint8_t *pkt;
	size_t len;

	if (size < 1 + 12) /* selector + DNS header */
		return 0;

	if (iters++ && !(iters & 255)) {
		lws_context_destroy(cx);
		if (ctx_create())
			return 0;
	}

#if defined(LWS_WITH_SYS_ASYNC_DNS_DNSSEC)
	lws_async_dns_dnssec_set_mode(cx,
			(lws_async_dns_dnssec_mode_t)(data[0] & 3) > LWS_ADNS_DNSSEC_REQUIRE ?
				LWS_ADNS_DNSSEC_OFF :
				(lws_async_dns_dnssec_mode_t)(data[0] & 3));
#endif

	qtype = qtypes[(data[0] >> 2) & 3];
	done = 0;

	if (lws_async_dns_query(cx, 0, "fuzz.invalid",
				(adns_query_type_t)(qtype | LWS_ADNS_NOCACHE),
				adns_cb, NULL, &marker, &q) !=
						LADNS_RET_CONTINUING || !q)
		goto out;

	dns  = lws_adns_get_async_dns(q);
	dsrv = lws_adns_get_server(q);
	tid  = lws_adns_get_tid(q);

	/* let lws compose and send the query, so the pending state is real */

	service_once();
	drain_sink();

	len = size - 1;
	pkt = malloc(len);
	if (!pkt)
		goto out;
	memcpy(pkt, data + 1, len);

	/* q may be destroyed inside the parse; don't touch it afterwards */

	pkt[0] = (uint8_t)(tid >> 8);
	pkt[1] = (uint8_t)(tid & 0xfe);
	lws_adns_parse_udp(dns, pkt, len, dsrv);

	/* A / AAAA lookups want both answers before completing: send the
	 * same packet again as the AAAA half (tid low bit set) */

	if (!done && (qtype == LWS_ADNS_RECORD_A ||
		      qtype == LWS_ADNS_RECORD_AAAA)) {
		pkt[1] |= 1;
		lws_adns_parse_udp(dns, pkt, len, dsrv);
	}

	free(pkt);

out:
	/* anything still pending (unparseable, TCP fallback, sub-lookup)
	 * gets cancelled, and the loop runs once for the deferred work */

	if (!done)
		lws_async_dns_cancel_by_opaque(cx, &marker);

	service_once();
	drain_sink();

	return 0;
}
