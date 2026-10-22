/*
 * lws-api-test-async-dns-smp
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Async DNS with more than one service thread (LWS_MAX_SMP > 1).
 *
 * The resolver's state is shared by the whole context, and its sockets to
 * the nameserver land on whichever service thread is least busy, so a
 * lookup asked on one thread is usually answered on another.  A lookup
 * belongs to the thread it was asked on, though: its timers are on that
 * thread's pt, and its requesters live there.  Before G-526, the thread the
 * answer arrived on called the requesters back itself and freed the lookup,
 * unlinking its timers from the other pt's list without that pt's lock while
 * the other thread was using the list.
 *
 * Every wsi, client or accepted, is tagged into a lifecycle group list of the
 * context's when it is created and untagged from it when it is freed.  Before
 * G-549 a client connection was tagged without the context lock, on the
 * service thread asking for it, while the other thread could be tagging, or
 * untagging a wsi it had just closed, on the same list.  So both threads also
 * make and close connections at volume, at once, from their callbacks.
 *
 * Each service thread, at once and in rounds, asks:
 *
 *  - standalone lookups of names of its own,
 *
 *  - lookups of names both threads ask about at the same moment, and
 *
 *  - raw client connections to names of its own, which resolve to our own
 *    raw listener on 127.0.0.1,
 *
 * of a fake nameserver on loopback, run by a thread of our own, that answers
 * every A question with 127.0.0.1 as soon as it arrives.  Each round, each
 * also starts chains of raw client connections straight to 127.0.0.1, each
 * closed as soon as it connects, and its CONNECTED callback asking for the
 * next of its chain.  Every lookup must be answered with that address, every
 * connection must connect, and every callback, the lookups' and the
 * connections', must come on the service thread that asked.
 *
 * With LWS_MAX_SMP 1 there is only one service thread, and it only checks
 * the lookups and connections complete.  Under ASan, the SMP builds also
 * check nothing is used after it was freed.
 *
 * By default the fd tables are sized to the process fd limit, so an fd finds
 * its wsi by indexing a table with it.  --fd-limit-per-thread <n> sets a
 * smaller info.fd_limit_per_thread, which selects the small lookup scheme
 * instead, where fds are found by searching a table: before G-635 that
 * table was shared by all the threads, and searching it dereferenced every
 * wsi in it, including other threads' as they were freed, while two threads
 * inserting at once could take the same slot.  ctest runs it both ways.
 */

#include <libwebsockets.h>

#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define THREADS_MAX		2
#define ROUNDS			8
#define ROUND_US		(20 * LWS_US_PER_MS)
#define PER_ROUND_OWN		12	/* standalone lookups of our own names */
#define PER_ROUND_SHARED	4	/* names both threads ask about */
#define PER_ROUND_CONNS		4	/* raw client connections */
#define PER_ROUND_CHAINS	4	/* ... chains of them to 127.0.0.1 */
#define CHAIN_LEN		8	/* connections in a chain */
#define CONNS_PER_THREAD	(ROUNDS * (PER_ROUND_CONNS + \
					   PER_ROUND_CHAINS * CHAIN_LEN))

/* a connection's opaque user data: the tsi it asked on, and how many more of
 * its chain to ask for when it connects */
#define CONN_OPAQUE(tsi, more)	((void *)((intptr_t)(tsi) | \
					  ((intptr_t)(more) << 8)))
#define CONN_TSI(o)		((int)((intptr_t)(o) & 0xff))
#define CONN_MORE(o)		((int)((intptr_t)(o) >> 8))
#define DEADLINE_US		(20 * LWS_US_PER_SEC)
#define DOMAIN			"adns-smp.invalid"

static const uint8_t answer_ads[] = { 127, 0, 0, 1 };

struct svc {
	lws_sorted_usec_list_t	sul_round;
	pthread_t		self;	/* written and read on this thread */
	pthread_t		thread;
	int			tsi;
	int			round;
	int			self_set;
};

static struct svc svc[THREADS_MAX];
static struct lws_context *context;
static struct lws_vhost *vh;
static lws_sorted_usec_list_t sul_deadline;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static int threads, ns_fd = -1, raw_port;
static volatile int interrupted, ns_stop;

/* guarded by lock */
static int asked, answered, wrong_thread, wrong_ads, failed, conns_asked,
	   conns_done, conns_failed, accepted;

static void
count(int *what, int n)
{
	pthread_mutex_lock(&lock);
	*what += n;
	pthread_mutex_unlock(&lock);
}

static int
done(void)
{
	int r;

	pthread_mutex_lock(&lock);
	r = answered + failed == asked && conns_done + conns_failed ==
						conns_asked &&
	    conns_asked == threads * CONNS_PER_THREAD;
	pthread_mutex_unlock(&lock);

	return r;
}

static void
finish_if_done(void)
{
	if (!done())
		return;

	interrupted = 1;
	lws_cancel_service(context);
}

/* is the calling thread service thread tsi? */

static int
on_thread(int tsi)
{
	if (tsi < 0 || tsi >= threads || !svc[tsi].self_set ||
	    !pthread_equal(pthread_self(), svc[tsi].self)) {
		count(&wrong_thread, 1);
		lwsl_err("%s: called back on the wrong thread for tsi %d\n",
			 __func__, tsi);

		return 0;
	}

	return 1;
}

static struct lws *
lookup_cb(struct lws *wsi, const char *ads, const struct addrinfo *result,
	  int n, void *opaque)
{
	int tsi = (int)(intptr_t)opaque;
	const struct addrinfo *ai;
	int good = 0;

	on_thread(tsi);

	if (n < 0 || (n & ~LWS_ADNS_DNSSEC_VALID) != LADNS_RET_FOUND) {
		lwsl_err("%s: %s failed %d\n", __func__, ads ? ads : "?", n);
		count(&failed, 1);
		goto bail;
	}

	for (ai = result; ai; ai = ai->ai_next)
		if (ai->ai_family == AF_INET &&
		    !memcmp(&((const struct sockaddr_in *)ai->ai_addr)->
				sin_addr, answer_ads, 4))
			good = 1;

	if (!good) {
		lwsl_err("%s: %s: not our answer\n", __func__, ads);
		count(&wrong_ads, 1);
	}

	count(&answered, 1);

bail:
	lws_async_dns_freeaddrinfo(&result);
	finish_if_done();

	return wsi ? wsi : LADNS_NO_WSI_BUT_OK;
}

static void
ask(int tsi, const char *name)
{
	count(&asked, 1);

	if (lws_async_dns_query(context, tsi, name,
				(adns_query_type_t)(LWS_ADNS_RECORD_A |
					LWS_ADNS_NOCACHE |
					LWS_ADNS_IGNORE_HOSTS_FILE |
					LWS_ADNS_INDICATE_LACKS_DNSSEC),
				lookup_cb, NULL, (void *)(intptr_t)tsi, NULL) <
							LADNS_RET_CONTINUING)
		lwsl_notice("%s: %s did not start\n", __func__, name);
		/* lookup_cb() was told, and counted it */
}

static void
connect_to(int tsi, const char *name, int more)
{
	struct lws_client_connect_info i;

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh;
	i.address		= name;
	i.host			= name;
	i.port			= raw_port;
	i.method		= "RAW";
	i.protocol		= "adns-smp-raw";
	i.opaque_user_data	= CONN_OPAQUE(tsi, more);

	count(&conns_asked, 1);

	if (!lws_client_connect_via_info(&i))
		/* CLIENT_CONNECTION_ERROR already counted it */
		lwsl_info("%s: %s did not start\n", __func__, name);
}

static void
sul_round_cb(lws_sorted_usec_list_t *sul)
{
	struct svc *s = lws_container_of(sul, struct svc, sul_round);
	char name[64];
	int n;

	if (!s->self_set) {
		s->self = pthread_self();
		s->self_set = 1;
	}

	for (n = 0; n < PER_ROUND_OWN; n++) {
		lws_snprintf(name, sizeof(name), "t%d-r%d-%d." DOMAIN,
			     s->tsi, s->round, n);
		ask(s->tsi, name);
	}

	for (n = 0; n < PER_ROUND_SHARED; n++) {
		lws_snprintf(name, sizeof(name), "shared-r%d-%d." DOMAIN,
			     s->round, n);
		ask(s->tsi, name);
	}

	for (n = 0; n < PER_ROUND_CONNS; n++) {
		lws_snprintf(name, sizeof(name), "c%d-r%d-%d." DOMAIN,
			     s->tsi, s->round, n);
		connect_to(s->tsi, name, 0);
	}

	for (n = 0; n < PER_ROUND_CHAINS; n++)
		connect_to(s->tsi, "127.0.0.1", CHAIN_LEN - 1);

	if (++s->round < ROUNDS)
		lws_sul_schedule(context, s->tsi, &s->sul_round, sul_round_cb,
				 ROUND_US);
}

static void
sul_deadline_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("%s: timed out\n", __func__);
	interrupted = 1;
	lws_cancel_service(context);
}

static int
callback_raw(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	void *o;

	switch (reason) {
	case LWS_CALLBACK_RAW_ADOPT:
		/* the server side of one of our connections */
		count(&accepted, 1);
		break;

	case LWS_CALLBACK_RAW_CONNECTED:
		o = lws_get_opaque_user_data(wsi);
		if (on_thread(CONN_TSI(o)) && lws_get_tsi(wsi) != CONN_TSI(o))
			count(&wrong_thread, 1);
		count(&conns_done, 1);

		/*
		 * The next of a chain is asked for from here, in a service
		 * thread's callback, like a protocol making a connection in
		 * reaction to another
		 */
		if (CONN_MORE(o))
			connect_to(CONN_TSI(o), "127.0.0.1", CONN_MORE(o) - 1);
		finish_if_done();

		/* that's all we wanted */
		lws_set_timeout(wsi, PENDING_TIMEOUT_USER_OK, LWS_TO_KILL_ASYNC);
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: connection failed: %s\n", __func__,
			 in ? (const char *)in : "?");
		on_thread(CONN_TSI(lws_get_opaque_user_data(wsi)));
		count(&conns_failed, 1);
		finish_if_done();
		break;

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols protocols[] = {
	{ "adns-smp-raw", callback_raw, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

/*
 * The fake nameserver: answer every question, as soon as it arrives, A with
 * our address and anything else (the AAAA half of the pair) with an empty
 * NOERROR
 */

static void *
ns_thread(void *d)
{
	uint8_t pkt[512], resp[sizeof(pkt) + 16];
	struct sockaddr_storage peer;
	struct pollfd pfd;
	socklen_t pl;
	ssize_t r;
	size_t o;

	(void)d;

	pfd.fd = ns_fd;
	pfd.events = POLLIN;

	while (!ns_stop) {
		if (poll(&pfd, 1, 50) <= 0)
			continue;

		pl = sizeof(peer);
		r = recvfrom(ns_fd, (char *)pkt, sizeof(pkt), 0,
			     (struct sockaddr *)&peer, &pl);
		if (r < 12 + 5)
			continue;

		/* past the qname: a query's has no compression pointers */
		o = 12;
		while (o < (size_t)r && pkt[o] && pkt[o] < 64)
			o += (size_t)pkt[o] + 1;
		if (o + 5 > (size_t)r || pkt[o])
			continue;
		o += 5; /* the root label, QTYPE and QCLASS */

		memcpy(resp, pkt, o);
		resp[2] = 0x81;		/* QR + RD */
		resp[3] = 0x80;		/* RA, NOERROR */
		memset(&resp[6], 0, 6);	/* no answer, auth, additional */

		if (pkt[o - 4] == 0 && pkt[o - 3] == LWS_ADNS_RECORD_A) {
			resp[7] = 1;
			resp[o++] = 0xc0;	/* NAME: pointer to the qname */
			resp[o++] = 0x0c;
			resp[o++] = 0;
			resp[o++] = LWS_ADNS_RECORD_A;
			resp[o++] = 0;
			resp[o++] = 1;		/* CLASS IN */
			resp[o++] = 0;
			resp[o++] = 0;
			resp[o++] = 0;
			resp[o++] = 60;		/* TTL */
			resp[o++] = 0;
			resp[o++] = 4;		/* RDLENGTH */
			memcpy(&resp[o], answer_ads, 4);
			o += 4;
		}

		if (sendto(ns_fd, (const char *)resp, o, 0,
			   (struct sockaddr *)&peer, pl) < 0)
			lwsl_err("%s: sendto failed, errno %d\n", __func__,
				 errno);
	}

	return NULL;
}

static int
ns_socket(uint16_t *port)
{
	struct sockaddr_in sin;
	socklen_t sl = sizeof(sin);
	int fd = socket(AF_INET, SOCK_DGRAM, 0);

	if (fd < 0)
		return -1;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family		= AF_INET;
	sin.sin_addr.s_addr	= htonl(INADDR_LOOPBACK);

	if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) ||
	    getsockname(fd, (struct sockaddr *)&sin, &sl)) {
		close(fd);
		return -1;
	}

	*port = ntohs(sin.sin_port);

	return fd;
}

static void *
service_thread(void *d)
{
	struct svc *s = (struct svc *)d;

	while (!interrupted && lws_service_tsi(context, 0, s->tsi) >= 0)
		;

	return NULL;
}

int
main(int argc, const char **argv)
{
	static const char *servers[] = { "127.0.0.1", NULL };
	struct lws_context_creation_info info;
	pthread_t ns_pthread;
	char portstr[16];
	lws_sockaddr46 sa46;
	uint16_t ns_port;
	int n, index = 0, result = 1;
	const char *p;
	void *retval;

	lws_context_info_defaults(&info, NULL);
	info.default_loglevel	= LLL_USER | LLL_ERR | LLL_WARN;
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	lwsl_user("LWS API selftest: async dns with %d service threads\n",
		  LWS_MAX_SMP < THREADS_MAX ? LWS_MAX_SMP : THREADS_MAX);

	ns_fd = ns_socket(&ns_port);
	if (ns_fd < 0) {
		lwsl_err("%s: can't make the nameserver socket\n", __func__);
		return 1;
	}

	/* the resolver asks its nameservers on this port */
	lws_snprintf(portstr, sizeof(portstr), "%u", ns_port);
	setenv("LWS_ASYNCDNS_PORT", portstr, 1);

	if (pthread_create(&ns_pthread, NULL, ns_thread, NULL)) {
		lwsl_err("%s: can't start the nameserver\n", __func__);
		close(ns_fd);
		return 1;
	}

	info.port		= CONTEXT_PORT_NO_LISTEN;
	info.options		|= LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
	info.async_dns_servers	= servers;
	/*
	 * By default, size everything to the process fd limit, which has room
	 * for every connection, both ends, and the resolver's sockets.  A
	 * nonzero limit below that selects the small lookup scheme
	 */
	info.fd_limit_per_thread = 0;
	p = lws_cmdline_option(argc, argv, "--fd-limit-per-thread");
	if (p) {
		n = atoi(p);
		if (n <= 0) {
			lwsl_err("%s: bad --fd-limit-per-thread\n", __func__);
			goto bail_ns;
		}
		info.fd_limit_per_thread = (unsigned int)n;
		lwsl_user("%s: fd_limit_per_thread %u\n", __func__,
			  info.fd_limit_per_thread);
	}
	info.count_threads	= LWS_MAX_SMP < THREADS_MAX ? LWS_MAX_SMP :
								THREADS_MAX;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("%s: context creation failed\n", __func__);
		goto bail_ns;
	}

	threads = lws_get_count_threads(context);

	/* only our own nameserver */
	while (!lws_plat_asyncdns_get_server(context, index++, &sa46))
		lws_async_dns_server_remove(context, &sa46);

	/* the raw listener our connections resolve to */
	info.port		= 0;
	info.iface		= "127.0.0.1";
	info.protocols		= protocols;
	info.vhost_name		= "raw";
	info.options		= LWS_SERVER_OPTION_ADOPT_APPLY_LISTEN_ACCEPT_CONFIG;
	info.listen_accept_role	= "raw-skt";
	info.listen_accept_protocol = "adns-smp-raw";
	vh = lws_create_vhost(context, &info);
	if (!vh) {
		lwsl_err("%s: vhost creation failed\n", __func__);
		goto bail_cx;
	}
	raw_port = lws_get_vhost_listen_port(vh);

	for (n = 0; n < threads; n++) {
		svc[n].tsi = n;
		lws_sul_schedule(context, n, &svc[n].sul_round, sul_round_cb,
				 ROUND_US);
	}
	lws_sul_schedule(context, 0, &sul_deadline, sul_deadline_cb,
			 DEADLINE_US);

	for (n = 0; n < threads; n++)
		if (pthread_create(&svc[n].thread, NULL, service_thread,
				   &svc[n])) {
			lwsl_err("%s: can't start service thread\n", __func__);
			interrupted = 1;
			lws_cancel_service(context);
			break;
		}

	while (--n >= 0)
		pthread_join(svc[n].thread, &retval);

	lws_sul_cancel(&sul_deadline);
	for (n = 0; n < threads; n++)
		lws_sul_cancel(&svc[n].sul_round);

	lwsl_user("%d threads: %d lookups asked, %d answered, %d failed, "
		  "%d with the wrong address; %d connections, %d connected, "
		  "%d failed, %d accepted; %d callbacks on the wrong thread\n",
		  threads, asked, answered, failed, wrong_ads, conns_asked,
		  conns_done, conns_failed, accepted, wrong_thread);

	if (asked == threads * ROUNDS * (PER_ROUND_OWN + PER_ROUND_SHARED) &&
	    answered == asked && !failed && !wrong_ads &&
	    conns_asked == threads * CONNS_PER_THREAD &&
	    conns_done == conns_asked && !conns_failed && !wrong_thread)
		result = 0;

bail_cx:
	lws_context_destroy(context);

bail_ns:
	ns_stop = 1;
	pthread_join(ns_pthread, &retval);
	close(ns_fd);

	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
