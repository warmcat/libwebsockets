/*
 * lws-api-test-quic-smp
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * h3 over QUIC with more than one service thread (LWS_MAX_SMP > 1).
 *
 * A QUIC connection belongs to the service thread of its network wsi: its
 * socket is serviced there, and so must its timers be, the probe timeout,
 * the pacer, the delayed ACK and the rest.  Before G-536 the probe timeout
 * and the pacer were always scheduled on pt 0, so for a connection on
 * another thread they ran on pt 0's thread while the connection's own thread
 * was using it, and its own thread cancelled them off pt 0's list without
 * pt 0's lock while pt 0's thread was changing the list.
 *
 * The TLS session cache is shared by the whole vhost, and the connections
 * of both threads to the same server offer, replace and resume the same
 * entry.  Before G-537 an entry's expiry timer was scheduled on the pt of
 * whichever connection last offered it, moving it between pt lists, and
 * cancelled without any pt lock.
 *
 * Both service threads start at once, so they both find the vhosts'
 * protocols not yet initialised.  Before G-542 nothing serialised that: both
 * could initialise the same vhosts, or one went on servicing, and making
 * connections, while the other was still initialising.  Every protocol must
 * see PROTOCOL_INIT exactly once per vhost, and the client protocol nothing
 * about a connection before it.  The first PROTOCOL_INIT takes its time, so
 * a thread not waiting for it makes its first connections meanwhile.
 *
 * A server vhost listening on both families with IPV6_V6ONLY has an IPv6
 * and an IPv4 QUIC listener.  A client that connects over IPv6 and migrates
 * to the server's IPv4 preferred address arrives on the IPv4 listener, which
 * finds the connection among the IPv6 listener's and drives it.  Before
 * G-544 the two listeners went on whichever threads were least busy, so the
 * IPv4 listener's thread could drive a connection belonging to the other
 * one's thread while that thread did too.
 *
 * Each service thread, at once and in rounds, opens h3 client connections
 * of its own (no pipelining, so each is a QUIC connection of its own) to an
 * h3 server vhost in the same process, and fetches a body big enough to
 * keep data in flight across several round trips.  With IPv6, each also
 * opens one to the dual stack vhost over IPv6, whose body is only sent once
 * the client has moved to IPv4.  Every fetch must complete with the whole
 * body, every client callback must come on the service thread that asked
 * for the connection, and every server callback on the thread of its
 * connection.
 *
 * With LWS_MAX_SMP 1 there is only one service thread, and it only checks
 * the fetches complete.  Under ASan, the SMP builds also check nothing is
 * used after it was freed.
 */

#include <libwebsockets.h>

#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>

#define QSMP_THREADS_MAX	2
#define QSMP_ROUNDS		4
#define QSMP_ROUND_US		(30 * LWS_US_PER_MS)
#define QSMP_PER_ROUND_PLAIN	4	/* connections per thread per round */
#if defined(LWS_WITH_IPV6)
#define QSMP_PER_ROUND_MIG	1	/* ... of them migrating to IPv4 */
#else
#define QSMP_PER_ROUND_MIG	0
#endif
#define QSMP_PER_ROUND		(QSMP_PER_ROUND_PLAIN + QSMP_PER_ROUND_MIG)
#define QSMP_MIG_WAIT_US	(20 * LWS_US_PER_MS)
#define QSMP_MIG_WAITS		250	/* at most 5s for a client to move */
#define QSMP_CHUNK		4096
#define QSMP_CHUNKS		24	/* the body is QSMP_CHUNKS * QSMP_CHUNK */
#define QSMP_DEADLINE_US	(40 * LWS_US_PER_SEC)
#define QSMP_HOST		"localhost"
#if defined(LWS_WITH_IPV6)
#define QSMP_VHOSTS		3	/* each with one protocol to init */
#else
#define QSMP_VHOSTS		2
#endif

enum qsmp_mode {
	QSMP_MODE_PLAIN,
	QSMP_MODE_MIGRATE,	/* to the dual stack server, over IPv6 */
};

/* a client's opaque user data: the tsi it asked on, and its mode */
#define QSMP_OPAQUE(tsi, mode)	((void *)((intptr_t)(tsi) | \
					  ((intptr_t)(mode) << 8)))
#define QSMP_TSI(o)		((int)((intptr_t)(o) & 0xff))
#define QSMP_MODE(o)		((int)((intptr_t)(o) >> 8))

struct qsmp_svc {
	lws_sorted_usec_list_t	sul_round;
	pthread_t		self;	/* guarded by lock */
	pthread_t		thread;
	int			tsi;
	int			round;
	int			self_set; /* guarded by lock */
};

struct qsmp_pss_srv {
	int			sent;	/* chunks */
	int			waits;	/* for the client to migrate */
};

struct qsmp_pss_cli {
	size_t			rx;
	int			established;
	int			done;
};

static struct qsmp_svc svc[QSMP_THREADS_MAX];
static struct lws_context *context;
static struct lws_vhost *vh_cli, *vh_dual;
static lws_sorted_usec_list_t sul_deadline;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static int threads, port = 7710, port_dual = 7711;
static volatile int interrupted;

/* guarded by lock */
static int asked, completed, failed, short_body, wrong_thread, served,
	   inits, migrated, not_migrated;

/* guarded by lock: the client protocol is initialised, callbacks before it */
static int cli_inited, cli_early;

static void
qsmp_count(int *what, int n)
{
	pthread_mutex_lock(&lock);
	*what += n;
	pthread_mutex_unlock(&lock);
}

static void
qsmp_finish_if_done(void)
{
	int r;

	pthread_mutex_lock(&lock);
	r = asked == threads * QSMP_ROUNDS * QSMP_PER_ROUND &&
	    completed + failed == asked;
	pthread_mutex_unlock(&lock);

	if (!r)
		return;

	interrupted = 1;
	lws_cancel_service(context);
}

/* is the calling thread service thread tsi? */

static int
qsmp_on_thread(int tsi)
{
	int r;

	pthread_mutex_lock(&lock);
	r = tsi >= 0 && tsi < threads && svc[tsi].self_set &&
	    pthread_equal(pthread_self(), svc[tsi].self);
	pthread_mutex_unlock(&lock);

	if (!r) {
		qsmp_count(&wrong_thread, 1);
		lwsl_err("%s: called back on the wrong thread for tsi %d\n",
			 __func__, tsi);

		return 0;
	}

	return 1;
}

/*
 * The first PROTOCOL_INIT, if it is on a service thread, holds on until every
 * service thread is running, then for longer than it takes them to start
 * their first round of connections, had they not waited for it
 */

static void
qsmp_slow_init(void)
{
	static int once;
	int n, on_svc = 0, started = 0, waits = 0;

	pthread_mutex_lock(&lock);
	if (!once++)
		for (n = 0; n < threads; n++)
			if (svc[n].self_set &&
			    pthread_equal(pthread_self(), svc[n].self))
				on_svc = 1;
	pthread_mutex_unlock(&lock);

	if (!on_svc)
		return;

	while (!started && waits++ < 2000) {
		pthread_mutex_lock(&lock);
		for (started = 1, n = 0; n < threads; n++)
			if (!svc[n].self_set)
				started = 0;
		pthread_mutex_unlock(&lock);
		if (!started)
			usleep(1000);
	}

	usleep(3 * QSMP_ROUND_US);
}

/* the client protocol hears of a connection: it must be initialised */

static void
qsmp_cli_check_inited(void)
{
	pthread_mutex_lock(&lock);
	if (!cli_inited)
		cli_early++;
	pthread_mutex_unlock(&lock);
}

/* the server: a body of QSMP_CHUNKS chunks */

static int
callback_srv(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	struct qsmp_pss_srv *pss = (struct qsmp_pss_srv *)user;
	uint8_t buf[LWS_PRE + QSMP_CHUNK], *start = &buf[LWS_PRE], *p = start,
		*end = &buf[sizeof(buf) - 1];
	int n;

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT:
		qsmp_count(&inits, 1);
		qsmp_slow_init();
		break;

	case LWS_CALLBACK_HTTP:
		qsmp_on_thread(lws_get_tsi(wsi));
		qsmp_count(&served, 1);
		pss->sent = 0;
		pss->waits = 0;

		if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
				"application/octet-stream",
				(lws_filepos_t)QSMP_CHUNKS * QSMP_CHUNK,
				&p, end) ||
		    lws_finalize_write_http_header(wsi, start, &p, end))
			return -1;

		lws_callback_on_writable(wsi);
		return 0;

	case LWS_CALLBACK_TIMER:
		qsmp_on_thread(lws_get_tsi(wsi));
		lws_callback_on_writable(wsi);
		return 0;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		if (!pss || pss->sent >= QSMP_CHUNKS)
			break;

		qsmp_on_thread(lws_get_tsi(wsi));

		if (lws_get_vhost(wsi) == vh_dual && !pss->sent) {
			char peer[64];

			/*
			 * The client came over IPv6 and is told to move to
			 * our IPv4 preferred address: the body waits for it
			 * to have moved, so it is sent, and acked, through
			 * the IPv4 listener
			 */
			lws_get_peer_simple(wsi, peer, sizeof(peer));
			if (strcmp(peer, "127.0.0.1")) {
				if (++pss->waits < QSMP_MIG_WAITS) {
					lws_set_timer_usecs(wsi,
							    QSMP_MIG_WAIT_US);
					return 0;
				}
				lwsl_err("%s: client stayed on %s\n",
					 __func__, peer);
				qsmp_count(&not_migrated, 1);
			} else
				qsmp_count(&migrated, 1);
		}

		memset(start, 'a' + (pss->sent % 26), QSMP_CHUNK);
		n = ++pss->sent == QSMP_CHUNKS ? LWS_WRITE_HTTP_FINAL :
						 LWS_WRITE_HTTP;
		if (lws_write(wsi, start, QSMP_CHUNK,
			      (enum lws_write_protocol)n) != QSMP_CHUNK)
			return -1;

		if (pss->sent == QSMP_CHUNKS) {
			if (lws_http_transaction_completed(wsi))
				return -1;
			return 0;
		}

		lws_callback_on_writable(wsi);
		return 0;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

/* the clients */

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	struct qsmp_pss_cli *pss = (struct qsmp_pss_cli *)user;
	void *o = lws_get_opaque_user_data(wsi);
	int tsi = QSMP_TSI(o);
	char buf[LWS_PRE + 1024], *px = buf + LWS_PRE;
	int lenx = (int)sizeof(buf) - LWS_PRE;

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT:
		pthread_mutex_lock(&lock);
		inits++;
		cli_inited = 1;
		pthread_mutex_unlock(&lock);
		break;

	case LWS_CALLBACK_CLIENT_HTTP_BIND_PROTOCOL:
		qsmp_cli_check_inited();
		break;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		qsmp_cli_check_inited();
		qsmp_on_thread(tsi);
		if (pss)
			pss->established = 1;
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		qsmp_on_thread(tsi);
		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;
		return 0;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		pss->rx += len;
		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		if (!pss || pss->done)
			break;
		pss->done = 1;
		qsmp_on_thread(tsi);
		if (pss->rx != (size_t)QSMP_CHUNKS * QSMP_CHUNK) {
			lwsl_err("%s: body %u, want %u\n", __func__,
				 (unsigned int)pss->rx,
				 (unsigned int)(QSMP_CHUNKS * QSMP_CHUNK));
			qsmp_count(&short_body, 1);
		}
		qsmp_count(&completed, 1);
		qsmp_finish_if_done();
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: mode %d: connection error: %s\n", __func__,
			 QSMP_MODE(o), in ? (const char *)in : "(null)");
		qsmp_cli_check_inited();
		qsmp_on_thread(tsi);
		if (pss) {
			if (pss->done)
				break;
			pss->done = 1;
		}
		qsmp_count(&failed, 1);
		qsmp_finish_if_done();
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		/*
		 * Only one of our requests: the h3 connection's control and
		 * qpack streams close on this protocol too, when it closes
		 * after its kept-warm time
		 */
		if (!pss || !pss->established || pss->done)
			break;
		lwsl_err("%s: mode %d: closed before completing\n", __func__,
			 QSMP_MODE(o));
		pss->done = 1;
		qsmp_count(&failed, 1);
		qsmp_finish_if_done();
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols_srv[] = {
	{ "qsmp", callback_srv, sizeof(struct qsmp_pss_srv), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_cli[] = {
	{ "qsmp", callback_cli, sizeof(struct qsmp_pss_cli), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void
qsmp_connect(int tsi, enum qsmp_mode mode)
{
	int dual = mode == QSMP_MODE_MIGRATE;
	struct lws_client_connect_info i;
	struct lws *wsi;

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli;
	i.address		= dual ? "::1" : "127.0.0.1";
	i.host			= QSMP_HOST;
	i.origin		= QSMP_HOST;
	i.port			= dual ? port_dual : port;
	i.path			= "/";
	i.method		= "GET";
	i.protocol		= "qsmp";
	i.alpn			= "h3";
	i.opaque_user_data	= QSMP_OPAQUE(tsi, mode);
	i.ssl_connection	= LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED |
				  LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
	/* it is the QUIC connection we are testing, not a fallback to tcp */
	i.disable_h3_fallback	= 1;

	qsmp_count(&asked, 1);

	wsi = lws_client_connect_via_info(&i);
	if (!wsi)
		/* CLIENT_CONNECTION_ERROR already counted it */
		lwsl_notice("%s: connection did not start\n", __func__);
	else if (lws_get_tsi(wsi) != tsi) {
		lwsl_err("%s: connection on tsi %d, asked on %d\n", __func__,
			 lws_get_tsi(wsi), tsi);
		qsmp_count(&wrong_thread, 1);
	}
}

static void
sul_round_cb(lws_sorted_usec_list_t *sul)
{
	struct qsmp_svc *s = lws_container_of(sul, struct qsmp_svc, sul_round);
	int n;

	for (n = 0; n < QSMP_PER_ROUND; n++)
		qsmp_connect(s->tsi, n < QSMP_PER_ROUND_PLAIN ?
					QSMP_MODE_PLAIN : QSMP_MODE_MIGRATE);

	if (++s->round < QSMP_ROUNDS)
		lws_sul_schedule(context, s->tsi, &s->sul_round, sul_round_cb,
				 QSMP_ROUND_US);
}

static void
sul_deadline_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("%s: timed out\n", __func__);
	interrupted = 1;
	lws_cancel_service(context);
}

static void *
service_thread(void *d)
{
	struct qsmp_svc *s = (struct qsmp_svc *)d;

	pthread_mutex_lock(&lock);
	s->self = pthread_self();
	s->self_set = 1;
	pthread_mutex_unlock(&lock);

	while (!interrupted && lws_service_tsi(context, 0, s->tsi) >= 0)
		;

	return NULL;
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p, *cert, *key;
#if defined(LWS_WITH_IPV6)
	char pref[32];
#endif
	int n, result = 1;
	void *retval;

	lws_context_info_defaults(&info, NULL);
	info.default_loglevel	= LLL_USER | LLL_ERR | LLL_WARN;
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--port-dual")))
		port_dual = atoi(p);
	cert = lws_cmdline_option(argc, argv, "--cert");
	key = lws_cmdline_option(argc, argv, "--key");
	if (!cert || !key) {
		lwsl_err("--cert and --key are required\n");
		return 1;
	}

	lwsl_user("LWS API selftest: h3 / QUIC with %d service threads\n",
		  LWS_MAX_SMP < QSMP_THREADS_MAX ? LWS_MAX_SMP :
						   QSMP_THREADS_MAX);

	info.options		= LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
				  LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	/* a server, and both ends of every connection */
	info.fd_limit_per_thread = 0;
	info.count_threads	= LWS_MAX_SMP < QSMP_THREADS_MAX ? LWS_MAX_SMP :
							QSMP_THREADS_MAX;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("%s: context creation failed\n", __func__);
		return 1;
	}

	threads = lws_get_count_threads(context);

	/* the h3 server: an alpn naming h3 brings up a quic listener */

	info.port			= port;
	info.iface			= "127.0.0.1";
	info.protocols			= protocols_srv;
	info.ssl_cert_filepath		= cert;
	info.ssl_private_key_filepath	= key;
	info.alpn			= "h3";
	info.vhost_name			= QSMP_HOST;
	if (!lws_create_vhost(context, &info)) {
		lwsl_err("%s: server vhost creation failed\n", __func__);
		goto bail;
	}

#if defined(LWS_WITH_IPV6)
	/*
	 * The dual stack h3 server: on both families, with IPV6_V6ONLY so each
	 * has a QUIC listener of its own, telling clients to move to IPv4
	 */

	lws_snprintf(pref, sizeof(pref), "127.0.0.1:%d", port_dual);
	info.port			= port_dual;
	info.iface			= NULL;
	info.options			|= LWS_SERVER_OPTION_IPV6_V6ONLY_MODIFY |
					   LWS_SERVER_OPTION_IPV6_V6ONLY_VALUE;
	info.quic_preferred_addresses	= pref;
	vh_dual = lws_create_vhost(context, &info);
	if (!vh_dual) {
		lwsl_err("%s: dual stack vhost creation failed\n", __func__);
		goto bail;
	}
	info.options			&= ~(uint64_t)
					(LWS_SERVER_OPTION_IPV6_V6ONLY_MODIFY |
					 LWS_SERVER_OPTION_IPV6_V6ONLY_VALUE);
	info.quic_preferred_addresses	= NULL;
#endif

	/* the client vhost, whose tls session cache both threads share */

	info.port			= CONTEXT_PORT_NO_LISTEN;
	info.iface			= NULL;
	info.ssl_cert_filepath		= NULL;
	info.ssl_private_key_filepath	= NULL;
	info.alpn			= NULL;
	info.protocols			= protocols_cli;
	info.vhost_name			= "cli";
	vh_cli = lws_create_vhost(context, &info);
	if (!vh_cli) {
		lwsl_err("%s: client vhost creation failed\n", __func__);
		goto bail;
	}

	for (n = 0; n < threads; n++) {
		svc[n].tsi = n;
		lws_sul_schedule(context, n, &svc[n].sul_round, sul_round_cb,
				 QSMP_ROUND_US);
	}
	lws_sul_schedule(context, 0, &sul_deadline, sul_deadline_cb,
			 QSMP_DEADLINE_US);

	/* the vhosts' protocols are initialised by the service threads */

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

	lwsl_user("%d threads: %d connections, %d completed, %d failed, %d "
		  "short; %d served; %d callbacks on the wrong thread; %d "
		  "protocol inits, %d client callbacks before its init; %d "
		  "migrated, %d did not\n", threads, asked, completed, failed,
		  short_body, served, wrong_thread, inits, cli_early, migrated,
		  not_migrated);

	if (asked == threads * QSMP_ROUNDS * QSMP_PER_ROUND &&
	    completed == asked && !failed && !short_body && !wrong_thread &&
	    inits == QSMP_VHOSTS && !cli_early && !not_migrated &&
	    migrated == threads * QSMP_ROUNDS * QSMP_PER_ROUND_MIG)
		result = 0;

bail:
	lws_context_destroy(context);

	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
