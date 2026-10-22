/*
 * lws-api-test-ws-server-threads-smp
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The minimal-ws-server-threads-smp example's protocol, built as the example
 * builds it, serves ws connections on two lws service threads (one if lws
 * was built with LWS_MAX_SMP 1), while its two "spam" threads add messages
 * to its ringbuffer and wake every service thread with lws_cancel_service().
 *
 * Clients in the same process keep connecting and closing, some as soon as
 * they are established, some after their first message, on both service
 * threads, for a few seconds, while another thread calls
 * lws_cancel_service() all the time as well, so each service thread is
 * walking its connections often while the other is opening and closing its
 * own.
 *
 * The test fails if anything crashes (run it under ASan), any client fails
 * to connect, any message is not one the example sends, or not enough
 * connections and messages happen.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>

#define LWS_PLUGIN_STATIC
#include "../../ws-server/minimal-ws-server-threads-smp/protocol_lws_minimal.c"

#define THREADS_MAX	2
#define CHURNERS	24	/* clients connecting and closing at once */
#define RUN_US		(5 * LWS_US_PER_SEC)
#define POKE_US		500	/* how often the poker thread wakes lws */
#define MIN_CONNS	200	/* we must see at least this many... */
#define MIN_MSGS	10	/* ...and this many messages */

struct churner {
	lws_sorted_usec_list_t	sul;
	struct lws		*wsi;
	int			tsi;
	int			idx;
	int			round;
};

struct svc {
	pthread_t		thread;
	int			tsi;
};

static struct lws_context *context;
static struct lws_vhost *vh_cli;
static struct churner churners[CHURNERS];
static struct svc svc[THREADS_MAX];
static lws_sorted_usec_list_t sul_stop;
static const char *server_address = "localhost";
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static int port, threads, conns, msgs, bad_msgs, conn_errors;
static volatile int stopping, interrupted;

static void
count(int *what)
{
	pthread_mutex_lock(&lock);
	(*what)++;
	pthread_mutex_unlock(&lock);
}

/* runs on the churner's own service thread */

static void
churner_connect_cb(lws_sorted_usec_list_t *sul)
{
	struct churner *ch = lws_container_of(sul, struct churner, sul);
	struct lws_client_connect_info i;

	if (stopping)
		return;

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli;
	i.address		= server_address;
	i.port			= port;
	i.path			= "/";
	i.host			= i.address;
	i.origin		= i.address;
	i.protocol		= "lws-minimal";
	i.local_protocol_name	= "smp-client";
	i.opaque_user_data	= ch;
	i.pwsi			= &ch->wsi;

	if (!lws_client_connect_via_info(&i)) {
		count(&conn_errors);
		/* try again in a moment */
		lws_sul_schedule(context, ch->tsi, &ch->sul,
				 churner_connect_cb, 10 * LWS_US_PER_MS);
	}
}

static int
callback_smp_client(struct lws *wsi, enum lws_callback_reasons reason,
		    void *user, void *in, size_t len)
{
	struct churner *ch = (struct churner *)lws_get_opaque_user_data(wsi);
	static const char prefix[] = "svc, test: tid: ";

	if (!ch)
		return lws_callback_http_dummy(wsi, reason, user, in, len);

	switch (reason) {
	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		count(&conns);
		/* half of them go again straight away */
		if ((ch->idx + ch->round++) & 1)
			lws_set_timeout(wsi, PENDING_TIMEOUT_USER_OK,
					LWS_TO_KILL_ASYNC);
		break;

	case LWS_CALLBACK_CLIENT_RECEIVE:
		if (len < sizeof(prefix) - 1 ||
		    memcmp(in, prefix, sizeof(prefix) - 1)) {
			lwsl_err("%s: unexpected message %.*s\n", __func__,
				 (int)len, (const char *)in);
			count(&bad_msgs);
		} else
			count(&msgs);
		/* the other half go after their first message */
		return -1;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: connection error %s\n", __func__,
			 in ? (const char *)in : "");
		count(&conn_errors);
		/* fallthru */
	case LWS_CALLBACK_CLIENT_CLOSED:
		ch->wsi = NULL;
		/* go again, from our own service thread */
		if (!stopping)
			lws_sul_schedule(context, ch->tsi, &ch->sul,
					 churner_connect_cb, 1);
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols_srv[] = {
	{ "http", lws_callback_http_dummy, 0, 0, 0, NULL, 0 },
	LWS_PLUGIN_PROTOCOL_MINIMAL,
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_cli[] = {
	{ "smp-client", callback_smp_client, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocol_vhost_options pvo_config = {
	NULL, NULL, "config", "test"
};

static const struct lws_protocol_vhost_options pvo = {
	NULL, &pvo_config, "lws-minimal", ""
};

static void
stop_cb(lws_sorted_usec_list_t *sul)
{
	stopping = 1;
	interrupted = 1;
	lws_cancel_service(context);
}

static void *
service_thread(void *d)
{
	struct svc *s = (struct svc *)d;

	while (!interrupted && lws_service_tsi(context, 0, s->tsi) >= 0)
		;

	return NULL;
}

/* wakes every service thread all the time, as a busy spam thread would */

static void *
poke_thread(void *d)
{
	while (!interrupted) {
		lws_cancel_service(context);
		usleep(POKE_US);
	}

	return NULL;
}

static void
sigint_handler(int sig)
{
	interrupted = 1;
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_vhost *vh;
	pthread_t poker;
	const char *p;
	int n, result = 1, poking = 0;
	void *retval;

	signal(SIGINT, sigint_handler);

	lws_context_info_defaults(&info, NULL);
	info.fd_limit_per_thread = 0;
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	if ((p = lws_cmdline_option(argc, argv, "--server")))
		server_address = p;

	info.options |= LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
	info.count_threads = LWS_MAX_SMP < THREADS_MAX ? LWS_MAX_SMP :
							 THREADS_MAX;

	lwsl_user("LWS API selftest: ws-server-threads-smp protocol, "
		  "%d service threads\n", info.count_threads);

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}
	threads = lws_get_count_threads(context);

	/* the example's protocol, on a random port */
	info.port = 0;
	info.vhost_name = "smp";
	info.protocols = protocols_srv;
	info.pvo = &pvo;
	vh = lws_create_vhost(context, &info);
	if (!vh) {
		lwsl_err("Failed to create server vhost\n");
		goto bail;
	}
	port = lws_get_vhost_listen_port(vh);

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.vhost_name = "cli";
	info.protocols = protocols_cli;
	info.pvo = NULL;
	vh_cli = lws_create_vhost(context, &info);
	if (!vh_cli) {
		lwsl_err("Failed to create client vhost\n");
		goto bail;
	}

	/* the churners start on every service thread */
	for (n = 0; n < CHURNERS; n++) {
		churners[n].idx = n;
		churners[n].tsi = n % threads;
		lws_sul_schedule(context, churners[n].tsi, &churners[n].sul,
				 churner_connect_cb, 1 + n);
	}
	lws_sul_schedule(context, 0, &sul_stop, stop_cb, RUN_US);

	if (!pthread_create(&poker, NULL, poke_thread, NULL))
		poking = 1;

	for (n = 0; n < threads; n++) {
		svc[n].tsi = n;
		if (pthread_create(&svc[n].thread, NULL, service_thread,
				   &svc[n])) {
			lwsl_err("%s: can't start service thread\n", __func__);
			interrupted = 1;
			lws_cancel_service(context);
			break;
		}
	}

	while (--n >= 0)
		pthread_join(svc[n].thread, &retval);
	if (poking)
		pthread_join(poker, &retval);

	lwsl_user("%d threads: %d connections, %d messages, %d bad messages, "
		  "%d connection errors\n", threads, conns, msgs, bad_msgs,
		  conn_errors);

	if (conns >= MIN_CONNS && msgs >= MIN_MSGS && !bad_msgs &&
	    !conn_errors)
		result = 0;

bail:
	lws_sul_cancel(&sul_stop);
	for (n = 0; n < CHURNERS; n++)
		lws_sul_cancel(&churners[n].sul);

	lws_context_destroy(context);

	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
