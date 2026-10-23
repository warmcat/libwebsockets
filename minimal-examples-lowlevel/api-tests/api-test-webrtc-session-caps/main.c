/*
 * lws-api-test-webrtc-session-caps
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Every ws session on the lws-webrtc protocol (and the protocols built on
 * it, like the mixer) is opened by whoever likes, and holds a media object
 * and, once media flows, a tx pacer thread.  So the sessions are capped,
 * overall ("max-sessions") and per peer host ("max-sessions-per-host"), and
 * a session that never gets as far as media costs no thread (G-242).
 *
 * The lws-webrtc protocol is built in from the plugin source, on a vhost
 * with CAP_SESSIONS as the cap under test; ws clients in the same process,
 * all from the one loopback host, then
 *
 *  - open CAP_SESSIONS sessions, which must all be established, without the
 *    process gaining a thread (where we can count them)
 *  - open one more, which must be refused at the upgrade
 *  - close one of the first, and open another, which must be established,
 *    since a closed session stops counting
 *
 * --case host: the per-host cap is CAP_SESSIONS, the overall one is bigger
 * --case total: the overall cap is CAP_SESSIONS, the per-host one is bigger
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#if defined(__linux__)
#include <fcntl.h>
#include <unistd.h>
#endif

#define CAP_SESSIONS		2
#define DEADLINE_S		20

extern const struct lws_protocols webrtc_protocols[];

enum step {
	ST_FILL,	/* opening the first CAP_SESSIONS */
	ST_EXCESS,	/* opening one too many */
	ST_REOPEN,	/* closed one, opening its replacement */
	ST_DONE
};

static struct lws_context *context;
static struct lws_vhost *vh_cli;
static lws_sorted_usec_list_t sul_deadline, sul_reopen;
static struct lws *open_wsi[CAP_SESSIONS];
static const char *server_addr = "127.0.0.1";
static enum step step;
static int port = 7681, established, fails, done, threads_base = -1;

/*
 * How many threads the process has, from /proc on Linux, else -1: idle
 * sessions must not each hold a pacer thread
 */
static int
thread_count(void)
{
#if defined(__linux__)
	char buf[2048], *p;
	ssize_t n;
	int fd;

	fd = open("/proc/self/status", O_RDONLY);
	if (fd < 0)
		return -1;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return -1;
	buf[n] = '\0';

	p = strstr(buf, "\nThreads:");
	if (!p)
		return -1;

	return atoi(p + 9);
#else
	return -1;
#endif
}

static void
finish(const char *why, int fail)
{
	if (done)
		return;

	if (fail) {
		lwsl_err("%s\n", why);
		fails++;
	} else
		lwsl_user("%s\n", why);

	done = 1;
	lws_cancel_service(context);
}

static void
deadline_cb(lws_sorted_usec_list_t *sul)
{
	finish("deadline expired", 1);
}

static int
open_session(void);

static void
reopen_cb(lws_sorted_usec_list_t *sul)
{
	if (open_session())
		finish("connect failed", 1);
}

static int
open_session(void)
{
	struct lws_client_connect_info i;

	memset(&i, 0, sizeof(i));
	i.context	= context;
	i.vhost		= vh_cli;
	i.address	= server_addr;
	i.port		= port;
	i.path		= "/";
	i.host		= i.address;
	i.origin	= i.address;
	i.protocol	= "lws-webrtc";

	return !lws_client_connect_via_info(&i);
}

static void
next(void)
{
	int t;

	switch (step) {
	case ST_FILL:
		if (established < CAP_SESSIONS) {
			if (open_session())
				finish("connect failed", 1);
			break;
		}

		t = thread_count();
		if (threads_base >= 0 && t >= 0 && t != threads_base) {
			lwsl_err("%d idle sessions: %d threads, was %d\n",
				 established, t, threads_base);
			finish("idle sessions hold threads", 1);
			break;
		}

		step = ST_EXCESS;
		if (open_session())
			finish("connect failed", 1);
		break;

	case ST_EXCESS:
		/* refused, as it must be: free one, then try again */
		step = ST_REOPEN;
		lws_set_timeout(open_wsi[0], PENDING_TIMEOUT_USER_OK,
				LWS_TO_KILL_ASYNC);
		break;

	case ST_REOPEN:
		/* give the server side a moment to see the close */
		lws_sul_schedule(context, 0, &sul_reopen, reopen_cb,
				 250 * LWS_US_PER_MS);
		break;

	default:
		break;
	}
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	int n;

	switch (reason) {
	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		switch (step) {
		case ST_FILL:
			open_wsi[established++] = wsi;
			lwsl_user("session %d established\n", established);
			next();
			break;
		case ST_EXCESS:
			finish("session past the cap was established", 1);
			break;
		case ST_REOPEN:
			step = ST_DONE;
			finish("replacement session established", 0);
			break;
		default:
			break;
		}
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_user("connection refused: %s\n",
			  in ? (const char *)in : "(null)");
		if (step == ST_EXCESS) {
			lwsl_user("session past the cap refused\n");
			next();
		} else
			finish("session within the cap was refused", 1);
		break;

	case LWS_CALLBACK_CLIENT_CLOSED:
		for (n = 0; n < CAP_SESSIONS; n++)
			if (open_wsi[n] == wsi) {
				open_wsi[n] = NULL;
				if (step == ST_REOPEN && !n)
					next();
				else if (!done)
					finish("session closed early", 1);
			}
		break;

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols protocols_cli[] = {
	{ "lws-webrtc", callback_cli, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void
sigint_handler(int sig)
{
	finish("interrupted", 1);
}

int
main(int argc, const char **argv)
{
	struct lws_protocol_vhost_options pvo_cap_host, pvo_cap_total,
					  pvo_udp_port, pvo_webrtc, pvo_udp;
	const struct lws_protocols *protocols_srv[3];
	struct lws_context_creation_info info;
	const char *p, *ccase = "host";
	char cap[8], cap_big[8], udp_port[8];
	int n = 0;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	info.fd_limit_per_thread = 0;

	lws_strncpy(udp_port, "7682", sizeof(udp_port));
	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "-u")))
		lws_strncpy(udp_port, p, sizeof(udp_port));
	if ((p = lws_cmdline_option(argc, argv, "--server")))
		server_addr = p;
	if ((p = lws_cmdline_option(argc, argv, "--case"))) {
		if (strcmp(p, "host") && strcmp(p, "total")) {
			lwsl_err("--case host (default) | total\n");
			return 1;
		}
		ccase = p;
	}

	signal(SIGINT, sigint_handler);
	lwsl_user("LWS API selftest: webrtc session caps, case %s\n", ccase);

	lws_snprintf(cap, sizeof(cap), "%d", CAP_SESSIONS);
	lws_snprintf(cap_big, sizeof(cap_big), "%d", CAP_SESSIONS * 4);

	memset(&pvo_cap_host, 0, sizeof(pvo_cap_host));
	memset(&pvo_cap_total, 0, sizeof(pvo_cap_total));
	memset(&pvo_udp_port, 0, sizeof(pvo_udp_port));
	memset(&pvo_webrtc, 0, sizeof(pvo_webrtc));
	memset(&pvo_udp, 0, sizeof(pvo_udp));

	pvo_cap_host.name	= "max-sessions-per-host";
	pvo_cap_host.value	= strcmp(ccase, "host") ? cap_big : cap;
	pvo_cap_total.next	= &pvo_cap_host;
	pvo_cap_total.name	= "max-sessions";
	pvo_cap_total.value	= strcmp(ccase, "total") ? cap_big : cap;
	pvo_udp_port.next	= &pvo_cap_total;
	pvo_udp_port.name	= "udp-port";
	pvo_udp_port.value	= udp_port;

	pvo_webrtc.next		= &pvo_udp;
	pvo_webrtc.name		= "lws-webrtc";
	pvo_webrtc.options	= &pvo_udp_port;
	pvo_webrtc.value	= "";
	pvo_udp.name		= "lws-webrtc-udp";
	pvo_udp.value		= "";
	pvo_udp.options		= &pvo_udp_port; /* it only needs some */

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
		       LWS_SERVER_OPTION_CPD_BYPASS;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	protocols_srv[0] = &webrtc_protocols[0];
	protocols_srv[1] = &webrtc_protocols[1];
	protocols_srv[2] = NULL;

	info.port = port;
	info.vhost_name = "srv";
	info.pprotocols = protocols_srv;
	info.pvo = &pvo_webrtc;
	if (!lws_create_vhost(context, &info)) {
		lwsl_err("server vhost failed\n");
		goto bail;
	}

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.vhost_name = "cli";
	info.pprotocols = NULL;
	info.protocols = protocols_cli;
	info.pvo = NULL;
	vh_cli = lws_create_vhost(context, &info);
	if (!vh_cli) {
		lwsl_err("client vhost failed\n");
		goto bail;
	}

	lws_sul_schedule(context, 0, &sul_deadline, deadline_cb,
			 DEADLINE_S * LWS_US_PER_SEC);

	/* let the protocols init (cert, UDP socket) before we count threads */
	lws_service(context, 0);
	threads_base = thread_count();

	next();

	while (!done && n >= 0)
		n = lws_service(context, 0);

bail:
	lws_sul_cancel(&sul_deadline);
	lws_sul_cancel(&sul_reopen);
	lws_context_destroy(context);

	lwsl_user("Completed: %s\n", fails || !done ? "FAIL" : "PASS");

	return fails || !done;
}
