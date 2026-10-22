/*
 * lws-api-test-ss-endpoint-subst
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * A Secure Streams policy endpoint can take ${metadata}, so where a stream
 * connects to can be chosen at runtime.  A metadata value that came from
 * outside the process (an ss proxy client set it, or it was captured from a
 * server's response header) may fill in where in the network the stream
 * goes, but not take it out of the network: if it went into the endpoint,
 * a resulting file:// url, or a host that is a '+' unix domain socket
 * address, is refused, unless the policy wrote the file:// or '+' literally,
 * before the first ${.  Values the app set itself are not restricted.
 *
 * A raw socket server in the same process listens on tcp and on a unix
 * domain socket, answering any request with a 200 and noting it.  The
 * response carries an "x-ep:" header, that the streamtypes capture into the
 * metadata their endpoint uses.  Each phase is a stream of its own, with no
 * retries.  Phases with a captured value connect once with a value the app
 * set, capture the server's value, and connect again with that:
 *
 *  - endpoint "${ep}" with a captured file:// url, a '+' socket inside a url,
 *    the same with the socket in [], and a bare '+' socket: all refused,
 *    without connecting or opening anything
 *
 *  - endpoint "${ep}" with a captured ordinary url to our tcp server:
 *    connects
 *
 *  - endpoint "+${sock}" with a captured socket name: connects to our unix
 *    domain socket server, since the policy wrote the '+'
 *
 *  - endpoint "${ep}" with a file:// url the app set: the file is read as rx
 *
 *  - endpoint "${ep}" with a bare '+' socket the app set: connects to our
 *    unix domain socket server
 */

#include <libwebsockets.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>

enum {
	LWS_SW_SERVER,
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_SERVER]	= { "--server",	"Address of the tcp test server "
					"(default localhost)" },
	[LWS_SW_HELP]	= { "--help",	"Show this help information" },
};

enum {
	SSEP_REFUSED,
	SSEP_FILE,
	SSEP_SERVER,
};

enum {
	SSEP_ARG_FILE,		/* our file's name */
	SSEP_ARG_SOCK,		/* our unix domain socket's name */
	SSEP_ARG_HOST,		/* our tcp server's host:port */
};

typedef struct ssep_phase {
	const char		*name;
	const char		*streamtype;
	const char		*md_name;
	const char		*app_fmt;	/* what the app sets, taking arg */
	int			app_arg;	/* SSEP_ARG_ */
	const char		*cap_fmt;	/* NULL, or what the server sends */
	int			cap_arg;	/* SSEP_ARG_ */
	int			expect;		/* SSEP_, for the last attempt */
} ssep_phase_t;

static const ssep_phase_t phases[] = {
	{ "captured file://", "cap", "ep",
		"http://%s/x", SSEP_ARG_HOST,
		"file://%s", SSEP_ARG_FILE, SSEP_REFUSED },
	{ "captured + socket in a url", "cap", "ep",
		"http://%s/x", SSEP_ARG_HOST,
		"http://+%s:/x", SSEP_ARG_SOCK, SSEP_REFUSED },
	{ "captured [+ socket] in a url", "cap", "ep",
		"http://%s/x", SSEP_ARG_HOST,
		"http://[+%s]:/x", SSEP_ARG_SOCK, SSEP_REFUSED },
	{ "captured bare + socket", "cap", "ep",
		"http://%s/x", SSEP_ARG_HOST,
		"+%s", SSEP_ARG_SOCK, SSEP_REFUSED },
	{ "captured network url", "cap", "ep",
		"http://%s/x", SSEP_ARG_HOST,
		"http://%s/y", SSEP_ARG_HOST, SSEP_SERVER },
	{ "captured socket after literal +", "cap-uds", "sock",
		"%s", SSEP_ARG_SOCK,
		"%s", SSEP_ARG_SOCK, SSEP_SERVER },
	{ "app-set file://", "cap", "ep",
		"file://%s", SSEP_ARG_FILE,
		NULL, 0, SSEP_FILE },
	{ "app-set bare + socket", "cap", "ep",
		"+%s", SSEP_ARG_SOCK,
		NULL, 0, SSEP_SERVER },
};

#define SSEP_FILE_CONTENT "the file's content"

static struct lws_context *context;
static lws_state_notify_link_t nl;
static lws_sorted_usec_list_t sul_timeout, sul_next, sul_again;
static struct lws_ss_handle *cur_ss;
static const char *server_ads = "localhost";
static char file_name[64], sock_name[64], host_port[128], md_value[256],
	    rx[64];
static unsigned int cur_phase;
static int failed, phase_done, connected, server_asked, attempt,
	   await_reconnect;
static size_t rx_len;

static const char *
ssep_arg(int arg)
{
	switch (arg) {
	case SSEP_ARG_FILE:
		return file_name;
	case SSEP_ARG_SOCK:
		return sock_name;
	default:
		return host_port;
	}
}

/*
 * The raw socket server side
 */

typedef struct srv_pss {
	char			req[1024];
	size_t			req_len;
	char			answered;	/* 1: to send, 2: sent */
} srv_pss_t;

static int
callback_srv(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	const ssep_phase_t *ph = &phases[cur_phase];
	srv_pss_t *pss = (srv_pss_t *)user;
	char cap[256], *start;
	uint8_t buf[LWS_PRE + 512];
	int n;

	switch (reason) {
	case LWS_CALLBACK_RAW_RX:
		if (pss->answered)
			break;

		if (len > sizeof(pss->req) - 1 - pss->req_len) {
			lwsl_err("%s: request too large\n", __func__);
			return -1;
		}
		memcpy(pss->req + pss->req_len, in, len);
		pss->req_len += len;
		pss->req[pss->req_len] = '\0';

		if (!strstr(pss->req, "\r\n\r\n"))
			break; /* wait for the rest of the request headers */

		lwsl_user("%s: server was asked: %.*s\n", __func__,
			  (int)(strchr(pss->req, '\r') - pss->req), pss->req);
		server_asked++;
		pss->answered = 1;
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		if (!pss->answered)
			break;
		if (pss->answered == 2)
			/* the response has gone out, it said we close */
			return -1;

		/* the phase's value for the client to capture, if any */
		cap[0] = '\0';
		if (ph->cap_fmt)
			lws_snprintf(cap, sizeof(cap), ph->cap_fmt, /* NOSONAR: const test table */
				     ssep_arg(ph->cap_arg));

		start = (char *)buf + LWS_PRE;
		n = lws_snprintf(start, sizeof(buf) - LWS_PRE,
				 "HTTP/1.1 200 OK\r\n"
				 "%s%s%s"
				 "Content-Length: 2\r\n"
				 "Connection: close\r\n\r\nok",
				 cap[0] ? "x-ep: " : "", cap,
				 cap[0] ? "\r\n" : "");
		if (lws_write(wsi, (uint8_t *)start, (size_t)n,
			      LWS_WRITE_RAW) != n)
			return -1;

		pss->answered = 2;
		lws_callback_on_writable(wsi);
		break;

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols protocols_srv[] = {
	{ "ssep-srv", callback_srv, sizeof(srv_pss_t), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

/*
 * The Secure Streams client side
 */

typedef struct cli {
	struct lws_ss_handle	*ss;
	void			*opaque_data;
} cli_t;

static void
start_phase(lws_sorted_usec_list_t *sul);

static void
phase_finish(int ok)
{
	lwsl_user("--- phase %s: %s (connected %d, rx %d, server asked %d) "
		  "---\n", phases[cur_phase].name, ok ? "PASS" : "FAIL",
		  connected, (int)rx_len, server_asked);
	if (!ok)
		failed = 1;

	/* destroy the stream and go on from the event loop */
	lws_sul_schedule(context, 0, &sul_next, start_phase, 1);
}

/* connect again, now with the value the client captured */

static void
connect_again(lws_sorted_usec_list_t *sul)
{
	lws_ss_state_return_t r;

	lwsl_user("%s: phase %s, second attempt\n", __func__,
		  phases[cur_phase].name);

	attempt = 1;
	phase_done = connected = 0;
	rx_len = 0;

	/* a refused endpoint fails the connect attempt, it's not an error */
	r = lws_ss_client_connect(cur_ss);
	if (r < 0) {
		lwsl_err("%s: connect returned %d\n", __func__, (int)r);
		failed = 1;
		lws_default_loop_exit(context);
	}
}

/* an attempt ended one way or the other: judge it */

static void
attempt_end(int completed)
{
	const ssep_phase_t *ph = &phases[cur_phase];
	int ok = 0;

	if (phase_done)
		return;
	phase_done = 1;

	if (ph->cap_fmt && !attempt) {
		/*
		 * The first attempt, to the endpoint the app set, only has to
		 * get the server's response for its header to be captured;
		 * we connect again once it has disconnected
		 */
		if (!completed || server_asked != 1) {
			phase_finish(0);
			return;
		}
		await_reconnect = 1;
		return;
	}

	switch (ph->expect) {
	case SSEP_REFUSED:
		ok = !completed && !connected && !rx_len &&
		     server_asked == !!ph->cap_fmt;
		break;
	case SSEP_FILE:
		ok = completed && rx_len == strlen(SSEP_FILE_CONTENT) &&
		     !memcmp(rx, SSEP_FILE_CONTENT, rx_len);
		break;
	case SSEP_SERVER:
		ok = completed && server_asked == 1 + !!ph->cap_fmt;
		break;
	}

	phase_finish(ok);
}

static lws_ss_state_return_t
cli_rx(void *userobj, const uint8_t *buf, size_t len, int flags)
{
	if (len > sizeof(rx) - rx_len)
		len = sizeof(rx) - rx_len;
	if (len) /* an EOM may come with no payload */
		memcpy(rx + rx_len, buf, len);
	rx_len += len;

	if (phases[cur_phase].expect == SSEP_FILE && (flags & LWSSS_FLAG_EOM))
		attempt_end(1);

	return LWSSSSRET_OK;
}

static lws_ss_state_return_t
cli_state(void *userobj, void *sh, lws_ss_constate_t state,
	  lws_ss_tx_ordinal_t ack)
{
	cli_t *m = (cli_t *)userobj;

	lwsl_ss_user(m->ss, "%s", lws_ss_state_name(state));

	switch (state) {
	case LWSSSCS_CONNECTED:
		connected = 1;
		if (attempt && phases[cur_phase].expect == SSEP_REFUSED)
			/* it should never have got this far: fail it now */
			attempt_end(1);
		break;

	case LWSSSCS_QOS_ACK_REMOTE:
		attempt_end(1);
		break;

	case LWSSSCS_DISCONNECTED:
		if (await_reconnect) {
			await_reconnect = 0;
			lws_sul_schedule(context, 0, &sul_again, connect_again,
					 1);
		}
		break;

	case LWSSSCS_QOS_NACK_REMOTE:
	case LWSSSCS_UNREACHABLE:
	case LWSSSCS_ALL_RETRIES_FAILED:
		attempt_end(0);
		break;

	default:
		break;
	}

	return LWSSSSRET_OK;
}

static const lws_ss_info_t ssi_cli = {
	.handle_offset			= offsetof(cli_t, ss),
	.opaque_user_data_offset	= offsetof(cli_t, opaque_data),
	.rx				= cli_rx,
	.state				= cli_state,
	.user_alloc			= sizeof(cli_t),
};

static void
start_phase(lws_sorted_usec_list_t *sul)
{
	lws_ss_info_t ssi = ssi_cli;
	const ssep_phase_t *ph;
	lws_ss_state_return_t r;

	if (cur_ss) {
		/* the last phase's stream */
		lws_ss_destroy(&cur_ss);
		if (++cur_phase == LWS_ARRAY_SIZE(phases)) {
			lws_default_loop_exit(context);
			return;
		}
	}

	ph = &phases[cur_phase];
	lwsl_user("=== phase %s ===\n", ph->name);
	phase_done = connected = server_asked = attempt = await_reconnect = 0;
	rx_len = 0;

	/* the metadata is bound by reference, so it lives in a static */
	lws_snprintf(md_value, sizeof(md_value), ph->app_fmt, /* NOSONAR: const test table */
		     ssep_arg(ph->app_arg));

	ssi.streamtype = ph->streamtype;

	if (lws_ss_create(context, 0, &ssi, NULL, &cur_ss, NULL, NULL) ||
	    lws_ss_set_metadata(cur_ss, ph->md_name, md_value,
				strlen(md_value))) {
		lwsl_err("%s: unable to start phase\n", __func__);
		failed = 1;
		lws_default_loop_exit(context);
		return;
	}

	r = lws_ss_client_connect(cur_ss);
	if (r < 0) {
		lwsl_err("%s: connect returned %d\n", __func__, (int)r);
		failed = 1;
		lws_default_loop_exit(context);
	}
}

static int
app_system_state_nf(lws_state_manager_t *mgr, lws_state_notify_link_t *link,
		    int current, int target)
{
	if (current != LWS_SYSTATE_OPERATIONAL ||
	    target != LWS_SYSTATE_OPERATIONAL)
		return 0;

	/* start from the event loop, with the servers certainly listening */
	lws_sul_schedule(context, 0, &sul_next, start_phase, 1);

	return 0;
}

static lws_state_notify_link_t * const app_notifier_list[] = {
	&nl, NULL
};

static void
sul_timeout_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("--- timeout in phase %s ---\n",
		 cur_phase < LWS_ARRAY_SIZE(phases) ?
				phases[cur_phase].name : "(end)");
	failed = 1;
	lws_default_loop_exit(context);
}

static void
sigint_handler(int sig)
{
	failed = 1;
	lws_default_loop_exit(context);
}

/* the metadata captures the response's x-ep: header */

#define SSEP_ST(name, endpoint, md) \
	"{\"" name "\":{" \
	"\"endpoint\":\"" endpoint "\",\"port\":80,\"protocol\":\"h1\"," \
	"\"http_method\":\"GET\",\"http_url\":\"x\",\"retry\":\"none\"," \
	"\"metadata\":[{\"" md "\":\"x-ep:\"}]}}"

static const char * const policy =
	"{\"release\":\"01234567\",\"product\":\"myproduct\","
	 "\"schema-version\":1,"
	 "\"retry\":[{\"none\":{\"backoff\":[],"
		"\"conceal\":0,\"jitterpc\":0,"
		"\"svalidping\":30,\"svalidhup\":35}}],"
	 "\"s\":["
	  SSEP_ST("cap", "${ep}", "ep") ","
	  SSEP_ST("cap-uds", "+${sock}", "sock")
	 "]}";

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_vhost *vh;
	const char *p;
	int fd;

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches,
					LWS_ARRAY_SIZE(switches));
		return 0;
	}

	lws_context_info_defaults(&info, NULL);
	info.fd_limit_per_thread = 0;
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	if ((p = lws_cmdline_option(argc, argv, switches[LWS_SW_SERVER].sw)))
		server_ads = p;

	signal(SIGINT, sigint_handler);

	lwsl_user("LWS API selftest: SS endpoint substitution stays in the "
		  "network\n");

	/* the file and socket, in the cwd, named for us */

	lws_snprintf(file_name, sizeof(file_name), "ssep-%d.txt", (int)getpid());
	lws_snprintf(sock_name, sizeof(sock_name), "ssep-%d.sock", (int)getpid());

	fd = open(file_name, O_CREAT | O_TRUNC | O_WRONLY, 0600);
	if (fd < 0) {
		lwsl_err("can't create %s\n", file_name);
		return 1;
	}
	if (write(fd, SSEP_FILE_CONTENT, strlen(SSEP_FILE_CONTENT)) !=
					(ssize_t)strlen(SSEP_FILE_CONTENT)) {
		lwsl_err("can't write %s\n", file_name);
		close(fd);
		goto bail_file;
	}
	close(fd);

	nl.name				= "app";
	nl.notify_cb			= app_system_state_nf;

	info.options			= LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
					  LWS_SERVER_OPTION_CPD_BYPASS;
	info.port			= CONTEXT_PORT_NO_LISTEN;
	info.pss_policies_json		= policy;
	info.register_notifier_list	= app_notifier_list;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		goto bail_file;
	}

	/* the raw socket servers, on tcp (any port) and a unix socket */

	info.protocols		= protocols_srv;
	info.options		= LWS_SERVER_OPTION_ADOPT_APPLY_LISTEN_ACCEPT_CONFIG;
	info.listen_accept_role	= "raw-skt";
	info.listen_accept_protocol = "ssep-srv";

	info.vhost_name		= "ssep-tcp";
	info.port		= 0;
	vh = lws_create_vhost(context, &info);
	if (!vh) {
		lwsl_err("Failed to create the tcp server vhost\n");
		goto bail;
	}
	/* an IPv6 literal goes in a url in brackets */
	lws_snprintf(host_port, sizeof(host_port),
		     strchr(server_ads, ':') ? "[%s]:%d" : "%s:%d", server_ads,
		     lws_get_vhost_listen_port(vh));

	info.vhost_name		= "ssep-uds";
	info.options		|= LWS_SERVER_OPTION_UNIX_SOCK;
	info.iface		= sock_name;
	if (!lws_create_vhost(context, &info)) {
		lwsl_err("Failed to create the unix socket server vhost\n");
		goto bail;
	}

	lws_sul_schedule(context, 0, &sul_timeout, sul_timeout_cb,
			 20 * LWS_US_PER_SEC);

	lws_context_default_loop_run_destroy(context);

	if (cur_phase != LWS_ARRAY_SIZE(phases))
		failed = 1;

	goto out;

bail:
	failed = 1;
	lws_context_destroy(context);
out:
	unlink(sock_name);
bail_file:
	unlink(file_name);

	lwsl_user("Completed: %s\n", failed ? "FAIL" : "PASS");

	return failed;
}
