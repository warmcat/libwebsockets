/*
 * lws-api-test-log-ship
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Drives a log shipper (lib/misc/log-ship) against the lws-log-ingest plugin,
 * built in, both in this one process: the shipper connects to the ingestor
 * over ws on loopback, and we use the ingestor's http api as an agent would,
 * the lws-login result stamped in the headers a trusted front end would send.
 *
 *  - the api refuses a request with no login state (403), and a session
 *    started with a body that isn't JSON (415)
 *
 *  - a shipper with the wrong secret is disconnected, and never listed
 *
 *  - the shipper connects and sends nothing until a session is started
 *
 *  - a session starting 30s in the past gets a line logged before it started,
 *    from the shipper's backlog, and a line logged at info while it's open,
 *    which is only logged because the session raised the level to info (or
 *    notice, in a build without info logs; a build with neither can't raise)
 *
 *  - once the session ends, info is no longer logged, and a line logged then
 *    is never sent
 *
 *  - the sync view lists the shipper's pane, and the pane has its lines
 *
 *  - a session can be stopped early
 */

#include <libwebsockets.h>

#define LWS_PLUGIN_STATIC
#include "protocol_lws_log_ingest.c"

#include <signal.h>
#include <unistd.h>

#define SECRET		"api-test-log-ship-secret"
#define RX_MAX		(64 * 1024)
#define POLL_TRIES	50
#define POLL_US		(200 * LWS_US_PER_MS)
#define SESSION_SECS	3

/* the level the session raises us to: the most the build has, past notice */
#if (_LWS_ENABLED_LOGS) & LLL_INFO
#define RAISE		LLL_INFO
#define RAISE_NAME	"info"
#define BASE		LLL_NOTICE
#define log_raised(...)	lwsl_info(__VA_ARGS__)
#elif (_LWS_ENABLED_LOGS) & LLL_NOTICE
#define RAISE		LLL_NOTICE
#define RAISE_NAME	"notice"
#define BASE		0
#define log_raised(...)	lwsl_notice(__VA_ARGS__)
#else
#define RAISE		0
#define RAISE_NAME	"err"
#define BASE		0
#define log_raised(...)
#endif

/* ... or nothing, which compilers don't like seeing tested as a constant */
static int raise_lvl = RAISE;

enum {
	ST_WAIT_CONNECTED,	/* GET sources until the shipper is there */
	ST_NO_LOGIN,		/* GET sources, no login state: 403 */
	ST_NOT_JSON,		/* POST sessions as text/plain: 415 */
	ST_BAD_SECRET,		/* a shipper with the wrong secret */
	ST_NOTHING_YET,		/* GET logs: nothing was sent */
	ST_START,		/* POST sessions, from 30s ago */
	ST_LOGS,		/* GET logs until both markers are there */
	ST_SYNC,		/* GET sync: our pane */
	ST_PANE,		/* GET pane: our lines */
	ST_WAIT_END,		/* until the session's end */
	ST_AFTER,		/* GET logs: the line after the end isn't */
	ST_START2,		/* POST sessions, a long one */
	ST_STOP2,		/* POST sessions/<id>/stop */
	ST_DONE
};

static struct lws_context *context;
static struct lws_vhost *vh;
static lws_sorted_usec_list_t sul_step;
static struct lws *bad_wsi;
static const char *server = "127.0.0.1";
static int port = 7700, state, tries, status, fails, bad_closed, done;
static char rx[RX_MAX], body[512], session[LI_SESSION_LEN + 1],
	    session2[LI_SESSION_LEN + 1], path[256], host[65];
static size_t rx_len;
static uint64_t session_until, marker_us;

/* the request for this step */

typedef struct {
	const char	*method;
	const char	*ct;
	const char	*body;
	int		login;
} req_t;

static req_t req;

static void
step(lws_sorted_usec_list_t *sul);

static void
next(int st, lws_usec_t us)
{
	state = st;
	tries = 0;
	lws_sul_schedule(context, 0, &sul_step, step, us);
}

static void
fail(const char *why)
{
	lwsl_user("FAIL: state %d: %s\n", state, why);
	fails++;
	state = ST_DONE;
	lws_sul_schedule(context, 0, &sul_step, step, 1);
}

static int
request(const char *method, const char *ct, const char *b, int login)
{
	struct lws_client_connect_info i;

	req.method	= method;
	req.ct		= ct;
	req.body	= NULL;
	req.login	= login;
	if (b) {
		/* it's sent later, from our own copy */
		lws_strncpy(body, b, sizeof(body));
		req.body = body;
	}
	rx_len		= 0;
	rx[0]		= '\0';
	status		= 0;

	memset(&i, 0, sizeof(i));
	i.context	= context;
	i.vhost		= vh;
	i.address	= server;
	i.port		= port;
	i.path		= path;
	i.host		= server;
	i.origin	= server;
	i.method	= method;
	i.protocol	= "api-client";
	i.local_protocol_name = "api-client";

	return !lws_client_connect_via_info(&i);
}

static void
get(const char *p, int login)
{
	lws_strncpy(path, p, sizeof(path));
	if (request("GET", NULL, NULL, login))
		fail("connect");
}

static void
post(const char *p, const char *ct, const char *b)
{
	lws_strncpy(path, p, sizeof(path));
	if (request("POST", ct, b, 1))
		fail("connect");
}

/* the first member of that name in the answer, without any quotes */

static int
member(const char *name, char *out, size_t len)
{
	const char *p;
	size_t alen;

	p = lws_json_simple_find(rx, rx_len, name, &alen);
	if (!p || !alen || alen >= len)
		return 1;
	memcpy(out, p, alen);
	out[alen] = '\0';

	return 0;
}

/* the answer to this step's request came */

static void
answered(void)
{
	char t[80];

	switch (state) {
	case ST_WAIT_CONNECTED:
		if (status == 200 && strstr(rx, "\"connected\":[{")) {
			if (!strstr(rx, "\"kind\":\"api-test\""))
				fail("wrong shipper connected");
			else
				next(ST_NO_LOGIN, 1);
			return;
		}
		if (++tries == POLL_TRIES)
			fail("shipper never connected");
		else
			lws_sul_schedule(context, 0, &sul_step, step, POLL_US);
		return;

	case ST_NO_LOGIN:
		if (status != 403)
			fail("no login state wasn't refused");
		else
			next(ST_NOT_JSON, 1);
		return;

	case ST_NOT_JSON:
		if (status != 415)
			fail("a body that isn't JSON wasn't refused");
		else
			next(ST_BAD_SECRET, 1);
		return;

	case ST_BAD_SECRET:
		/* only one shipper may be listed, and it's ours */
		if (status != 200 || strstr(rx, "intruder"))
			fail("shipper with the wrong secret was listed");
		else
			next(ST_NOTHING_YET, 1);
		return;

	case ST_NOTHING_YET:
		if (status != 200 || !strstr(rx, "\"lines\":[]"))
			fail("lines were sent with no session open");
		else {
			lwsl_user("log-ship-marker-before\n");
			/* the pane is looked at around when it was logged */
			marker_us = lws_log_ship_utc_us();
			/* let it be timestamped before the session starts */
			next(ST_START, 50 * LWS_US_PER_MS);
		}
		return;

	case ST_START:
		if (status != 200 ||
		    member("\"session\":", session, sizeof(session)) ||
		    member("\"until_us\":", t, sizeof(t))) {
			fail("session start");
			return;
		}
		session_until = (uint64_t)strtoull(t, NULL, 10);
		if (raise_lvl && !lwsl_visible(raise_lvl)) {
			fail("the session didn't raise the level");
			return;
		}
		log_raised("log-ship-marker-during\n");
		next(ST_LOGS, POLL_US);
		return;

	case ST_LOGS:
		if (status == 200 && strstr(rx, "log-ship-marker-before") &&
		    (!raise_lvl || strstr(rx, "log-ship-marker-during"))) {
			next(ST_SYNC, 1);
			return;
		}
		if (++tries == POLL_TRIES)
			fail("markers never arrived");
		else
			lws_sul_schedule(context, 0, &sul_step, step, POLL_US);
		return;

	case ST_SYNC:
		lws_snprintf(t, sizeof(t), "\"pane\":\"api-test/%s\"", host);
		if (status != 200 || !strstr(rx, t))
			fail("sync has no pane for us");
		else
			next(ST_PANE, 1);
		return;

	case ST_PANE:
		if (status != 200 || !strstr(rx, "log-ship-marker-before"))
			fail("pane has no lines");
		else
			next(ST_WAIT_END, 1);
		return;

	case ST_AFTER:
		if (status != 200 || !strstr(rx, "\"lines\":[]"))
			fail("a line from after the session was sent");
		else
			next(ST_START2, 1);
		return;

	case ST_START2:
		if (status != 200 ||
		    member("\"session\":", session2, sizeof(session2)) ||
		    !strstr(rx, "\"open\":true"))
			fail("second session start");
		else
			next(ST_STOP2, 1);
		return;

	case ST_STOP2:
		if (status != 200 || !strstr(rx, "\"open\":false"))
			fail("session stop");
		else
			next(ST_DONE, 1);
		return;
	}
}

static void
bad_shipper(void)
{
	struct lws_client_connect_info i;

	memset(&i, 0, sizeof(i));
	i.context	= context;
	i.vhost		= vh;
	i.address	= server;
	i.port		= port;
	i.path		= "/ship";
	i.host		= server;
	i.origin	= server;
	i.protocol	= LWS_LOG_SHIP_WS_PROTOCOL;
	i.local_protocol_name = "bad-shipper";
	i.pwsi		= &bad_wsi;

	if (!lws_client_connect_via_info(&i))
		fail("bad shipper connect");
}

static void
step(lws_sorted_usec_list_t *sul)
{
	char p[160];

	switch (state) {
	case ST_WAIT_CONNECTED:
		get("/api/sources", 1);
		break;
	case ST_NO_LOGIN:
		get("/api/sources", 0);
		break;
	case ST_NOT_JSON:
		post("/api/sessions", "text/plain", "{}");
		break;
	case ST_BAD_SECRET:
		if (!bad_wsi && !bad_closed) {
			bad_shipper();
			lws_sul_schedule(context, 0, &sul_step, step, POLL_US);
			break;
		}
		if (!bad_closed) {
			if (++tries == POLL_TRIES)
				fail("shipper with the wrong secret stayed");
			else
				lws_sul_schedule(context, 0, &sul_step, step,
						 POLL_US);
			break;
		}
		get("/api/sources", 1);
		break;
	case ST_NOTHING_YET:
		get("/api/logs?from=-120&grep=log-ship-marker", 1);
		break;
	case ST_START:
		lws_snprintf(p, sizeof(p), "{\"from\":\"-30\",\"duration\":%d,"
			     "\"lvl\":\"" RAISE_NAME "\",\"src\":\"api-test\","
			     "\"note\":\"ctest\"}", SESSION_SECS);
		post("/api/sessions", "application/json", p);
		break;
	case ST_LOGS:
		lws_snprintf(p, sizeof(p), "/api/logs?session=%s&"
			     "grep=log-ship-marker", session);
		get(p, 1);
		break;
	case ST_SYNC:
		lws_snprintf(p, sizeof(p), "/api/sync?session=%s", session);
		get(p, 1);
		break;
	case ST_PANE:
		lws_snprintf(p, sizeof(p), "/api/pane?pane=api-test/%s&at=%llu",
			     host, (unsigned long long)marker_us);
		get(p, 1);
		break;
	case ST_WAIT_END:
		if (lws_log_ship_utc_us() < session_until + 500000ull) {
			lws_sul_schedule(context, 0, &sul_step, step, POLL_US);
			break;
		}
		if (raise_lvl && lwsl_visible(raise_lvl)) {
			fail("level still raised after the session");
			break;
		}
		lwsl_user("log-ship-marker-after\n");
		/* the shipper looks every 500ms: give it the chance */
		next(ST_AFTER, 1500 * LWS_US_PER_MS);
		break;
	case ST_AFTER:
		get("/api/logs?from=-120&grep=log-ship-marker-after", 1);
		break;
	case ST_START2:
		post("/api/sessions", "application/json",
		     "{\"duration\":600,\"src\":\"nobody\"}");
		break;
	case ST_STOP2:
		lws_snprintf(p, sizeof(p), "/api/sessions/%s/stop", session2);
		post(p, "application/json", "{}");
		break;
	case ST_DONE:
		done = 1;
		lws_cancel_service(context);
		break;
	}
}

static int
callback_api_client(struct lws *wsi, enum lws_callback_reasons reason,
		    void *user, void *in, size_t len)
{
	char buf[LWS_PRE + 1024], *px = buf + LWS_PRE;
	uint8_t **p, *end;
	int n = sizeof(buf) - LWS_PRE;

	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		fail(in ? (const char *)in : "connection error");
		break;

	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
		p = (uint8_t **)in;
		end = (*p) + len;
		if (req.login) {
			/* what lws-login stamps for a global admin */
			if (lws_add_http_header_by_name(wsi,
					(const uint8_t *)LWS_LOGIN_HDR_STATE ":",
					(const uint8_t *)"4", 1, p, end) ||
			    lws_add_http_header_by_name(wsi,
					(const uint8_t *)LWS_LOGIN_HDR_SUB ":",
					(const uint8_t *)"ctest", 5, p, end))
				return -1;
		}
		if (req.body) {
			char cl[16];

			n = lws_snprintf(cl, sizeof(cl), "%u",
					 (unsigned int)strlen(req.body));
			if (lws_add_http_header_by_token(wsi,
					WSI_TOKEN_HTTP_CONTENT_TYPE,
					(const uint8_t *)req.ct,
					(int)strlen(req.ct), p, end) ||
			    lws_add_http_header_by_token(wsi,
					WSI_TOKEN_HTTP_CONTENT_LENGTH,
					(const uint8_t *)cl, n, p, end))
				return -1;
			lws_client_http_body_pending(wsi, 1);
			lws_callback_on_writable(wsi);
		}
		break;

	case LWS_CALLBACK_CLIENT_HTTP_WRITEABLE:
		if (!req.body)
			break;
		n = (int)strlen(req.body);
		memcpy(px, req.body, (size_t)n);
		lws_client_http_body_pending(wsi, 0);
		if (lws_write(wsi, (uint8_t *)px, (size_t)n,
			      LWS_WRITE_HTTP_FINAL) != n)
			return -1;
		break;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		status = (int)lws_http_client_http_response(wsi);
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		if (rx_len + len >= sizeof(rx))
			return -1;
		memcpy(rx + rx_len, in, len);
		rx_len += len;
		rx[rx_len] = '\0';
		return 0;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		if (lws_http_client_read(wsi, &px, &n) < 0)
			return -1;
		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		answered();
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

/* a shipper that doesn't know the secret */

static int
callback_bad_shipper(struct lws *wsi, enum lws_callback_reasons reason,
		     void *user, void *in, size_t len)
{
	static const char hello[] = "{\"schema\":\"lws-log-ship-hello\","
		"\"secret\":\"guess\",\"kind\":\"intruder\",\"host\":\"x\","
		"\"inst\":\"0123456789abcdef\"}";
	uint8_t buf[LWS_PRE + sizeof(hello)];

	switch (reason) {
	case LWS_CALLBACK_CLIENT_ESTABLISHED:
		lws_callback_on_writable(wsi);
		break;
	case LWS_CALLBACK_CLIENT_WRITEABLE:
		memcpy(buf + LWS_PRE, hello, sizeof(hello) - 1);
		if (lws_write(wsi, buf + LWS_PRE, sizeof(hello) - 1,
			      LWS_WRITE_TEXT) != (int)sizeof(hello) - 1)
			return -1;
		break;
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
	case LWS_CALLBACK_CLIENT_CLOSED:
		bad_closed = 1;
		bad_wsi = NULL;
		break;
	default:
		break;
	}

	return 0;
}

static const struct lws_protocols protocols[] = {
	LWS_PLUGIN_PROTOCOL_LWS_LOG_INGEST,
	{ "api-client", callback_api_client, 0, 0, 0, NULL, 0 },
	{ "bad-shipper", callback_bad_shipper, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_http_mount mount_api = {
	.mountpoint		= "/api",
	.origin			= LWS_LOG_SHIP_WS_PROTOCOL,
	.origin_protocol	= LWSMPRO_CALLBACK,
	.mountpoint_len		= 4,
};

static struct lws_protocol_vhost_options pvo_trust = {
	NULL, NULL, "trust-login-headers", "1"
}, pvo_own = {
	&pvo_trust, NULL, "own-logs", "0"
}, pvo_secret = {
	&pvo_own, NULL, "secret", SECRET
}, pvo_db = {
	&pvo_secret, NULL, "database", "api-test-log-ship.sqlite3"
}, pvo = {
	NULL, &pvo_db, LWS_LOG_SHIP_WS_PROTOCOL, ""
};

static void
sigint_handler(int sig)
{
	lws_cancel_service(context);
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	struct lws_log_ship_info si;
	struct lws_log_ship *ls;
	char url[128];
	const char *p;

	signal(SIGINT, sigint_handler);

	/*
	 * The session raises it to info, and then puts it back.  At info, lws
	 * logs enough for its spew handling to swallow some, which might be
	 * the line saying why we failed
	 */
	lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN | BASE |
			  LLLF_LOG_SPEW_OFF, NULL);
	lwsl_user("LWS API selftest: log shipping and ingest\n");

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--server")))
		server = p;

	/* each run starts with nothing stored */
	unlink("api-test-log-ship.sqlite3");
	unlink("api-test-log-ship.sqlite3-wal");
	unlink("api-test-log-ship.sqlite3-shm");

	memset(&info, 0, sizeof(info));
	info.port = port;
	info.protocols = protocols;
	info.pvo = &pvo;
	info.mounts = &mount_api;
	info.vhost_name = "localhost";
	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	vh = lws_create_vhost(context, &info);
	if (!vh) {
		lwsl_err("vhost creation failed\n");
		goto bail;
	}

	lws_snprintf(url, sizeof(url), "ws://%s%s%s:%d/ship",
		     strchr(server, ':') ? "[" : "", server,
		     strchr(server, ':') ? "]" : "", port);

	memset(&si, 0, sizeof(si));
	si.vhost	= vh;
	si.url		= url;
	si.secret	= SECRET;
	si.kind		= "api-test";
	ls = lws_log_ship_create(&si);
	if (!ls) {
		lwsl_err("log shipper creation failed\n");
		goto bail;
	}
	lws_strncpy(host, lws_log_ship_host(ls), sizeof(host));

	next(ST_WAIT_CONNECTED, LWS_US_PER_SEC);

	while (!done && lws_service(context, 0) >= 0)
		;

	if (!done)
		fails++;

	lws_log_ship_destroy(&ls);
	lws_context_destroy(context);

	lwsl_user("Completed: %s\n", fails ? "FAIL" : "PASS");

	return !!fails;

bail:
	lws_context_destroy(context);

	return 1;
}
