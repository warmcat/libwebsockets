/*
 * lws-api-test-lws_spa
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * One process: an h1 server whose callback mounts parse each POSTed form
 * with lws_spa and answer with what the spa made of it, and a raw client
 * that sends each case's request bytes on a connection of its own and
 * checks the answers.
 *
 * /form keeps the parameter values in the spa's own storage, /form-ac keeps
 * them in an lwsac: the cases that are about the values run against both.
 *
 * The answer to a form lists every parameter the spa was asked for, as
 * name=NULL when the form did not have it, else name='value'/length, and
 * then what the file upload callback saw as up=opens/finals/bytes.  A GET to
 * either mount is answered "get", so a case can follow its form with a
 * pipelined request and see that request answered as itself.
 *
 * A case can hold back the end of its request body and send it with
 * whatever follows it after a pause, the way a slow client or a proxy
 * streaming a body would: the server then sees the body in two reads.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>

#define SPA_RX_MAX		4096
#define SPA_TX_MAX		4096
#define SPA_RESP_MAX		512
#define SPA_CASE_TIMEOUT_S	10
/* how long the second part of a case's request is held back */
#define SPA_PAUSE_MS		200

#define URLENC	"application/x-www-form-urlencoded"
#define MPART	"multipart/form-data; boundary=XyZ"

struct spa_case {
	const char	*name;
	const char	*path;
	const char	*ctype;
	const char	*body;		/* sent with the request head */
	const char	*held;		/* the rest of the body, sent later */
	const char	*pipelined;	/* sent after the body, with held */
	const char	*expect;	/* the answers' bodies, '|' between */
};

static const struct spa_case cases[] = {

	/* urlencoded, in both kinds of storage */

	{ "urlencoded values", "/form", URLENC,
	  "a=1&b=two&c=x%20y+z", NULL, NULL,
	  "a='1'/1 b='two'/3 c='x y z'/5 text=NULL up=0/0/0" },
	{ "urlencoded names without a value", "/form", URLENC,
	  "a&b=1&c", NULL, NULL,
	  "a=''/0 b='1'/1 c=''/0 text=NULL up=0/0/0" },
	{ "urlencoded empty values", "/form", URLENC,
	  "a=&b=1&c=", NULL, NULL,
	  "a=''/0 b='1'/1 c=''/0 text=NULL up=0/0/0" },
	{ "urlencoded values, lwsac", "/form-ac", URLENC,
	  "a=1&b=two&c=x%20y+z", NULL, NULL,
	  "a='1'/1 b='two'/3 c='x y z'/5 text=NULL up=0/0/0" },
	{ "urlencoded names without a value, lwsac", "/form-ac", URLENC,
	  "a&b=1&c", NULL, NULL,
	  "a=''/0 b='1'/1 c=''/0 text=NULL up=0/0/0" },
	{ "urlencoded empty values, lwsac", "/form-ac", URLENC,
	  "a=&b=1&c=", NULL, NULL,
	  "a=''/0 b='1'/1 c=''/0 text=NULL up=0/0/0" },
};

static struct lws_context *context;
static struct lws_vhost *vh_cli;
static lws_sorted_usec_list_t sul_next, sul_watchdog, sul_held;
static const char *only;
static int port = 7681, fails, case_idx = -1;

/*
 * The server side
 */

static const char * const param_names[] = { "a", "b", "c", "text" };

struct pss_srv {
	struct lws_spa		*spa;
	struct lwsac		*ac;
	char			resp[SPA_RESP_MAX];
	int			resp_len;

	/* what the upload callback saw during this form */
	int			opens;
	int			finals;
	int			bytes;
};

static int
upload_cb(void *data, const char *name, const char *filename, char *buf,
	  int len, enum lws_spa_fileupload_states state)
{
	struct pss_srv *pss = (struct pss_srv *)data;

	switch (state) {
	case LWS_UFS_OPEN:
		pss->opens++;
		break;
	case LWS_UFS_CONTENT:
		pss->bytes += len;
		break;
	case LWS_UFS_FINAL_CONTENT:
		pss->bytes += len;
		pss->finals++;
		break;
	case LWS_UFS_CLOSE:
		break;
	}

	return 0;
}

static int
srv_answer(struct lws *wsi, struct pss_srv *pss)
{
	uint8_t buf[LWS_PRE + 256], *start = &buf[LWS_PRE], *p = start,
		*end = &buf[sizeof(buf) - 1];

	if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK, "text/plain",
					(lws_filepos_t)pss->resp_len, &p, end) ||
	    lws_finalize_write_http_header(wsi, start, &p, end))
		return 1;

	lws_callback_on_writable(wsi);

	return 0;
}

static void
srv_describe(struct pss_srv *pss)
{
	char *p = pss->resp, *end = pss->resp + sizeof(pss->resp);
	const char *v;
	int n;

	for (n = 0; n < (int)LWS_ARRAY_SIZE(param_names); n++) {
		v = lws_spa_get_string(pss->spa, n);
		if (!v)
			p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
					  "%s=NULL ", param_names[n]);
		else
			p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
					  "%s='%s'/%d ", param_names[n], v,
					  lws_spa_get_length(pss->spa, n));
	}

	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p), "up=%d/%d/%d",
			  pss->opens, pss->finals, pss->bytes);

	pss->resp_len = lws_ptr_diff(p, pss->resp);
}

static int
callback_spa(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	     void *in, size_t len)
{
	struct pss_srv *pss = (struct pss_srv *)user;
	uint8_t buf[LWS_PRE + SPA_RESP_MAX];
	lws_spa_create_info_t i;
	char uri[32];

	switch (reason) {
	case LWS_CALLBACK_HTTP:
		pss->opens = pss->finals = pss->bytes = 0;

		if (lws_hdr_copy(wsi, uri, sizeof(uri),
				 WSI_TOKEN_POST_URI) <= 0) {
			pss->resp_len = lws_snprintf(pss->resp,
						     sizeof(pss->resp), "get");
			return srv_answer(wsi, pss);
		}

		memset(&i, 0, sizeof(i));
		i.param_names		= param_names;
		i.count_params		= (int)LWS_ARRAY_SIZE(param_names);
		i.max_storage		= 1024;
		i.opt_cb		= upload_cb;
		i.opt_data		= pss;
		if (!strcmp(uri, "/form-ac"))
			i.ac		= &pss->ac;

		pss->spa = lws_spa_create_via_info(wsi, &i);

		return !pss->spa;

	case LWS_CALLBACK_HTTP_BODY:
		if (!pss->spa || lws_spa_process(pss->spa, in, (int)len))
			return -1;
		break;

	case LWS_CALLBACK_HTTP_BODY_COMPLETION:
		if (!pss->spa)
			return -1;
		lws_spa_finalize(pss->spa);
		srv_describe(pss);
		lws_spa_destroy(pss->spa);
		pss->spa = NULL;

		return srv_answer(wsi, pss);

	case LWS_CALLBACK_HTTP_WRITEABLE:
		if (!pss->resp_len)
			break;
		memcpy(buf + LWS_PRE, pss->resp, (size_t)pss->resp_len);
		if (lws_write(wsi, buf + LWS_PRE, (size_t)pss->resp_len,
			      LWS_WRITE_HTTP_FINAL) != pss->resp_len)
			return 1;
		pss->resp_len = 0;
		if (lws_http_transaction_completed(wsi))
			return -1;
		break;

	case LWS_CALLBACK_HTTP_DROP_PROTOCOL:
	case LWS_CALLBACK_CLOSED_HTTP:
		if (pss && pss->spa) {
			lws_spa_destroy(pss->spa);
			pss->spa = NULL;
		}
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols_srv[] = {
	{ "http", callback_spa, sizeof(struct pss_srv), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_http_mount mount_form_ac = {
	.mountpoint		= "/form-ac",
	.origin			= "http",
	.origin_protocol	= LWSMPRO_CALLBACK,
	.mountpoint_len		= 8,
};

static const struct lws_http_mount mount_form = {
	.mount_next		= &mount_form_ac,
	.mountpoint		= "/form",
	.origin			= "http",
	.origin_protocol	= LWSMPRO_CALLBACK,
	.mountpoint_len		= 5,
};

/*
 * The client side
 */

static struct conn {
	struct lws	*wsi;
	char		tx[LWS_PRE + SPA_TX_MAX];
	char		tx2[LWS_PRE + SPA_TX_MAX];
	char		rx[SPA_RX_MAX + 1];
	char		got[SPA_RX_MAX];
	size_t		tx_len;
	size_t		tx2_len;
	size_t		rx_len;
	int		nresp;
	uint8_t		sent;
	uint8_t		held_due;
	uint8_t		done;
} cn;

static void
next_case(lws_sorted_usec_list_t *sul);

static void
case_done(const char *why)
{
	const struct spa_case *c = &cases[case_idx];

	if (cn.done)
		return;
	cn.done = 1;

	lws_sul_cancel(&sul_watchdog);
	lws_sul_cancel(&sul_held);

	if (why) {
		lwsl_err("%s: FAIL: %s\n", c->name, why);
		lwsl_err("  expected: %s\n", c->expect);
		lwsl_err("  got:      %s\n", cn.got);
		fails++;
	} else
		lwsl_user("%s: PASS\n", c->name);

	cn.wsi = NULL;
	lws_sul_schedule(context, 0, &sul_next, next_case, 1);
}

static int
lc_match(const char *p, const char *lc, size_t n)
{
	char c;

	while (n--) {
		c = *p++;
		if (c >= 'A' && c <= 'Z')
			c = (char)(c + 'a' - 'A');
		if (c != *lc++)
			return 0;
	}

	return 1;
}

/*
 * Take the h1 responses that have arrived whole off the front of cn.rx,
 * adding each body to cn.got.  Returns 1 once the case's count of them is
 * in, 0 if more is needed
 */

static int
rx_responses(void)
{
	const struct spa_case *c = &cases[case_idx];
	size_t hl, cl, pos = 0, gl;
	int want = 1, status;
	const char *q;

	for (q = c->expect; *q; q++)
		if (*q == '|')
			want++;

	while (cn.nresp < want) {
		const char *h = cn.rx + pos, *hdr_end = NULL;
		size_t avail = cn.rx_len - pos;

		for (hl = 0; hl + 4 <= avail; hl++)
			if (!memcmp(h + hl, "\r\n\r\n", 4)) {
				hdr_end = h + hl;
				break;
			}
		if (!hdr_end)
			return 0;

		status = 0;
		if (hl > 12 && !memcmp(h, "HTTP/1.1 ", 9))
			status = atoi(h + 9);

		cl = 0;
		for (q = h; q < hdr_end; q++)
			if (q[0] == '\n' &&
			    (size_t)(hdr_end - q) > 16 &&
			    lc_match(q + 1, "content-length:", 15)) {
				cl = (size_t)atol(q + 16);
				break;
			}

		if (avail - hl - 4 < cl)
			return 0;

		gl = strlen(cn.got);
		if (cn.nresp)
			gl += (size_t)lws_snprintf(cn.got + gl,
						   sizeof(cn.got) - gl, "|");
		if (status != 200)
			lws_snprintf(cn.got + gl, sizeof(cn.got) - gl,
				     "status %d", status);
		else
			lws_snprintf(cn.got + gl, sizeof(cn.got) - gl, "%.*s",
				     (int)cl, hdr_end + 4);

		pos += hl + 4 + cl;
		cn.nresp++;
	}

	return 1;
}

static void
held_cb(lws_sorted_usec_list_t *sul)
{
	cn.held_due = 1;
	if (cn.wsi)
		lws_callback_on_writable(cn.wsi);
}

static int
callback_raw_cli(struct lws *wsi, enum lws_callback_reasons reason,
		 void *user, void *in, size_t len)
{
	if (wsi != cn.wsi && reason != LWS_CALLBACK_CLIENT_CONNECTION_ERROR &&
	    reason != LWS_CALLBACK_RAW_CLOSE)
		return 0;

	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		if (wsi == cn.wsi)
			case_done("could not connect");
		break;

	case LWS_CALLBACK_RAW_CONNECTED:
		lws_callback_on_writable(wsi);
		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		if (!cn.sent) {
			cn.sent = 1;
			if (lws_write(wsi, (uint8_t *)cn.tx + LWS_PRE,
				      cn.tx_len, LWS_WRITE_RAW) !=
							(int)cn.tx_len)
				return -1;
			if (cn.tx2_len)
				lws_sul_schedule(context, 0, &sul_held, held_cb,
						 SPA_PAUSE_MS * LWS_US_PER_MS);
			break;
		}
		if (cn.held_due && cn.tx2_len) {
			if (lws_write(wsi, (uint8_t *)cn.tx2 + LWS_PRE,
				      cn.tx2_len, LWS_WRITE_RAW) !=
							(int)cn.tx2_len)
				return -1;
			cn.tx2_len = 0;
		}
		break;

	case LWS_CALLBACK_RAW_RX:
		if (len > SPA_RX_MAX - cn.rx_len) {
			case_done("too much came back");
			return -1;
		}
		memcpy(cn.rx + cn.rx_len, in, len);
		cn.rx_len += len;
		if (!rx_responses())
			break;
		case_done(strcmp(cn.got, cases[case_idx].expect) ?
				"wrong answer" : NULL);
		return -1;

	case LWS_CALLBACK_RAW_CLOSE:
		if (wsi == cn.wsi)
			case_done("closed before the answers");
		break;

	default:
		break;
	}

	return 0;
}

static const struct lws_protocols protocols_cli[] = {
	{ "raw-cli", callback_raw_cli, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void
watchdog_cb(lws_sorted_usec_list_t *sul)
{
	case_done("timed out");
}

/*
 * The request head and the first part of the body go in cn.tx; what the
 * case holds back, and anything pipelined after it, in cn.tx2
 */

static int
compose(const struct spa_case *c)
{
	size_t bl = strlen(c->body), hl = c->held ? strlen(c->held) : 0;
	int n;

	n = lws_snprintf(cn.tx + LWS_PRE, SPA_TX_MAX,
			 "POST %s HTTP/1.1\r\n"
			 "Host: localhost\r\n"
			 "Content-Type: %s\r\n"
			 "Content-Length: %u\r\n"
			 "\r\n%s", c->path, c->ctype, (unsigned int)(bl + hl),
			 c->body);
	if (n >= SPA_TX_MAX - 1)
		return 1;
	cn.tx_len = (size_t)n;

	if (!c->held && !c->pipelined)
		return 0;

	n = lws_snprintf(cn.tx2 + LWS_PRE, SPA_TX_MAX, "%s%s",
			 c->held ? c->held : "",
			 c->pipelined ? c->pipelined : "");
	if (n >= SPA_TX_MAX - 1)
		return 1;
	cn.tx2_len = (size_t)n;

	return 0;
}

static void
next_case(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;

	do {
		if (++case_idx == (int)LWS_ARRAY_SIZE(cases)) {
			lws_default_loop_exit(context);
			return;
		}
	} while (only && !strstr(cases[case_idx].name, only));

	memset(&cn, 0, sizeof(cn));
	if (compose(&cases[case_idx])) {
		lwsl_err("%s: request does not fit\n", cases[case_idx].name);
		fails++;
		lws_default_loop_exit(context);
		return;
	}

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli;
	i.address		= "127.0.0.1";
	i.host			= i.address;
	i.origin		= i.address;
	i.port			= port;
	i.method		= "RAW";
	i.local_protocol_name	= "raw-cli";
	i.pwsi			= &cn.wsi;

	lws_sul_schedule(context, 0, &sul_watchdog, watchdog_cb,
			 SPA_CASE_TIMEOUT_S * LWS_US_PER_SEC);

	if (!lws_client_connect_via_info(&i))
		case_done("connect failed");
}

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(context);
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p;
	int n = 0;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	/* a listener and client connections: see lws_context_info_defaults() */
	info.fd_limit_per_thread = 0;

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);
	only = lws_cmdline_option(argc, argv, "--only");

	signal(SIGINT, sigint_handler);
	lwsl_user("LWS API selftest: lws_spa form parsing\n");

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	info.port = port;
	info.vhost_name = "srv";
	info.protocols = protocols_srv;
	info.mounts = &mount_form;
	if (!lws_create_vhost(context, &info))
		goto bail;

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.vhost_name = "cli";
	info.protocols = protocols_cli;
	info.mounts = NULL;
	vh_cli = lws_create_vhost(context, &info);
	if (!vh_cli)
		goto bail;

	lws_sul_schedule(context, 0, &sul_next, next_case, 1);

	while (n >= 0)
		n = lws_service(context, 0);

bail:
	if (case_idx < 0) {
		lwsl_err("--- setup failed ---\n");
		fails++;
	}
	lws_sul_cancel(&sul_watchdog);
	lws_sul_cancel(&sul_held);
	lws_context_destroy(context);
	lwsl_user("Completed: %s\n", fails ? "FAIL" : "PASS");

	return !!fails;
}
