/*
 * lws-api-test-h3-header-amplification
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * An h3 field section can cost a decoder far more than its bytes on the
 * wire: thousands of one-byte field lines, each costing the 32 bytes of
 * overhead RFC 9114 4.2.2 counts for it, references to one big QPACK dynamic
 * table entry that each decode to all of it, more HEADERS frames chained on
 * a stream, or a frame declaring a size it never sends ("header accordion"
 * attacks).  lws must refuse each of these at a cost to the server of about
 * what came on the wire, and only refuse the request or the connection
 * involved: the server still serves afterwards.
 *
 * lws is both ends.  The lws h3 client adds the hostile field lines to its
 * request in APPEND_HANDSHAKE_HEADER, or frames what it sends after its
 * request headers itself, since a write that isn't http goes out as it is.
 * Built with fault injection, the client's h3_qpack_enc_big_entry fault has
 * its connection's QPACK encoder stream put a 4KiB cookie entry in the
 * server's dynamic table, for its later requests to refer to.
 *
 * A counting allocator follows lws' heap: each step must stay within
 * HAMP_HEAP_BUDGET above where it started, however much the field section it
 * sent decodes to.
 *
 * One server vhost has the stock SETTINGS_MAX_FIELD_SECTION_SIZE (65536),
 * another advertises HAMP_SMALL_SECTION, and must serve a request whose
 * section is just under it and refuse one just over it with 431.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#if defined(LWS_HAVE_MALLOC_USABLE_SIZE)
#include <malloc.h>
#endif

/* the most a step may raise lws' heap use above where it started */
#define HAMP_HEAP_BUDGET	(384 * 1024)
/* the field section size the "small" server vhost advertises */
#define HAMP_SMALL_SECTION	2048
#define HAMP_SMALL_VHOST	"hamp-small"
/* the value length of the h3_qpack_enc_big_entry fault's cookie entry */
#define HAMP_BIG_ENTRY_LEN	4058
#define HAMP_STEP_TIMEOUT_S	10
#define HAMP_MAX_STEPS		3

enum hamp_kind {
	HK_END,		/* no more steps in the case */
	HK_PLAIN,	/* a normal GET */
	HK_NAMES,	/* n literal fields with distinct names, vlen values */
	HK_STATIC,	/* n one-byte references to a static table row */
	HK_DYNREFS,	/* n one-byte references to the big dynamic entry */
	HK_TRAILERS,	/* POST, then n HEADERS frames after the head */
	HK_HUGE_DECL,	/* POST, then a HEADERS frame declaring 16MiB */
};

enum hamp_expect {
	HE_200,		/* served */
	HE_431,		/* the request alone refused, "Oversized headers" */
	HE_REFUSED,	/* the connection failed, nothing served */
};

static const char * const expect_names[] = { "200", "431", "refused" };

struct hamp_step {
	uint8_t		kind;
	uint8_t		expect;
	unsigned int	n;
	unsigned int	vlen;
};

struct hamp_case {
	const char		*name;
	uint8_t			small;	/* to the small section server */
	uint8_t			fi;	/* client: h3_qpack_enc_big_entry */
	/*
	 * the steps go one after another on one client vhost, so a later
	 * one joins the warm h3 connection of the one before
	 */
	struct hamp_step	steps[HAMP_MAX_STEPS];
	/*
	 * how many bytes of field section the hostile step would decode to,
	 * as RFC 9114 4.2.2 counts it, for the log
	 */
	size_t			decodes_to;
};

#define HAMP_FIELD(n, v)	((size_t)(n) * (4 + (v) + 32))

static const struct hamp_case cases[] = {
	{ "plain request", 0, 0, { { HK_PLAIN, HE_200, 0, 0 } }, 0 },

	/*
	 * Distinct short names, so no decoder could share them: a section
	 * over 64KiB from under 64KiB on the wire
	 */
	{ "1000 distinct field names", 0, 0,
	  { { HK_NAMES, HE_431, 1000, 50 } }, HAMP_FIELD(1000, 50) },

	/* a field line can be one byte: past LWS_H3_MAX_FIELD_LINES */
	{ "1100 one-byte field lines", 0, 0,
	  { { HK_STATIC, HE_REFUSED, 1100, 0 } }, (size_t)1100 * (6 + 3 + 32) },

	/* nothing is set aside for what a frame says is coming */
	{ "HEADERS frame declaring 16MiB", 0, 0,
	  { { HK_HUGE_DECL, HE_REFUSED, 0, 0 } }, (size_t)16 * 1024 * 1024 },

	/*
	 * HEADERS frames chained on one stream: the head, its trailers, and
	 * then more, which may not follow the trailers (RFC 9114 4.1)
	 */
	{ "chained HEADERS frames", 0, 0,
	  { { HK_TRAILERS, HE_REFUSED, 50, 0 } }, (size_t)50 * 15 * (6 + 3 + 32) },

#if defined(LWS_WITH_SYS_FAULT_INJECTION)
	/*
	 * The accordion: a first request sets up the connection and the 4KiB
	 * dynamic entry, the second refers to the entry 1000 times in 1000
	 * bytes, which is 4MiB decoded.  It alone is refused: a third on the
	 * same connection is served.
	 */
	{ "1000 references to a 4KiB dynamic table entry", 0, 1,
	  { { HK_PLAIN, HE_200, 0, 0 },
	    { HK_DYNREFS, HE_431, 1000, 0 },
	    { HK_PLAIN, HE_200, 0, 0 } },
	  (size_t)1000 * (6 + HAMP_BIG_ENTRY_LEN + 32) },

	/* ... and past the field line limit, the connection fails */
	{ "1100 references to a 4KiB dynamic table entry", 0, 1,
	  { { HK_PLAIN, HE_200, 0, 0 },
	    { HK_DYNREFS, HE_REFUSED, 1100, 0 } },
	  (size_t)1100 * (6 + HAMP_BIG_ENTRY_LEN + 32) },
#endif

#if defined(LWS_WITH_HTTP2)
	/*
	 * The vhost's h2 settings give the section size it advertises, so it
	 * takes a build with h2 to set one apart from the stock 65536.  Each
	 * HK_NAMES field is 4 + 60 + 32 = 96: 18 of them, 1728, fit with the
	 * request's own fields, and 22, 2112, are over even without them.
	 */
	{ "field section under the advertised size", 1, 0,
	  { { HK_NAMES, HE_200, 18, 60 } }, HAMP_FIELD(18, 60) },
	{ "field section over the advertised size", 1, 0,
	  { { HK_NAMES, HE_431, 22, 60 } }, HAMP_FIELD(22, 60) },
#endif

	/* the server is still serving */
	{ "plain request after the attacks", 0, 0,
	  { { HK_PLAIN, HE_200, 0, 0 } }, 0 },
};

static struct lws_context *context;
static struct lws_vhost *vh_cli[LWS_ARRAY_SIZE(cases)];
static lws_sorted_usec_list_t sul_next, sul_watchdog;
static int result = 1, cur = -1, step, port_h3 = 7690, port_h3_small = 7691;
/* every case ran: the connections closing at the end are no step's */
static uint8_t finished;
static const char *server_addr = "127.0.0.1";

/* what the client heard for the current step */
static struct {
	char		body[256];
	char		err[128];	/* the client's connection error */
	size_t		body_len;
	int		status;
	uint8_t		done;
	uint8_t		sent_after;	/* the raw bytes after the head went */
} cli;

/*
 * lws' heap, through lws_set_allocator(): what is allocated now, and the
 * most since the current step started
 */
static int64_t heap_live, heap_peak, heap_step_start;

#if defined(LWS_HAVE_MALLOC_USABLE_SIZE)
static void *
hamp_realloc(void *ptr, size_t size, const char *reason)
{
	int64_t old = ptr ? (int64_t)malloc_usable_size(ptr) : 0;
	void *v;

	(void)reason;

	if (!size) {
		free(ptr);
		heap_live -= old;

		return NULL;
	}

	v = realloc(ptr, size);
	if (!v)
		return NULL;

	heap_live += (int64_t)malloc_usable_size(v) - old;
	if (heap_live > heap_peak)
		heap_peak = heap_live;

	return v;
}
#endif

/* a self-signed test cert for the h3 servers */

static const char * const test_cert =
"-----BEGIN CERTIFICATE-----\n"
"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\n"
"e2Hl/7M0c/lbZ4FvXgARlex2rkgS0Ka06HE=\n"
"-----END CERTIFICATE-----\n";

static const char * const test_key =
"-----BEGIN PRIVATE KEY-----\n"
"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\n"
"fBrpEY1IATtPq1taBZZogRqI3rOkkPk=\n"
"-----END PRIVATE KEY-----\n";


/*
 * The server: 200 "ok" to anything that gets as far as it.  A POST is only
 * answered once its body is in, which the hostile POSTs never complete, so
 * the stream is still open for what the client sends after the head.
 */

static int
callback_srv(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	uint8_t buf[LWS_PRE + 256], *start = &buf[LWS_PRE], *p = start,
		*end = &buf[sizeof(buf) - 1];

	switch (reason) {
	case LWS_CALLBACK_HTTP:
		if (lws_hdr_total_length(wsi, WSI_TOKEN_POST_URI))
			return 0;
		/* fallthru */
	case LWS_CALLBACK_HTTP_BODY_COMPLETION:
		if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
				"text/plain", 2, &p, end) ||
		    lws_finalize_write_http_header(wsi, start, &p, end))
			return 1;
		lws_callback_on_writable(wsi);
		return 0;

	case LWS_CALLBACK_HTTP_BODY:
		return 0;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		memcpy(start, "ok", 2);
		if (lws_write(wsi, start, 2, LWS_WRITE_HTTP_FINAL) != 2)
			return 1;
		if (lws_http_transaction_completed(wsi))
			return -1;
		return 0;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static void
next_step(lws_sorted_usec_list_t *sul);

static const struct hamp_step *
cur_step(void)
{
	return &cases[cur].steps[step];
}

static void
step_done(const char *why)
{
	const struct hamp_case *c = &cases[cur];
	int64_t grew = heap_peak - heap_step_start;

	lws_sul_cancel(&sul_watchdog);

	if (!why && grew > HAMP_HEAP_BUDGET)
		why = "heap grew past the budget";

	if (why) {
		lwsl_err("--- %s, step %d: FAIL: %s (status %d, heap +%lld%s%s) "
			 "---\n", c->name, step, why, cli.status,
			 (long long)grew, cli.err[0] ? ", " : "", cli.err);
		lws_default_loop_exit(context);
		return;
	}

	lwsl_user("--- %s, step %d: %s: heap +%lld for a section of %llu "
		  "decoded: PASS ---\n", c->name, step,
		  expect_names[cur_step()->expect], (long long)grew,
		  (unsigned long long)(cur_step()->kind == HK_PLAIN ? 0 :
				       c->decodes_to));

	lws_sul_schedule(context, 0, &sul_next, next_step, 1);
}

static void
step_evaluate(void)
{
	switch (cur_step()->expect) {
	case HE_200:
		if (cli.status != HTTP_STATUS_OK ||
		    cli.body_len != 2 || memcmp(cli.body, "ok", 2))
			step_done("not served");
		else
			step_done(NULL);
		return;

	case HE_431:
		if (cli.status != HTTP_STATUS_REQ_HEADER_FIELDS_TOO_LARGE)
			step_done("not answered 431");
		else if (!strstr(cli.body, "Oversized headers"))
			step_done("431 does not say why");
		else
			step_done(NULL);
		return;

	default:
		if (cli.status)
			step_done("answered, not refused");
		else
			step_done(NULL);
		return;
	}
}

/*
 * The hostile field lines, added to the request's own field section
 */

static int
append_fields(struct lws *wsi, const struct hamp_step *s, unsigned char **p,
	      unsigned char *end)
{
	char name[4], val[64];
	unsigned int n;
	int m;

	switch (s->kind) {
	case HK_NAMES:
		/* "xaaa", "xaab"...: names no decoder has seen before */
		if (s->vlen > sizeof(val))
			return -1;
		memset(val, 'v', s->vlen);
		name[0] = 'x';
		for (n = 0; n < s->n; n++) {
			name[1] = (char)('a' + (n / 676) % 26);
			name[2] = (char)('a' + (n / 26) % 26);
			name[3] = (char)('a' + n % 26);
			m = lws_qpack_encode_literal_with_literal_name(*p,
					lws_ptr_diff_size_t(end, *p),
					name, sizeof(name), val, s->vlen);
			if (m < 0)
				return -1;
			*p += m;
		}
		return 0;

	case HK_STATIC:
		/* static table row 29, "accept: * / *" */
		for (n = 0; n < s->n; n++) {
			m = lws_qpack_encode_static(*p,
					lws_ptr_diff_size_t(end, *p), 29);
			if (m < 0)
				return -1;
			*p += m;
		}
		return 0;

	case HK_DYNREFS:
		/*
		 * The section's prefix says it needs the one entry the fault
		 * inserted, with a base of 0: each reference is then a
		 * one-byte post-base index 0 to it
		 */
		lws_qpack_set_wsi_base_and_ric(wsi, 0, 1);
		for (n = 0; n < s->n; n++) {
			m = lws_qpack_tx_encode_dynamic_index(*p,
					lws_ptr_diff_size_t(end, *p), 0, 0);
			if (m < 0)
				return -1;
			*p += m;
		}
		return 0;

	case HK_TRAILERS:
	case HK_HUGE_DECL:
		/* a POST, whose body is never ended: we send what follows */
		lws_client_http_body_pending(wsi, 1);
		lws_callback_on_writable(wsi);
		return 0;

	default:
		return 0;
	}
}

/*
 * What follows the request's head on its stream, framed by us
 */

static int
send_after_head(struct lws *wsi, const struct hamp_step *s)
{
	/* 16MiB as a four-byte varint, and a little of what it promised */
	static const uint8_t huge[] = {
		0x01, 0x81, 0x00, 0x00, 0x00,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	};
	uint8_t buf[LWS_PRE + 1024], *p = &buf[LWS_PRE];
	unsigned int n, m;

	if (cli.sent_after)
		/* an unasked for WRITEABLE */
		return 0;
	cli.sent_after = 1;

	if (s->kind == HK_HUGE_DECL) {
		memcpy(p, huge, sizeof(huge));
		p += sizeof(huge);
	} else
		/*
		 * HEADERS frames of a static-only section: the qpack prefix
		 * and 15 one-byte references to static row 29.  The first is
		 * the request's trailers, the rest are refused after them.
		 */
		for (n = 0; n < s->n &&
			    lws_ptr_diff_size_t(&buf[sizeof(buf)], p) >= 19;
		     n++) {
			*p++ = 0x01;
			*p++ = 17;
			*p++ = 0;
			*p++ = 0;
			for (m = 0; m < 15; m++)
				*p++ = 0xc0 | 29;
		}

	n = (unsigned int)lws_ptr_diff_size_t(p, &buf[LWS_PRE]);
	if (lws_write(wsi, &buf[LWS_PRE], n, LWS_WRITE_BINARY) != (int)n)
		return -1;

	return 0;
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	char buf[LWS_PRE + 1024], *px = buf + LWS_PRE;
	int lenx = (int)sizeof(buf) - LWS_PRE;

	switch (reason) {
	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
	case LWS_CALLBACK_CLIENT_HTTP_WRITEABLE:
		/*
		 * An earlier step's connection or stream finishing its close
		 * is not news.  The request carries its step.
		 */
		if (cur < 0 || finished ||
		    lws_get_opaque_user_data(wsi) != cur_step())
			return lws_callback_http_dummy(wsi, reason, user, in,
						       len);
		break;
	default:
		break;
	}

	switch (reason) {
	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER: {
		unsigned char **p = (unsigned char **)in, *end = (*p) + len;

		if (append_fields(wsi, cur_step(), p, end)) {
			lwsl_err("%s: no room for the fields\n", __func__);
			return -1;
		}
		break;
	}

	case LWS_CALLBACK_CLIENT_HTTP_WRITEABLE:
		if (cur_step()->kind == HK_TRAILERS ||
		    cur_step()->kind == HK_HUGE_DECL)
			return send_after_head(wsi, cur_step());
		break;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		cli.status = (int)lws_http_client_http_response(wsi);
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;
		return 0;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		if (cli.body_len + len >= sizeof(cli.body))
			len = sizeof(cli.body) - 1 - cli.body_len;
		memcpy(cli.body + cli.body_len, in, len);
		cli.body_len += len;
		cli.body[cli.body_len] = '\0';
		return 0;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lws_strncpy(cli.err, in ? (const char *)in : "connection error",
			    sizeof(cli.err));
		/* fallthru */
	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		if (!cli.done) {
			cli.done = 1;
			step_evaluate();
		}
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols_srv[] = {
	{ "http", callback_srv, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_cli[] = {
	{ "cli", callback_cli, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void
sul_watchdog_cb(lws_sorted_usec_list_t *sul)
{
	step_done("timed out");
}

static void
next_step(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;
	const struct hamp_step *s;

	if (cur < 0 || ++step == HAMP_MAX_STEPS ||
	    cases[cur].steps[step].kind == HK_END) {
		step = 0;
		if (cur + 1 == (int)LWS_ARRAY_SIZE(cases)) {
			lwsl_user("--- all cases passed ---\n");
			finished = 1;
			result = 0;
			lws_default_loop_exit(context);
			return;
		}
		cur++;
	}
	s = cur_step();
	memset(&cli, 0, sizeof(cli));

	memset(&i, 0, sizeof(i));
	i.context		= context;
	/* a client vhost per case: its steps share its h3 connection */
	i.vhost			= vh_cli[cur];
	i.address		= server_addr;
	/*
	 * With the Host its address, and pipelining, a step joins the warm
	 * connection of the one before.  QUIC vhosts on their own udp ports
	 * still count as one listener for SNI, so a name that matches no
	 * vhost is refused there: the small server's cases, which take one
	 * step each, name it.
	 */
	i.host			= cases[cur].small ? HAMP_SMALL_VHOST :
						     server_addr;
	i.origin		= i.host;
	i.port			= cases[cur].small ? port_h3_small : port_h3;
	i.alpn			= "h3";
	i.ssl_connection	= LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED |
				  LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK |
				  LCCSCF_PIPELINE;
	i.protocol		= "cli";
	i.local_protocol_name	= "cli";
	i.opaque_user_data	= (void *)s;

	if (s->kind == HK_TRAILERS || s->kind == HK_HUGE_DECL) {
		i.path		= "/post";
		i.method	= "POST";
	} else {
		i.path		= "/";
		i.method	= "GET";
	}

#if defined(LWS_WITH_SYS_FAULT_INJECTION)
	if (cases[cur].fi && !step) {
		lws_fi_t fi;

		memset(&fi, 0, sizeof(fi));
		fi.name = "h3_qpack_enc_big_entry";
		fi.type = LWSFI_ALWAYS;
		if (lws_fi_add(&i.fic, &fi)) {
			step_done("OOM");
			return;
		}
	}
#endif

	heap_step_start = heap_peak = heap_live;
	lws_sul_schedule(context, 0, &sul_watchdog, sul_watchdog_cb,
			 HAMP_STEP_TIMEOUT_S * LWS_US_PER_SEC);

	if (!lws_client_connect_via_info(&i)) {
#if defined(LWS_WITH_SYS_FAULT_INJECTION)
		/* the client wsi takes the faults, unless there was none */
		lws_fi_destroy(&i.fic);
#endif
		if (!cli.done) {
			cli.done = 1;
			step_done("connect failed");
		}
	}
}

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(context);
}

/*
 * The quic listener, on udp.  "localhost" is both 127.0.0.1 and ::1, and a
 * client may try either first: on FreeBSD, ::1.  A udp socket bound to the
 * name gets only its first address, so a client trying the other relies on
 * an ICMP port unreachable to move on, which can be lost, or not sent when
 * the kernel rate limits them under parallel tests.  So for "localhost",
 * listen on both.
 */
static int
quic_listen(struct lws_vhost *vh, int port, const char *protocol)
{
	static const char * const lo[] = {
#if defined(LWS_WITH_IPV4)
		"127.0.0.1",
#endif
#if defined(LWS_WITH_IPV6)
		"::1",
#endif
	};
	size_t n;

	if (!vh)
		return 1;

	if (strcmp(server_addr, "localhost"))
		return !lws_create_adopt_udp(vh, server_addr, port,
					     LWS_CAUDP_BIND, protocol, NULL,
					     NULL, NULL, NULL, "quic_listen");

	for (n = 0; n < LWS_ARRAY_SIZE(lo); n++)
		if (!lws_create_adopt_udp(vh, lo[n], port, LWS_CAUDP_BIND,
					  protocol, NULL, NULL, NULL, NULL,
					  "quic_listen"))
			return 1;

	return 0;
}

static struct lws_vhost *
create_h3_server(struct lws_context_creation_info *info, const char *name,
		 int port)
{
	struct lws_vhost *vh;

	/* a quic listener on udp only */
	info->port = CONTEXT_PORT_NO_LISTEN_SERVER;
	info->vhost_name = name;
	info->listen_accept_role = "quic";
	info->listen_accept_protocol = "http";
	info->alpn = "h3";
	vh = lws_create_vhost(context, info);
	if (!vh || quic_listen(vh, port, "http"))
		return NULL;

	return vh;
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	char name[16];
	const char *p;
	size_t n;
	int m = 0;

#if defined(LWS_HAVE_MALLOC_USABLE_SIZE)
	/* before lws allocates anything */
	lws_set_allocator(hamp_realloc);
#endif

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	info.fd_limit_per_thread = 0;

	if ((p = lws_cmdline_option(argc, argv, "--small-port")))
		port_h3_small = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port_h3 = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--server")))
		server_addr = p;

	signal(SIGINT, sigint_handler);
	lwsl_user("LWS API selftest: h3 header amplification\n");

#if !defined(LWS_HAVE_MALLOC_USABLE_SIZE)
	lwsl_user("No malloc_usable_size(): heap use is not checked\n");
#endif

	/* room for the client to compose its biggest field section */
	info.pt_serv_buf_size = 128 * 1024;
	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
		       LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	info.protocols = protocols_srv;
	info.server_ssl_cert_mem = test_cert;
	info.server_ssl_cert_mem_len = (unsigned int)strlen(test_cert);
	info.server_ssl_private_key_mem = test_key;
	info.server_ssl_private_key_mem_len = (unsigned int)strlen(test_key);

	/* as dialled in ctest, where server_addr is "localhost" */
	if (!create_h3_server(&info, "localhost", port_h3))
		goto bail;

	/* lws' stock h2 settings, but for the header list size */
	info.http2_settings[0] = 1;
	info.http2_settings[H2SET_HEADER_TABLE_SIZE] = 65536;
	info.http2_settings[H2SET_ENABLE_PUSH] = 0;
	info.http2_settings[H2SET_MAX_CONCURRENT_STREAMS] = 24;
	info.http2_settings[H2SET_INITIAL_WINDOW_SIZE] = 0;
	info.http2_settings[H2SET_MAX_FRAME_SIZE] = 16384;
	info.http2_settings[H2SET_MAX_HEADER_LIST_SIZE] = HAMP_SMALL_SECTION;
	if (!create_h3_server(&info, HAMP_SMALL_VHOST, port_h3_small))
		goto bail;

	memset(&info.http2_settings, 0, sizeof(info.http2_settings));
	info.listen_accept_role = NULL;
	info.listen_accept_protocol = NULL;
	info.alpn = NULL;
	info.server_ssl_cert_mem = NULL;
	info.server_ssl_cert_mem_len = 0;
	info.server_ssl_private_key_mem = NULL;
	info.server_ssl_private_key_mem_len = 0;

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.protocols = protocols_cli;
	for (n = 0; n < LWS_ARRAY_SIZE(cases); n++) {
		lws_snprintf(name, sizeof(name), "cli%u", (unsigned int)n);
		info.vhost_name = name;
		vh_cli[n] = lws_create_vhost(context, &info);
		if (!vh_cli[n])
			goto bail;
	}

	lws_sul_schedule(context, 0, &sul_next, next_step, 1);

	while (m >= 0)
		m = lws_service(context, 0);

bail:
	if (cur < 0)
		lwsl_err("--- setup failed ---\n");
	lws_sul_cancel(&sul_watchdog);
	lws_sul_cancel(&sul_next);
	lws_context_destroy(context);
	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
