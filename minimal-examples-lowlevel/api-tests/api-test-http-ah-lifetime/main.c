/*
 * lws-api-test-http-ah-lifetime
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * A server request's header table (ah) comes from a small pool, and lws
 * should hold one only while it is needed.  Changing when it is given back
 * once went wrong in production: an h1 connection that had let its ah go
 * got a fresh one attached in the middle of a file transfer, which armed the
 * short ah idle timeout over the transfer.  These cases pin down what must
 * keep working, whenever the ah is released, in a server whose ah idle
 * timeout (AHL_AH_IDLE_S) is much shorter than its other timeouts:
 *
 *  --case file-stall (h1): a raw client GETs a file larger than the socket
 *     buffers from a file mount and stops reading it for longer than the ah
 *     idle timeout, sending a pipelined GET in its own write meanwhile.  The
 *     server must still be sending the file when the client reads again (or
 *     the case proves nothing), the whole file must arrive, and then the
 *     answer to the pipelined GET, in that order.  With LWS_WITH_ASYNC_QUEUE
 *     the file is read by the async worker, so the transfer also passes
 *     through LRS_AWAITING_FILE_READ.
 *
 *  --case pipeline-depth (h1): the server limits how many requests it
 *     answers pipelined behind one another without the client's rx running
 *     dry.  A raw client sends 64 GETs in one write, then one more in its
 *     own write once all 64 are answered: all 65 must be answered and the
 *     connection kept, since the depth starts again when nothing is left
 *     queued.  A second connection sends 80 GETs in one write: the server
 *     must answer at least 64 of them, but not all, and close the
 *     connection.
 *
 *  --case slow-cl, --case slow-stream (h1, h2, h3): an lws client POSTs a
 *     body in pieces, pausing for longer than the ah idle timeout after the
 *     request headers and again after the first piece, with a
 *     Content-Length (slow-cl) or without one (chunked on h1, ended by the
 *     stream on h2 and h3).  The request's Content-Type must be readable at
 *     LWS_CALLBACK_HTTP, the server must have seen the pauses, and its
 *     answer must report exactly the body that was sent.  A server that
 *     gave the ah back at dispatch and then attached a fresh one to read
 *     the body would arm the ah idle timeout over the first pause.
 *
 *  --case late-spa (h1, h2, h3): an lws client POSTs a multipart form.  The
 *     server gives the request headers back at LWS_CALLBACK_HTTP
 *     (lws_http_headers_detach()), the way a server releasing them at
 *     dispatch would, and only creates its lws_spa at the first
 *     LWS_CALLBACK_HTTP_BODY, as apps commonly do.  The spa must still know
 *     the body is multipart, and its boundary, from the Content-Type the
 *     request came with, and so find the form's field.
 *
 *  --case late-range, --case late-coded (h1, h2, h3): an lws client GETs a
 *     path whose server gives the request headers back at
 *     LWS_CALLBACK_HTTP and only then serves a file for it with
 *     lws_serve_http_file().  late-range asks for "Range: bytes=2-11": the
 *     answer must be a 206 of exactly those bytes.  late-coded says
 *     "Accept-Encoding: deflate": the text file must come deflated.  What
 *     the request asked for must still decide the answer when the headers
 *     have gone, on every role.
 *
 *  --case body-rate (h1, h2, h3): the server's request bodies must keep up
 *     with a minimum rate, here AHL_RATE bytes/s after AHL_RATE_GRACE_S, as
 *     well as come within the timeout between pieces.  Two lws clients POST
 *     at once, on one connection on h2 and h3: /trickle sends 10 bytes
 *     every 500ms, renewing the timeout each time but far below the rate,
 *     and must be reset by the server soon after the grace time, without
 *     its body completing; /steady sends 16KB at 4KB/s, with a 1.5s pause
 *     in the middle, and must arrive whole after that, on the same
 *     connection on h2 / h3.
 *
 *  --case mux-cap (h2, h3): the streams of one connection waiting on the
 *     peer may only hold so many request header tables at once (AHL_MUX_CAP
 *     here).  Four lws clients POST on one connection, holding their bodies
 *     back, and three GET on it too: the server must dispatch only
 *     AHL_MUX_CAP of the POSTs, refusing the others on their own, but answer
 *     every GET, which arrives whole and never waits on the peer.  When the
 *     bodies are sent the POSTs it took must be answered.
 *
 * lws is both ends here, in one process: a crash or memory error in the
 * server fails the test as well as a wrong answer does.
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#if !defined(WIN32)
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#endif

/* the server's ah idle timeout, and its other timeouts, much longer */
#define AHL_AH_IDLE_S		2
#define AHL_TIMEOUT_S		10
/* how long the file-stall client stops reading, well over the ah idle */
#define AHL_STALL_MS		((AHL_AH_IDLE_S * 1000) + 2000)
/* file-stall: the pipelined GET goes this long into the stall */
#define AHL_PIPELINE_AFTER_MS	300
/* file-stall: the file, much larger than the socket buffers */
#define AHL_FILE_LEN		(8 * 1024 * 1024)
/* late-range, late-coded: the file is much smaller */
#define AHL_LATE_FILE_LEN	4096
/* late-range: the range asked for */
#define AHL_RANGE_FROM		2
#define AHL_RANGE_TO		11
#define AHL_SNDBUF		16384

/* pipeline-depth: the most requests lws answers back to back */
#define AHL_DEPTH		64
/* pipeline-depth: a write of more than that, which must not all be answered */
#define AHL_TOO_DEEP		80

/* slow-*: the body, in pieces, two pauses longer than the ah idle */
#define AHL_PIECES		6
#define AHL_PIECE_LEN		1000
#define AHL_LONG_GAP_MS		((AHL_AH_IDLE_S * 1000) + 1000)
#define AHL_SHORT_GAP_MS	200
/* the Content-Type the client sends, read back at LWS_CALLBACK_HTTP */
#define AHL_CT			"application/x-ahl-probe"

/* late-spa: the form the client POSTs, and the field the server looks for */
#define AHL_FORM_CT		"multipart/form-data; boundary=ahlb"
#define AHL_FORM_FIELD		"f"
#define AHL_FORM_VALUE		"late"
#define AHL_FORM		"--ahlb\r\n" \
				"Content-Disposition: form-data; name=\"" \
					AHL_FORM_FIELD "\"\r\n\r\n" \
				AHL_FORM_VALUE "\r\n" \
				"--ahlb--\r\n"

#define AHL_DEADLINE_S		30

/* body-rate: the server's minimum body rate and its grace time */
#define AHL_RATE		1000
#define AHL_RATE_GRACE_S	2
/* body-rate: /trickle, 10 bytes every 500ms, would take this long */
#define AHL_TRICKLE_PIECE	10
#define AHL_TRICKLE_MS		500
#define AHL_TRICKLE_PIECES	10
/* body-rate: /steady, 1000 bytes every 250ms, a pause after the 8th */
#define AHL_STEADY_PIECE	1000
#define AHL_STEADY_MS		250
#define AHL_STEADY_PIECES	16
#define AHL_STEADY_PAUSE_AT	8
#define AHL_STEADY_PAUSE_MS	1500

/* mux-cap: the server's cap, the POSTs and GETs on one connection, and when */
#define AHL_MUX_CAP		2
#define AHL_MUX_REQS		4
#define AHL_MUX_GETS		3
#define AHL_MUX_RELEASE_MS	1500

/* a small answer, for the pipelined GETs */
#define AHL_SMALL_PATH		"/s"
#define AHL_SMALL_BODY		"ok"

/* the most of a response head the raw client keeps */
#define AHL_HEAD_MAX		1024

enum ahl_case {
	AHL_FILE_STALL,
	AHL_PIPELINE_DEPTH,
	AHL_SLOW_CL,
	AHL_SLOW_STREAM,
	AHL_LATE_SPA,
	AHL_LATE_RANGE,
	AHL_LATE_CODED,
	AHL_BODY_RATE,
	AHL_MUX_CAP_CASE,
};

static const char * const case_names[] = {
	"file-stall", "pipeline-depth", "slow-cl", "slow-stream", "late-spa",
	"late-range", "late-coded", "body-rate", "mux-cap"
};

enum ahl_role {
	AHL_H1,
	AHL_H2,
	AHL_H3,
};

static const char * const role_names[] = { "h1", "h2", "h3" };

static struct lws_context *context;
static struct lws_vhost *vh_cli;
static lws_sorted_usec_list_t sul_watchdog;
static enum ahl_case tcase;
static enum ahl_role role;
static const char *server_addr = "127.0.0.1";
static int port = 7681, result = 1, finished;

#if !defined(WIN32)
static char docroot[64], fpath[96];
#endif

static int
late_file_case(void)
{
	return tcase == AHL_LATE_RANGE || tcase == AHL_LATE_CODED;
}

/* what the server saw */

static struct {
	int		small_served;	/* answers to AHL_SMALL_PATH */
	int		file_done;	/* LWS_CALLBACK_HTTP_FILE_COMPLETION */
	int		slow_http;	/* LWS_CALLBACK_HTTP for /slow */
	int		ct_ok;		/* ... with the client's Content-Type */
	int		completions;	/* /slow and /spa body completions */
	int		trickle_resets;	/* /trickle closed before its body */
	lws_usec_t	trickle_reset_us; /* ... this long after its dispatch */
	int		held;		/* /hold dispatched, its body to come */
	int		held_max;
	int		hold_dispatched;
	lws_usec_t	max_gap_us;	/* longest wait for a piece of /slow */
} srv;

/* the deterministic content of the file and of the POST bodies */

static uint8_t
pat(size_t n)
{
	return (uint8_t)((n * 7) + (n >> 8) + 3);
}

static uint32_t
sum_add(uint32_t s, const uint8_t *p, size_t len)
{
	while (len--)
		s = (s * 31) + *p++;

	return s;
}

static uint32_t
sum_pat(size_t len)
{
	uint32_t s = 0;
	size_t n;

	for (n = 0; n < len; n++) {
		uint8_t b = pat(n);

		s = sum_add(s, &b, 1);
	}

	return s;
}

static void
finish(int ok, const char *why)
{
	if (finished)
		return;

	finished = 1;
	result = !ok;
	if (ok)
		lwsl_user("%s: %s\n", __func__, why);
	else
		lwsl_err("%s: FAIL: %s\n", __func__, why);

	lws_default_loop_exit(context);
}

/*
 * The server
 */

static const char * const form_names[] = { AHL_FORM_FIELD };

struct pss_srv {
	struct lws_spa	*spa;		/* /spa: made at the first body */
	lws_usec_t	start_us;	/* when it was dispatched */
	lws_usec_t	last_us;	/* /slow: when the last piece came */
	size_t		rx_len;
	uint32_t	rx_sum;
	char		resp[LWS_PRE + 64];
	size_t		resp_len;
	char		kind;		/* 't'rickle, 'h'old, or 0 */
	char		body_done;
};

/*
 * The response headers go now, the body in pss->resp from the writeable,
 * where the transaction completes: so it completes after the callback that
 * dispatched the request has returned, as an app answering later does
 */
static int
answer(struct lws *wsi, struct pss_srv *pss)
{
	uint8_t hdr[LWS_PRE + 256], *start = &hdr[LWS_PRE], *p = start,
		*end = &hdr[sizeof(hdr) - 1];

	if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK, "text/plain",
					(lws_filepos_t)pss->resp_len, &p, end) ||
	    lws_finalize_write_http_header(wsi, start, &p, end))
		return -1;

	lws_callback_on_writable(wsi);

	return 0;
}

static int
callback_srv(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	struct pss_srv *pss = (struct pss_srv *)user;
	const char *path = (const char *)in;
	char ct[64];
	lws_usec_t now;

	switch (reason) {

#if !defined(WIN32)
	case LWS_CALLBACK_FILTER_NETWORK_CONNECTION:
		if (tcase == AHL_FILE_STALL) {
			struct lws_filter_network_conn_args *a =
				(struct lws_filter_network_conn_args *)user;
			int sb = AHL_SNDBUF;

			/* keep what the kernel takes off our hands small */
			if (setsockopt(a->accept_fd, SOL_SOCKET, SO_SNDBUF,
				       &sb, sizeof(sb)))
				lwsl_warn("%s: SO_SNDBUF failed\n", __func__);
		}
		break;
#endif

	case LWS_CALLBACK_HTTP:
		if (path && !strcmp(path, AHL_SMALL_PATH)) {
			srv.small_served++;
			pss->resp_len = strlen(AHL_SMALL_BODY);
			memcpy(&pss->resp[LWS_PRE], AHL_SMALL_BODY,
			       pss->resp_len);

			return answer(wsi, pss);
		}

		if (path && !strcmp(path, "/spa")) {
			memset(pss, 0, sizeof(*pss));
			/*
			 * Done with the request headers already, as if they
			 * had been released at dispatch: the spa, made later,
			 * must not need them
			 */
			if (lws_http_headers_detach(wsi))
				return -1;

			return 0;
		}

#if defined(LWS_WITH_FILE_OPS) && !defined(WIN32)
		if (path && !strcmp(path, "/late") && late_file_case()) {
			int n;

			/*
			 * Done with the request headers already, as if they
			 * had been released at dispatch: what the request
			 * asked of the file must not need them
			 */
			if (lws_http_headers_detach(wsi))
				return -1;

			n = lws_serve_http_file(wsi, fpath, "text/plain",
						NULL, 0);
			if (n < 0 || (n > 0 &&
				      lws_http_transaction_completed(wsi)))
				return -1;

			return 0;
		}
#endif

		if (path && (!strcmp(path, "/trickle") ||
			     !strcmp(path, "/steady") ||
			     !strcmp(path, "/hold"))) {
			/* the body follows, summed as for /slow */
			memset(pss, 0, sizeof(*pss));
			pss->start_us = pss->last_us = lws_now_usecs();
			pss->kind = path[1] == 's' ? 0 : path[1];
			if (pss->kind == 'h') {
				srv.hold_dispatched++;
				if (++srv.held > srv.held_max)
					srv.held_max = srv.held;
			}
			return 0;
		}

		if (!path || strcmp(path, "/slow")) {
			if (lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND,
						   NULL) ||
			    lws_http_transaction_completed(wsi))
				return -1;
			return 0;
		}

		memset(pss, 0, sizeof(*pss));
		pss->last_us = lws_now_usecs();
		srv.slow_http++;

		/* the request headers are all there for this callback */
		if (lws_hdr_copy(wsi, ct, sizeof(ct),
				 WSI_TOKEN_HTTP_CONTENT_TYPE) ==
					(int)strlen(AHL_CT) &&
		    !strcmp(ct, AHL_CT))
			srv.ct_ok++;
		else
			lwsl_err("%s: Content-Type not readable at "
				 "LWS_CALLBACK_HTTP\n", __func__);

		/* the body follows */
		return 0;

	case LWS_CALLBACK_HTTP_BODY:
		if (tcase == AHL_LATE_SPA) {
			if (!pss->spa) {
				pss->spa = lws_spa_create(wsi, form_names,
						LWS_ARRAY_SIZE(form_names),
						256, NULL, NULL);
				if (!pss->spa)
					return -1;
			}

			return lws_spa_process(pss->spa, (const char *)in,
					       (int)len);
		}

		now = lws_now_usecs();
		if (now - pss->last_us > srv.max_gap_us)
			srv.max_gap_us = now - pss->last_us;
		pss->last_us = now;

		pss->rx_sum = sum_add(pss->rx_sum, (const uint8_t *)in, len);
		pss->rx_len += len;
		return 0;

	case LWS_CALLBACK_HTTP_BODY_COMPLETION:
		srv.completions++;
		pss->body_done = 1;
		if (pss->kind == 'h')
			srv.held--;

		if (tcase == AHL_LATE_SPA) {
			const char *v = NULL;

			if (pss->spa && !lws_spa_finalize(pss->spa))
				v = lws_spa_get_string(pss->spa, 0);
			pss->resp_len = (size_t)lws_snprintf(
					&pss->resp[LWS_PRE],
					sizeof(pss->resp) - LWS_PRE,
					AHL_FORM_FIELD "=%s", v ? v : "(none)");
			if (pss->spa) {
				lws_spa_destroy(pss->spa);
				pss->spa = NULL;
			}

			return answer(wsi, pss);
		}

		lwsl_user("%s: body complete, %u bytes, longest wait %dms\n",
			  __func__, (unsigned int)pss->rx_len,
			  (int)(srv.max_gap_us / LWS_US_PER_MS));
		pss->resp_len = (size_t)lws_snprintf(&pss->resp[LWS_PRE],
				sizeof(pss->resp) - LWS_PRE, "len=%u sum=%08x",
				(unsigned int)pss->rx_len, pss->rx_sum);

		return answer(wsi, pss);

	case LWS_CALLBACK_HTTP_WRITEABLE:
		if (!pss || !pss->resp_len)
			break;
		if (lws_write(wsi, (uint8_t *)&pss->resp[LWS_PRE],
			      pss->resp_len, LWS_WRITE_HTTP_FINAL) !=
							(int)pss->resp_len)
			return -1;
		pss->resp_len = 0;

		return lws_http_transaction_completed(wsi) ? -1 : 0;

	case LWS_CALLBACK_CLOSED_HTTP:
		if (pss && pss->spa) {
			lws_spa_destroy(pss->spa);
			pss->spa = NULL;
		}
		if (pss && pss->kind == 't' && !pss->body_done) {
			srv.trickle_resets++;
			srv.trickle_reset_us = lws_now_usecs() - pss->start_us;
			lwsl_user("%s: /trickle closed after %dms, body "
				  "incomplete at %u bytes\n", __func__,
				  (int)(srv.trickle_reset_us / LWS_US_PER_MS),
				  (unsigned int)pss->rx_len);
		}
		if (pss && pss->kind == 'h' && !pss->body_done) {
			srv.held--;
			pss->kind = 0;
		}
		break;

	case LWS_CALLBACK_HTTP_FILE_COMPLETION:
		srv.file_done++;
		lwsl_user("%s: file sent\n", __func__);
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

/*
 * The raw h1 client of file-stall and pipeline-depth.  It counts the
 * responses as they stream in: each response's head is collected until its
 * blank line, and its Content-Length body summed as it passes.
 */

static struct {
	uint8_t		head[AHL_HEAD_MAX];
	size_t		head_len;
	size_t		remain;		/* body bytes still to come */
	size_t		body_len;	/* the current response's body */
	uint32_t	sum;		/* ... and its sum so far */
	int		responses;	/* whole responses so far */
	int		conn;		/* pipeline-depth: 0, then 1 */
	int		phase;		/* file-stall: timer steps taken */
	char		stall_checked;
} raw;

/* case-insensitive match of a header name at p */
static int
raw_hdr_is(const uint8_t *p, const uint8_t *end, const char *name)
{
	size_t n = strlen(name), i;

	if ((size_t)(end - p) < n)
		return 0;

	for (i = 0; i < n; i++) {
		uint8_t c = p[i];

		if (c >= 'A' && c <= 'Z')
			c = (uint8_t)(c + ('a' - 'A'));
		if (c != (uint8_t)name[i])
			return 0;
	}

	return 1;
}

/* the Content-Length of the 200 response head in raw.head, or -1 */
static long
raw_head_cl(void)
{
	const uint8_t *h, *e = raw.head + raw.head_len;
	long cl = -1;

	if (raw.head_len < 12 || memcmp(raw.head, "HTTP/1.1 200", 12))
		return -1;

	for (h = raw.head; h < e; h++)
		if (h[0] == '\n' && raw_hdr_is(h + 1, e, "content-length:")) {
			h += 1 + strlen("content-length:");
			while (h < e && *h == ' ')
				h++;
			cl = 0;
			while (h < e && *h >= '0' && *h <= '9' &&
			       cl <= AHL_FILE_LEN)
				cl = (cl * 10) + (*h++ - '0');
			break;
		}

	return cl > AHL_FILE_LEN ? -1 : cl;
}

/* a response is whole: is it the one we expected next? */
static int
raw_response_ok(void)
{
	static uint32_t small_sum;
	size_t sl = strlen(AHL_SMALL_BODY);

	if (!small_sum)
		small_sum = sum_add(0, (const uint8_t *)AHL_SMALL_BODY, sl);

	if (tcase == AHL_FILE_STALL && !raw.responses)
		return raw.body_len == AHL_FILE_LEN &&
		       raw.sum == sum_pat(AHL_FILE_LEN);

	return raw.body_len == sl && raw.sum == small_sum;
}

/* returns the number of whole responses so far, or -1 if they are wrong */
static int
raw_rx(const uint8_t *p, size_t len)
{
	while (len) {
		if (!raw.remain) {
			long cl;

			/* a head byte */
			if (raw.head_len == sizeof(raw.head))
				return -1;
			raw.head[raw.head_len++] = *p++;
			len--;
			if (raw.head_len < 4 ||
			    memcmp(raw.head + raw.head_len - 4, "\r\n\r\n", 4))
				continue;

			cl = raw_head_cl();
			if (cl < 0)
				return -1;
			raw.head_len = 0;
			raw.sum = 0;
			raw.body_len = (size_t)cl;
			raw.remain = (size_t)cl;
			if (cl)
				continue;
		} else {
			size_t n = len < raw.remain ? len : raw.remain;

			raw.sum = sum_add(raw.sum, p, n);
			raw.remain -= n;
			p += n;
			len -= n;
			if (raw.remain)
				continue;
		}

		/* a response's body is all here */
		if (!raw_response_ok())
			return -1;
		raw.responses++;
	}

	return raw.responses;
}

static int
raw_send_small(struct lws *wsi, int count)
{
	static const char req[] = "GET " AHL_SMALL_PATH " HTTP/1.1\r\n"
				  "Host: ahl\r\n\r\n";
	size_t rl = sizeof(req) - 1, n;
	uint8_t *buf;
	int r;

	buf = malloc(LWS_PRE + (rl * (size_t)count));
	if (!buf)
		return -1;

	for (n = 0; n < (size_t)count; n++)
		memcpy(buf + LWS_PRE + (n * rl), req, rl);

	n = rl * (size_t)count;
	r = lws_write(wsi, buf + LWS_PRE, n, LWS_WRITE_RAW) != (int)n;
	free(buf);

	return r ? -1 : 0;
}

static int raw_connect(void);

static int
callback_raw(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	static const char get_file[] = "GET /f/big.txt HTTP/1.1\r\n"
				       "Host: ahl\r\n\r\n";
	uint8_t buf[LWS_PRE + 64];
	int n;

	/*
	 * Only the current connection's events count: the first
	 * pipeline-depth connection closes after the second is started
	 */
	if (!wsi ||
	    (intptr_t)lws_get_opaque_user_data(wsi) != raw.conn + 1)
		return 0;

	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		finish(0, in ? (const char *)in : "raw connection error");
		break;

	case LWS_CALLBACK_RAW_CONNECTED:
		memset(&raw.head, 0, sizeof(raw.head));
		raw.head_len = raw.remain = 0;
		raw.responses = 0;

		if (tcase == AHL_PIPELINE_DEPTH)
			/*
			 * First connection: as deep as lws goes, then one more
			 * after.  Second: deeper than that, in one write
			 */
			return raw_send_small(wsi, raw.conn ? AHL_TOO_DEEP :
							      AHL_DEPTH);

		/* file-stall: the file, and we don't read it for now */
		memcpy(buf + LWS_PRE, get_file, sizeof(get_file) - 1);
		if (lws_write(wsi, buf + LWS_PRE, sizeof(get_file) - 1,
			      LWS_WRITE_RAW) != (int)sizeof(get_file) - 1 ||
		    lws_rx_flow_control(wsi, 0))
			return -1;
		lws_set_timer_usecs(wsi, AHL_PIPELINE_AFTER_MS * LWS_US_PER_MS);
		break;

	case LWS_CALLBACK_TIMER:
		if (tcase != AHL_FILE_STALL)
			break;

		switch (raw.phase++) {
		case 0:
			/* the next request goes while the file waits */
			if (raw_send_small(wsi, 1))
				return -1;
			lws_set_timer_usecs(wsi, (AHL_STALL_MS -
						  AHL_PIPELINE_AFTER_MS) *
						 LWS_US_PER_MS);
			break;
		case 1:
			/*
			 * The file must still be going, or the stall did not
			 * hold the transfer over the ah idle timeout
			 */
			lwsl_user("%s: reading again after %dms\n", __func__,
				  AHL_STALL_MS);
			if (srv.file_done || srv.small_served) {
				finish(0, "the file was not still being sent "
					  "after the stall: make it larger");
				return -1;
			}
			raw.stall_checked = 1;
			if (lws_rx_flow_control(wsi, 1))
				return -1;
			break;
		default:
			break;
		}
		break;

	case LWS_CALLBACK_RAW_RX:
		n = raw_rx((const uint8_t *)in, len);
		if (n < 0) {
			lwsl_err("%s: unexpected response %d\n", __func__,
				 raw.responses + 1);
			finish(0, "unexpected response");
			return -1;
		}

		if (tcase == AHL_FILE_STALL) {
			if (n < 2)
				break;
			if (!raw.stall_checked || srv.file_done != 1 ||
			    srv.small_served != 1)
				finish(0, "answers out of step with the server");
			else
				finish(1, "the file, then the pipelined GET");
			return -1;
		}

		/* pipeline-depth */
		if (!raw.conn) {
			if (n == AHL_DEPTH) {
				/*
				 * Nothing is left queued: the depth starts
				 * again, so one more is answered
				 */
				if (raw_send_small(wsi, 1))
					return -1;
				break;
			}
			if (n == AHL_DEPTH + 1) {
				lwsl_user("%s: %d answered on the first "
					  "connection\n", __func__, n);
				raw.conn = 1;
				if (raw_connect())
					finish(0, "second connection failed");
				return -1;
			}
			break;
		}

		if (n == AHL_TOO_DEEP)
			finish(0, "answered every request pipelined beyond "
				  "the depth limit");
		break;

	case LWS_CALLBACK_RAW_CLOSE:
		if (tcase == AHL_FILE_STALL) {
			finish(0, "connection closed before both answers");
			break;
		}
		if (!raw.conn) {
			if (raw.responses <= AHL_DEPTH)
				finish(0, "first connection closed early");
			break;
		}
		if (raw.responses >= AHL_DEPTH &&
		    raw.responses < AHL_TOO_DEEP) {
			lwsl_user("%s: %d answered, then closed\n", __func__,
				  raw.responses);
			finish(1, "the pipelining depth is limited");
		} else
			finish(0, "second connection closed with the wrong "
				  "number of answers");
		break;

	default:
		break;
	}

	return 0;
}

static int
raw_connect(void)
{
	struct lws_client_connect_info i;

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh_cli;
	i.address		= server_addr;
	i.host			= server_addr;
	i.origin		= server_addr;
	i.port			= port;
	i.method		= "RAW";
	i.protocol		= "ahl-raw";
	i.local_protocol_name	= "ahl-raw";
	i.opaque_user_data	= (void *)(intptr_t)(raw.conn + 1);

	return !lws_client_connect_via_info(&i);
}

/*
 * The lws client of slow-cl and slow-stream
 */

static struct {
	lws_sorted_usec_list_t	sul;	/* the pause before the next piece */
	struct lws		*wsi;
	char			body[64];
	size_t			body_len;
	size_t			rx_total;	/* late-*: all the body */
	char			ce[32];		/* late-*: content-encoding */
	int			piece;
	int			status;
	char			ready;	/* the next piece may go */
	char			completed;
} cli;

static void
cli_next_piece(lws_sorted_usec_list_t *sul)
{
	cli.ready = 1;
	if (cli.wsi)
		lws_callback_on_writable(cli.wsi);
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	uint8_t buf[LWS_PRE + AHL_PIECE_LEN];
	char rb[LWS_PRE + 256], *px = rb + LWS_PRE, cl[24];
	int lenx = (int)sizeof(rb) - LWS_PRE, n, wp;

	switch (reason) {
	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER: {
		unsigned char **p = (unsigned char **)in, *end = (*p) + len;

		if (tcase == AHL_LATE_RANGE) {
			n = lws_snprintf(cl, sizeof(cl), "bytes=%d-%d",
					 AHL_RANGE_FROM, AHL_RANGE_TO);
			return lws_add_http_header_by_token(wsi,
					WSI_TOKEN_HTTP_RANGE,
					(const unsigned char *)cl, n, p, end);
		}
		if (tcase == AHL_LATE_CODED)
			return lws_add_http_header_by_token(wsi,
					WSI_TOKEN_HTTP_ACCEPT_ENCODING,
					(const unsigned char *)"deflate", 7,
					p, end);

		if (tcase == AHL_LATE_SPA) {
			/* the form, all of it as soon as it can go */
			n = lws_snprintf(cl, sizeof(cl), "%u",
					 (unsigned int)strlen(AHL_FORM));
			if (lws_add_http_header_by_token(wsi,
					WSI_TOKEN_HTTP_CONTENT_TYPE,
					(const unsigned char *)AHL_FORM_CT,
					(int)strlen(AHL_FORM_CT), p, end) ||
			    lws_add_http_header_by_token(wsi,
					WSI_TOKEN_HTTP_CONTENT_LENGTH,
					(const unsigned char *)cl, n, p, end))
				return -1;

			cli.wsi = wsi;
			cli.ready = 1;
			lws_client_http_body_pending(wsi, 1);
			lws_callback_on_writable(wsi);
			return 0;
		}

		if (lws_add_http_header_by_token(wsi,
				WSI_TOKEN_HTTP_CONTENT_TYPE,
				(const unsigned char *)AHL_CT,
				(int)strlen(AHL_CT), p, end))
			return -1;

		if (tcase == AHL_SLOW_CL) {
			n = lws_snprintf(cl, sizeof(cl), "%u",
					 (unsigned int)(AHL_PIECES *
							AHL_PIECE_LEN));
			if (lws_add_http_header_by_token(wsi,
					WSI_TOKEN_HTTP_CONTENT_LENGTH,
					(const unsigned char *)cl, n, p, end))
				return -1;
		}

		/*
		 * The body follows, from the writeable, but not until a
		 * long pause after the headers
		 */
		cli.wsi = wsi;
		lws_client_http_body_pending(wsi, 1);
		lws_sul_schedule(context, 0, &cli.sul, cli_next_piece,
				 AHL_LONG_GAP_MS * LWS_US_PER_MS);
		return 0;
	}

	case LWS_CALLBACK_CLIENT_HTTP_WRITEABLE:
		if (!cli.ready || cli.piece == AHL_PIECES)
			return 0;

		if (tcase == AHL_LATE_SPA) {
			n = (int)strlen(AHL_FORM);
			memcpy(buf + LWS_PRE, AHL_FORM, (size_t)n);
			lws_client_http_body_pending(wsi, 0);
			cli.ready = 0;
			cli.piece = AHL_PIECES;

			return lws_write(wsi, buf + LWS_PRE, (size_t)n,
					 LWS_WRITE_HTTP_FINAL) != n ? -1 : 0;
		}

		for (n = 0; n < AHL_PIECE_LEN; n++)
			buf[LWS_PRE + n] = pat((size_t)((cli.piece *
							 AHL_PIECE_LEN) + n));

		wp = LWS_WRITE_HTTP;
		if (cli.piece == AHL_PIECES - 1) {
			lws_client_http_body_pending(wsi, 0);
			wp = LWS_WRITE_HTTP_FINAL;
		}

		if (lws_write(wsi, buf + LWS_PRE, AHL_PIECE_LEN,
			      (enum lws_write_protocol)wp) != AHL_PIECE_LEN)
			return -1;

		cli.ready = 0;
		if (++cli.piece == AHL_PIECES)
			return 0;

		/* another long pause after the first piece */
		lws_sul_schedule(context, 0, &cli.sul, cli_next_piece,
				 (cli.piece == 1 ? AHL_LONG_GAP_MS :
						   AHL_SHORT_GAP_MS) *
				 LWS_US_PER_MS);
		return 0;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		cli.status = (int)lws_http_client_http_response(wsi);
		if (lws_hdr_copy(wsi, cli.ce, sizeof(cli.ce),
				 WSI_TOKEN_HTTP_CONTENT_ENCODING) < 0)
			cli.ce[0] = '\0';
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;
		return 0;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		cli.rx_total += len;
		if (len > sizeof(cli.body) - 1 - cli.body_len)
			len = sizeof(cli.body) - 1 - cli.body_len;
		memcpy(cli.body + cli.body_len, in, len);
		cli.body_len += len;
		cli.body[cli.body_len] = '\0';
		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		cli.completed = 1;
		cli.status = (int)lws_http_client_http_response(wsi);
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		cli.wsi = NULL;
		lws_sul_cancel(&cli.sul);
		finish(0, in ? (const char *)in : "client connection error");
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP: {
		char want[64];

		cli.wsi = NULL;
		lws_sul_cancel(&cli.sul);

		if (tcase == AHL_LATE_RANGE || tcase == AHL_LATE_CODED) {
			int want_status = tcase == AHL_LATE_RANGE ? 206 : 200;
			size_t k;

			if (!cli.completed || cli.status != want_status) {
				lwsl_err("%s: status %d, want %d\n", __func__,
					 cli.status, want_status);
				finish(0, "the file was not answered as the "
					  "request asked");
				break;
			}
			if (tcase == AHL_LATE_CODED) {
				if (strcmp(cli.ce, "deflate") || !cli.rx_total)
					finish(0, "the file did not come "
						  "deflated");
				else
					finish(1, "the late file came "
						  "deflated");
				break;
			}
			if (cli.rx_total != AHL_RANGE_TO - AHL_RANGE_FROM + 1) {
				finish(0, "the range is the wrong length");
				break;
			}
			for (k = 0; k < cli.rx_total; k++)
				if ((uint8_t)cli.body[k] !=
						pat(AHL_RANGE_FROM + k))
					break;
			if (k != cli.rx_total)
				finish(0, "the range has the wrong bytes");
			else
				finish(1, "the late file honoured the range");
			break;
		}

		if (tcase == AHL_LATE_SPA)
			lws_strncpy(want, AHL_FORM_FIELD "=" AHL_FORM_VALUE,
				    sizeof(want));
		else
			lws_snprintf(want, sizeof(want), "len=%u sum=%08x",
				     (unsigned int)(AHL_PIECES * AHL_PIECE_LEN),
				     sum_pat(AHL_PIECES * AHL_PIECE_LEN));

		if (!cli.completed || cli.status != 200)
			finish(0, "the POST was not answered 200");
		else if (strcmp(cli.body, want)) {
			lwsl_err("%s: answer '%s', want '%s'\n", __func__,
				 cli.body, want);
			finish(0, "the server did not get the body sent");
		} else if (tcase == AHL_LATE_SPA) {
			if (srv.completions != 1)
				finish(0, "the form was not completed once");
			else
				finish(1, "the late spa parsed the multipart "
					  "form");
		} else if (srv.slow_http != 1 || srv.ct_ok != 1 ||
			   srv.completions != 1)
			finish(0, "the request headers were not readable at "
				  "LWS_CALLBACK_HTTP, or the request was not "
				  "dispatched and completed once");
		else if (srv.max_gap_us < AHL_AH_IDLE_S * LWS_US_PER_SEC)
			finish(0, "the server did not wait longer than the ah "
				  "idle timeout for a piece of the body");
		else
			finish(1, "the slow body arrived whole");
		break;
	}

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

/*
 * The lws clients of body-rate and mux-cap: several requests at once, each
 * with its own state, on one connection on h2 and h3
 */

struct mreq {
	lws_sorted_usec_list_t	sul;	/* the wait for its next piece */
	struct lws		*wsi;
	const char		*path;
	size_t			piece_len;
	int			pieces;
	int			piece_ms;
	int			pause_at;	/* a longer pause after this one */
	int			pause_ms;
	int			piece;	/* pieces sent */
	int			status;
	char			body[64];
	size_t			body_len;
	char			ready;	/* the next piece may go */
	char			held;	/* mux-cap: until the release */
	char			get;	/* mux-cap: a GET, no body */
	char			completed;
	char			closed;
};

static struct mreq mreqs[AHL_MUX_REQS + AHL_MUX_GETS];
static int mreq_count;
static lws_sorted_usec_list_t sul_release;

static size_t
mreq_cl(const struct mreq *r)
{
	return r->piece_len * (size_t)r->pieces;
}

static void
mreq_next_piece(lws_sorted_usec_list_t *sul)
{
	struct mreq *r = lws_container_of(sul, struct mreq, sul);

	r->ready = 1;
	if (r->wsi)
		lws_callback_on_writable(r->wsi);
}

static void
mux_cap_release(lws_sorted_usec_list_t *sul)
{
	int n;

	if (srv.hold_dispatched != AHL_MUX_CAP ||
	    srv.held_max != AHL_MUX_CAP) {
		lwsl_err("%s: server dispatched %d of %d, held %d at once, "
			 "cap %d\n", __func__, srv.hold_dispatched,
			 AHL_MUX_REQS, srv.held_max, AHL_MUX_CAP);
		finish(0, "the server did not take exactly the cap's worth "
			  "of the connection's POSTs");
		return;
	}

	/* the requests the server took get their bodies now */
	for (n = 0; n < mreq_count; n++)
		if (!mreqs[n].get && mreqs[n].wsi && !mreqs[n].closed) {
			mreqs[n].held = 0;
			mreq_next_piece(&mreqs[n].sul);
		}
}

static void
multi_check(void)
{
	struct mreq *tr = &mreqs[0], *st = &mreqs[1];
	char want[64];
	int n, answered = 0, gets = 0;

	if (tcase == AHL_MUX_CAP_CASE) {
		for (n = 0; n < mreq_count; n++) {
			if (!mreqs[n].closed)
				continue;
			if (mreqs[n].get) {
				if (!mreqs[n].completed ||
				    mreqs[n].status != 200 ||
				    strcmp(mreqs[n].body, AHL_SMALL_BODY)) {
					finish(0, "a GET on the capped "
						  "connection was not served");
					return;
				}
				gets++;
				continue;
			}
			if (mreqs[n].completed && mreqs[n].status == 200)
				answered++;
		}
		if (answered == AHL_MUX_CAP && gets == AHL_MUX_GETS)
			finish(1, "the cap refused the POSTs over it, the "
				  "others and every GET were answered");
		return;
	}

	/* body-rate */
	if (tr->closed && tr->completed && tr->status == 200) {
		finish(0, "the trickling body was served");
		return;
	}
	if (!st->closed)
		return;

	lws_snprintf(want, sizeof(want), "len=%u sum=%08x",
		     (unsigned int)mreq_cl(st), sum_pat(mreq_cl(st)));
	if (!st->completed || st->status != 200 || strcmp(st->body, want)) {
		lwsl_err("%s: status %d, answer '%s', want '%s'\n", __func__,
			 st->status, st->body, want);
		finish(0, "the steady upload was cut or got the wrong body");
		return;
	}
	if (srv.trickle_resets != 1) {
		finish(0, "the trickling body was not reset");
		return;
	}
	if (srv.trickle_reset_us < AHL_RATE_GRACE_S * LWS_US_PER_SEC ||
	    srv.trickle_reset_us >= (AHL_TRICKLE_PIECES - 1) *
				AHL_TRICKLE_MS * LWS_US_PER_MS) {
		lwsl_err("%s: reset after %dms\n", __func__,
			 (int)(srv.trickle_reset_us / LWS_US_PER_MS));
		finish(0, "the trickling body was not reset at its deadline");
		return;
	}

	finish(1, "the trickling body was reset at its deadline, the steady "
		  "upload arrived whole");
}

static int
callback_multi(struct lws *wsi, enum lws_callback_reasons reason,
	       void *user, void *in, size_t len)
{
	struct mreq *r = (struct mreq *)lws_get_opaque_user_data(wsi);
	uint8_t buf[LWS_PRE + AHL_STEADY_PIECE];
	char rb[LWS_PRE + 256], *px = rb + LWS_PRE, cl[24];
	int lenx = (int)sizeof(rb) - LWS_PRE, n, wp;
	size_t o;

	if (!r)
		return lws_callback_http_dummy(wsi, reason, user, in, len);

	switch (reason) {
	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER: {
		unsigned char **p = (unsigned char **)in, *end = (*p) + len;

		if (r->get) {
			r->wsi = wsi;
			return 0;
		}

		n = lws_snprintf(cl, sizeof(cl), "%u",
				 (unsigned int)mreq_cl(r));
		if (lws_add_http_header_by_token(wsi,
				WSI_TOKEN_HTTP_CONTENT_LENGTH,
				(const unsigned char *)cl, n, p, end))
			return -1;

		r->wsi = wsi;
		lws_client_http_body_pending(wsi, 1);
		if (!r->held)
			lws_sul_schedule(context, 0, &r->sul, mreq_next_piece,
					 r->piece_ms * LWS_US_PER_MS);
		return 0;
	}

	case LWS_CALLBACK_CLIENT_HTTP_WRITEABLE:
		if (r->get || !r->ready || r->held || r->piece == r->pieces)
			return 0;

		o = r->piece_len * (size_t)r->piece;
		for (n = 0; n < (int)r->piece_len; n++)
			buf[LWS_PRE + n] = pat(o + (size_t)n);

		wp = LWS_WRITE_HTTP;
		if (r->piece == r->pieces - 1) {
			lws_client_http_body_pending(wsi, 0);
			wp = LWS_WRITE_HTTP_FINAL;
		}

		if (lws_write(wsi, buf + LWS_PRE, r->piece_len,
			      (enum lws_write_protocol)wp) != (int)r->piece_len)
			return -1;

		r->ready = 0;
		if (++r->piece == r->pieces)
			return 0;

		lws_sul_schedule(context, 0, &r->sul, mreq_next_piece,
				 (r->piece == r->pause_at ? r->pause_ms :
							    r->piece_ms) *
				 LWS_US_PER_MS);
		return 0;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;
		return 0;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		if (len > sizeof(r->body) - 1 - r->body_len)
			len = sizeof(r->body) - 1 - r->body_len;
		memcpy(r->body + r->body_len, in, len);
		r->body_len += len;
		r->body[r->body_len] = '\0';
		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		r->completed = 1;
		r->status = (int)lws_http_client_http_response(wsi);
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		if (r->closed)
			break;
		lwsl_user("%s: %s (%d) closed, status %d, '%s'\n", __func__,
			  r->path, (int)(r - mreqs),
			  r->completed ? r->status : 0, r->body);
		r->closed = 1;
		r->wsi = NULL;
		lws_sul_cancel(&r->sul);
		lws_set_opaque_user_data(wsi, NULL);
		multi_check();
		return 0;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static int
multi_start(void)
{
	struct lws_client_connect_info i;
	int n;

	memset(mreqs, 0, sizeof(mreqs));
	if (tcase == AHL_BODY_RATE) {
		mreqs[0].path		= "/trickle";
		mreqs[0].piece_len	= AHL_TRICKLE_PIECE;
		mreqs[0].pieces		= AHL_TRICKLE_PIECES;
		mreqs[0].piece_ms	= AHL_TRICKLE_MS;
		mreqs[0].pause_at	= -1;
		mreqs[1].path		= "/steady";
		mreqs[1].piece_len	= AHL_STEADY_PIECE;
		mreqs[1].pieces		= AHL_STEADY_PIECES;
		mreqs[1].piece_ms	= AHL_STEADY_MS;
		mreqs[1].pause_at	= AHL_STEADY_PAUSE_AT;
		mreqs[1].pause_ms	= AHL_STEADY_PAUSE_MS;
		mreq_count = 2;
	} else {
		for (n = 0; n < AHL_MUX_REQS; n++) {
			mreqs[n].path		= "/hold";
			mreqs[n].piece_len	= 1;
			mreqs[n].pieces		= 1;
			mreqs[n].pause_at	= -1;
			mreqs[n].held		= 1;
		}
		/* GETs too, which arrive whole and must not be refused */
		for (n = AHL_MUX_REQS; n < AHL_MUX_REQS + AHL_MUX_GETS; n++) {
			mreqs[n].path		= AHL_SMALL_PATH;
			mreqs[n].get		= 1;
		}
		mreq_count = AHL_MUX_REQS + AHL_MUX_GETS;
		lws_sul_schedule(context, 0, &sul_release, mux_cap_release,
				 AHL_MUX_RELEASE_MS * LWS_US_PER_MS);
	}

	for (n = 0; n < mreq_count; n++) {
		memset(&i, 0, sizeof(i));
		i.context		= context;
		i.vhost			= vh_cli;
		i.address		= server_addr;
		i.host			= server_addr;
		i.origin		= server_addr;
		i.port			= port;
		i.path			= mreqs[n].path;
		i.method		= mreqs[n].get ? "GET" : "POST";
		i.protocol		= "ahl-multi";
		i.opaque_user_data	= &mreqs[n];
		if (role == AHL_H2)
			/* one connection for them all */
			i.ssl_connection = LCCSCF_H2_PRIOR_KNOWLEDGE |
					   LCCSCF_PIPELINE;
#if defined(LWS_ROLE_H3)
		if (role == AHL_H3) {
			i.alpn = "h3";
			i.ssl_connection = LCCSCF_USE_SSL |
					   LCCSCF_ALLOW_SELFSIGNED |
					LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK |
					   LCCSCF_PIPELINE;
			i.disable_h3_fallback = 1;
		}
#endif
		/* on h1, each its own connection, so they go at once */

		if (!lws_client_connect_via_info(&i))
			return 1;
	}

	return 0;
}

static const struct lws_protocols protocols_srv[] = {
	{ "ahl", callback_srv, sizeof(struct pss_srv), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols_cli[] = {
	{ "ahl-cli", callback_cli, 0, 0, 0, NULL, 0 },
	{ "ahl-raw", callback_raw, 0, 0, 0, NULL, 0 },
	{ "ahl-multi", callback_multi, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

#if !defined(WIN32)
static struct lws_http_mount mount_file = {
	.mountpoint		= "/f",
	.mountpoint_len		= 2,
	.origin_protocol	= LWSMPRO_FILE,
	.protocol		= "ahl",
	.def			= "big.txt",
};

/* the file to serve, made at runtime under the cwd, owner-only */
static int
make_file(size_t len)
{
	uint8_t b[4096];
	size_t n, o;
	int fd;

	lws_snprintf(docroot, sizeof(docroot), "ahl-docroot-%d", port);
	lws_snprintf(fpath, sizeof(fpath), "%s/big.txt", docroot);

	if (mkdir(docroot, 0700) && errno != EEXIST)
		return 1;

	fd = open(fpath, O_CREAT | O_TRUNC | O_WRONLY, 0600);
	if (fd < 0)
		return 1;

	for (o = 0; o < len; o += sizeof(b)) {
		for (n = 0; n < sizeof(b); n++)
			b[n] = pat(o + n);
		if (write(fd, b, sizeof(b)) != (ssize_t)sizeof(b)) {
			close(fd);
			return 1;
		}
	}
	close(fd);
	mount_file.origin = docroot;

	return 0;
}

static void
remove_file(void)
{
	if (!fpath[0])
		return;
	unlink(fpath);
	rmdir(docroot);
}
#endif

static void
watchdog_cb(lws_sorted_usec_list_t *sul)
{
	finish(0, "timed out");
}

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(context);
}

static int
pick(const char *v, const char * const *names, size_t count)
{
	size_t n;

	for (n = 0; v && n < count; n++)
		if (!strcmp(v, names[n]))
			return (int)n;

	return -1;
}

int main(int argc, const char **argv)
{
	const char *p, *cert = NULL, *key = NULL;
	struct lws_context_creation_info info;
	struct lws_client_connect_info i;
	int c, r;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	/* a server and its clients */
	info.fd_limit_per_thread = 0;

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);
	if ((p = lws_cmdline_option(argc, argv, "--server")))
		server_addr = p;
	cert = lws_cmdline_option(argc, argv, "--cert");
	key = lws_cmdline_option(argc, argv, "--key");

	c = pick(lws_cmdline_option(argc, argv, "--case"), case_names,
		 LWS_ARRAY_SIZE(case_names));
	r = pick(lws_cmdline_option(argc, argv, "--role"), role_names,
		 LWS_ARRAY_SIZE(role_names));
	if (r < 0)
		r = AHL_H1;
	if (c < 0 || (c < AHL_SLOW_CL && r != AHL_H1) ||
	    (c == AHL_MUX_CAP_CASE && r == AHL_H1) ||
	    (r == AHL_H3 && (!cert || !key))) {
		lwsl_err("--case file-stall | pipeline-depth (h1 only) | "
			 "slow-cl | slow-stream | late-spa | late-range | "
			 "late-coded | body-rate | mux-cap (h2, h3 only), "
			 "--role h1 | h2 | h3 (h3 needs --cert and --key)\n");
		return 1;
	}
	tcase = (enum ahl_case)c;
	role = (enum ahl_role)r;

#if !defined(LWS_ROLE_H2)
	if (role == AHL_H2) {
		lwsl_err("this build has no h2\n");
		return 1;
	}
#endif
#if !defined(LWS_ROLE_H3)
	if (role == AHL_H3) {
		lwsl_err("this build has no h3\n");
		return 1;
	}
#endif

#if !defined(LWS_WITH_RANGES)
	if (tcase == AHL_LATE_RANGE) {
		lwsl_err("this build has no ranges\n");
		return 1;
	}
#endif
#if !defined(LWS_WITH_HTTP_STREAM_COMPRESSION)
	if (tcase == AHL_LATE_CODED) {
		lwsl_err("this build has no stream compression\n");
		return 1;
	}
#endif

#if defined(WIN32) || !defined(LWS_WITH_FILE_OPS)
	if (tcase == AHL_FILE_STALL || late_file_case()) {
		lwsl_err("%s is not supported on this platform\n",
			 case_names[tcase]);
		return 1;
	}
#else
	if (((tcase == AHL_FILE_STALL && make_file(AHL_FILE_LEN)) ||
	     (late_file_case() && make_file(AHL_LATE_FILE_LEN)))) {
		lwsl_err("could not make the file to serve\n");
		return 1;
	}
#endif

	signal(SIGINT, sigint_handler);
	lwsl_user("LWS API selftest: http ah lifetime, %s on %s\n",
		  case_names[tcase], role_names[role]);

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS |
		       LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.timeout_secs = AHL_TIMEOUT_S;
	info.timeout_secs_ah_idle = AHL_AH_IDLE_S;
	if (tcase == AHL_MUX_CAP_CASE)
		info.max_http_header_pool_per_mux = AHL_MUX_CAP;
	if (tcase == AHL_BODY_RATE) {
		/* the server vhost's, below */
		info.http_body_min_rate = AHL_RATE;
		info.http_body_grace_secs = AHL_RATE_GRACE_S;
	}

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		goto bail1;
	}

	info.port = port;
	info.vhost_name = "ahl";
	info.protocols = protocols_srv;
#if !defined(WIN32)
	if (tcase == AHL_FILE_STALL)
		info.mounts = &mount_file;
#endif
	if (role == AHL_H2)
		info.options |= LWS_SERVER_OPTION_H2_PRIOR_KNOWLEDGE;
#if defined(LWS_ROLE_H3)
	if (role == AHL_H3) {
		info.ssl_cert_filepath = cert;
		info.ssl_private_key_filepath = key;
		info.alpn = "h2,http/1.1,h3";
	}
#endif

	if (!lws_create_vhost(context, &info)) {
		lwsl_err("Failed to create the server vhost\n");
		goto bail;
	}

	info.options &= ~(uint64_t)LWS_SERVER_OPTION_H2_PRIOR_KNOWLEDGE;
#if defined(LWS_ROLE_H3)
	info.ssl_cert_filepath = NULL;
	info.ssl_private_key_filepath = NULL;
	info.alpn = NULL;
#endif
	info.mounts = NULL;
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.vhost_name = "cli";
	info.protocols = protocols_cli;
	vh_cli = lws_create_vhost(context, &info);
	if (!vh_cli) {
		lwsl_err("Failed to create the client vhost\n");
		goto bail;
	}

	lws_sul_schedule(context, 0, &sul_watchdog, watchdog_cb,
			 AHL_DEADLINE_S * LWS_US_PER_SEC);

	if (tcase < AHL_SLOW_CL) {
		if (raw_connect()) {
			lwsl_err("The raw connection could not be started\n");
			goto bail;
		}
	} else if (tcase >= AHL_BODY_RATE) {
		if (multi_start()) {
			lwsl_err("The connections could not be started\n");
			goto bail;
		}
	} else {
		memset(&i, 0, sizeof(i));
		i.context	= context;
		i.vhost		= vh_cli;
		i.address	= server_addr;
		i.host		= server_addr;
		i.origin	= server_addr;
		i.port		= port;
		i.path		= tcase == AHL_LATE_SPA ? "/spa" :
				  (late_file_case() ? "/late" : "/slow");
		i.method	= late_file_case() ? "GET" : "POST";
		i.protocol	= "ahl-cli";
		if (role == AHL_H2)
			i.ssl_connection = LCCSCF_H2_PRIOR_KNOWLEDGE;
#if defined(LWS_ROLE_H3)
		if (role == AHL_H3) {
			i.alpn = "h3";
			i.ssl_connection = LCCSCF_USE_SSL |
					   LCCSCF_ALLOW_SELFSIGNED |
					LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
			/* decided on h3, not by a fallback to tcp */
			i.disable_h3_fallback = 1;
		}
#endif

		if (!lws_client_connect_via_info(&i)) {
			lwsl_err("The connection could not be started\n");
			goto bail;
		}
	}

	while (!finished && lws_service(context, 0) >= 0)
		;

bail:
	lws_sul_cancel(&sul_watchdog);
	lws_sul_cancel(&cli.sul);
	lws_sul_cancel(&sul_release);
	for (c = 0; c < mreq_count; c++)
		lws_sul_cancel(&mreqs[c].sul);
	lws_context_destroy(context);
bail1:
#if !defined(WIN32)
	remove_file();
#endif

	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
