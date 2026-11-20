/*
 * lws fuzzing: the server application the fuzzed peer talks to
 *
 * Written in 2010 - 2026 Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * A server whose callbacks only return 0 never sends anything but what
 * lws sends by itself, so how the parsers' state meets the tx side (a
 * response going out in pieces while the request body still comes, a
 * window spent, a close crossing a partial write) is never exercised.
 * This application answers the way real ones do, and which way is the
 * peer's choice, by the url it asks for:
 *
 *   /post...	the body goes through the urlencoded / multipart parser
 *		(lws_spa), and the answer is made when it completes
 *   /early...	answered, and the transaction completed, at once, whatever
 *		body the request still has to come
 *   /stream...	an answer of pieces written a writeable callback at a time:
 *		the last char of the url says how many pieces and how big,
 *		and if there's a content-length or the end is the close
 *   /status...	the status page for a status the last char picks
 *   /redir...	a redirect
 *   /files/...	a file mount (index, a big file for ranges, a gzipped one)
 *   others	the 404 lws makes for anything not mounted
 *
 * and a ws protocol "echo" that sends back each message once it has had
 * all of it, so the peer's frames get answers to cross.
 *
 * The harness' EVENT ops 2 .. 7 are the application doing something of its
 * own accord to the connection it heard from last: asking to write, stopping
 * and restarting rx, closing it from its next callback, or giving it a
 * timeout.
 *
 * The worst server bugs don't crash: a path that walks out of the mount, a
 * header value that carries a CR LF into what the application builds.  So the
 * application also checks what lws promises it, and aborts, for libFuzzer to
 * report, when lws breaks a promise:
 *
 *  - every request's path, as the application is told it, is decoded and
 *    normalised: no control bytes, no empty, "." or ".." segments, and as
 *    long as it says it is; the args have no control bytes either
 *
 *  - no header value, known or custom, has a NUL, CR or LF in it
 *
 *  - no file outside the mount's dir is ever opened to be served, and the
 *    secrets that sit next to it, one in a dir whose name starts with the
 *    mount dir's, are never sent
 */

#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>

#define FZA_MSG_MAX	4096
#define FZA_PIECE_MAX	8192

struct fza_pss {
	struct lws_spa		*spa;
	size_t			pieces;	/* still to send */
	size_t			piece;	/* how big each is */
	uint8_t			no_length;
	uint8_t			answering;
	uint8_t			binary;
	size_t			msg_len;
	uint8_t			msg[FZA_MSG_MAX];
	uint8_t			msg_ready;
};

/*
 * The last wsi the application heard from, while it's bound to one of our
 * protocols: once it's moved off them, eg, onto another vhost, we don't hear
 * of it going away
 */
static struct lws *fza_wsi;
static int fza_close_next;
static char fza_root[64];	/* everything we make goes in here */
static char fza_dir[96];	/* the mount's origin, fza_root/www */
static char fza_dir_real[PATH_MAX];
static volatile size_t fza_sink;

/*
 * What sits next to the mount's dir and must never be served: in fza_root
 * itself, and in a dir whose name the mount dir's is a prefix of, for a check
 * that compares paths without the '/' after it
 */
static const char fza_secret[] = "lws-fuzz-secret-8d1e5a7c3f\n";
#define FZA_SECRET_LEN (sizeof(fza_secret) - 1)

static uint8_t fza_tx_tail[FZA_SECRET_LEN];
static size_t fza_tx_tail_len;

/* each input is a new connection, nothing of the last one's is left to act on */
static void
fza_session_start(void)
{
	fza_wsi = NULL;
	fza_close_next = 0;
	fza_tx_tail_len = 0;
}

static void
fza_broken_promise(const char *what, const char *detail, size_t len)
{
	fprintf(stderr, "LWS FUZZ ORACLE: %s: '%.*s'\n", what,
		(int)(len > 256 ? 256 : len), detail);
	abort();
}

static int
fza_is_ctl(uint8_t c)
{
	return c < 0x20 || c == 0x7f;
}

/*
 * The request's path as the application is told it, from the uri sanitiser
 * (lws_parse_urldecode()): %xx are decoded, then runs of '/' are one, and "."
 * and ".." segments are gone, whether they came as such or escaped
 */
static void
fza_check_path(const char *uri, size_t len)
{
	size_t n, seg = 0;

	if (strlen(uri) != len)
		fza_broken_promise("path is not as long as it says", uri, len);

	for (n = 0; n <= len; n++) {
		if (n < len && fza_is_ctl((uint8_t)uri[n]))
			fza_broken_promise("control byte in path", uri, len);

		if (n < len && uri[n] != '/')
			continue;

		/* uri[seg .. n) is a segment */
		if (n && n == seg && n < len)
			fza_broken_promise("empty segment in path", uri, len);
		if ((n - seg == 1 && uri[seg] == '.') ||
		    (n - seg == 2 && uri[seg] == '.' && uri[seg + 1] == '.'))
			fza_broken_promise("dot segment in path", uri, len);
		seg = n + 1;
	}
}

static void
fza_check_value(const char *what, const char *v, size_t len)
{
	if (memchr(v, '\0', len) || memchr(v, '\r', len) ||
	    memchr(v, '\n', len))
		fza_broken_promise(what, v, len);
}

#if defined(LWS_WITH_CUSTOM_HEADERS)
static void
fza_check_custom(const char *name, int nlen, void *opaque)
{
	struct lws *wsi = (struct lws *)opaque;
	static char v[8192];
	int n;

	fza_check_value("NUL, CR or LF in custom header name", name,
			(size_t)nlen);

	n = lws_hdr_custom_copy(wsi, v, (int)sizeof(v), name, nlen);
	if (n > 0)
		fza_check_value("NUL, CR or LF in custom header value", v,
				(size_t)n);
}
#endif

/* everything the application is told about the request, as it's dispatched */
static void
fza_check_request(struct lws *wsi, const char *uri, size_t len)
{
	static char v[8192];
	int h, n, f;

	if (uri)
		fza_check_path(uri, len);

	for (f = 0; ; f++) {
		n = lws_hdr_copy_fragment(wsi, v, (int)sizeof(v),
					  WSI_TOKEN_HTTP_URI_ARGS, f);
		if (n < 0)
			break;
		for (h = 0; h < n; h++)
			if (fza_is_ctl((uint8_t)v[h]))
				fza_broken_promise("control byte in uri arg",
						   v, (size_t)n);
	}

	for (h = 0; h < WSI_TOKEN_COUNT; h++) {
		n = lws_hdr_total_length(wsi, (enum lws_token_indexes)h);
		if (n <= 0 || n >= (int)sizeof(v))
			continue;
		if (lws_hdr_copy(wsi, v, (int)sizeof(v),
				 (enum lws_token_indexes)h) != n)
			fza_broken_promise("header copy is not as long as its "
					   "length", lws_token_to_string(
					   (enum lws_token_indexes)h) ?
					   (const char *)lws_token_to_string(
					   (enum lws_token_indexes)h) : "?", 1);
		fza_check_value("NUL, CR or LF in header value", v, (size_t)n);
	}

#if defined(LWS_WITH_CUSTOM_HEADERS)
	lws_hdr_custom_name_foreach(wsi, fza_check_custom, wsi);
#endif
}

static int
fza_has_secret(const uint8_t *p, size_t len)
{
	size_t n;

	for (n = 0; n + FZA_SECRET_LEN <= len; n++)
		if (p[n] == (uint8_t)fza_secret[0] &&
		    !memcmp(p + n, fza_secret, FZA_SECRET_LEN))
			return 1;

	return 0;
}

/*
 * Everything lws sends goes by here: the secrets must never be in it.  The
 * last FZA_SECRET_LEN - 1 bytes sent are kept, for a secret split across
 * writes.
 */
static void
fza_tx_check(const uint8_t *buf, size_t len)
{
	uint8_t join[2 * FZA_SECRET_LEN];
	size_t k = len < FZA_SECRET_LEN - 1 ? len : FZA_SECRET_LEN - 1, keep;

	memcpy(join, fza_tx_tail, fza_tx_tail_len);
	memcpy(join + fza_tx_tail_len, buf, k);
	if (fza_has_secret(join, fza_tx_tail_len + k) ||
	    fza_has_secret(buf, len))
		fza_broken_promise("a secret outside the mount was sent",
				   fza_secret, FZA_SECRET_LEN);

	if (len >= FZA_SECRET_LEN - 1) {
		memcpy(fza_tx_tail, buf + len - (FZA_SECRET_LEN - 1),
		       FZA_SECRET_LEN - 1);
		fza_tx_tail_len = FZA_SECRET_LEN - 1;
		return;
	}

	keep = FZA_SECRET_LEN - 1 - len;
	if (keep > fza_tx_tail_len)
		keep = fza_tx_tail_len;
	memmove(fza_tx_tail, fza_tx_tail + fza_tx_tail_len - keep, keep);
	memcpy(fza_tx_tail + keep, buf, len);
	fza_tx_tail_len = keep + len;
}

/*
 * Every file lws opens under fza_root comes here first, by the file ops'
 * path signature, which is fza_root.  What it opens has to be in the mount's
 * dir, whatever the path said to get there.  Then it's opened by the
 * platform's own ops, which the opened file is bound to after.
 */
static lws_fop_fd_t
fza_fops_open(const struct lws_plat_file_ops *fops_own,
	      const struct lws_plat_file_ops *fops, const char *filename,
	      const char *vpath, lws_fop_flags_t *flags)
{
	char real[PATH_MAX];
	size_t dl = strlen(fza_dir_real);
	lws_fop_fd_t fd;

	(void)fops_own;

	fd = fops->LWS_FOP_OPEN(fops, fops, filename, vpath, flags);
	if (!fd)
		return NULL;

	if (!realpath(filename, real) || strncmp(real, fza_dir_real, dl) ||
	    real[dl] != '/')
		fza_broken_promise("opened a file outside the mount", filename,
				   strlen(filename));

	return fd;
}

static struct lws_plat_file_ops fza_fops = {
	.LWS_FOP_OPEN		= fza_fops_open,
};

static const char * const fza_params[] = { "a", "b", "file", "text" };

static int
fza_upload_cb(void *data, const char *name, const char *filename,
	      char *buf, int len, enum lws_spa_fileupload_states state)
{
	(void)data;
	(void)name;
	(void)filename;
	(void)buf;
	(void)len;
	(void)state;

	return 0;
}

static int
fza_answer_headers(struct lws *wsi, struct fza_pss *pss, int status,
		   size_t content_len)
{
	uint8_t buf[LWS_PRE + 512], *start = &buf[LWS_PRE], *p = start,
		*end = &buf[sizeof(buf) - 1];

	if (lws_add_http_common_headers(wsi, (unsigned int)status, "text/plain",
					pss && pss->no_length ?
					    LWS_ILLEGAL_HTTP_CONTENT_LEN :
					    (lws_filepos_t)content_len,
					&p, end))
		return 1;
	if (lws_finalize_write_http_header(wsi, start, &p, end))
		return 1;

	return 0;
}

/* a short complete answer, and the transaction is done */
static int
fza_answer_short(struct lws *wsi, int status)
{
	uint8_t buf[LWS_PRE + 16];

	if (fza_answer_headers(wsi, NULL, status, 3))
		return -1;
	memcpy(&buf[LWS_PRE], "ok\n", 3);
	if (lws_write(wsi, &buf[LWS_PRE], 3, LWS_WRITE_HTTP_FINAL) != 3)
		return -1;

	return lws_http_transaction_completed(wsi) ? -1 : 0;
}

static int
fza_callback_http(struct lws *wsi, enum lws_callback_reasons reason,
		  void *user, void *in, size_t len)
{
	struct fza_pss *pss = (struct fza_pss *)user;
	uint8_t buf[LWS_PRE + FZA_PIECE_MAX];
	const char *uri = (const char *)in;
	uint8_t c;
	int n;

	switch (reason) {
	case LWS_CALLBACK_FILTER_HTTP_CONNECTION:
		/* every request, mounted or not, before it's dispatched */
		fza_check_request(wsi, uri, len);
		break;

	case LWS_CALLBACK_HTTP:
		fza_wsi = wsi;
		if (!uri || !pss)
			break;
		c = len ? (uint8_t)uri[len - 1] : 0;

		if (!strncmp(uri, "/post", 5))
			/* it exists: wait for the body */
			return 0;

		if (!strncmp(uri, "/early", 6))
			return fza_answer_short(wsi, HTTP_STATUS_OK);

		if (!strncmp(uri, "/stream", 7)) {
			pss->pieces = (size_t)(c & 7) + 1;
			pss->piece = (size_t)16 << ((c >> 3) & 7);
			if (pss->piece > FZA_PIECE_MAX)
				pss->piece = FZA_PIECE_MAX;
			pss->no_length = !!(c & 0x80);
			pss->answering = 1;
			if (fza_answer_headers(wsi, pss, HTTP_STATUS_OK,
					       pss->pieces * pss->piece))
				return -1;
			lws_callback_on_writable(wsi);
			return 0;
		}

		if (!strncmp(uri, "/status", 7)) {
			static const unsigned int st[] = {
				HTTP_STATUS_BAD_REQUEST,
				HTTP_STATUS_FORBIDDEN,
				HTTP_STATUS_NOT_FOUND,
				HTTP_STATUS_METHOD_NOT_ALLOWED,
				HTTP_STATUS_REQ_ENTITY_TOO_LARGE,
				HTTP_STATUS_INTERNAL_SERVER_ERROR,
				HTTP_STATUS_SERVICE_UNAVAILABLE,
				HTTP_STATUS_NO_CONTENT,
			};

			if (lws_return_http_status(wsi, st[c & 7], NULL))
				return -1;

			return lws_http_transaction_completed(wsi) ? -1 : 0;
		}

		if (!strncmp(uri, "/redir", 6)) {
			uint8_t *start = &buf[LWS_PRE], *p = start,
				*end = &buf[LWS_PRE + 512];

			if (lws_http_redirect(wsi, HTTP_STATUS_FOUND,
					      (unsigned char *)"/files/", 7,
					      &p, end) < 0)
				return -1;

			return lws_http_transaction_completed(wsi) ? -1 : 0;
		}
		break;

	case LWS_CALLBACK_HTTP_BODY:
		fza_wsi = wsi;
		if (!pss)
			break;
		if (!pss->spa) {
			lws_spa_create_info_t i;

			memset(&i, 0, sizeof(i));
			i.param_names = fza_params;
			i.count_params = (int)LWS_ARRAY_SIZE(fza_params);
			i.max_storage = 1024;
			i.opt_cb = fza_upload_cb;
			pss->spa = lws_spa_create_via_info(wsi, &i);
			if (!pss->spa)
				return -1;
		}
		if (lws_spa_process(pss->spa, in, (int)len))
			return -1;
		break;

	case LWS_CALLBACK_HTTP_BODY_COMPLETION:
		fza_wsi = wsi;
		if (pss && pss->spa) {
			lws_spa_finalize(pss->spa);
			/* what was decoded is all there, for ASan to see */
			for (n = 0; n < (int)LWS_ARRAY_SIZE(fza_params); n++)
				if (lws_spa_get_string(pss->spa, n))
					fza_sink += strlen(lws_spa_get_string(
								pss->spa, n));
			lws_spa_destroy(pss->spa);
			pss->spa = NULL;
		}
		if (pss && pss->answering)
			/* the stream answer is already going */
			break;

		return fza_answer_short(wsi, HTTP_STATUS_OK);

	case LWS_CALLBACK_HTTP_WRITEABLE:
		fza_wsi = wsi;
		if (!pss || !pss->pieces)
			break;
		memset(&buf[LWS_PRE], 'a' + (int)(pss->pieces % 26),
		       pss->piece);
		pss->pieces--;
		if (lws_write(wsi, &buf[LWS_PRE], pss->piece,
			      pss->pieces ? LWS_WRITE_HTTP :
					    LWS_WRITE_HTTP_FINAL) !=
							(int)pss->piece)
			return -1;
		if (pss->pieces) {
			lws_callback_on_writable(wsi);
			break;
		}
		pss->answering = 0;

		return lws_http_transaction_completed(wsi) ? -1 : 0;

	case LWS_CALLBACK_CLOSED_HTTP:
	case LWS_CALLBACK_HTTP_DROP_PROTOCOL:
		/*
		 * The pss lives as long as the transaction's protocol bind, and
		 * the transaction can end before its body: a /stream answer
		 * completes it with the body still coming, and the keepalive
		 * connection is bound again with a fresh pss
		 */
		if (pss && pss->spa) {
			lws_spa_destroy(pss->spa);
			pss->spa = NULL;
		}
		if (reason == LWS_CALLBACK_CLOSED_HTTP)
			break;
		if (wsi == fza_wsi)
			fza_wsi = NULL;
		break;

	case LWS_CALLBACK_WSI_DESTROY:
		if (wsi == fza_wsi)
			fza_wsi = NULL;
		break;

	default:
		break;
	}

	if (fza_close_next && wsi == fza_wsi && reason != LWS_CALLBACK_WSI_DESTROY) {
		fza_close_next = 0;
		return -1;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static int
fza_callback_echo(struct lws *wsi, enum lws_callback_reasons reason,
		  void *user, void *in, size_t len)
{
	struct fza_pss *pss = (struct fza_pss *)user;
	uint8_t buf[LWS_PRE + FZA_MSG_MAX];

	switch (reason) {
	case LWS_CALLBACK_ESTABLISHED:
		fza_wsi = wsi;
		break;

	case LWS_CALLBACK_RECEIVE:
		fza_wsi = wsi;
		if (!pss || pss->msg_ready)
			/* still sending the last one: take it as lost */
			break;
		if (lws_is_first_fragment(wsi)) {
			pss->msg_len = 0;
			pss->binary = !!lws_frame_is_binary(wsi);
		}
		if (len > sizeof(pss->msg) - pss->msg_len)
			len = sizeof(pss->msg) - pss->msg_len;
		memcpy(pss->msg + pss->msg_len, in, len);
		pss->msg_len += len;
		if (lws_is_final_fragment(wsi)) {
			pss->msg_ready = 1;
			lws_callback_on_writable(wsi);
		}
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		fza_wsi = wsi;
		if (!pss || !pss->msg_ready)
			break;
		memcpy(&buf[LWS_PRE], pss->msg, pss->msg_len);
		if (lws_write(wsi, &buf[LWS_PRE], pss->msg_len,
			      pss->binary ? LWS_WRITE_BINARY :
					    LWS_WRITE_TEXT) <
							(int)pss->msg_len)
			return -1;
		pss->msg_ready = 0;
		break;

	case LWS_CALLBACK_WSI_DESTROY:
		if (wsi == fza_wsi)
			fza_wsi = NULL;
		break;

	default:
		break;
	}

	if (fza_close_next && wsi == fza_wsi && reason != LWS_CALLBACK_WSI_DESTROY) {
		fza_close_next = 0;
		return -1;
	}

	return 0;
}

static const struct lws_protocols fza_protocols[] = {
	{ "http", fza_callback_http, sizeof(struct fza_pss), 0, 0, NULL, 0 },
	{ "echo", fza_callback_echo, sizeof(struct fza_pss), FZA_MSG_MAX,
	  0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

#if !defined(LWS_WITHOUT_EXTENSIONS)
static const struct lws_extension fza_extensions[] = {
	{ "permessage-deflate", lws_extension_callback_pm_deflate,
	  "permessage-deflate; client_max_window_bits" },
	{ NULL, NULL, NULL }
};
#endif

static struct lws_http_mount fza_mount = {
	.mountpoint		= "/files",
	.mountpoint_len		= 6,
	.origin_protocol	= LWSMPRO_FILE,
	.def			= "index.html",
};

/* the application doing something of its own accord: EVENT ops 2 .. 7 */
static void
fza_event(struct fzp_transport *t, int ev)
{
	(void)t;

	if (!fza_wsi)
		return;

	switch (ev) {
	case 2:
		lws_callback_on_writable(fza_wsi);
		break;
	case 3:
		lws_rx_flow_control(fza_wsi, 0);
		break;
	case 4:
		lws_rx_flow_control(fza_wsi, 1);
		break;
	case 5:
		fza_close_next = 1;
		lws_callback_on_writable(fza_wsi);
		break;
	case 6:
		lws_set_timeout(fza_wsi, PENDING_TIMEOUT_USER_OK, 1);
		break;
	case 7:
		lws_set_timeout(fza_wsi, PENDING_TIMEOUT_USER_OK,
				LWS_TO_KILL_ASYNC);
		break;
	default:
		break;
	}
}

static int
fza_file(const char *dir, const char *name, const uint8_t *pat,
	 size_t pat_len, size_t len)
{
	char path[160];
	uint8_t b[1024];
	size_t i, k;
	int fd;

	lws_snprintf(path, sizeof(path), "%s/%s", dir, name);
	fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
	if (fd < 0)
		return 1;
	for (i = 0; i < len; i += k) {
		size_t j;

		k = len - i < sizeof(b) ? len - i : sizeof(b);
		for (j = 0; j < k; j++)
			b[j] = pat[(i + j) % pat_len];
		if (write(fd, b, k) != (ssize_t)k) {
			close(fd);
			return 1;
		}
	}
	close(fd);

	return 0;
}

static void
fza_cleanup(void)
{
	static const char * const f[] = {
		"www/index.html", "www/big.txt", "www/t.txt.gz", "www/sub/x.txt",
		"secret.txt", "www-private/secret.txt"
	}, * const d[] = { "www/sub", "www", "www-private", "" };
	char path[160];
	size_t n;

	for (n = 0; n < LWS_ARRAY_SIZE(f); n++) {
		lws_snprintf(path, sizeof(path), "%s/%s", fza_root, f[n]);
		unlink(path);
	}
	for (n = 0; n < LWS_ARRAY_SIZE(d); n++) {
		lws_snprintf(path, sizeof(path), "%s/%s", fza_root, d[n]);
		rmdir(path);
	}
}

/*
 * The files the mount serves go in a dir of their own, www, next to the
 * secrets, in a dir that goes again at exit.  The gzip is "hello\n", for the
 * serving of precompressed files.
 */
static int
fza_files(void)
{
	char sub[128], priv[128];

	static const uint8_t gz[] = {
		0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
		0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0xe7, 0x02, 0x00, 0x20, 0x30,
		0x3a, 0x36, 0x06, 0x00, 0x00, 0x00
	};
	const char *tmp = getenv("TMPDIR");

	lws_snprintf(fza_root, sizeof(fza_root), "%s/lws-fuzz-XXXXXX",
		     tmp && strlen(tmp) < 40 ? tmp : "/tmp"); /* NOSONAR: mkdtemp */
	if (!mkdtemp(fza_root))
		return 1;
	atexit(fza_cleanup);

	lws_snprintf(fza_dir, sizeof(fza_dir), "%s/www", fza_root);
	lws_snprintf(sub, sizeof(sub), "%s/sub", fza_dir);
	lws_snprintf(priv, sizeof(priv), "%s/www-private", fza_root);
	if (mkdir(fza_dir, 0700) || mkdir(sub, 0700) || mkdir(priv, 0700) ||
	    !realpath(fza_dir, fza_dir_real))
		return 1;

	if (fza_file(fza_dir, "index.html",
		     (const uint8_t *)"<html>fuzz</html>\n", 18, 18) ||
	    fza_file(fza_dir, "big.txt", (const uint8_t *)"0123456789abcdef",
		     16, 200000) ||
	    fza_file(fza_dir, "t.txt.gz", gz, sizeof(gz), sizeof(gz)) ||
	    fza_file(sub, "x.txt", (const uint8_t *)"sub\n", 4, 4) ||
	    fza_file(fza_root, "secret.txt", (const uint8_t *)fza_secret,
		     FZA_SECRET_LEN, FZA_SECRET_LEN) ||
	    fza_file(priv, "secret.txt", (const uint8_t *)fza_secret,
		     FZA_SECRET_LEN, FZA_SECRET_LEN))
		return 1;

	fza_mount.origin = fza_dir;

	/* lws opens anything under fza_root through fza_fops first */
	fza_fops.fi[0].sig = fza_root;
	fza_fops.fi[0].len = (uint8_t)strlen(fza_root);

	return 0;
}

/* a context with the application, and vhost "fuzz" with options for it */
static struct lws_vhost *
fza_init(uint64_t vh_options)
{
	struct lws_context_creation_info info;

	if (fza_files())
		return NULL;

	memset(&info, 0, sizeof(info));
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
	info.fops = &fza_fops;
	fzp_tx_hook = fza_tx_check;

	if (fzp_init(&info))
		return NULL;

	info.vhost_name = "fuzz";
	info.protocols = fza_protocols;
	info.mounts = &fza_mount;
#if !defined(LWS_WITHOUT_EXTENSIONS)
	info.extensions = fza_extensions;
#endif
	info.options = vh_options;
	fzp_event_hook = fza_event;

	return lws_create_vhost(fzp_cx, &info);
}
