/*
 * lws-api-test-form-post-file
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Fences minimal-http-server-form-post-file (G-552, G-554), which ctest runs
 * as a fixture with a small --max-size and --max-files.  We POST multipart
 * uploads to it, one at a time, and look at what it did on disk:
 *
 *  - an ordinary file is stored in the upload dir with what we sent
 *  - absolute, "../" and "..\" filenames are stored inside the upload dir
 *    under their purified names, and nothing appears where they pointed
 *  - a name that already exists is refused (409), the existing file intact
 *  - a symlink planted in the upload dir is not followed (409), nothing
 *    appears where it points
 *  - a file one byte over --max-size is refused (413), nothing kept
 *  - a body declared far over the limit is refused, nothing kept
 *  - an upload abandoned partway (the connection closes) leaves no partial
 *    file, and the same name can then be uploaded
 *  - refused and abandoned uploads don't use up the file budget: exactly
 *    --max-files files are stored, and then uploads are refused (503)
 */

#include <libwebsockets.h>

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#if !defined(WIN32)
#include <unistd.h>
#else
#include <io.h>
#endif

#define BOUNDARY	"lws-apitest-fpf-b0undary"
#define MAX_FILES	6	/* must match the fixture's --max-files */

enum {
	F_STORED	= (1 << 0),	/* expect it stored under .stored */
	F_ABSENT	= (1 << 1),	/* expect nothing under .stored */
	F_ABORT		= (1 << 2),	/* close the connection mid-file */
	F_DECLARE_HUGE	= (1 << 3),	/* declare a huge body, send none */
	F_SYMLINK	= (1 << 4),	/* plant .stored as a symlink first */
	F_OVERSIZE	= (1 << 5),	/* .size is max_size + 1 */
	F_OUTSIDE_FN	= (1 << 6),	/* filename is outside_dir + .filename */
	F_RETRY_409	= (1 << 7),	/* retry a while if it gets 409 */
};

struct tcase {
	const char	*filename;	/* what we tell the server */
	const char	*stored;	/* what it should store it as */
	const char	*escape;	/* NULL, or where the unpurified name
					 * points, relative to the upload dir
					 * (outside dir for F_SYMLINK); it must
					 * not appear */
	size_t		size;
	unsigned int	status;		/* expected response, 0 = none */
	unsigned int	flags;
};

static const struct tcase cases[] = {
	{ "plain.txt", "plain.txt", NULL, 1000,
		HTTP_STATUS_SEE_OTHER, F_STORED },
	{ "/abs-target.txt", NULL, NULL, 200,
		HTTP_STATUS_SEE_OTHER, F_STORED | F_OUTSIDE_FN },
	{ "../escape.txt", "___escape.txt", "../escape.txt", 200,
		HTTP_STATUS_SEE_OTHER, F_STORED },
	{ "..\\..\\winesc.txt", "______winesc.txt", NULL, 200,
		HTTP_STATUS_SEE_OTHER, F_STORED },
	/* plain.txt exists: refused, and still what case 0 sent */
	{ "plain.txt", "plain.txt", NULL, 300,
		HTTP_STATUS_CONFLICT, 0 },
#if !defined(WIN32)
	{ "link.txt", "link.txt", "link-target.txt", 200,
		HTTP_STATUS_CONFLICT, F_SYMLINK },
#endif
	{ "big.bin", "big.bin", NULL, 0,
		HTTP_STATUS_REQ_ENTITY_TOO_LARGE, F_ABSENT | F_OVERSIZE },
	/*
	 * The server refuses it with a 413 as soon as it has the headers and
	 * closes, but an h1 client still owing its body doesn't read the
	 * response (it times out instead): we can only check nothing is kept
	 */
	{ "huge.bin", "huge.bin", NULL, 0,
		0, F_ABSENT | F_DECLARE_HUGE },
	{ "abort.bin", "abort.bin", NULL, 4000,
		0, F_ABSENT | F_ABORT },
	/*
	 * The server removes the partial file when it sees our close, which
	 * can be after it took this connection: it takes a few goes while
	 * the name is still there.  Old code that kept the partial file never
	 * succeeds here.
	 */
	{ "abort.bin", "abort.bin", NULL, 100,
		HTTP_STATUS_SEE_OTHER, F_STORED | F_RETRY_409 },
	{ "fill-1.txt", "fill-1.txt", NULL, 10,
		HTTP_STATUS_SEE_OTHER, F_STORED },
	/* that was the MAX_FILES'th file stored: the budget is used up */
	{ "fill-2.txt", "fill-2.txt", NULL, 10,
		HTTP_STATUS_SERVICE_UNAVAILABLE, F_ABSENT },
};

static struct lws_context *cx;
static lws_sorted_usec_list_t sul_next, sul_timeout;
static const char *server = "localhost", *upload_dir, *outside_dir;
static unsigned long long max_size = 8192;
static int port, case_idx = -1, fails, finished, retries;

/* the case in flight */
static struct {
	char		*body;		/* the whole multipart body */
	size_t		body_len;	/* what we send of it */
	size_t		declared;	/* Content-Length */
	size_t		sent;
	size_t		size;		/* file content length */
	char		stored[512];	/* the name we expect it stored as */
	char		escape[1024];	/* "", or a path that must not appear */
	unsigned int	status;
	char		done;
} cur;

static void next_case(lws_sorted_usec_list_t *sul);

static char
content_byte(size_t n, int seed)
{
	return (char)('a' + ((n * 7u + (unsigned int)seed) % 26u));
}

static int
path_exists(const char *path)
{
	struct stat st;

#if !defined(WIN32)
	return !lstat(path, &st);
#else
	return !stat(path, &st);
#endif
}

/* the file must hold exactly size bytes of content_byte(seed) */

static int
file_matches(const char *path, size_t size, int seed)
{
	char buf[1024];
	size_t ofs = 0;
	int fd, n, m;

	fd = lws_open(path, O_RDONLY);
	if (fd < 0)
		return 0;

	while ((n = (int)read(fd, buf, sizeof(buf))) > 0) {
		for (m = 0; m < n; m++)
			if (buf[m] != content_byte(ofs + (size_t)m, seed)) {
				close(fd);
				return 0;
			}
		ofs += (size_t)n;
	}
	close(fd);

	return n == 0 && ofs == size;
}

static int
callback_http(struct lws *wsi, enum lws_callback_reasons reason,
	      void *user, void *in, size_t len)
{
	char buf[LWS_PRE + 2048], *px = buf + LWS_PRE;
	const struct tcase *c;
	int n, lenx;
	size_t chunk;

	if (case_idx < 0 || case_idx >= (int)LWS_ARRAY_SIZE(cases))
		/* eg, protocol init, before we start any case */
		return lws_callback_http_dummy(wsi, reason, user, in, len);

	c = &cases[case_idx];

	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_notice("%s: case %d: connection error %s\n", __func__,
			    case_idx, in ? (const char *)in : "");
		goto done;

	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER: {
		unsigned char **p = (unsigned char **)in, *end = (*p) + len;

		*p += lws_snprintf((char *)*p, lws_ptr_diff_size_t(end, *p),
				   "Content-Type: multipart/form-data; "
				   "boundary=" BOUNDARY "\x0d\x0a"
				   "Content-Length: %llu\x0d\x0a",
				   (unsigned long long)cur.declared);
		lws_client_http_body_pending(wsi, 1);
		if (!(c->flags & F_DECLARE_HUGE))
			lws_callback_on_writable(wsi);
		break;
	}

	case LWS_CALLBACK_CLIENT_HTTP_WRITEABLE:
		if (cur.sent == cur.body_len)
			return 0;

		chunk = cur.body_len - cur.sent;
		if (chunk > sizeof(buf) - LWS_PRE)
			chunk = sizeof(buf) - LWS_PRE;
		memcpy(px, cur.body + cur.sent, chunk);
		cur.sent += chunk;

		n = LWS_WRITE_HTTP;
		if (cur.sent == cur.declared) {
			lws_client_http_body_pending(wsi, 0);
			n = LWS_WRITE_HTTP_FINAL;
		}

		if (lws_write(wsi, (unsigned char *)px, chunk,
			      (enum lws_write_protocol)n) != (int)chunk)
			return -1;

		if (cur.sent == cur.body_len) {
			if (c->flags & F_ABORT) {
				/* walk away partway through the file */
				lwsl_user("case %d: abandoning upload\n",
					  case_idx);
				return -1;
			}
			return 0;
		}

		lws_callback_on_writable(wsi);
		return 0;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		cur.status = lws_http_client_http_response(wsi);
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		lenx = (int)(sizeof(buf) - LWS_PRE);
		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;
		return 0;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		if (!cur.done) {
			cur.done = 1;
			lws_sul_schedule(cx, 0, &sul_next, next_case, 1);
		}
		/* we don't reuse the connection */
		return -1;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		goto done;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);

done:
	if (!cur.done) {
		cur.done = 1;
		lws_sul_schedule(cx, 0, &sul_next, next_case, 1);
	}

	return 0;
}

static const struct lws_protocols protocols[] = {
	{ "http", callback_http, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

/* look at what the server did with the case just finished */

static void
check_case(void)
{
	const struct tcase *c = &cases[case_idx];
	char path[1024];

	if (c->status && cur.status != c->status) {
		lwsl_err("case %d (%s): status %u, expected %u\n", case_idx,
			 c->filename, cur.status, c->status);
		fails++;
	}

	if (cur.escape[0] && path_exists(cur.escape)) {
		lwsl_err("case %d (%s): %s was written outside the upload "
			 "dir\n", case_idx, c->filename, cur.escape);
		fails++;
	}

	lws_snprintf(path, sizeof(path), "%s/%s", upload_dir, cur.stored);

	if ((c->flags & F_STORED) &&
	    !file_matches(path, cur.size, case_idx)) {
		lwsl_err("case %d (%s): %s missing or wrong\n", case_idx,
			 c->filename, path);
		fails++;
	}

	if ((c->flags & F_ABSENT) && path_exists(path)) {
		lwsl_err("case %d (%s): %s was left behind\n", case_idx,
			 c->filename, path);
		fails++;
	}

	if (!strcmp(c->filename, "plain.txt") && !(c->flags & F_STORED) &&
	    !file_matches(path, cases[0].size, 0)) {
		lwsl_err("case %d: the existing plain.txt was changed\n",
			 case_idx);
		fails++;
	}
}

static int
build_body(const struct tcase *c)
{
	char head[1024], fn[512];
	size_t hl, tl, n;
	static const char tail[] = "\x0d\x0a--" BOUNDARY "--\x0d\x0a";

	if (c->flags & F_OUTSIDE_FN)
		lws_snprintf(fn, sizeof(fn), "%s%s", outside_dir, c->filename);
	else
		lws_strncpy(fn, c->filename, sizeof(fn));

	/* the server only ever stores a purified single component */
	lws_strncpy(cur.stored, c->stored ? c->stored : fn,
		    sizeof(cur.stored));
	if (!c->stored)
		lws_filename_purify_inplace(cur.stored);

	if (c->flags & F_OUTSIDE_FN)
		lws_strncpy(cur.escape, fn, sizeof(cur.escape));
	else if (c->escape)
		lws_snprintf(cur.escape, sizeof(cur.escape), "%s/%s",
			     (c->flags & F_SYMLINK) ? outside_dir : upload_dir,
			     c->escape);

	cur.size = c->size;
	if (c->flags & F_OVERSIZE)
		cur.size = (size_t)max_size + 1;

	hl = (size_t)lws_snprintf(head, sizeof(head),
		"--" BOUNDARY "\x0d\x0a"
		"Content-Disposition: form-data; name=\"text1\"\x0d\x0a\x0d\x0a"
		"hello\x0d\x0a"
		"--" BOUNDARY "\x0d\x0a"
		"Content-Disposition: form-data; name=\"file\"; "
		"filename=\"%s\"\x0d\x0a"
		"Content-Type: application/octet-stream\x0d\x0a\x0d\x0a", fn);
	tl = sizeof(tail) - 1;

	cur.body_len = hl + cur.size + tl;
	cur.body = malloc(cur.body_len);
	if (!cur.body)
		return 1;

	memcpy(cur.body, head, hl);
	for (n = 0; n < cur.size; n++)
		cur.body[hl + n] = content_byte(n, case_idx);
	memcpy(cur.body + hl + cur.size, tail, tl);

	cur.declared = cur.body_len;

	if (c->flags & F_DECLARE_HUGE)
		/* far past the server's body limit, and we send none of it */
		cur.declared = (size_t)max_size * 4 + 65536;

	if (c->flags & F_ABORT)
		/* we stop halfway through the file content */
		cur.body_len = hl + cur.size / 2;

	return 0;
}

static void
finish(int failed)
{
	if (failed)
		fails++;
	finished = 1;
	lws_cancel_service(cx);
}

static void
next_case(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;
	const struct tcase *c;
	char path[1024];

	if (case_idx >= 0 && cur.done) {
		c = &cases[case_idx];
		free(cur.body);
		cur.body = NULL;

		if ((c->flags & F_RETRY_409) &&
		    cur.status == HTTP_STATUS_CONFLICT && retries++ < 30) {
			/* the same case again, a little later */
			cur.done = 0;
			lws_sul_schedule(cx, 0, &sul_next, next_case,
					 100 * LWS_US_PER_MS);
			return;
		}

		/*
		 * The server removes an abandoned upload's partial file when
		 * it sees our close, which can be a little after we closed:
		 * give it a few goes to be gone before it counts as left behind
		 */
		lws_snprintf(path, sizeof(path), "%s/%s", upload_dir,
			     cur.stored);
		if ((c->flags & F_ABORT) && path_exists(path) &&
		    retries++ < 30) {
			lws_sul_schedule(cx, 0, &sul_next, next_case,
					 100 * LWS_US_PER_MS);
			return;
		}

		retries = 0;
		check_case();
	}

	/* not done: a retry of the case in hand */
	if (case_idx < 0 || cur.done)
		if (++case_idx == (int)LWS_ARRAY_SIZE(cases)) {
			finish(0);
			return;
		}

	c = &cases[case_idx];
	memset(&cur, 0, sizeof(cur));

	if (build_body(c)) {
		finish(1);
		return;
	}

#if !defined(WIN32)
	if (c->flags & F_SYMLINK) {
		lws_snprintf(path, sizeof(path), "%s/%s", upload_dir,
			     cur.stored);
		if (symlink(cur.escape, path)) {
			lwsl_err("unable to plant symlink %s\n", path);
			finish(1);
			return;
		}
	}
#endif

	lwsl_user("case %d: '%s', %llu bytes\n", case_idx, c->filename,
		  (unsigned long long)cur.size);

	memset(&i, 0, sizeof(i));
	i.context	= cx;
	i.address	= server;
	i.host		= server;
	i.origin	= server;
	i.port		= port;
	i.path		= "/form1";
	i.method	= "POST";
	i.protocol	= protocols[0].name;
	/* the 303 is what we want to see, not where it points */
	i.ssl_connection = LCCSCF_HTTP_NO_FOLLOW_REDIRECT;

	if (!lws_client_connect_via_info(&i) && !cur.done) {
		lwsl_err("case %d: connect failed\n", case_idx);
		cur.done = 1;
		lws_sul_schedule(cx, 0, &sul_next, next_case, 1);
	}
}

static void
timed_out(lws_sorted_usec_list_t *sul)
{
	lwsl_err("timed out at case %d\n", case_idx);
	finish(1);
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	unsigned long long ull;
	const char *p;
	int n = 0;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	lwsl_user("LWS API selftest: form-post-file example uploads\n");

	if ((p = lws_cmdline_option(argc, argv, "--server")))
		server = p;
	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);
	upload_dir = lws_cmdline_option(argc, argv, "--upload-dir");
	outside_dir = lws_cmdline_option(argc, argv, "--outside-dir");
	if ((p = lws_cmdline_option(argc, argv, "--max-size"))) {
		ull = strtoull(p, NULL, 10);
		if (ull)
			max_size = ull;
	}

	if (port <= 0 || port > 65535 || !upload_dir || !outside_dir) {
		lwsl_err("Usage: %s -p <port> --upload-dir <dir> "
			 "--outside-dir <dir> [--max-size <n>] "
			 "[--server <host>]\n", argv[0]);
		return 1;
	}

	info.port = CONTEXT_PORT_NO_LISTEN;
	info.protocols = protocols;
	/* the huge.bin case ends with our client's timeout */
	info.timeout_secs = 3;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	lws_sul_schedule(cx, 0, &sul_next, next_case, 1);
	lws_sul_schedule(cx, 0, &sul_timeout, timed_out, 60 * LWS_US_PER_SEC);

	while (n >= 0 && !finished)
		n = lws_service(cx, 0);

	lws_sul_cancel(&sul_next);
	lws_sul_cancel(&sul_timeout);
	lws_context_destroy(cx);
	free(cur.body);

	if (!finished)
		fails++;

	lwsl_user("Completed: %s\n", fails ? "FAIL" : "PASS");

	return !!fails;
}
