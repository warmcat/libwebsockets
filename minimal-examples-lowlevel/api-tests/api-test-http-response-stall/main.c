/*
 * lws-api-test-http-response-stall
 *
 * A response that is still going must be bounded by how long it stalls, not
 * how long it takes, and the stall it is allowed is the vhost's
 * http_response_stall_secs.
 *
 * The file sender used to arm the content timeout, timeout_secs, for each
 * piece of a file it sent, which overrode the response watchdog the headers
 * armed: a peer that stopped reading a big download for longer than
 * timeout_secs (15s by default), eg, a browser draining its cache to a slow
 * device, had it cut off, logged only at info level.
 *
 * The server vhost here serves a file much bigger than the socket buffers,
 * with timeout_secs of 2s and http_response_stall_secs of 6s.  The client
 * reads a little of it and stops reading with rx flow control:
 *
 *  - resuming after 4s, longer than timeout_secs, it must get the whole file;
 *  - not resuming, the server must give up on it, but no sooner than
 *    http_response_stall_secs after it stopped.  The client, not reading, can't
 *    see that, so the server's side of the test tells it, and it resumes to
 *    find the file cut off.
 *
 * The server's stall counts from the last it sent, and the last the client
 * read before it stopped was sent a little before that, so the server can
 * give up a few ms short of http_response_stall_secs after the client
 * stopped.  It must still be well past timeout_secs, the cut the file sender
 * used to make.
 *
 * The second does not resume at a set time, because a peer that stops
 * reading may still take a little more, which is progress that renews the
 * watchdog.  On the BSDs and macOS, the sender's persist timer probes the
 * closed window after 5s, and the receiver opens it for the room it had held
 * back from advertising, less than a segment, so the server's stall starts
 * again there and it gives up about 11s after the client stopped, not 6s.
 *
 * A second server vhost, with http_response_stall_secs of 2s, answers with
 * the whole of a 1.5MB response in one write, with the socket buffers on
 * both sides made small, so most of it waits in lws to be sent.  The client
 * takes it slowly, stopping for 150ms in each 64KB, so it takes far longer
 * than 2s to go:
 *
 *  - it must get all of it: what lws had waiting being taken is progress, and
 *    renews the watchdog, as much as the write was.
 *
 * This file is made available under the Creative Commons CC0 1.0 Universal
 * Public Domain Dedication.
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#define TIMEOUT_SECS	2
#define STALL_SECS	6
/* far bigger than loopback's socket buffers, so the server must wait */
#define FILE_SIZE	((off_t)64 * 1024 * 1024)
/* how much the client reads before it stops reading */
#define PAUSE_AT	(1024 * 1024)
/* how long a client that never resumes waits for the server to give up */
#define CUTOFF_GUARD_SECS	30
/* how much sooner than STALL_SECS the client may see it cut off, see above */
#define CUTOFF_SKEW_MS		500

/* the vhost answering with one big write, and how its client paces it */
#define BIG_STALL_SECS	2
/* within the 2MB lws holds for a wsi's unsent output */
#define BIG_SIZE	(1536 * 1024)
#define BIG_SKTBUF	(16 * 1024)
#define PACE_STEP	(64 * 1024)
#define PACE_MS		150

static const struct run {
	const char	*name;
	const char	*path;
	int		pause_secs;
	int		want_whole;
	int		paced;		/* to the big write's vhost */
} runs[] = {
	{ "pause past timeout_secs",	"/f/big.bin",	4, 1, 0 },
	{ "stop reading until cut off",	"/f/big.bin",	0, 0, 0 },
	{ "one big write, taken slowly", "/big",	0, 1, 1 },
};

/* the big write's vhost's side of its connection */
struct pss_big {
	int		sent;
};

static struct lws_context *context;
static lws_sorted_usec_list_t sul_timeout, sul_connect, sul_resume;
static struct lws *cli_wsi;
static int port = 7710, fail, done;
static size_t cur;
static uint64_t got;
static lws_usec_t paused_at, cut_at, started_at;
static uint64_t next_pace;
static int paused, completed;
static uint8_t *big;
static char fixture_dir[64], fixture_path[96];

static void
sul_connect_cb(lws_sorted_usec_list_t *sul);

static void
run_end(void)
{
	const struct run *r = &runs[cur];
	uint64_t size = r->paced ? (uint64_t)BIG_SIZE : (uint64_t)FILE_SIZE;
	int whole = completed && got == size;

	lwsl_user("%s: %s: got %llu of %llu%s\n", __func__, r->name,
		  (unsigned long long)got, (unsigned long long)size,
		  completed ? ", completed" : "");

	if (!paused) {
		lwsl_err("%s: %s: never paused, proves nothing\n", __func__,
			 r->name);
		fail++;
	} else if (whole != r->want_whole) {
		lwsl_err("%s: %s: want %s\n", __func__, r->name,
			 r->want_whole ? "the whole file" : "it cut off");
		fail++;
	} else if (r->paced) {
		lws_usec_t us = lws_now_usecs() - started_at;

		lwsl_user("%s: %s: took %lldms\n", __func__, r->name,
			  (long long)(us / LWS_US_PER_MS));
		if (us < (lws_usec_t)BIG_STALL_SECS * LWS_US_PER_SEC) {
			lwsl_err("%s: %s: took less than its vhost's "
				 "http_response_stall_secs, proves nothing\n",
				 __func__, r->name);
			fail++;
		}
	} else if (!r->want_whole) {
		lws_usec_t us = cut_at - paused_at;

		lwsl_user("%s: %s: cut off %lldms after it stopped reading\n",
			  __func__, r->name, (long long)(us / LWS_US_PER_MS));
		if (us < (lws_usec_t)STALL_SECS * LWS_US_PER_SEC -
			 (lws_usec_t)CUTOFF_SKEW_MS * LWS_US_PER_MS) {
			lwsl_err("%s: %s: cut off sooner than "
				 "http_response_stall_secs\n", __func__,
				 r->name);
			fail++;
		}
	}

	cli_wsi = NULL;
	lws_sul_cancel(&sul_resume);

	if (fail || ++cur == LWS_ARRAY_SIZE(runs)) {
		done = 1;
		lws_cancel_service(context);
		return;
	}

	lws_sul_schedule(context, 0, &sul_connect, sul_connect_cb, 1);
}

static void
sul_resume_cb(lws_sorted_usec_list_t *sul)
{
	if (!cli_wsi)
		return;

	if (runs[cur].pause_secs || runs[cur].paced || cut_at) {
		lws_rx_flow_control(cli_wsi, 1);
		return;
	}

	/* the server never gave up on the client that stopped reading */
	lwsl_err("%s: %s: not cut off %ds after it stopped reading\n",
		 __func__, runs[cur].name, CUTOFF_GUARD_SECS);
	fail++;
	done = 1;
	lws_cancel_service(context);
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	if (reason == LWS_CALLBACK_CONNECTING && runs[cur].paced) {
		lws_sockfd_type sfd = (lws_sockfd_type)(intptr_t)in;
		int rb = BIG_SKTBUF;

		/* small, so the big write can't hide in the kernel */
		if (setsockopt(sfd, SOL_SOCKET, SO_RCVBUF, (const char *)&rb,
			       sizeof(rb)))
			lwsl_warn("%s: SO_RCVBUF failed\n", __func__);

		return 0;
	}

	/* only our own connection: lws may make others, eg, to check the net */
	if (wsi != cli_wsi)
		return lws_callback_http_dummy(wsi, reason, user, in, len);

	switch (reason) {

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		if (lws_http_client_http_response(wsi) != HTTP_STATUS_OK) {
			lwsl_err("%s: response status %d\n", __func__,
				 (int)lws_http_client_http_response(wsi));
			fail++;
			return -1;
		}
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP: {
		char b[4096 + LWS_PRE], *px = b + LWS_PRE;
		int lenx = (int)sizeof(b) - LWS_PRE;

		if (lws_http_client_read(wsi, &px, &lenx) < 0)
			return -1;
		return 0;
	}

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		if (!got)
			started_at = lws_now_usecs();
		got += len;
		if (runs[cur].paced) {
			if (got < next_pace)
				return 0;
			/* stop a while, then go on */
			next_pace += PACE_STEP;
			paused = 1;
			lws_rx_flow_control(wsi, 0);
			lws_sul_schedule(context, 0, &sul_resume, sul_resume_cb,
					 PACE_MS * LWS_US_PER_MS);
			return 0;
		}
		if (!paused && got >= PAUSE_AT) {
			/* stop reading, as a browser draining to disk does */
			paused = 1;
			paused_at = lws_now_usecs();
			lws_rx_flow_control(wsi, 0);
			lws_sul_schedule(context, 0, &sul_resume, sul_resume_cb,
					 (lws_usec_t)(runs[cur].pause_secs ?
						runs[cur].pause_secs :
						CUTOFF_GUARD_SECS) *
							LWS_US_PER_SEC);
		}
		return 0;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		completed = 1;
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		run_end();
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

/* the server's side: its connection closing while the client stopped reading */
static int
callback_srv(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	if (reason == LWS_CALLBACK_CLOSED_HTTP && cli_wsi && paused &&
	    !runs[cur].want_whole && !cut_at) {
		cut_at = lws_now_usecs();
		/* the client resumes, to find what it got cut off */
		lws_sul_schedule(context, 0, &sul_resume, sul_resume_cb, 1);
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

/* the big write's vhost: the whole response in one lws_write() */
static int
callback_big(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	struct pss_big *pss = (struct pss_big *)user;
	uint8_t hdr[LWS_PRE + 256], *start = &hdr[LWS_PRE], *p = start,
		*end = &hdr[sizeof(hdr) - 1];

	switch (reason) {
	case LWS_CALLBACK_HTTP: {
		lws_sockfd_type sfd = lws_get_socket_fd(wsi);
		int sb = BIG_SKTBUF;

		if (strcmp((const char *)in, "/big"))
			return lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND,
						      NULL);

		/* small, so most of the write must wait in lws */
		if (sfd != LWS_SOCK_INVALID &&
		    setsockopt(sfd, SOL_SOCKET, SO_SNDBUF, (const char *)&sb,
			       sizeof(sb)))
			lwsl_warn("%s: SO_SNDBUF failed\n", __func__);

		if (lws_add_http_common_headers(wsi, HTTP_STATUS_OK,
						"application/octet-stream",
						BIG_SIZE, &p, end) ||
		    lws_finalize_write_http_header(wsi, start, &p, end))
			return 1;

		pss->sent = 0;
		lws_callback_on_writable(wsi);
		return 0;
	}

	case LWS_CALLBACK_HTTP_WRITEABLE:
		if (pss->sent)
			return 0;
		pss->sent = 1;
		if (lws_write(wsi, big + LWS_PRE, BIG_SIZE,
			      LWS_WRITE_HTTP_FINAL) != BIG_SIZE)
			return 1;
		/* it completes when what lws holds of it has gone */
		if (lws_http_transaction_completed(wsi))
			return -1;
		return 0;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols_big[] = {
	{ "http", callback_big, sizeof(struct pss_big), 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static const struct lws_protocols protocols[] = {
	{ "http", callback_srv, 0, 0, 0, NULL, 0 },
	{ "stall-cli", callback_cli, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

/* lws serves no file type it doesn't know */
static const struct lws_protocol_vhost_options mime_bin = {
	NULL, NULL, ".bin", "application/octet-stream"
};

static struct lws_http_mount mount = {
	.mountpoint		= "/f",
	.origin			= NULL,		/* the fixture dir */
	.extra_mimetypes	= &mime_bin,
	.origin_protocol	= LWSMPRO_FILE,
	.mountpoint_len		= 2,
};

static void
sul_timeout_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("%s: timed out in run %d\n", __func__, (int)cur);
	fail++;
	done = 1;
	lws_cancel_service(context);
}

static void
sul_connect_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;

	got		= 0;
	next_pace	= PACE_STEP;
	cut_at		= 0;
	paused		= 0;
	completed	= 0;

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= lws_get_vhost_by_name(context, "cli");
	i.address		= "127.0.0.1";
	i.port			= runs[cur].paced ? port + 1 : port;
	i.path			= runs[cur].path;
	i.host			= "127.0.0.1";
	i.origin		= "127.0.0.1";
	i.method		= "GET";
	i.protocol		= "stall-cli";
	i.local_protocol_name	= "stall-cli";
	i.alpn			= "http/1.1";
	i.pwsi			= &cli_wsi;

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("%s: connect failed\n", __func__);
		fail++;
		done = 1;
	}
}

/* a sparse file of FILE_SIZE, in a private temp dir */
static int
make_fixture(void)
{
	int fd;

	lws_strncpy(fixture_dir, "/tmp/lws-resp-stall-XXXXXX", // NOSONAR
		    sizeof(fixture_dir));
	if (!mkdtemp(fixture_dir)) {
		lwsl_err("%s: mkdtemp: %s\n", __func__, strerror(errno));
		return 1;
	}
	lws_snprintf(fixture_path, sizeof(fixture_path), "%s/big.bin",
		     fixture_dir);

	fd = open(fixture_path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
	if (fd < 0)
		return 1;
	if (ftruncate(fd, FILE_SIZE)) {
		close(fd);
		return 1;
	}
	close(fd);

	return 0;
}

static void
sigint_handler(int sig)
{
	done = 1;
	fail++;
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	const char *p;
	int n = 0;

	signal(SIGINT, sigint_handler);

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);

	lwsl_user("LWS API selftest: http response stall\n");

	if (make_fixture()) {
		lwsl_err("fixture creation failed\n");
		return 1;
	}
	mount.origin = fixture_dir;

	info.options		= LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
	info.fd_limit_per_thread = 0;
	info.timeout_secs	= TIMEOUT_SECS;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		fail++;
		goto bail_fixture;
	}

	info.vhost_name			= "srv";
	info.port			= port;
	info.protocols			= protocols;
	info.mounts			= &mount;
	info.http_response_stall_secs	= STALL_SECS;
	if (!lws_create_vhost(context, &info)) {
		lwsl_err("server vhost creation failed\n");
		fail++;
		goto bail;
	}

	big = calloc(1, LWS_PRE + BIG_SIZE);
	if (!big) {
		lwsl_err("OOM\n");
		fail++;
		goto bail;
	}

	info.vhost_name			= "srv-big";
	info.port			= port + 1;
	info.protocols			= protocols_big;
	info.mounts			= NULL;
	info.http_response_stall_secs	= BIG_STALL_SECS;
	if (!lws_create_vhost(context, &info)) {
		lwsl_err("big write's server vhost creation failed\n");
		fail++;
		goto bail;
	}

	info.vhost_name			= "cli";
	info.port			= CONTEXT_PORT_NO_LISTEN;
	info.protocols			= protocols;
	info.http_response_stall_secs	= 0;
	if (!lws_create_vhost(context, &info)) {
		lwsl_err("client vhost creation failed\n");
		fail++;
		goto bail;
	}

	lws_sul_schedule(context, 0, &sul_timeout, sul_timeout_cb,
			 60 * LWS_US_PER_SEC);
	lws_sul_schedule(context, 0, &sul_connect, sul_connect_cb, 1);

	while (n >= 0 && !done)
		n = lws_service(context, 0);

	lws_sul_cancel(&sul_timeout);
	lws_sul_cancel(&sul_resume);

bail:
	lws_context_destroy(context);
	free(big);
bail_fixture:
	unlink(fixture_path);
	rmdir(fixture_dir);

	lwsl_user("Completed: %s\n", fail ? "FAIL" : "PASS");

	return !!fail;
}
