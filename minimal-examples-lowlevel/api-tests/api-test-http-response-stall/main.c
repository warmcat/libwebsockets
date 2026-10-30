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

static const struct run {
	const char	*name;
	int		pause_secs;
	int		want_whole;
} runs[] = {
	{ "pause past timeout_secs",		 4, 1 },
	{ "stop reading until cut off",		 0, 0 },
};

static struct lws_context *context;
static lws_sorted_usec_list_t sul_timeout, sul_connect, sul_resume;
static struct lws *cli_wsi;
static int port = 7710, fail, done;
static size_t cur;
static uint64_t got;
static lws_usec_t paused_at, cut_at;
static int paused, completed;
static char fixture_dir[64], fixture_path[96];

static void
sul_connect_cb(lws_sorted_usec_list_t *sul);

static void
run_end(void)
{
	const struct run *r = &runs[cur];
	int whole = completed && got == (uint64_t)FILE_SIZE;

	lwsl_user("%s: %s: got %llu of %llu%s\n", __func__, r->name,
		  (unsigned long long)got, (unsigned long long)FILE_SIZE,
		  completed ? ", completed" : "");

	if (!paused) {
		lwsl_err("%s: %s: never paused, proves nothing\n", __func__,
			 r->name);
		fail++;
	} else if (whole != r->want_whole) {
		lwsl_err("%s: %s: want %s\n", __func__, r->name,
			 r->want_whole ? "the whole file" : "it cut off");
		fail++;
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

	if (runs[cur].pause_secs || cut_at) {
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
		got += len;
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
	    !runs[cur].pause_secs && !cut_at) {
		cut_at = lws_now_usecs();
		/* the client resumes, to find what it got cut off */
		lws_sul_schedule(context, 0, &sul_resume, sul_resume_cb, 1);
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

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
	cut_at		= 0;
	paused		= 0;
	completed	= 0;

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= lws_get_vhost_by_name(context, "cli");
	i.address		= "127.0.0.1";
	i.port			= port;
	i.path			= "/f/big.bin";
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

	info.vhost_name			= "cli";
	info.port			= CONTEXT_PORT_NO_LISTEN;
	info.mounts			= NULL;
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
bail_fixture:
	unlink(fixture_path);
	rmdir(fixture_dir);

	lwsl_user("Completed: %s\n", fail ? "FAIL" : "PASS");

	return !!fail;
}
