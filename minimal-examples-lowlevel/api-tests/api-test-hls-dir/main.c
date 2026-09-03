/*
 * lws-api-test-hls-dir
 *
 * Fences the F-059 fix in the HLS plugin's directory listing
 * (lws_hls_serve_dir()): the listing HTML used to be composed with the
 * naive `p += snprintf(p, rem, ...)` cursor pattern over a fixed
 * 512-byte-per-entry estimate, while each entry interpolates the
 * (untrusted, up-to-255-char) media filename four times after only
 * HTML-text escaping of nothing at all:
 *
 *  - with enough long filenames the per-entry snprintf truncated, the
 *    cursor advanced past the allocation and the next `rem` underflowed
 *    to a huge size_t, so the following snprintf wrote unbounded past
 *    the heap buffer;
 *  - quote / angle-bracket characters in filenames reached the page
 *    text and the single-quoted href / data-file attributes unescaped
 *    (stored XSS on the HLS origin).
 *
 * The whole plugin is folded into the test statically (the same way
 * test-sshd folds in the sshd plugin) and served from a fixture media
 * dir containing the attack names; an in-process client fetches the
 * listing and asserts:
 *
 *  - every entry made it into the listing (nothing silently truncated),
 *    the declared content-length matches the body length, and the page
 *    tail is intact (pre-fix, the 20 x 254-char names alone blow the
 *    old 512-per-entry budget by ~7 KB);
 *  - HTML-significant characters in filenames appear only as entities
 *    (&#39; &quot; &lt; &gt; &amp;), never raw, in both text and
 *    attribute contexts.
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

/* import the whole of the HLS plugin statically */
#include <lws-plugin-hls-static-build-includes.h>

#define N_LONG_ENTRIES	48	/* 254-char names: ~18 KB over the old
				 * fixed 512-per-entry estimate */
#define LONG_NAME_LEN	254	/* chars including the ".mp4" suffix */

static struct lws_context *context;
static struct lws *cli_wsi;
static lws_sorted_usec_list_t sul_timeout;
static lws_sorted_usec_list_t sul_connect;
static volatile char interrupted;
static int result = 1;
static int tests, fail;

static uint16_t port_hls = 21080;

static char fixture_dir[128];

/* collected response */

static char body[64 * 1024];
static size_t body_len;
static int got_status;
static long got_cl = -1;
static char done;

/* -------------------------------------------------------------- server */

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len);

static const struct lws_protocols
	defprot = { "defprot", lws_callback_http_dummy, 0, 0, 0, NULL, 0 },
	prot_hls = LWS_PLUGIN_PROTOCOL_LWS_HLS,
	prot_cli = { "lws-api-test-hls-dir-cli", callback_cli, 0, 0, 0, NULL, 0 };

static const struct lws_protocols
	*pprotocols_hls[] = { &defprot, &prot_hls, NULL },
	*pprotocols_cli[]  = { &defprot, &prot_cli, NULL };

static const struct lws_http_mount
	mount_hls = {
		.mountpoint		= "/media",
		.protocol		= "lws-hls",
		.origin_protocol	= LWSMPRO_CALLBACK,
		.mountpoint_len		= 6,
	};

/* pvo chain handing the plugin its fixture media dir */
static struct lws_protocol_vhost_options
	pvo_hls		= { NULL, NULL, "lws-hls", NULL },
	pvo_media_dir	= { NULL, NULL, "media-dir", NULL };

/* -------------------------------------------------------------- client */

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len);

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	switch (reason) {

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP: {
		char cl[16];
		int n;

		got_status = (int)lws_http_client_http_response(wsi);
		if (got_status != HTTP_STATUS_OK) {
			lwsl_err("%s: bad response %d\n", __func__, got_status);
			done = -1;
			return -1;
		}

		n = lws_hdr_copy(wsi, cl, sizeof(cl),
				 WSI_TOKEN_HTTP_CONTENT_LENGTH);
		if (n > 0) {
			cl[n] = '\0';
			got_cl = atol(cl);
		}
		break;
	}

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP: {
		char buffer[4096 + LWS_PRE];
		char *px = buffer + LWS_PRE;
		int alen = (int)sizeof(buffer) - LWS_PRE;

		if (lws_http_client_read(wsi, &px, &alen) < 0)
			return -1;
		break;
	}

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		if (body_len + len >= sizeof(body)) {
			lwsl_err("%s: body overran collection buffer\n",
				 __func__);
			done = -1;
			return -1;
		}
		memcpy(body + body_len, in, len);
		body_len += len;
		body[body_len] = '\0';
		break;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		if (reason == LWS_CALLBACK_CLIENT_CONNECTION_ERROR)
			lwsl_err("%s: client connection error: %s\n",
				 __func__, in ? (const char *)in : "?");
		done = reason == LWS_CALLBACK_COMPLETED_CLIENT_HTTP ? 1 : -1;
		lws_cancel_service(lws_get_context(wsi));
		break;

	default:
		break;
	}

	return 0;
}

static void
sul_timeout_cb(lws_sorted_usec_list_t *sul)
{
	(void)sul;
	lwsl_err("%s: timed out\n", __func__);
	interrupted = 1;
}

static void
sul_connect_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_vhost *vh = lws_get_vhost_by_name(context, "cli");
	struct lws_client_connect_info i;

	(void)sul;

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost		= vh;
	i.address		= "127.0.0.1";
	i.port			= port_hls;
	i.path			= "/media/";
	i.host			= "127.0.0.1";
	i.method		= "GET";
	i.protocol		= "defprot";
	i.local_protocol_name	= "lws-api-test-hls-dir-cli";
	i.pwsi			= &cli_wsi;

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("%s: connect failed\n", __func__);
		interrupted = 1;
	}
}

/* ------------------------------------------------------------ fixtures */

static int
touch(const char *dir, const char *name)
{
	char path[384];
	int fd;

	lws_snprintf(path, sizeof(path), "%s/%s", dir, name);

	fd = open(path, O_CREAT | O_WRONLY, 0644);
	if (fd < 0) {
		lwsl_err("%s: open %s: %s\n", __func__, path,
			 strerror(errno));
		return 1;
	}
	close(fd);

	return 0;
}

static int
build_fixture_dir(void)
{
	char name[LONG_NAME_LEN + 1];
	int i;

	lws_snprintf(fixture_dir, sizeof(fixture_dir),
		     "/tmp/lws-hls-dir-test-%d", (int)getpid());

	if (mkdir(fixture_dir, 0755) && errno != EEXIST) {
		lwsl_err("%s: mkdir %s: %s\n", __func__, fixture_dir,
			 strerror(errno));
		return 1;
	}

	/* attribute-breakout + markup metacharacters in one name */
	if (touch(fixture_dir, "x'\"><&.mp4"))
		return 1;

	/* script injection in element text (slash-free: '/' cannot appear
	 * in a filename component) */
	if (touch(fixture_dir, "<svg onload=alert(1)>.mp4"))
		return 1;

	/* enough 254-char names to blow the old 512-per-entry budget:
	 * each interpolates ~1.2 KB against it */
	for (i = 0; i < N_LONG_ENTRIES; i++) {
		memset(name, 'L', sizeof(name) - 1);
		name[0] = (char)('a' + (i % 26));
		name[1] = (char)('a' + ((i / 26) % 26));
		memcpy(name + LONG_NAME_LEN - 4, ".mp4", 4);
		name[LONG_NAME_LEN] = '\0';
		if (touch(fixture_dir, name))
			return 1;
	}

	return 0;
}

static void
remove_fixture_dir(void)
{
	char path[512];
	int i;

	(void)snprintf(path, sizeof(path), "%s/x'\\\"><&.mp4", fixture_dir);
	unlink(path);
	(void)snprintf(path, sizeof(path),
		       "%s/<svg onload=alert(1)>.mp4", fixture_dir);
	unlink(path);

	for (i = 0; i < N_LONG_ENTRIES; i++) {
		char name[LONG_NAME_LEN + 1];
		memset(name, 'L', sizeof(name) - 1);
		name[0] = (char)('a' + (i % 26));
		name[1] = (char)('a' + ((i / 26) % 26));
		memcpy(name + LONG_NAME_LEN - 4, ".mp4", 4);
		name[LONG_NAME_LEN] = '\0';
		snprintf(path, sizeof(path), "%s/%s", fixture_dir, name);
		unlink(path);
	}

	rmdir(fixture_dir);
}

/* ------------------------------------------------------------ assertions */

static int
count_str(const char *hay, const char *needle)
{
	const char *p = hay;
	int n = 0;

	while ((p = strstr(p, needle))) {
		n++;
		p++;
	}

	return n;
}

static void
expect(const char *name, int cond)
{
	tests++;
	if (!cond) {
		fail++;
		lwsl_err("FAIL: %s\n", name);
	}
}

static void
check_body(void)
{
	body[body_len] = '\0';

	expect("HTTP 200", got_status == HTTP_STATUS_OK);
	expect("body arrived", body_len > 0);

	/* F-059 leg 1: exact accounting, nothing truncated or overshot */
	expect("content-length matches body length",
	       got_cl >= 0 && (size_t)got_cl == body_len);
	expect("page tail intact",
	       body_len > 20 &&
	       !strcmp(body + body_len - 20, "</div></body></html>"));
	expect("every entry listed",
	       count_str(body, "player.html?v=hls/stream/") == 2 + N_LONG_ENTRIES);

	/* F-059 leg 2: names only reach markup as entities */
	expect("script payload escaped",
	       !!strstr(body, "&lt;svg onload=alert(1)&gt;"));
	expect("quote-breakout name escaped",
	       !!strstr(body, "x&#39;&quot;&gt;&lt;&amp;.mp4"));
	expect("no raw quote-breakout characters from filenames",
	       !strstr(body, "x'\""));
	expect("no raw script tag from filenames",
	       !strstr(body, "<svg"));
	expect("no raw single-quote breakout in hrefs",
	       !strstr(body, "stream/x'"));
}

static void
sigint_handler(int sig)
{
	interrupted = 1;
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	int n = 0;

	signal(SIGINT, sigint_handler);

	memset(&info, 0, sizeof(info));
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	{
		const char *p = lws_cmdline_option(argc, argv, "-p");
		if (p)
			port_hls = (uint16_t)atoi(p);
	}

	lws_set_log_level(LLL_ERR | LLL_WARN | LLL_USER | LLL_NOTICE, NULL);

	lwsl_user("LWS API selftest: HLS media dir listing (F-059)\n");

	if (build_fixture_dir())
		goto bail;

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws_create_context failed\n");
		goto bail;
	}

	/* HLS vhost serving the fixture media dir */
	pvo_media_dir.value	= fixture_dir;
	pvo_hls.options		= &pvo_media_dir;

	info.port		= port_hls;
	info.vhost_name		= "hls";
	info.pprotocols		= pprotocols_hls;
	info.mounts		= &mount_hls;
	info.pvo		= &pvo_hls;

	if (!lws_create_vhost(context, &info)) {
		lwsl_err("Failed to create hls vhost\n");
		goto bail;
	}

	/* client vhost: no listener */
	info.port		= CONTEXT_PORT_NO_LISTEN;
	info.vhost_name		= "cli";
	info.pprotocols		= pprotocols_cli;
	info.mounts		= NULL;
	info.pvo		= NULL;

	if (!lws_create_vhost(context, &info)) {
		lwsl_err("Failed to create client vhost\n");
		goto bail;
	}

	lws_sul_schedule(context, 0, &sul_timeout, sul_timeout_cb,
			 20 * LWS_US_PER_SEC);
	lws_sul_schedule(context, 0, &sul_connect, sul_connect_cb, 1);

	while (n >= 0 && !interrupted && !done)
		n = lws_service(context, 0);

	lws_sul_cancel(&sul_timeout);

	if (done == 1)
		check_body();
	else
		expect("listing fetched", 0);

	result = !!fail;

bail:
	lws_context_destroy(context);
	remove_fixture_dir();

	lwsl_user("Completed: %s (tests=%d fail=%d)\n",
		  result ? "FAIL" : "PASS", tests, fail);

	return result;
}
