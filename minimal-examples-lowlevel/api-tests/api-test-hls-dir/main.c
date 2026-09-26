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
 *    attribute contexts;
 *  - the link text is the friendly name (bracket groups snipped, '.'
 *    separators spaced) while href / src / data-file keep the raw name,
 *    and a name that snips down to nothing falls back to the filename.
 *
 * It then drives the delete endpoint, with the login grant level forwarded
 * the way an lws-login proxy in front stamps it (trust-login-headers):
 *
 *  - a delete without the grant is refused and the file stays;
 *  - media in a subdirectory is deleted by its path, and the subdirectory
 *    goes with it once nothing playable is left in it, stray non-media
 *    contents included;
 *  - a name with characters that are ordinary in media names but were
 *    once "purified" away (':' '$' '%') is deleted as named.
 *
 * With LWS_WITH_STUB, deletes are done by the plugin's privilege-separated
 * stub child, which is this same executable re-run with --lws-stub=; main()
 * then does nothing but host the plugin for it.
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdlib.h>
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
#define N_FRIENDLY	5	/* friendly-name massage fixtures */
#define N_NESTED	1	/* media in its own subdirectory */
#define N_SPECIAL	1	/* ':' '$' '%' in the name */

#define NESTED_DIR	"Movies.2020"
#define NESTED_MEDIA	NESTED_DIR "/Nested.Bunny.1080p.WEB-DL.mkv"
#define NESTED_STRAY	NESTED_DIR "/Nested.Bunny.en.srt"
#define SPECIAL_MEDIA	"Colon: Dollar$ 50%.mkv"
/* ...as it goes in a request path */
#define SPECIAL_URL	"Colon:%20Dollar$%2050%25.mkv"
#define REFUSED_MEDIA	"Friendly.Name.Test.2020.mp4"

static struct lws_context *context;
static lws_sorted_usec_list_t sul_timeout;
static lws_sorted_usec_list_t sul_connect;
static int result = 1;
static int tests, fail;

static uint16_t port_hls = 21080;

static char fixture_dir[128];

/* collected response of the current step */

static char body[64 * 1024];
static size_t body_len;
static int got_status;
static long got_cl = -1;
static int step_over;		/* this step's transaction has ended */
static int done;		/* 1 = all steps ran, -1 = failed */

static void check_listing(void);
static void check_refused(void);
static void check_nested_deleted(void);
static void check_special_deleted(void);

/*
 * The client's requests, in order.  grant sends the login grant level an
 * lws-login proxy in front would forward (the vhost trusts it, see
 * pvo_trust); status is the response status the step expects.
 */
static const struct step {
	const char	*method;
	const char	*path;
	int		grant;
	int		status;
	void		(*check)(void);
} steps[] = {
	{ "GET",  "/media/",				0, 200, check_listing },
	{ "POST", "/media/delete/" REFUSED_MEDIA,	0, 403, check_refused },
	{ "POST", "/media/delete/" NESTED_MEDIA,	1, 200,
						check_nested_deleted },
	{ "POST", "/media/delete/" SPECIAL_URL,	1, 200,
						check_special_deleted },
};
static size_t cur;

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

/*
 * pvo chain handing the plugin its fixture media dir, and telling it to
 * trust the login grant level forwarded in the request, as it would behind
 * an lws-login gated proxy
 */
static struct lws_protocol_vhost_options
	pvo_trust	= { NULL, NULL, "trust-login-headers", "1" },
	pvo_media_dir	= { &pvo_trust, NULL, "media-dir", NULL },
	pvo_hls		= { NULL, &pvo_media_dir, "lws-hls", NULL };

/* -------------------------------------------------------------- client */

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len);

static void
expect(const char *name, int cond);

static void
sul_connect_cb(lws_sorted_usec_list_t *sul);

/* the current step's transaction is over, however it ended */
static void
step_end(int ok)
{
	const struct step *st = &steps[cur];
	char name[128];

	if (step_over)
		return;
	step_over = 1;

	lws_snprintf(name, sizeof(name), "%s %s: status %d (want %d)",
		     st->method, st->path, got_status, st->status);
	expect(name, ok && got_status == st->status);
	if (ok && got_status == st->status && st->check)
		st->check();

	if (++cur == LWS_ARRAY_SIZE(steps)) {
		done = 1;
		lws_cancel_service(context);
		return;
	}

	lws_sul_schedule(context, 0, &sul_connect, sul_connect_cb, 1);
}

static int
callback_cli(struct lws *wsi, enum lws_callback_reasons reason,
	     void *user, void *in, size_t len)
{
	/*
	 * Each step's connection carries its step number: the previous
	 * step's connection can still be closing (CLOSED after COMPLETED)
	 * while the next one runs, and must not be taken for it
	 */
	if ((uintptr_t)lws_get_opaque_user_data(wsi) != cur + 1)
		return 0;

	switch (reason) {

	case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER: {
		unsigned char **p = (unsigned char **)in, *end = (*p) + len;

		if (steps[cur].grant &&
		    lws_add_http_header_by_name(wsi,
				(const unsigned char *)LWS_LOGIN_HDR_GRANT_LEVEL ":",
				(const unsigned char *)"2", 1, p, end))
			return -1;

		/* a bodyless POST, as the pages send it */
		if (!strcmp(steps[cur].method, "POST") &&
		    lws_add_http_header_by_token(wsi,
				WSI_TOKEN_HTTP_CONTENT_LENGTH,
				(const unsigned char *)"0", 1, p, end))
			return -1;
		break;
	}

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP: {
		char cl[16];
		int n;

		got_status = (int)lws_http_client_http_response(wsi);

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
			step_end(0);
			return -1;
		}
		memcpy(body + body_len, in, len);
		body_len += len;
		body[body_len] = '\0';
		break;

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		step_end(1);
		break;

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		/* a refusal is a complete response the server closes after */
		step_end(got_status != 0);
		break;

	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: client connection error: %s\n",
			 __func__, in ? (const char *)in : "?");
		step_end(0);
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
	lwsl_err("%s: timed out in step %d\n", __func__, (int)cur);
	done = -1;
	lws_cancel_service(context);
}

static void
sul_connect_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_vhost *vh = lws_get_vhost_by_name(context, "cli");
	struct lws_client_connect_info i;

	(void)sul;

	body_len = 0;
	body[0] = '\0';
	got_status = 0;
	got_cl = -1;
	step_over = 0;

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= vh;
	i.address		= "127.0.0.1";
	i.port			= port_hls;
	i.path			= steps[cur].path;
	i.host			= "127.0.0.1";
	i.method		= steps[cur].method;
	i.protocol		= "defprot";
	i.local_protocol_name	= "lws-api-test-hls-dir-cli";
	i.opaque_user_data	= (void *)(uintptr_t)(cur + 1);

	if (!lws_client_connect_via_info(&i)) {
		lwsl_err("%s: connect failed\n", __func__);
		done = -1;
		lws_cancel_service(context);
	}
}

/* ------------------------------------------------------------ fixtures */

static int
touch(const char *dir, const char *name)
{
	char path[384];
	int fd;

	lws_snprintf(path, sizeof(path), "%s/%s", dir, name);

	fd = open(path, O_CREAT | O_WRONLY, 0600);
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

	/*
	 * The fixture media dir holds deliberately hostile names for the
	 * plugin to list, and lives in /tmp so it works from any cwd; mkdtemp
	 * gives it an unpredictable, owner-private name rather than a
	 * guessable, possibly pre-created one.
	 */

	lws_strncpy(fixture_dir, "/tmp/lws-hls-dir-test-XXXXXX", // NOSONAR
		    sizeof(fixture_dir));

	if (!mkdtemp(fixture_dir)) {
		lwsl_err("%s: mkdtemp: %s\n", __func__, strerror(errno));
		return 1;
	}

	/* attribute-breakout + markup metacharacters in one name */
	if (touch(fixture_dir, "x'\"><&.mp4"))
		return 1;

	/* script injection in element text (slash-free: '/' cannot appear
	 * in a filename component) */
	if (touch(fixture_dir, "<svg onload=alert(1)>.mp4"))
		return 1;

	/*
	 * friendly-name massage: bracket groups snipped, '.' separators
	 * become spaces, and the title ends at the first release-furniture
	 * token (year / resolution / codec-source tag); a name that snips
	 * to nothing shows as-is
	 */
	if (touch(fixture_dir, "The.Matrix.(1999).[1080p].x265.mkv"))
		return 1;
	if (touch(fixture_dir, "Friendly.Name.Test.2020.mp4"))
		return 1;
	if (touch(fixture_dir, "[only.groups].mkv"))
		return 1;
	if (touch(fixture_dir,
		   "Word.word.word.2026.1080p.word.word.word.2.0.H.264-word.word.mkv"))
		return 1;
	if (touch(fixture_dir, "2015.Some.Movie.720p.WEB-DL.aac.mkv"))
		return 1;

	/* a movie that arrived in its own subdirectory: the listing walks
	 * it, and every route has to take the subdir in the name.  Its
	 * sidecar is not playable, so deleting the movie takes the whole
	 * subdirectory */
	{
		char sub[384];

		lws_snprintf(sub, sizeof(sub), "%s/" NESTED_DIR, fixture_dir);
		if (mkdir(sub, 0700))
			return 1;
		if (touch(fixture_dir, NESTED_MEDIA) ||
		    touch(fixture_dir, NESTED_STRAY))
			return 1;
	}

	/* characters that are ordinary in a media name */
	if (touch(fixture_dir, SPECIAL_MEDIA))
		return 1;

	/* a subdirectory with nothing playable in it: it and its stray
	 * contents are removed once the server starts */
	{
		char sub[384];

		lws_snprintf(sub, sizeof(sub), "%s/Dead.2020", fixture_dir);
		if (mkdir(sub, 0700))
			return 1;
		if (touch(sub, "note.nfo"))
			return 1;
	}

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

	(void)snprintf(path, sizeof(path), "%s/%s", fixture_dir,
		       "The.Matrix.(1999).[1080p].x265.mkv");
	unlink(path);
	(void)snprintf(path, sizeof(path), "%s/%s", fixture_dir,
		       "Friendly.Name.Test.2020.mp4");
	unlink(path);
	(void)snprintf(path, sizeof(path), "%s/%s", fixture_dir,
		       "[only.groups].mkv");
	unlink(path);
	(void)snprintf(path, sizeof(path), "%s/%s", fixture_dir,
		       "Word.word.word.2026.1080p.word.word.word.2.0.H.264-word.word.mkv");
	unlink(path);
	(void)snprintf(path, sizeof(path), "%s/%s", fixture_dir,
		       "2015.Some.Movie.720p.WEB-DL.aac.mkv");
	unlink(path);
	/* the deletes should have removed these already */
	(void)snprintf(path, sizeof(path), "%s/%s", fixture_dir, NESTED_MEDIA);
	unlink(path);
	(void)snprintf(path, sizeof(path), "%s/%s", fixture_dir, NESTED_STRAY);
	unlink(path);
	(void)snprintf(path, sizeof(path), "%s/%s", fixture_dir, SPECIAL_MEDIA);
	unlink(path);
	{
		char sub[384];

		/* Dead.2020/note.nfo is the purge's business now; it should
		 * already be gone, tidy up defensively if it is not */
		lws_snprintf(sub, sizeof(sub), "%s/Dead.2020/note.nfo",
			     fixture_dir);
		unlink(sub);
		lws_snprintf(sub, sizeof(sub), "%s/Dead.2020", fixture_dir);
		rmdir(sub);
		lws_snprintf(sub, sizeof(sub), "%s/" NESTED_DIR, fixture_dir);
		rmdir(sub);
	}

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

/* does fixture-relative rel exist? */
static int
fixture_exists(const char *rel)
{
	struct stat st;
	char path[512];

	lws_snprintf(path, sizeof(path), "%s/%s", fixture_dir, rel);

	return !stat(path, &st);
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
check_listing(void)
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
	       count_str(body, "player.html?v=stream/") ==
					2 + N_FRIENDLY + N_NESTED + N_SPECIAL +
					N_LONG_ENTRIES);

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

	/* friendly names as link text, raw names kept for href/src/data-file */
	expect("friendly name: furniture cut after the title",
	       !!strstr(body, "<br>The Matrix</a>"));
	expect("friendly name: year ends the title",
	       !!strstr(body, "<br>Friendly Name Test</a>"));
	expect("friendly name: snipped to nothing shows the filename",
	       !!strstr(body, "<br>[only.groups].mkv</a>"));
	expect("friendly name: release tail dropped",
	       !!strstr(body, "<br>Word word word</a>"));
	expect("friendly name: leading year kept, tail cut",
	       !!strstr(body, "<br>2015 Some Movie</a>"));

	/* media in its own subdirectory: listed with its path, friendly
	 * named from the basename */
	expect("nested media listed by path",
	       !!strstr(body, "player.html?v=stream/" NESTED_MEDIA));
	expect("nested media friendly name from the basename",
	       !!strstr(body, "<br>Nested Bunny</a>"));

	/*
	 * Subdirectory lifecycle: the purge pass at init removed the
	 * subdirectory with nothing playable in it, contents and all, and
	 * left the one that still has media (it is in the listing above).
	 */
	{
		struct stat st;
		char sub[384];

		lws_snprintf(sub, sizeof(sub), "%s/Dead.2020/note.nfo",
			     fixture_dir);
		expect("media-less subdirectory purged, contents and all",
		       stat(sub, &st) != 0);
		lws_snprintf(sub, sizeof(sub), "%s/Dead.2020", fixture_dir);
		expect("media-less subdirectory purged, dir gone",
		       stat(sub, &st) != 0);
		lws_snprintf(sub, sizeof(sub), "%s/" NESTED_DIR, fixture_dir);
		expect("subdirectory with media survives the purge",
		       !stat(sub, &st) && S_ISDIR(st.st_mode));
	}

	/*
	 * Links are relative only: the app is expected behind a reverse
	 * proxy that mounts it at an unknown point of a public URL space,
	 * where an absolute path would escape the mount.
	 */
	expect("listing links are relative",
	       !!strstr(body, "href='player.html?v="));
	expect("no absolute hrefs in the listing",
	       !strstr(body, "href='/"));

	/* the listing request carried no grant: no delete buttons */
	expect("no delete buttons without a grant",
	       !strstr(body, "del-btn"));
}

static void
check_refused(void)
{
	expect("refused delete leaves the media", fixture_exists(REFUSED_MEDIA));
}

static void
check_nested_deleted(void)
{
	expect("nested media deleted by its path", !fixture_exists(NESTED_MEDIA));
	expect("subdirectory with nothing playable left removed, contents "
	       "and all", !fixture_exists(NESTED_STRAY) &&
			  !fixture_exists(NESTED_DIR));
	expect("unrelated media untouched by the subdirectory purge",
	       fixture_exists(REFUSED_MEDIA));
}

static void
check_special_deleted(void)
{
	expect("media named with ':' '$' '%' deleted as named",
	       !fixture_exists(SPECIAL_MEDIA));
}

static void
sigint_handler(int sig)
{
	lws_default_loop_exit(context);
}

/*
 * We are the plugin's stub child (LWS_WITH_STUB): the plugin in the parent
 * re-ran this executable with --lws-stub=lws-hls-stub, to do its deletes
 * with the privileges it may have dropped.  All we have to do is host the
 * plugin on a vhost that listens on nothing: its PROTOCOL_INIT sees the
 * option and sets up the stub side, taking its media dir from the parent.
 * The stub layer exits the process when the parent goes away.
 */
static int
run_stub(struct lws_context_creation_info *info)
{
	int n = 0;

	info->options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;

	context = lws_create_context(info);
	if (!context)
		return 1;

	/* no pvo to instantiate the plugin by: instantiate everything */
	info->options		|= LWS_SERVER_OPTION_VH_INSTANTIATE_ALL_PROTOCOLS;
	info->port		= CONTEXT_PORT_NO_LISTEN;
	info->vhost_name	= "hls-stub";
	info->pprotocols	= pprotocols_hls;

	if (!lws_create_vhost(context, info)) {
		lws_context_destroy(context);
		return 1;
	}

	while (n >= 0)
		n = lws_service(context, 0);

	lws_context_destroy(context);

	return 0;
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

	if (lws_cmdline_option(argc, argv, "--lws-stub="))
		return run_stub(&info);

	lwsl_user("LWS API selftest: HLS media dir listing and deletion\n");

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
			 30 * LWS_US_PER_SEC);
	/*
	 * With LWS_WITH_STUB the plugin spawned its stub child at vhost
	 * creation; give it a moment to come up and listen before the first
	 * delete needs it (the listing comes first anyway)
	 */
	lws_sul_schedule(context, 0, &sul_connect, sul_connect_cb, 1);

	while (n >= 0 && !done)
		n = lws_service(context, 0);

	lws_sul_cancel(&sul_timeout);

	expect("every step ran", done == 1);

	result = !!fail;

bail:
	lws_context_destroy(context);
	remove_fixture_dir();

	lwsl_user("Completed: %s (tests=%d fail=%d)\n",
		  result ? "FAIL" : "PASS", tests, fail);

	return result;
}
