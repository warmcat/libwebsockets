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
#include <sys/time.h>

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

/* media that is not all there: listed, but not playable */
#define ARRIVING_MEDIA	"Arriving.Film.2024.mkv"	/* being written */
#define STALLED_MEDIA	"Stalled.Film.2024.mkv"		/* copy stopped short */
#define NOMOOV_MEDIA	"NoMoov.Film.2024.mp4"		/* moov not there yet */
#define SHORTMDAT_MEDIA	"Short.Mdat.2024.mp4"		/* mdat past EOF */
#define N_PENDING	4
/* how rsync names a copy in progress: not media, not listed */
#define RSYNC_TEMP	".Rsync.Temp.2024.mkv.Xq3v9A"
/* a subdirectory something is being copied into under a temporary name */
#define INCOMING_DIR	"Incoming.2024"
#define INCOMING_TEMP	INCOMING_DIR "/.Incoming.2024.mkv.Ab12Cd"

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
static int steps_done;		/* ...waiting for the feed to catch up */

/*
 * The listing's change feed ("events"), subscribed to once the listing is
 * fetched and kept open across the steps: it must first say the
 * generation the listing page was built with, and after the deletes, a
 * different one
 */
#define FEED_TAG	((uintptr_t)0x10000)
static char listing_gen[17], feed_first[17], feed_last[17];
static int feed_count, feed_closed;
static lws_sorted_usec_list_t sul_feed;
static struct lws *feed_wsi;

static void check_listing(void);
static void check_index_arriving(void);
static void check_index_incomplete(void);
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
	/* not all there: the player is told why, and nothing is built */
	{ "GET",  "/media/index/" ARRIVING_MEDIA,	0, 200,
						check_index_arriving },
	{ "GET",  "/media/index/" STALLED_MEDIA,	0, 200,
						check_index_incomplete },
	{ "GET",  "/media/stream/" STALLED_MEDIA,	0, 503, NULL },
	{ "GET",  "/media/segment/" SHORTMDAT_MEDIA "/0", 0, 503, NULL },
	{ "GET",  "/media/preview/" NOMOOV_MEDIA,	0, 404, NULL },
	/* ...but an admin can delete a copy that died */
	{ "POST", "/media/delete/" STALLED_MEDIA,	1, 200, NULL },
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

/* the change feed's client connection */
static int
callback_feed(struct lws *wsi, enum lws_callback_reasons reason, void *in,
	      size_t len)
{
	switch (reason) {
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP: {
		char buffer[1024 + LWS_PRE];
		char *px = buffer + LWS_PRE;
		int alen = (int)sizeof(buffer) - LWS_PRE;

		if (lws_http_client_read(wsi, &px, &alen) < 0)
			return -1;
		break;
	}

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ: {
		const char *p = (const char *)in, *e = p + len;

		/* each "data: <16 hex>" event arrives whole */
		while ((p = memchr(p, 'd', lws_ptr_diff_size_t(e, p))) &&
		       e - p >= 22) {
			if (!strncmp(p, "data: ", 6)) {
				lws_strncpy(feed_last, p + 6, sizeof(feed_last));
				if (!feed_count++)
					lws_strncpy(feed_first, feed_last,
						    sizeof(feed_first));
				else if (strcmp(feed_last, feed_first) &&
					 steps_done) {
					done = 1;
					lws_cancel_service(context);
				}
			}
			p++;
		}
		break;
	}

	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		feed_closed = 1;
		feed_wsi = NULL;
		if (steps_done) {
			done = 1;
			lws_cancel_service(context);
		}
		break;

	default:
		break;
	}

	return 0;
}

static void
sul_feed_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;

	memset(&i, 0, sizeof(i));
	i.context		= context;
	i.vhost			= lws_get_vhost_by_name(context, "cli");
	i.address		= "127.0.0.1";
	i.port			= port_hls;
	i.path			= "/media/events";
	i.host			= "127.0.0.1";
	i.method		= "GET";
	i.protocol		= "defprot";
	i.local_protocol_name	= "lws-api-test-hls-dir-cli";
	i.opaque_user_data	= (void *)FEED_TAG;
	i.pwsi			= &feed_wsi;

	if (!lws_client_connect_via_info(&i))
		feed_closed = 1;
}

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
		steps_done = 1;
		/* the deletes kicked the watch: the feed has news, or will */
		if (feed_count > 1 || feed_closed) {
			done = 1;
			lws_cancel_service(context);
		}
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
	if ((uintptr_t)lws_get_opaque_user_data(wsi) == FEED_TAG)
		return callback_feed(wsi, reason, in, len);

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

/*
 * The listing only offers media that is all there: a container whose
 * framing is complete, not written to in the last HLS_MEDIA_SETTLE_SECS.
 * These are the smallest such files: an mp4 of an ftyp and a moov box, and
 * a matroska of an empty EBML header and an empty Segment.
 */
static const uint8_t
	stub_mp4[] = { 0, 0, 0, 8, 'f', 't', 'y', 'p',
		       0, 0, 0, 8, 'm', 'o', 'o', 'v' },
	stub_mkv[] = { 0x1a, 0x45, 0xdf, 0xa3, 0x80,
		       0x18, 0x53, 0x80, 0x67, 0x80 },
	/* a copy that stopped short: the Segment says 1000 bytes follow */
	short_mkv[] = { 0x1a, 0x45, 0xdf, 0xa3, 0x80,
			0x18, 0x53, 0x80, 0x67, 0x43, 0xe8, 0xec, 0x80 },
	/* the moov of a non-faststart mp4 is written last */
	nomoov_mp4[] = { 0, 0, 0, 8, 'f', 't', 'y', 'p',
			 0, 0, 0, 8, 'm', 'd', 'a', 't' },
	/* the mdat says it is much bigger than what arrived */
	shortmdat_mp4[] = { 0, 0, 0, 8, 'f', 't', 'y', 'p',
			    0, 1, 0, 0, 'm', 'd', 'a', 't', 1, 2, 3, 4 };

/*
 * Create dir/name holding data, last written an hour ago unless fresh (a
 * copy that is still going on)
 */
static int
mkfile(const char *dir, const char *name, const uint8_t *data, size_t len,
       int fresh)
{
	struct timeval tv[2];
	char path[384];
	int fd;

	lws_snprintf(path, sizeof(path), "%s/%s", dir, name);

	fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
	if (fd < 0) {
		lwsl_err("%s: open %s: %s\n", __func__, path,
			 strerror(errno));
		return 1;
	}
	if (len && write(fd, data, len) != (ssize_t)len) {
		close(fd);
		return 1;
	}
	close(fd);

	if (fresh)
		return 0;

	gettimeofday(&tv[0], NULL);
	tv[0].tv_sec -= 3600;
	tv[1] = tv[0];

	return utimes(path, tv);
}

/* a complete, settled file, framed according to its extension */
static int
touch(const char *dir, const char *name)
{
	size_t nl = strlen(name);

	if (nl > 4 && !strcmp(name + nl - 4, ".mkv"))
		return mkfile(dir, name, stub_mkv, sizeof(stub_mkv), 0);
	if (nl > 4 && !strcmp(name + nl - 4, ".mp4"))
		return mkfile(dir, name, stub_mp4, sizeof(stub_mp4), 0);

	return mkfile(dir, name, NULL, 0, 0);
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

	/* media that is not all there, in the ways we can tell */
	if (mkfile(fixture_dir, ARRIVING_MEDIA, stub_mkv, sizeof(stub_mkv), 1) ||
	    mkfile(fixture_dir, STALLED_MEDIA, short_mkv, sizeof(short_mkv), 0) ||
	    mkfile(fixture_dir, NOMOOV_MEDIA, nomoov_mp4,
		   sizeof(nomoov_mp4), 0) ||
	    mkfile(fixture_dir, SHORTMDAT_MEDIA, shortmdat_mp4,
		   sizeof(shortmdat_mp4), 0) ||
	    mkfile(fixture_dir, RSYNC_TEMP, stub_mkv, sizeof(stub_mkv), 1))
		return 1;

	/* nothing playable in it yet, but something is arriving: the purge
	 * at startup must leave it alone */
	{
		char sub[384];

		lws_snprintf(sub, sizeof(sub), "%s/" INCOMING_DIR, fixture_dir);
		if (mkdir(sub, 0700) ||
		    mkfile(fixture_dir, INCOMING_TEMP, stub_mkv,
			   sizeof(stub_mkv), 1))
			return 1;
	}

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
	{
		static const char * const pending[] = {
			ARRIVING_MEDIA, STALLED_MEDIA, NOMOOV_MEDIA,
			SHORTMDAT_MEDIA, RSYNC_TEMP, INCOMING_TEMP,
			INCOMING_DIR
		};
		size_t j;

		for (j = 0; j < LWS_ARRAY_SIZE(pending); j++) {
			(void)snprintf(path, sizeof(path), "%s/%s",
				       fixture_dir, pending[j]);
			if (unlink(path))
				rmdir(path);
		}
	}

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
	const char *g;

	body[body_len] = '\0';

	/* the generation the page was built with, for the change feed */
	g = strstr(body, "<body data-gen='");
	expect("listing carries its generation", !!g);
	if (g)
		lws_strncpy(listing_gen, g + 16, sizeof(listing_gen));
	lws_sul_schedule(context, 0, &sul_feed, sul_feed_cb, 1);

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
		expect("subdirectory something is arriving in survives the "
		       "purge", fixture_exists(INCOMING_TEMP));
	}

	/*
	 * Media that is not all there is listed as pending, with its state
	 * where the thumbnail would be, and nothing to play or cut a
	 * thumbnail from
	 */
	expect("pending media listed as pending",
	       count_str(body, "class='item pending'") == N_PENDING);
	expect("a copy in progress shows as still arriving",
	       count_str(body, ">still arriving<") == 1);
	expect("copies that stopped short show as incomplete",
	       count_str(body, ">incomplete<") == N_PENDING - 1);
	expect("pending media friendly named",
	       !!strstr(body, "<br>Arriving Film"));
	expect("no player link for pending media",
	       !strstr(body, "stream/" ARRIVING_MEDIA) &&
	       !strstr(body, "stream/" STALLED_MEDIA) &&
	       !strstr(body, "stream/" NOMOOV_MEDIA) &&
	       !strstr(body, "stream/" SHORTMDAT_MEDIA));
	expect("no thumbnail asked of pending media",
	       !strstr(body, "preview/" ARRIVING_MEDIA) &&
	       !strstr(body, "preview/" SHORTMDAT_MEDIA));
	expect("a copy in progress under a dotfile name is not listed",
	       !strstr(body, "Rsync") && !strstr(body, "Incoming"));

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
check_index_arriving(void)
{
	expect("index status says a copy in progress is arriving",
	       !!strstr(body, "\"media\":\"arriving\"") &&
	       !!strstr(body, "\"ready\":false"));
}

static void
check_index_incomplete(void)
{
	expect("index status says a copy that stopped short is incomplete",
	       !!strstr(body, "\"media\":\"incomplete\"") &&
	       !!strstr(body, "\"running\":false"));
	expect("nothing indexed for an incomplete file",
	       !fixture_exists(".index"));
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

	/* the change feed */
	expect("feed opened with the listing's generation",
	       feed_count && !strcmp(feed_first, listing_gen));
	expect("feed told of the deletes",
	       feed_count > 1 && strcmp(feed_last, feed_first));
	expect("feed still open at the end", !feed_closed);
	if (feed_wsi)
		lws_set_timeout(feed_wsi, PENDING_TIMEOUT_USER_OK,
				LWS_TO_KILL_SYNC);

	result = !!fail;

bail:
	lws_context_destroy(context);
	remove_fixture_dir();

	lwsl_user("Completed: %s (tests=%d fail=%d)\n",
		  result ? "FAIL" : "PASS", tests, fail);

	return result;
}
