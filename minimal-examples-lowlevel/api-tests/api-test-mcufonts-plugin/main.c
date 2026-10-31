/*
 * lws-api-test-mcufonts-plugin
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Serves the .ttf files in a directory with the lws-mcufonts plugin, and
 * fetches from it over http as a device would: fonts.json, which is 404 until
 * the plugin has learned the faces, then a page of a face, which is 404 until
 * the plugin has made it, and page 0000 of each face, which the plugin makes
 * at startup since it's in its warm-pages.  Urls for faces, pages or names it
 * doesn't have must be 404 without anything being made: at the end, the cache
 * must hold just the two faces' info, their page 0000 and the one other page.
 *
 * With --cached, it's run again on the same cache, when both must be there
 * from the start.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

#define LWS_PLUGIN_STATIC
#include "../../../plugins/protocol_lws_mcufonts/protocol_lws_mcufonts.c"

enum {
	LWS_SW_ENCODER,
	LWS_SW_TTF_DIR,
	LWS_SW_CACHE_DIR,
	LWS_SW_CACHED,
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_ENCODER]	= { "--encoder",   "Path to lws-mcufont-encoder" },
	[LWS_SW_TTF_DIR]	= { "--ttf-dir",   "Directory of .ttf files to serve" },
	[LWS_SW_CACHE_DIR]	= { "--cache-dir", "Directory for the plugin's cache" },
	[LWS_SW_CACHED]		= { "--cached",    "Expect fonts.json and the page to be ready from the start" },
	[LWS_SW_HELP]		= { "--help",      "Show this help information" },
};

/* what we check a response for */

enum {
	CHK_NONE,
	CHK_MANIFEST,
	CHK_PAGE,
};

/* how a url comes to be there */

enum {
	MADE_NEVER,	/* never: not one the plugin has */
	MADE_ASKED,	/* when it's first asked for */
	MADE_WARM,	/* at startup */
};

typedef struct {
	const char	*url;
	int		want;
	uint8_t		made;	/* MADE_: 404 until it's made, unless --cached */
	uint8_t		check;
} step_t;

static const step_t steps[] = {
	{ "fonts.json",				  200, MADE_WARM,  CHK_MANIFEST },
	{ "FiraSansCondensed-Regular14/0020.mcufont", 200, MADE_ASKED, CHK_PAGE },
	{ "FiraSansCondensed-Regular14/0000.mcufont", 200, MADE_WARM, CHK_NONE },
	{ "FiraSansCondensed-Bold14/0000.mcufont",    200, MADE_WARM, CHK_NONE },

	/* none of these may make anything */
	{ "FiraSansCondensed-Regular14/0e00.mcufont", 404, MADE_NEVER, CHK_NONE },
	{ "FiraSansCondensed-Regular15/0000.mcufont", 404, MADE_NEVER, CHK_NONE },
	{ "FiraSansCondensed-Regular14/0020.MCUFONT", 404, MADE_NEVER, CHK_NONE },
	{ "FiraSansCondensed-Regular14/00020.mcufont", 404, MADE_NEVER, CHK_NONE },
	{ "FiraSansCondensed-Regular14/0020.mcufont/", 404, MADE_NEVER, CHK_NONE },
	{ "FiraSansCondensed-Regular14/0000.mcufontx", 404, MADE_NEVER, CHK_NONE },
	{ "FiraSansCondensed-Regular14",	      404, MADE_NEVER, CHK_NONE },
	{ "nonexistent",			      404, MADE_NEVER, CHK_NONE },
};

/* the manifest, parsed as the device parses it */

typedef struct {
	lws_dll2_t	list;
	char		name[64];
	char		path[64];
	char		pages[160];
	unsigned int	line_height;
} face_t;

typedef struct {
	lws_dll2_owner_t fonts;
} manifest_t;

static const lws_struct_map_t lsm_face[] = {
	LSM_CARRAY	(face_t, name,		"name"),
	LSM_CARRAY	(face_t, path,		"path"),
	LSM_CARRAY	(face_t, pages,		"pages"),
	LSM_UNSIGNED	(face_t, line_height,	"line_height"),
};

static const lws_struct_map_t lsm_manifest[] = {
	LSM_LIST	(manifest_t, fonts, face_t, list, NULL, lsm_face, "fonts"),
};

static const lws_struct_map_t lsm_manifest_schema[] = {
	LSM_SCHEMA	(manifest_t, NULL, lsm_manifest, "manifest"),
};

static struct lws_context *cx;
static struct lws_vhost *vh;
static lws_sorted_usec_list_t sul_next, sul_timeout;
static uint8_t body[65536];
static size_t body_len;
static unsigned int regular_lh;
static int step, status, tries, result = 1, cached, done;

static void
next_cb(lws_sorted_usec_list_t *sul);

static void
finish(int ok)
{
	result = !ok;
	done = 1;
	lws_cancel_service(cx);
}

static int
check_manifest(void)
{
	struct lejp_ctx jctx;
	lws_struct_args_t a;
	manifest_t *m;
	int n, seen = 0;

	memset(&a, 0, sizeof(a));
	a.map_st[0] = lsm_manifest_schema;
	a.map_entries_st[0] = LWS_ARRAY_SIZE(lsm_manifest_schema);
	a.ac_block_size = 1024;

	lws_struct_json_init_parse(&jctx, NULL, &a);
	n = lejp_parse(&jctx, body, (int)body_len);
	lejp_destruct(&jctx);
	if (n < 0 || !a.dest) {
		lwsl_err("%s: fonts.json doesn't parse\n", __func__);
		lwsac_free(&a.ac);
		return 1;
	}

	m = (manifest_t *)a.dest;
	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(&m->fonts)) {
		face_t *f = lws_container_of(d, face_t, list);

		lwsl_user("face '%s' at %s, line height %u, pages %s\n",
			  f->name, f->path, f->line_height, f->pages);

		if (!f->line_height || strncmp(f->pages, "0000", 4))
			break;

		if (!strcmp(f->path, "FiraSansCondensed-Bold14") &&
		    !strcmp(f->name, "Fira Sans Condensed Bold 14"))
			seen |= 1;

		/* fetching page 0020 of it later shows it's listed */
		if (!strcmp(f->path, "FiraSansCondensed-Regular14") &&
		    !strcmp(f->name, "Fira Sans Condensed Regular 14")) {
			regular_lh = f->line_height;
			seen |= 2;
		}
	} lws_end_foreach_dll(d);

	n = (int)m->fonts.count;
	lwsac_free(&a.ac);

	if (seen != 3 || n != 2) {
		lwsl_err("%s: fonts.json doesn't list the two faces\n",
			 __func__);
		return 1;
	}

	return 0;
}

/* the page is an mcufont of the glyphs from U+2000, at the face's line height */

static int
check_page(void)
{
	uint32_t ro, rn, first;

	if (body_len < 64 || memcmp(body, "MCUF", 4)) {
		lwsl_err("%s: not an mcufont\n", __func__);
		return 1;
	}

	ro = lws_ser_ru32be(body + 0x24);
	rn = lws_ser_ru32be(body + 0x28);
	if (!rn || ro > body_len || rn > (body_len - ro) / 16) {
		lwsl_err("%s: bad range tables\n", __func__);
		return 1;
	}

	first = lws_ser_ru32be(body + ro);
	if (first < 0x2000 || first > 0x20ff ||
	    lws_ser_ru16be(body + 0x3c) != regular_lh) {
		lwsl_err("%s: page starts at U+%04x, line height %u\n",
			 __func__, (unsigned int)first,
			 (unsigned int)lws_ser_ru16be(body + 0x3c));
		return 1;
	}

	lwsl_user("page 0020 is %u bytes from U+%04x\n",
		  (unsigned int)body_len, (unsigned int)first);

	return 0;
}

/* a response to the step's request has completed */

static void
step_done(void)
{
	const step_t *s = &steps[step];

	lwsl_user("%s: %d\n", s->url, status);

	if (s->made && status == 404) {
		/* it can only be on its way if we didn't expect it ready */
		if (cached || ++tries > 360) { /* 90s, for slow builds */
			lwsl_err("%s: never ready\n", s->url);
			finish(0);
			return;
		}
		lws_sul_schedule(cx, 0, &sul_next, next_cb,
				 250 * LWS_US_PER_MS);
		return;
	}

	if (status != s->want ||
	    (s->check == CHK_MANIFEST && check_manifest()) ||
	    (s->check == CHK_PAGE && check_page())) {
		finish(0);
		return;
	}

	/* on a fresh cache, what's made when asked for isn't there at first */
	if (s->made == MADE_ASKED && !cached && !tries) {
		lwsl_err("%s: ready before it could be made\n", s->url);
		finish(0);
		return;
	}

	step++;
	tries = 0;
	lws_sul_schedule(cx, 0, &sul_next, next_cb, 1);
}

static int
callback_client(struct lws *wsi, enum lws_callback_reasons reason,
		void *user, void *in, size_t len)
{
	switch (reason) {
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("%s: connection error: %s\n", __func__,
			 in ? (const char *)in : "");
		finish(0);
		break;

	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
		status = (int)lws_http_client_http_response(wsi);
		body_len = 0;
		break;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		if (body_len + len > sizeof(body))
			return -1;
		memcpy(body + body_len, in, len);
		body_len += len;
		return 0;

	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP: {
		char buf[1024 + LWS_PRE], *p = buf + LWS_PRE;
		int n = (int)sizeof(buf) - LWS_PRE;

		if (lws_http_client_read(wsi, &p, &n) < 0)
			return -1;
		return 0;
	}

	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		step_done();
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static void
next_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;
	char path[256];

	if (step == (int)LWS_ARRAY_SIZE(steps)) {
		finish(1);
		return;
	}

	lws_snprintf(path, sizeof(path), "/%s", steps[step].url);
	status = 0;

	memset(&i, 0, sizeof(i));
	i.context		= cx;
	i.vhost			= vh;
	i.address		= "127.0.0.1";
	i.port			= lws_get_vhost_listen_port(vh);
	i.path			= path;
	i.host			= i.address;
	i.origin		= i.address;
	i.method		= "GET";
	i.local_protocol_name	= "mcuf-test-client";

	if (!lws_client_connect_via_info(&i))
		finish(0);
}

static void
timeout_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("%s: timed out at %s\n", __func__, steps[step].url);
	finish(0);
}

static int
count_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	char p[512];

	if (lde->type == LDOT_DIR) {
		lws_snprintf(p, sizeof(p), "%s/%s", dirpath, lde->name);
		lws_dir(p, user, count_cb);
		return 0;
	}

	/* a temp object left behind would be named <hash>~<pid>-<n> */
	if (strchr(lde->name, '~'))
		*(int *)user += 1000;
	else
		(*(int *)user)++;

	return 0;
}

static const struct lws_protocols protocols[] = {
	LWS_PLUGIN_PROTOCOL_LWS_MCUFONTS,
	{ "mcuf-test-client", callback_client, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static void
sigint_handler(int sig)
{
	finish(0);
}

int
main(int argc, const char **argv)
{
	struct lws_protocol_vhost_options pvo_warm = {
		NULL, NULL, "warm-pages", "0000" },
					   pvo_jobs = {
		&pvo_warm, NULL, "jobs", "3" },
					   pvo_iter = {
		&pvo_jobs, NULL, "iterations", "1" },
					   pvo_sizes = {
		&pvo_iter, NULL, "sizes", "14" },
					   pvo_enc = {
		&pvo_sizes, NULL, "encoder", NULL },
					   pvo_cache = {
		&pvo_enc, NULL, "cache-dir", NULL },
					   pvo_ttf = {
		&pvo_cache, NULL, "ttf-dir", NULL },
					   pvo = {
		NULL, &pvo_ttf, "lws-mcufonts", "" };
	struct lws_http_mount mount;
	struct lws_context_creation_info info;
	const char *p;
	int files = 0;

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches,
					LWS_ARRAY_SIZE(switches));
		return 0;
	}

	signal(SIGINT, sigint_handler);
	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	lwsl_user("LWS API selftest: mcufonts plugin\n");

	pvo_enc.value = lws_cmdline_option(argc, argv,
					   switches[LWS_SW_ENCODER].sw);
	pvo_ttf.value = lws_cmdline_option(argc, argv,
					   switches[LWS_SW_TTF_DIR].sw);
	pvo_cache.value = lws_cmdline_option(argc, argv,
					     switches[LWS_SW_CACHE_DIR].sw);
	cached = !!lws_cmdline_option(argc, argv, switches[LWS_SW_CACHED].sw);
	if (!pvo_enc.value || !pvo_ttf.value || !pvo_cache.value) {
		lwsl_err("needs --encoder, --ttf-dir and --cache-dir\n");
		return 1;
	}

	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	memset(&mount, 0, sizeof(mount));
	mount.mountpoint	= "/";
	mount.mountpoint_len	= 1;
	mount.origin		= "lws-mcufonts";
	mount.origin_protocol	= LWSMPRO_CALLBACK;

	info.vhost_name		= "mcufonts";
	info.iface		= "127.0.0.1";
	info.port		= 0;
	info.protocols		= protocols;
	info.pvo		= &pvo;
	info.mounts		= &mount;

	vh = lws_create_vhost(cx, &info);
	if (!vh) {
		lwsl_err("vhost creation failed\n");
		goto bail;
	}

	lws_sul_schedule(cx, 0, &sul_next, next_cb, 1);
	lws_sul_schedule(cx, 0, &sul_timeout, timeout_cb,
			 150 * LWS_US_PER_SEC);

	while (!done && lws_service(cx, 0) >= 0)
		;

	lws_sul_cancel(&sul_next);
	lws_sul_cancel(&sul_timeout);

bail:
	lws_context_destroy(cx);

	/* the faces' info, their page 0000, the other page and nothing else */

	p = pvo_cache.value;
	lws_dir(p, &files, count_cb);
	if (!result && files != 5) {
		lwsl_err("cache holds %d objects, not 5\n", files);
		result = 1;
	}

	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
