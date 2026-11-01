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
 * the plugin has learned the faces, then a page of a face at a size nothing
 * made before, which is 404 until the plugin has made it, and page 0000 of
 * each face at 14px, which the plugin makes at startup since they're its
 * warm-pages and warm-sizes.  Urls for faces, sizes, pages or names it
 * doesn't have must be 404 without anything being made: at the end, the cache
 * must hold just the two faces' info, their page 0000 and the one other page.
 *
 * Then, in a build that can, it registers the manifest as a device does, and
 * checks the sizes of the faces the chooser comes up with for the heights it
 * asks for.
 *
 * With --cached, it's run again on the same cache, when both must be there
 * from the start.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>

#define LWS_PLUGIN_STATIC
#include "../../../plugins/protocol_lws_mcufonts/protocol_lws_mcufonts.c"

#if defined(LWS_WITH_DLO) && defined(LWS_WITH_SECURE_STREAMS)
/* the build can fetch faces from a manifest, so we check that too */
#define DEVICE
#endif

/* the plugin offers sizes up to this */
#define MAX_SIZE		"40"

/* builds without ipv4 can only use ipv6 loopback */
#if defined(LWS_WITH_IPV4)
#define LOOPBACK		"127.0.0.1"
#define LOOPBACK_URL		"127.0.0.1"
#else
#define LOOPBACK		"::1"
#define LOOPBACK_URL		"[::1]"
#endif

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
	{ "FiraSansCondensed-Regular/23/0020.mcufont", 200, MADE_ASKED, CHK_PAGE },
	{ "FiraSansCondensed-Regular/14/0000.mcufont", 200, MADE_WARM, CHK_NONE },
	{ "FiraSansCondensed-Bold/14/0000.mcufont",    200, MADE_WARM, CHK_NONE },

	/* none of these may make anything */
	{ "FiraSansCondensed-Regular/14/0e00.mcufont", 404, MADE_NEVER, CHK_NONE },
	{ "FiraSansCondensed-Regular/41/0000.mcufont", 404, MADE_NEVER, CHK_NONE },
	{ "FiraSansCondensed-Regular/5/0000.mcufont",  404, MADE_NEVER, CHK_NONE },
	{ "FiraSansCondensed-Regular/014/0000.mcufont", 404, MADE_NEVER, CHK_NONE },
	{ "FiraSansCondensed-Regular/+14/0000.mcufont", 404, MADE_NEVER, CHK_NONE },
	{ "FiraSansCondensed-Regular//0000.mcufont",   404, MADE_NEVER, CHK_NONE },
	{ "FiraSansCondensed-Regular/0000.mcufont",    404, MADE_NEVER, CHK_NONE },
	{ "FiraSansCondensed-Regular/14/0020.MCUFONT", 404, MADE_NEVER, CHK_NONE },
	{ "FiraSansCondensed-Regular/14/00020.mcufont", 404, MADE_NEVER, CHK_NONE },
	{ "FiraSansCondensed-Regular/14/0020.mcufont/", 404, MADE_NEVER, CHK_NONE },
	{ "FiraSansCondensed-Regular/14/0000.mcufontx", 404, MADE_NEVER, CHK_NONE },
	{ "FiraSansCondensed-Regular14/0000.mcufont",  404, MADE_NEVER, CHK_NONE },
	{ "FiraSansCondensed-Regular",		       404, MADE_NEVER, CHK_NONE },
	{ "nonexistent",			       404, MADE_NEVER, CHK_NONE },
};

/* the manifest, parsed as the device parses it */

typedef struct {
	lws_dll2_t	list;
	char		name[64];
	char		path[64];
	char		pages[160];
	char		sizes[64];
	unsigned int	height;
	unsigned int	units_per_em;
} face_t;

typedef struct {
	lws_dll2_owner_t fonts;
} manifest_t;

static const lws_struct_map_t lsm_face[] = {
	LSM_CARRAY	(face_t, name,		"name"),
	LSM_CARRAY	(face_t, path,		"path"),
	LSM_CARRAY	(face_t, pages,		"pages"),
	LSM_CARRAY	(face_t, sizes,		"sizes"),
	LSM_UNSIGNED	(face_t, height,	"height"),
	LSM_UNSIGNED	(face_t, units_per_em,	"units_per_em"),
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
static unsigned int regular_height, regular_upem;
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

		lwsl_user("face '%s' at %s, sizes %s, height %u / %u, "
			  "pages %s\n", f->name, f->path, f->sizes, f->height,
			  f->units_per_em, f->pages);

		if (!f->height || !f->units_per_em ||
		    strcmp(f->sizes, "6-" MAX_SIZE) ||
		    strncmp(f->pages, "0000", 4))
			break;

		if (!strcmp(f->path, "FiraSansCondensed-Bold") &&
		    !strcmp(f->name, "Fira Sans Condensed Bold"))
			seen |= 1;

		/* fetching page 0020 of it later shows it's listed */
		if (!strcmp(f->path, "FiraSansCondensed-Regular") &&
		    !strcmp(f->name, "Fira Sans Condensed Regular")) {
			regular_height = f->height;
			regular_upem = f->units_per_em;
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

/*
 * The page is an mcufont of the glyphs from U+2000, named as the manifest
 * names the face, which is what a device checks it against, at the line
 * height the manifest says the face has at 23px
 */

static int
check_page(void)
{
	static const char name[] = "Fira Sans Condensed Regular";
	unsigned int lh = ((regular_height * 23) + (regular_upem / 2)) /
								regular_upem;
	uint32_t ro, rn, first, no;

	if (body_len < 64 || memcmp(body, "MCUF", 4)) {
		lwsl_err("%s: not an mcufont\n", __func__);
		return 1;
	}

	no = lws_ser_ru32be(body + 8);
	if (no > body_len || body_len - no < sizeof(name) ||
	    memcmp(body + no, name, sizeof(name))) {
		lwsl_err("%s: not named '%s'\n", __func__, name);
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
	    lws_ser_ru16be(body + 0x3c) != lh) {
		lwsl_err("%s: page starts at U+%04x, line height %u not %u\n",
			 __func__, (unsigned int)first,
			 (unsigned int)lws_ser_ru16be(body + 0x3c), lh);
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

#if defined(DEVICE)

/*
 * The device's side: with one face of its own, it learns the faces from the
 * plugin's manifest, and the chooser makes them at the sizes it's asked for
 */

static const uint8_t fira_c_r_12[] = {
#include "../../../contrib/mcufont/fonts/FiraSansCondensed-Regular12.mcufont.h"
};

static const char * const device_policy =
	"{"
		"\"release\":\"1\","
		"\"product\":\"mcufonts-plugin-test\","
		"\"schema-version\":1,"
		"\"retry\":[{\"default\":{"
			"\"backoff\":[100,200],"
			"\"conceal\":2,"
			"\"jitterpc\":0,"
			"\"svalidping\":30,"
			"\"svalidhup\":35"
		"}}],"
		"\"s\":[{\"__default\":{"
			"\"endpoint\":\"${endpoint}\","
			"\"port\":80,"
			"\"protocol\":\"h1\","
			"\"http_method\":\"GET\","
			"\"http_url\":\"\","
			"\"metadata\":[{"
				"\"endpoint\":\"\","
				"\"acc\":\"accept\","
				"\"ua\":\"user-agent\""
			"}],"
			"\"retry\":\"default\","
			"\"timeout_ms\":10000"
		"}}]"
	"}";

static const lws_display_font_t *
choose(const char *family, uint16_t weight, uint16_t height)
{
	lws_font_choice_t hints = { .family_name = family, .weight = weight,
				    .fixed_height = height };

	return lws_font_choose(cx, &hints);
}

/*
 * The plugin offers 6 to 40px, and the Fira faces' line height at a size is
 * (1200 * size + 500) / 1000.  Each height asked for gets the size of a face
 * whose line height is closest, up to 8 sizes of a face, then the closest of
 * those.  A size of a face nearer the height beats the weight asked for, so
 * once the bold face has its 8 sizes, the closest of them is only chosen
 * over the regular face once that has its 8 sizes too
 */

#define REG	"Fira Sans Condensed Regular"
#define BOLD	"Fira Sans Condensed Bold"

static const struct {
	uint16_t	weight;
	uint16_t	want;
	const char	*face;	/* what we get... */
	uint16_t	lh;	/* ...with this line height */
} picks[] = {
	{ 400, 17, REG,  17 },	/* 14px: an ad-hoc size, made when chosen */
	{ 700, 23, BOLD, 23 },	/* 19px */
	{ 700, 23, BOLD, 23 },	/* ...the same face again */
	{ 700, 60, BOLD, 48 },	/* past max-size: the biggest it has */
	{ 700, 3,  BOLD, 7 },	/* the smallest, 6px */
	{ 700, 12, BOLD, 12 },
	{ 700, 14, BOLD, 14 },
	{ 700, 16, BOLD, 16 },
	{ 700, 18, BOLD, 18 },
	{ 700, 26, BOLD, 26 },	/* bold's eighth size */
	{ 700, 30, REG,  30 },	/* closer than any bold size made */
	{ 400, 7,  REG,  7 },
	{ 400, 12, REG,  12 },
	{ 400, 20, REG,  20 },	/* not 14: the face we have wins a tie */
	{ 400, 16, REG,  16 },
	{ 400, 18, REG,  18 },
	{ 400, 23, REG,  23 },	/* regular's eighth size, with 17 and 30 */
	{ 700, 26, BOLD, 26 },	/* both full: the closest sizes made */
	{ 700, 27, BOLD, 26 },
	{ 400, 29, REG,  30 },
	{ 700, 2,  BOLD, 7 },
	{ 400, 17, REG,  17 },
};

static int device_tries;

static int
device_checks(void)
{
	const lws_display_font_t *f, *f23 = NULL;
	size_t n;

	for (n = 0; n < LWS_ARRAY_SIZE(picks); n++) {
		f = choose("Fira Sans Condensed", picks[n].weight,
			   picks[n].want);
		if (!f || strcmp(f->choice.family_name, picks[n].face) ||
		    f->choice.fixed_height != picks[n].lh) {
			lwsl_err("%s: %u for %u is '%s' at %u, not '%s' at "
				 "%u\n", __func__, picks[n].weight,
				 picks[n].want,
				 f ? f->choice.family_name : "none",
				 f ? f->choice.fixed_height : 0,
				 picks[n].face, picks[n].lh);
			return 1;
		}
		lwsl_user("%u for %u: '%s' at %u\n", picks[n].weight,
			  picks[n].want, f->choice.family_name,
			  f->choice.fixed_height);

		if (picks[n].weight == 700 && picks[n].want == 23) {
			if (f23 && f != f23) {
				lwsl_err("%s: 23 made twice\n", __func__);
				return 1;
			}
			f23 = f;
		}
	}

	return 0;
}

static void
device_cb(lws_sorted_usec_list_t *sul)
{
	const lws_display_font_t *f = choose("Fira Sans Condensed", 400, 17);

	/* until the manifest is here, only the face we have can be chosen */

	if (!f || !strcmp(f->choice.family_name,
			  "Fira Sans Condensed Regular 12")) {
		if (++device_tries > 100) {
			lwsl_err("%s: the manifest never came\n", __func__);
			finish(0);
			return;
		}
		lws_sul_schedule(cx, 0, &sul_next, device_cb,
				 100 * LWS_US_PER_MS);
		return;
	}

	finish(!device_checks());
}

static void
device_start(void)
{
	char url[64];

	lws_snprintf(url, sizeof(url), "http://" LOOPBACK_URL ":%d/fonts.json",
		     lws_get_vhost_listen_port(vh));

	if (lws_font_register(cx, fira_c_r_12, sizeof(fira_c_r_12)) ||
	    lws_fonts_register_manifest(cx, url)) {
		lwsl_err("%s: can't use %s\n", __func__, url);
		finish(0);
		return;
	}

	lws_sul_schedule(cx, 0, &sul_next, device_cb, 1);
}
#endif

static void
next_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_client_connect_info i;
	char path[256];

	if (step == (int)LWS_ARRAY_SIZE(steps)) {
#if defined(DEVICE)
		device_start();
#else
		finish(1);
#endif
		return;
	}

	lws_snprintf(path, sizeof(path), "/%s", steps[step].url);
	status = 0;

	memset(&i, 0, sizeof(i));
	i.context		= cx;
	i.vhost			= vh;
	i.address		= LOOPBACK;
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
		&pvo_iter, NULL, "warm-sizes", "14" },
					   pvo_max = {
		&pvo_sizes, NULL, "max-size", MAX_SIZE },
					   pvo_enc = {
		&pvo_max, NULL, "encoder", NULL },
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
#if defined(DEVICE)
	info.pss_policies_json = device_policy;
#endif
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
	info.iface		= LOOPBACK;
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
