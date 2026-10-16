/*
 * lws-api-test-plugins
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Every protocol plugin this build made must load: it opens, exports its
 * header, matches our build hash and class, and brings protocols that have
 * a name and a callback.
 *
 * It's also ctest's first test, run by itself (see CMakeLists.txt).  It
 * looks for the plugins where every other test's context will, so the cost
 * some platforms charge for the first load of a new library, which is
 * seconds per plugin on macOS, is paid here once, instead of by all the
 * tests starting together while their peers wait for them to listen.
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdlib.h>

struct pt_args {
	struct lws_plugin	*list;
	const char		*suffix;
	int			candidates;
	int			fails;
};

/*
 * The base name the lib gives a protocol plugin's file, eg,
 * "libprotocol_lws_mirror.so" -> "lws_mirror", or NULL if the file isn't a
 * protocol plugin of ours, eg, an import lib or a debug symbol file beside
 * the shared lib, that has the right start but not our suffix
 */

static const char *
plugin_base(const char *name, const char *suffix, char *base, size_t len)
{
	size_t nl = strlen(name), sl = strlen(suffix);
	const char *p = name;

	if (!strncmp(p, "lib", 3))
		p += 3;
	if (strncmp(p, "protocol_", 9))
		return NULL;
	p += 9;

	if (nl <= sl || strcmp(name + nl - sl, suffix))
		return NULL;

	lws_strnncpy(base, p, strcspn(p, "."), len);

	return base;
}

static int
dir_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	struct pt_args *a = (struct pt_args *)user;
	const struct lws_plugin *pin;
	char base[64];

	if (lde->type == LDOT_DIR)
		return 0;

	if (!plugin_base(lde->name, a->suffix, base, sizeof(base)))
		return 0;

	a->candidates++;

	for (pin = a->list; pin; pin = pin->list)
		if (!strcmp(pin->basename, base))
			return 0;

	lwsl_err("%s: %s/%s was not loaded\n", __func__, dirpath, lde->name);
	a->fails++;

	return 0;
}

static int
check_plugin(const struct lws_plugin *pin)
{
	const lws_plugin_protocol_t *plpr =
				(const lws_plugin_protocol_t *)pin->hdr;
	int n;

	if (!pin->hdr->name || !pin->hdr->name[0]) {
		lwsl_err("%s: %s: no name\n", __func__, pin->basename);
		return 1;
	}

	if (plpr->count_protocols < 1 || !plpr->protocols) {
		lwsl_err("%s: %s: no protocols\n", __func__, pin->hdr->name);
		return 1;
	}

	for (n = 0; n < plpr->count_protocols; n++)
		if (!plpr->protocols[n].name || !plpr->protocols[n].callback) {
			lwsl_err("%s: %s: protocol %d incomplete\n", __func__,
				 pin->hdr->name, n);
			return 1;
		}

	lwsl_info("%s: %s: %d protocols\n", __func__, pin->hdr->name,
		  plpr->count_protocols);

	return 0;
}

int
main(int argc, const char **argv)
{
	int logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE, loaded = 0;
	const char *dirs[2] = { NULL, NULL }, *p;
	const struct lws_plugin *pin;
	struct pt_args a;
	lws_usec_t us;

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS API selftest: protocol plugins load\n");

	memset(&a, 0, sizeof(a));

	dirs[0] = lws_cmdline_option(argc, argv, "--dir");
	a.suffix = lws_cmdline_option(argc, argv, "--suffix");
	if (!dirs[0] || !a.suffix) {
		lwsl_err("Usage: %s --dir <plugin dir> --suffix <.so|.dylib|.dll>"
			 " [-d <loglevel>]\n", argv[0]);
		return 1;
	}

	/*
	 * Like the lib does for a context, this looks in the dirs on
	 * LD_LIBRARY_PATH before the dirs we give it, so we load the same
	 * copies the other tests will
	 */

	us = lws_now_usecs();
	lws_plugins_init(&a.list, dirs, "lws_protocol_plugin", NULL,
			 NULL, NULL);
	us = lws_now_usecs() - us;

	for (pin = a.list; pin; pin = pin->list) {
		loaded++;
		if (check_plugin(pin))
			a.fails++;
	}

	lwsl_user("%s: loaded %d plugins in %dms\n", __func__, loaded,
		  (int)(us / LWS_US_PER_MS));

	/*
	 * Everything this build made must be one of them.  A dir we can't
	 * read finds no plugins, which fails below.
	 */

	lws_dir(dirs[0], &a, dir_cb);

	if (!a.candidates) {
		lwsl_err("%s: no protocol plugins in %s\n", __func__, dirs[0]);
		a.fails++;
	}

	lws_plugins_destroy(&a.list, NULL, NULL);

	lwsl_user("Completed: %s\n", a.fails ? "FAIL" : "PASS");

	return !!a.fails;
}
