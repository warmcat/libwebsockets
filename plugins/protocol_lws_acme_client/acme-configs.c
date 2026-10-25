/*
 * libwebsockets ACME client protocol plugin
 *
 * Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * The certs we manage, from <base>/domains/<zone>/conf.d/<name>.json
 *
 * The dnssec monitor writes and removes these files while we run, when a cert
 * is added to or deleted from a domain in its UI.  So the configs we hold are
 * brought up to date with the files whenever nothing is using them, rather
 * than read once at startup: a cert added afterwards was otherwise not
 * renewed, nor could its reissue be forced, until lwsws was restarted.
 *
 * A config that is still there keeps its state, its backoff and any forced
 * reissue, across a sync, even if its file was rewritten.  The files are a
 * few hundred bytes, so each sync just reads them again and compares: a
 * rewrite within the same second as the last, of the same size, is still
 * seen.
 *
 * The scan at startup runs as root, but later ones run as the unprivileged
 * user we dropped to, which can only read the files the monitor shared with
 * it.  A file or directory we can't read is not taken to be gone: whatever we
 * already loaded from it is kept.
 */

#if !defined(LWS_PLUGIN_STATIC)
#if !defined(LWS_DLL)
#define LWS_DLL
#endif
#if !defined(LWS_INTERNAL)
#define LWS_INTERNAL
#endif
#include <libwebsockets.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include "private-acme-client.h"

/* a cert config is a few hundred bytes of JSON: anything much bigger isn't */
#define ACME_CONF_MAX	4096

static const lws_struct_map_t map_acme_acme_obj[] = {
	LSM_STRING_PTR(struct lws_acme_cert_config_acme, country, "country"),
	LSM_STRING_PTR(struct lws_acme_cert_config_acme, state, "state"),
	LSM_STRING_PTR(struct lws_acme_cert_config_acme, locality, "locality"),
	LSM_STRING_PTR(struct lws_acme_cert_config_acme, organization, "organization"),
	LSM_STRING_PTR(struct lws_acme_cert_config_acme, directory_url, "directory-url"),
};

static const lws_struct_map_t map_acme_cert_config[] = {
	LSM_STRING_PTR(struct lws_acme_cert_config, common_name, "common-name"),
	LSM_STRING_PTR(struct lws_acme_cert_config, challenge_type_str, "challenge-type"),
	LSM_STRING_PTR(struct lws_acme_cert_config, email, "email"),
	LSM_STRING_PTR(struct lws_acme_cert_config, profile, "profile"),
	LSM_CHILD_PTR(struct lws_acme_cert_config, acme, struct lws_acme_cert_config_acme, NULL, map_acme_acme_obj, "acme"),
};

static const lws_struct_map_t map_acme_cert_config_root[] = {
	LSM_SCHEMA(struct lws_acme_cert_config, NULL, map_acme_cert_config, "lws-acme-client-config"),
};

struct acme_sync_zone {
	struct acme_sync	*sync;
	const char		*zone;
	char			listed;	/* conf.d was listed, not just empty */
};

const char *
acme_cert_zone(const struct lws_acme_cert_config *cfg)
{
	return cfg->pvop[LWS_TLS_SET_ROOT_DOMAIN] ?
			cfg->pvop[LWS_TLS_SET_ROOT_DOMAIN] :
			cfg->pvop[LWS_TLS_REQ_ELEMENT_COMMON_NAME];
}

/*
 * Domain directory names and config common-names end up in the JSON control
 * messages we send to the root-privileged daemon, and (for dns-01) in the zone
 * lines it signs.  Nothing that is not a plausible hostname has any business
 * being there, so refuse it at the point we load it rather than relying on
 * escaping downstream.  '*' is allowed for wildcard certs.
 */
int
acme_valid_hostname(const char *p)
{
	size_t n = 0;

	if (!p || !*p)
		return 0;

	while (*p) {
		if (!isalnum((unsigned char)*p) && *p != '.' && *p != '-' &&
		    *p != '_' && *p != '*')
			return 0;
		p++;
		if (++n > 255)
			return 0;
	}

	return 1;
}

int
acme_cert_set_paths(const char *base_dir, struct lws_acme_cert_config *cfg,
		    const char *env_dir)
{
	static const int pv[] = { LWS_TLS_SET_CERT_PATH, LWS_TLS_SET_KEY_PATH };
	static const char * const kind[] = { "crt", "key" };
	const char *zone = acme_cert_zone(cfg),
		   *cn = cfg->pvop[LWS_TLS_REQ_ELEMENT_COMMON_NAME];
	char path[512];
	size_t n;

	if (!zone || !cn)
		return 1;

	for (n = 0; n < LWS_ARRAY_SIZE(pv); n++) {
		if ((size_t)lws_snprintf(path, sizeof(path),
				"%s/domains/%s/certs/%s/%s/%s-latest.%s",
				base_dir, zone, env_dir, kind[n], cn,
				kind[n]) >= sizeof(path) - 1)
			return 1;

		if (cfg->pvop[pv[n]] && !strcmp(cfg->pvop[pv[n]], path))
			continue;

		free((void *)cfg->pvop[pv[n]]);
		cfg->pvop[pv[n]] = strdup(path);
		if (!cfg->pvop[pv[n]])
			return 1;
	}

	return 0;
}

void
acme_config_free(struct lws_acme_cert_config *cfg)
{
	struct lwsac *ac = cfg->ac;

	lws_dll2_remove(&cfg->list);

	/* the only ones that aren't in the cfg's own lwsac */
	free((void *)cfg->pvop[LWS_TLS_SET_CERT_PATH]);
	free((void *)cfg->pvop[LWS_TLS_SET_KEY_PATH]);

	/* the cfg itself is in there too */
	lwsac_free(&ac);
}

void
acme_configs_free_all(lws_dll2_owner_t *owner)
{
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(owner)) {
		acme_config_free(lws_container_of(d,
					struct lws_acme_cert_config, list));
	} lws_end_foreach_dll_safe(d, d1);
}

struct lws_acme_cert_config *
acme_configs_find(lws_dll2_owner_t *owner, const char *zone, const char *cn)
{
	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(owner)) {
		struct lws_acme_cert_config *cfg = lws_container_of(d,
					struct lws_acme_cert_config, list);
		const char *z = acme_cert_zone(cfg),
			   *c = cfg->pvop[LWS_TLS_REQ_ELEMENT_COMMON_NAME];

		if (z && c && !strcmp(z, zone) && !strcmp(c, cn))
			return cfg;
	} lws_end_foreach_dll(d);

	return NULL;
}

/* the one we loaded from this file of the zone, if any */

static struct lws_acme_cert_config *
acme_configs_find_conf(lws_dll2_owner_t *owner, const char *zone,
		       const char *conf)
{
	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(owner)) {
		struct lws_acme_cert_config *cfg = lws_container_of(d,
					struct lws_acme_cert_config, list);

		if (!strcmp(acme_cert_zone(cfg), zone) &&
		    !strcmp(cfg->conf, conf))
			return cfg;
	} lws_end_foreach_dll(d);

	return NULL;
}

/* keep whatever we have from the zone, we can't tell what's still there */

static void
acme_configs_keep_zone(lws_dll2_owner_t *owner, const char *zone)
{
	lws_start_foreach_dll(struct lws_dll2 *, d, lws_dll2_get_head(owner)) {
		struct lws_acme_cert_config *cfg = lws_container_of(d,
					struct lws_acme_cert_config, list);

		if (!strcmp(acme_cert_zone(cfg), zone))
			cfg->seen = 1;
	} lws_end_foreach_dll(d);
}

static char *
acme_ac_strdup(struct lwsac **ac, const char *s)
{
	size_t n = strlen(s) + 1;
	char *p = lwsac_use(ac, n, 0);

	if (p)
		memcpy(p, s, n);

	return p;
}

/*
 * A new config from the JSON in buf, with everything it points at in its own
 * lwsac, or NULL if it isn't one we can use
 */

static struct lws_acme_cert_config *
acme_config_parse(const char *base_dir, const char *zone, const char *conf,
		  const char *path, const char *buf, size_t len)
{
	char cn_s[128], *q = cn_s, *auth_path, *json;
	struct lws_acme_cert_config *cfg;
	struct lws_struct_args args;
	struct lejp_ctx ctx;
	const char *p;
	size_t al;
	int m;

	memset(&args, 0, sizeof(args));
	args.map_st[0] = map_acme_cert_config_root;
	args.map_entries_st[0] = LWS_ARRAY_SIZE(map_acme_cert_config_root);
	args.ac_block_size = 512;

	lws_struct_json_init_parse(&ctx, NULL, &args);
	m = lejp_parse(&ctx, (const uint8_t *)buf, (int)len);
	lejp_destruct(&ctx);

	cfg = (struct lws_acme_cert_config *)args.dest;
	if (m < 0 || !cfg) {
		lwsl_warn("acme: %s: unable to parse (%d)\n", path, m);
		goto bail;
	}

	if (!acme_valid_hostname(cfg->common_name)) {
		lwsl_err("acme: %s: refusing invalid common-name\n", path);
		goto bail;
	}

	cfg->ac = args.ac;
	cfg->conf = acme_ac_strdup(&cfg->ac, conf);
	json = lwsac_use(&cfg->ac, len, 0);
	if (json) {
		memcpy(json, buf, len);
		cfg->conf_json = json;
		cfg->conf_json_len = len;
	}
	cfg->pvop[LWS_TLS_SET_ROOT_DOMAIN] = acme_ac_strdup(&cfg->ac, zone);

	/* the account key's file is named after the cert, made safe for it */
	for (p = cfg->common_name; *p && q < &cn_s[sizeof(cn_s) - 1]; p++)
		*q++ = (isalnum((unsigned char)*p) || *p == '.' || *p == '-') ?
				*p : '_';
	*q = '\0';

	al = strlen(base_dir) + strlen(zone) + strlen(cn_s) + 32;
	auth_path = lwsac_use(&cfg->ac, al, 0);
	if (!cfg->conf || !cfg->conf_json || !cfg->pvop[LWS_TLS_SET_ROOT_DOMAIN] ||
	    !auth_path) {
		lwsl_err("acme: %s: OOM\n", path);
		goto bail;
	}
	lws_snprintf(auth_path, al, "%s/domains/%s/%s-auth.jwk", base_dir, zone,
		     cn_s);
	cfg->pvop[LWS_TLS_SET_AUTH_PATH] = auth_path;

	cfg->pvop[LWS_TLS_REQ_ELEMENT_COMMON_NAME] = cfg->common_name;
	cfg->pvop[LWS_TLS_REQ_ELEMENT_EMAIL] = cfg->email;
	if (cfg->acme) {
		cfg->pvop[LWS_TLS_REQ_ELEMENT_COUNTRY] = cfg->acme->country;
		cfg->pvop[LWS_TLS_REQ_ELEMENT_STATE] = cfg->acme->state;
		cfg->pvop[LWS_TLS_REQ_ELEMENT_LOCALITY] = cfg->acme->locality;
		cfg->pvop[LWS_TLS_REQ_ELEMENT_ORGANIZATION] =
						cfg->acme->organization;
		cfg->pvop[LWS_TLS_SET_DIR_URL] = cfg->acme->directory_url;
	}

	cfg->challenge_type = LWS_ACME_CHALLENGE_TYPE_HTTP_01;
	if (cfg->challenge_type_str &&
	    !strcmp(cfg->challenge_type_str, "dns-01"))
		cfg->challenge_type = LWS_ACME_CHALLENGE_TYPE_DNS_01;

	lws_dll2_clear(&cfg->list);

	return cfg;

bail:
	lwsac_free(&args.ac);

	return NULL;
}

static int
acme_sync_conf_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	struct acme_sync_zone *sz = (struct acme_sync_zone *)user;
	struct acme_sync *s = sz->sync;
	struct lws_acme_cert_config *old, *cfg;
	char path[512], buf[ACME_CONF_MAX];
	size_t nl = strlen(lde->name);
	ssize_t n;
	int fd;

	if (!lde->name[0]) {
		/* the toplevel callback: we only get it if it was listed */
		sz->listed = 1;
		return 0;
	}

	if (lde->type != LDOT_FILE || nl < 6 ||
	    strcmp(&lde->name[nl - 5], ".json"))
		return 0;

	if ((size_t)lws_snprintf(path, sizeof(path), "%s/%s", dirpath,
				 lde->name) >= sizeof(path) - 1)
		return 0;

	old = acme_configs_find_conf(s->owner, sz->zone, lde->name);

	fd = lws_open(path, O_RDONLY);
	if (fd < 0) {
		/* not gone, but we can't tell what it says now */
		if (old)
			old->seen = 1;
		else
			lwsl_warn("acme: unable to read %s: errno %d\n", path,
				  errno);
		return 0;
	}

	n = read(fd, buf, sizeof(buf));
	close(fd);
	if (n <= 0 || (size_t)n == sizeof(buf)) {
		lwsl_warn("acme: %s: unreadable or too big\n", path);
		if (old)
			old->seen = 1;
		return 0;
	}

	if (old && old->conf_json_len == (size_t)n &&
	    !memcmp(old->conf_json, buf, (size_t)n)) {
		/* what we already have */
		old->seen = 1;
		return 0;
	}

	cfg = acme_config_parse(s->base_dir, sz->zone, lde->name, path, buf,
				(size_t)n);
	if (!cfg) {
		/* the one we had is better than none */
		if (old)
			old->seen = 1;
		return 0;
	}

	cfg->seen = 1;

	if (old) {
		if (!s->may_free) {
			/* it must stay where it is for now: try again later */
			acme_config_free(cfg);
			old->seen = 1;
			return 0;
		}

		/* the same cert, rewritten, keeps where it had got to */
		if (!strcmp(old->common_name, cfg->common_name)) {
			cfg->force_reissue = old->force_reissue;
			cfg->retry_not_before = old->retry_not_before;
			cfg->fail_count = old->fail_count;
		}

		lwsl_notice("acme: reloaded cert %s from %s\n",
			    cfg->common_name, path);
		acme_config_free(old);
	} else
		lwsl_notice("acme: loaded cert %s\n", cfg->common_name);

	lws_dll2_add_tail(&cfg->list, s->owner);
	s->added++;

	return 0;
}

static void
acme_sync_zone(struct acme_sync *s, const char *zone)
{
	struct acme_sync_zone sz;
	struct lws_dir_info info;
	char path[512];
	struct stat st;

	/* the directory name is used as the domain in the daemon IPC */
	if (!acme_valid_hostname(zone)) {
		lwsl_warn("acme: ignoring domain dir '%s': not a valid "
			  "hostname\n", zone);
		return;
	}

	/* what we had from a disabled domain goes */
	lws_snprintf(path, sizeof(path), "%s/domains/%s/acme_disabled",
		     s->base_dir, zone);
	if (!stat(path, &st)) {
		lwsl_info("acme: skipping domain %s (acme_disabled present)\n",
			  zone);
		return;
	}

	lws_snprintf(path, sizeof(path), "%s/domains/%s/conf.d", s->base_dir,
		     zone);

	/* none at all is something we can be sure about */
	if (stat(path, &st) && errno == ENOENT)
		return;

	memset(&sz, 0, sizeof(sz));
	sz.sync = s;
	sz.zone = zone;

	memset(&info, 0, sizeof(info));
	info.dirpath = path;
	info.user = &sz;
	info.cb = acme_sync_conf_cb;
	info.do_toplevel_cb = 1;
	lws_dir_via_info(&info);

	if (!sz.listed) {
		/* there may be something, we can't tell */
		lwsl_warn("acme: unable to list %s\n", path);
		acme_configs_keep_zone(s->owner, zone);
	}
}

static int
acme_sync_domains_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	struct acme_sync *s = (struct acme_sync *)user;

	if (!lde->name[0]) {
		s->listed = 1;
		return 0;
	}

	if (lde->type == LDOT_DIR && strcmp(lde->name, ".") &&
	    strcmp(lde->name, ".."))
		acme_sync_zone(s, lde->name);

	return 0;
}

void
acme_configs_sync(struct acme_sync *s)
{
	struct lws_dir_info info;
	char path[512];

	s->added = 0;
	s->removed = 0;
	s->listed = 0;

	lws_start_foreach_dll(struct lws_dll2 *, d,
			      lws_dll2_get_head(s->owner)) {
		struct lws_acme_cert_config *cfg = lws_container_of(d,
					struct lws_acme_cert_config, list);

		/* out of scope ones are left alone */
		cfg->seen = s->zone && strcmp(acme_cert_zone(cfg), s->zone);
	} lws_end_foreach_dll(d);

	if (s->zone) {
		s->listed = 1;
		acme_sync_zone(s, s->zone);
	} else {
		lws_snprintf(path, sizeof(path), "%s/domains", s->base_dir);

		memset(&info, 0, sizeof(info));
		info.dirpath = path;
		info.user = s;
		info.cb = acme_sync_domains_cb;
		info.do_toplevel_cb = 1;
		lws_dir_via_info(&info);

		if (!s->listed)
			lwsl_warn("acme: unable to list %s\n", path);
	}

	/*
	 * If we couldn't see what domains there are, we can't tell which are
	 * gone either
	 */
	if (!s->listed || !s->may_free)
		return;

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(s->owner)) {
		struct lws_acme_cert_config *cfg = lws_container_of(d,
					struct lws_acme_cert_config, list);

		if (!cfg->seen) {
			lwsl_notice("acme: cert %s (%s) is no longer "
				    "configured\n", cfg->common_name,
				    acme_cert_zone(cfg));
			acme_config_free(cfg);
			s->removed++;
		}
	} lws_end_foreach_dll_safe(d, d1);
}
