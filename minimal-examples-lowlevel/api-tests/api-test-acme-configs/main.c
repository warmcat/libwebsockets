/*
 * lws-api-test-acme-configs
 *
 * Written in 2026 by Andy Green <andy@warmcat.com>
 * Note: CC0 1.0 Universal Public Domain Dedication
 *
 * Brings the ACME client plugin's certs up to date with a scratch
 * domains/<zone>/conf.d tree, the way the plugin does at the start of each
 * evaluation (see plugins/protocol_lws_acme_client/acme-configs.c), while the
 * tree changes the way the dnssec monitor changes it.
 *
 * Covered behaviours:
 *
 *  - every zone's *.json are loaded, other files and zone dirs that aren't
 *    hostnames are not, and a malformed config is refused
 *  - a cert added after the first scan is picked up by the next one, which
 *    leaves the ones already loaded where they are, with their state
 *  - a rewritten config is reloaded keeping its backoff and forced reissue,
 *    but only when it may be freed: until then the old one stays as it was
 *  - a removed config goes, but only when it may be freed, and so does a
 *    zone given an acme_disabled file
 *  - a sync for one zone leaves the other zones alone
 *  - a domains dir that can't be listed, and a config that can't be read,
 *    are not taken to be empty or gone: what was loaded is kept
 */

#include <libwebsockets.h>

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include "private-acme-client.h"

static char base[256];

static int
t_expect(int cond, const char *what)
{
	if (!cond) {
		lwsl_err("FAILED: %s\n", what);

		return 1;
	}

	return 0;
}

static int
t_mkdir(const char *rel)
{
	char p[512];

	lws_snprintf(p, sizeof(p), "%s/%s", base, rel);
	if (mkdir(p, 0700) && errno != EEXIST) {
		lwsl_err("unable to make %s\n", p);

		return 1;
	}

	return 0;
}

static int
t_write(const char *rel, const char *content)
{
	char p[512];
	ssize_t n;
	int fd;

	lws_snprintf(p, sizeof(p), "%s/%s", base, rel);
	fd = open(p, O_CREAT | O_WRONLY | O_TRUNC, 0600);
	if (fd < 0) {
		lwsl_err("unable to write %s\n", p);

		return 1;
	}
	n = write(fd, content, strlen(content));
	close(fd);

	return n != (ssize_t)strlen(content);
}

static int
t_unlink(const char *rel)
{
	char p[512];

	lws_snprintf(p, sizeof(p), "%s/%s", base, rel);

	return unlink(p);
}

static int
t_rename(const char *from, const char *to)
{
	char p[512], p1[512];

	lws_snprintf(p, sizeof(p), "%s/%s", base, from);
	lws_snprintf(p1, sizeof(p1), "%s/%s", base, to);

	return rename(p, p1);
}

static void
t_rm_tree(void)
{
	lws_dir(base, NULL, lws_dir_rm_rf_cb);
	rmdir(base);
}

static void
t_sync(struct acme_sync *s, lws_dll2_owner_t *owner, const char *zone,
       int may_free)
{
	memset(s, 0, sizeof(*s));
	s->owner	= owner;
	s->base_dir	= base;
	s->zone		= zone;
	s->may_free	= (char)may_free;

	acme_configs_sync(s);
}

static const char *
t_conf(const char *cn, const char *extra)
{
	static char buf[512];

	lws_snprintf(buf, sizeof(buf), "{\"common-name\":\"%s\","
		     "\"challenge-type\":\"dns-01\",\"email\":\"a@b.c\"%s}",
		     cn, extra ? extra : "");

	return buf;
}

int
main(int argc, const char **argv)
{
	struct lws_acme_cert_config *www, *c;
	lws_dll2_owner_t owner;
	struct acme_sync s;
	int bad = 0, logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE;
	const char *p;

	if ((p = lws_cmdline_option(argc, argv, "-d")))
		logs = atoi(p);

	lws_set_log_level(logs, NULL);
	lwsl_user("LWS API selftest: ACME client cert configs\n");

	memset(&owner, 0, sizeof(owner));

	lws_snprintf(base, sizeof(base), "acme-configs-%u",
		     (unsigned int)getpid());
	t_rm_tree();
	if (mkdir(base, 0700) || t_mkdir("domains") ||
	    t_mkdir("domains/a.com") || t_mkdir("domains/a.com/conf.d") ||
	    t_mkdir("domains/b.com") || t_mkdir("domains/b.com/conf.d") ||
	    t_mkdir("domains/no zone") || t_mkdir("domains/no zone/conf.d") ||
	    t_write("domains/a.com/conf.d/a.com.json", t_conf("a.com", NULL)) ||
	    t_write("domains/a.com/conf.d/www.a.com.json",
		    t_conf("www.a.com", NULL)) ||
	    t_write("domains/a.com/conf.d/www.a.com.port", "443\n") ||
	    t_write("domains/a.com/conf.d/bad.json", "{\"common-name\":") ||
	    t_write("domains/a.com/conf.d/evil.json",
		    t_conf("evil\\\",\\\"x", NULL)) ||
	    t_write("domains/b.com/conf.d/b.com.json", t_conf("b.com", NULL)) ||
	    t_write("domains/no zone/conf.d/x.json", t_conf("x", NULL))) {
		bad = 1;
		goto bail;
	}

	/* the first scan */

	t_sync(&s, &owner, NULL, 1);
	bad |= t_expect(s.listed && s.added == 3 && !s.removed &&
			lws_dll2_count(&owner) == 3, "first scan loads 3");

	www = acme_configs_find(&owner, "a.com", "www.a.com");
	bad |= t_expect(!!www, "www.a.com is in a.com");
	bad |= t_expect(!acme_configs_find(&owner, "b.com", "www.a.com"),
			"www.a.com is not in b.com");
	if (!www)
		goto bail;

	bad |= t_expect(!strcmp(acme_cert_zone(www), "a.com"), "its zone");
	bad |= t_expect(www->challenge_type == LWS_ACME_CHALLENGE_TYPE_DNS_01,
			"its challenge type");
	bad |= t_expect(www->pvop[LWS_TLS_SET_AUTH_PATH] &&
			!!strstr(www->pvop[LWS_TLS_SET_AUTH_PATH],
				 "/domains/a.com/www.a.com-auth.jwk"),
			"its account key path");
	bad |= t_expect(!acme_cert_set_paths(base, www, "staging") &&
			!!strstr(www->pvop[LWS_TLS_SET_CERT_PATH],
			      "/domains/a.com/certs/staging/crt/www.a.com-latest.crt"),
			"its cert path");

	www->fail_count = 3;
	www->retry_not_before = 1234;
	www->force_reissue = 1;

	/* nothing changed: nothing happens */

	t_sync(&s, &owner, NULL, 1);
	bad |= t_expect(!s.added && !s.removed && lws_dll2_count(&owner) == 3 &&
			acme_configs_find(&owner, "a.com", "www.a.com") == www,
			"rescan of the same files changes nothing");

	/* a cert added since, while they are in use */

	bad |= t_write("domains/a.com/conf.d/mail.home.a.com.json",
		       t_conf("mail.home.a.com", NULL));
	t_sync(&s, &owner, "a.com", 0);
	bad |= t_expect(s.added == 1 && !s.removed &&
			lws_dll2_count(&owner) == 4 &&
			!!acme_configs_find(&owner, "a.com", "mail.home.a.com"),
			"added cert is picked up");
	bad |= t_expect(acme_configs_find(&owner, "a.com", "www.a.com") == www &&
			www->fail_count == 3 && www->retry_not_before == 1234 &&
			www->force_reissue, "the others are left as they were");

	/* a rewritten config waits until it may be freed */

	bad |= t_write("domains/a.com/conf.d/www.a.com.json",
		       t_conf("www.a.com", ",\"profile\":\"shortlived\""));
	t_sync(&s, &owner, NULL, 0);
	bad |= t_expect(!s.added && !s.removed &&
			acme_configs_find(&owner, "a.com", "www.a.com") == www &&
			!www->profile, "rewritten config waits while in use");

	t_sync(&s, &owner, NULL, 1);
	c = acme_configs_find(&owner, "a.com", "www.a.com");
	bad |= t_expect(s.added == 1 && !s.removed && c &&
			lws_dll2_count(&owner) == 4, "rewritten config reloads");
	if (!c)
		goto bail;
	bad |= t_expect(c->profile && !strcmp(c->profile, "shortlived"),
			"with what it says now");
	bad |= t_expect(c->fail_count == 3 && c->retry_not_before == 1234 &&
			c->force_reissue, "keeping its state");
	www = c;

	/* a rewrite that doesn't parse leaves the old one */

	bad |= t_write("domains/a.com/conf.d/www.a.com.json", "{\"comm");
	t_sync(&s, &owner, NULL, 1);
	bad |= t_expect(!s.added && !s.removed &&
			acme_configs_find(&owner, "a.com", "www.a.com") == www,
			"unparseable rewrite keeps the old one");
	bad |= t_write("domains/a.com/conf.d/www.a.com.json",
		       t_conf("www.a.com", ",\"profile\":\"shortlived\""));

	/* a removed one goes, but only when it may be freed */

	bad |= t_unlink("domains/b.com/conf.d/b.com.json");
	t_sync(&s, &owner, NULL, 0);
	bad |= t_expect(!s.removed && lws_dll2_count(&owner) == 4 &&
			!!acme_configs_find(&owner, "b.com", "b.com"),
			"removed config stays while in use");
	t_sync(&s, &owner, NULL, 1);
	bad |= t_expect(s.removed == 1 && lws_dll2_count(&owner) == 3 &&
			!acme_configs_find(&owner, "b.com", "b.com"),
			"removed config goes");

	/* a sync of one zone doesn't touch the others */

	bad |= t_write("domains/b.com/conf.d/b.com.json", t_conf("b.com", NULL));
	t_sync(&s, &owner, NULL, 1);
	bad |= t_unlink("domains/b.com/conf.d/b.com.json");
	t_sync(&s, &owner, "a.com", 1);
	bad |= t_expect(!s.removed && !!acme_configs_find(&owner, "b.com",
							   "b.com"),
			"a.com sync leaves b.com alone");

	/* domains that can't be listed aren't taken to be empty */

	bad |= t_rename("domains", "domains-away");
	t_sync(&s, &owner, NULL, 1);
	bad |= t_expect(!s.listed && !s.removed && lws_dll2_count(&owner) == 4,
			"unlistable domains dir keeps everything");
	bad |= t_rename("domains-away", "domains");

	/* nor is a config we can no longer read (root reads it anyway) */

	if (geteuid()) {
		char path[512];

		lws_snprintf(path, sizeof(path),
			     "%s/domains/a.com/conf.d/www.a.com.json", base);
		bad |= chmod(path, 0);
		t_sync(&s, &owner, "a.com", 1);
		bad |= t_expect(acme_configs_find(&owner, "a.com",
						  "www.a.com") == www,
				"unreadable config is kept");
		bad |= chmod(path, 0600);
	}

	/* a disabled zone's certs go */

	bad |= t_write("domains/a.com/acme_disabled", "");
	t_sync(&s, &owner, NULL, 1);
	bad |= t_expect(s.removed == 4 && !lws_dll2_count(&owner),
			"disabled zone's certs go, with b.com's removed one");

bail:
	acme_configs_free_all(&owner);
	bad |= t_expect(!lws_dll2_count(&owner), "all freed");
	t_rm_tree();

	lwsl_user("Completed: %s\n", bad ? "FAIL" : "PASS");

	return bad;
}
