/*
 * Sai push - src/push/pu-sai.c
 *
 * Copyright (C) 2026 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 *
 * sai-push follows sai-web feeds of events (the JSON form of the rss feed,
 * using its long poll), and when an event for a watched repository succeeds
 * on a branch a rule matches, eg, main-dev, it pushes that commit on to the
 * branch the rule maps it to, eg, main.
 *
 * It's started as root, sets up its repo cache dir, then becomes the conf's
 * "user" before it does anything on the network.  That user is one that
 * exists just for this, whose ssh keys the git server accepts for pushing to
 * the repos it should manage, and whose known_hosts already has the git
 * server's host key.
 *
 * Mirrors get the same pushes as the primary remote.  A mirror reached by
 * https with a token (eg, github with a fine-grained access token limited to
 * the mirror repos) names a token file: git runs sai-push itself as its
 * GIT_ASKPASS to read it, see saip_askpass().
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <pwd.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "pu-private.h"

saip_t saip;
static int interrupted;

static const struct lws_protocols *pprotocols[] = {
	&protocol_saip_feed,
	&protocol_saip_git,
	NULL
};

/*
 * We read the JSON conf using lws_struct... instrument the related structures
 */

static const lws_struct_map_t lsm_saip_rule[] = {
	LSM_STRING_PTR	(saip_rule_t, match,			"match"),
	LSM_STRING_PTR	(saip_rule_t, branch_suffix,		"branch-suffix"),
	LSM_BOOLEAN	(saip_rule_t, force,			"force"),
};

static const lws_struct_map_t lsm_saip_mirror[] = {
	LSM_STRING_PTR	(saip_mirror_t, url,			"url"),
	LSM_STRING_PTR	(saip_mirror_t, token_file,		"token-file"),
};

static const lws_struct_map_t lsm_saip_watch[] = {
	LSM_STRING_PTR	(saip_watch_t, feed,			"feed"),
	LSM_STRING_PTR	(saip_watch_t, fetchurl,		"fetchurl"),
	LSM_STRING_PTR	(saip_watch_t, remote,			"remote"),
	LSM_LIST	(saip_watch_t, rules, saip_rule_t, list,
			 NULL, lsm_saip_rule,			"rules"),
	LSM_LIST	(saip_watch_t, mirrors, saip_mirror_t, list,
			 NULL, lsm_saip_mirror,			"mirrors"),
};

static const lws_struct_map_t lsm_saip[] = {
	LSM_STRING_PTR	(saip_conf_t, user,			"user"),
	LSM_STRING_PTR	(saip_conf_t, repo_cache,		"repo-cache"),
	LSM_LIST	(saip_conf_t, watches, saip_watch_t, list,
			 NULL, lsm_saip_watch,			"watches"),
};

static const lws_struct_map_t lsm_saip_schema[] = {
	LSM_SCHEMA	(saip_conf_t, NULL, lsm_saip,		"sai-push"),
};

/*
 * Work out where to connect for the watch's feed.  It may be given as the
 * rss.xml url people know, but we want the same feed as JSON.  Only loopback
 * feeds may be plain http: we act on what the feed says, so it must come
 * from the sai we think it does.
 */
static int
saip_watch_feed_url(saip_watch_t *w)
{
	lws_parse_uri_t *u = lws_parse_uri_create(w->feed);
	size_t l;
	int bad;

	if (!u || !u->host[0] || u->unix_skt) {
		lwsl_err("%s: can't parse feed url %s\n", __func__, w->feed);
		lws_parse_uri_destroy(&u);
		return 1;
	}

	w->tls = !strcmp(u->scheme, "https");
	bad = !w->tls && (strcmp(u->scheme, "http") ||
			  (strcmp(u->host, "localhost") &&
			   strcmp(u->host, "127.0.0.1") &&
			   strcmp(u->host, "::1")));

	lws_strncpy(w->host, u->host, sizeof(w->host));
	w->port = u->port;
	lws_snprintf(w->path, sizeof(w->path), "/%s", u->path);
	lws_parse_uri_destroy(&u);

	if (bad) {
		lwsl_err("%s: feed %s must be https\n", __func__, w->feed);
		return 1;
	}

	l = strlen(w->path);
	if (l > 7 && !strcmp(w->path + l - 7, "rss.xml"))
		/* the same feed, as JSON */
		memcpy(w->path + l - 7, "rss.json", 9);
	else if (l < 8 || strcmp(w->path + l - 8, "rss.json")) {
		lwsl_err("%s: feed %s should end in rss.xml or rss.json\n",
			 __func__, w->feed);
		return 1;
	}

	return 0;
}

/*
 * Credentials go in a token file, never in the url, which gets logged
 */
static int
saip_url_has_credentials(const char *url)
{
	const char *p = strstr(url, "://"), *at, *sl;

	if (!p || (strncmp(url, "https://", 8) && strncmp(url, "http://", 7)))
		/* eg, git@host: for ssh, the user is not a secret */
		return 0;

	p += 3;
	at = strchr(p, '@');
	sl = strchr(p, '/');

	return at && (!sl || at < sl);
}

static int
saip_mirror_check(saip_mirror_t *m)
{
	struct stat s;

	if (!m->url || !m->url[0]) {
		lwsl_err("%s: each mirror needs a \"url\"\n", __func__);
		return 1;
	}

	if (saip_url_has_credentials(m->url)) {
		/* not logging the url, it has the secret in it */
		lwsl_err("%s: a mirror url has credentials in it: put them "
			 "in a \"token-file\"\n", __func__);
		return 1;
	}

	if (!m->token_file)
		return 0;

	if (m->token_file[0] != '/') {
		lwsl_err("%s: mirror %s: \"token-file\" must be an absolute "
			 "path\n", __func__, m->url);
		return 1;
	}

	if (stat(m->token_file, &s)) {
		lwsl_err("%s: mirror %s: can't stat %s: %s\n", __func__,
			 m->url, m->token_file, strerror(errno));
		return 1;
	}

	if (s.st_mode & 0007) {
		lwsl_err("%s: %s is readable by anyone, it should be readable "
			 "only by the sai-push user\n", __func__,
			 m->token_file);
		return 1;
	}

	return 0;
}

/*
 * lws_struct silently skips members its maps don't know, and a value of the
 * wrong type, eg, "force": "true", just doesn't set the member.  So a member
 * put in the wrong place, misspelled or given the wrong kind of value, would
 * leave part of the conf quietly unused.  Before parsing the conf for real,
 * walk it once checking every member against this list of where each one
 * belongs and what kind of value it takes.
 */

enum {
	SAIP_CT_STR,
	SAIP_CT_BOOL,
	SAIP_CT_LIST,
	SAIP_CT_OBJ,
	SAIP_CT_OTHER	/* numbers and null: nothing in the conf takes them */
};

static const char * const saip_ct_names[] = {
	"a string", "true or false", "a list, [ ... ]", "an object, { ... }",
	"a number or null"
};

static const struct saip_conf_member {
	const char		*path;
	uint8_t			type;
} saip_conf_members[] = {
	{ "schema",				SAIP_CT_STR },
	{ "user",				SAIP_CT_STR },
	{ "repo-cache",				SAIP_CT_STR },
	{ "watches",				SAIP_CT_LIST },
	{ "watches[]",				SAIP_CT_OBJ },
	{ "watches[].feed",			SAIP_CT_STR },
	{ "watches[].fetchurl",			SAIP_CT_STR },
	{ "watches[].remote",			SAIP_CT_STR },
	{ "watches[].rules",			SAIP_CT_LIST },
	{ "watches[].rules[]",			SAIP_CT_OBJ },
	{ "watches[].rules[].match",		SAIP_CT_STR },
	{ "watches[].rules[].branch-suffix",	SAIP_CT_STR },
	{ "watches[].rules[].force",		SAIP_CT_BOOL },
	{ "watches[].mirrors",			SAIP_CT_LIST },
	{ "watches[].mirrors[]",		SAIP_CT_OBJ },
	{ "watches[].mirrors[].url",		SAIP_CT_STR },
	{ "watches[].mirrors[].token-file",	SAIP_CT_STR },
};

typedef struct saip_conf_check {
	int			problems;
	uint8_t			schema_seen;
} saip_conf_check_t;

static const struct saip_conf_member *
saip_conf_member(const char *path)
{
	size_t n;

	for (n = 0; n < LWS_ARRAY_SIZE(saip_conf_members); n++)
		if (!strcmp(saip_conf_members[n].path, path))
			return &saip_conf_members[n];

	return NULL;
}

static const char *
saip_last_name(const char *path)
{
	const char *p = strrchr(path, '.');

	return p ? p + 1 : path;
}

static signed char
saip_conf_check_cb(struct lejp_ctx *ctx, char reason)
{
	saip_conf_check_t *cc = (saip_conf_check_t *)ctx->user;
	const struct saip_conf_member *m;
	char path[sizeof(ctx->path)], *dot;
	const char *name;
	size_t l, n;
	int got;

	lws_strncpy(path, ctx->path, sizeof(path));

	switch (reason) {
	case LEJPCB_PAIR_NAME:
		if (saip_conf_member(path))
			return 0;

		/*
		 * Only complain about the outermost unknown member, not
		 * everything inside it as well
		 */
		dot = strrchr(path, '.');
		if (dot) {
			*dot = '\0';
			if (!saip_conf_member(path))
				return 0;
		}

		name = saip_last_name(ctx->path);
		cc->problems++;

		/* is it a real member, just in the wrong place? */
		for (n = 0; n < LWS_ARRAY_SIZE(saip_conf_members); n++)
			if (!strcmp(saip_last_name(saip_conf_members[n].path),
				    name)) {
				lwsl_err("%s: line %d: \"%s\" doesn't belong "
					 "there (%s), it goes in %s\n", __func__,
					 ctx->line, name, ctx->path,
					 saip_conf_members[n].path);
				return 0;
			}

		lwsl_err("%s: line %d: unknown member \"%s\" (%s)\n", __func__,
			 ctx->line, name, ctx->path);
		return 0;

	case LEJPCB_VAL_STR_END:
		got = SAIP_CT_STR;
		if (!strcmp(path, "schema")) {
			cc->schema_seen = 1;
			if (strcmp(ctx->buf, "sai-push")) {
				lwsl_err("%s: line %d: \"schema\" must be "
					 "\"sai-push\"\n", __func__, ctx->line);
				cc->problems++;
			}
		}
		break;

	case LEJPCB_VAL_TRUE:
	case LEJPCB_VAL_FALSE:
		got = SAIP_CT_BOOL;
		break;

	case LEJPCB_VAL_NUM_INT:
	case LEJPCB_VAL_NUM_FLOAT:
	case LEJPCB_VAL_NULL:
		got = SAIP_CT_OTHER;
		break;

	case LEJPCB_ARRAY_START:
		/* the path already has the [] of the list's elements */
		l = strlen(path);
		if (l >= 2 && !strcmp(path + l - 2, "[]"))
			path[l - 2] = '\0';
		got = SAIP_CT_LIST;
		break;

	case LEJPCB_OBJECT_START:
		if (!path[0])
			return 0; /* the conf itself */
		got = SAIP_CT_OBJ;
		break;

	default:
		return 0;
	}

	m = saip_conf_member(path);
	if (!m || m->type == got)
		/* if it's unknown, we already said so at its name */
		return 0;

	lwsl_err("%s: line %d: \"%s\" (%s) should be %s, not %s\n", __func__,
		 ctx->line, saip_last_name(path), path,
		 saip_ct_names[m->type], saip_ct_names[got]);
	cc->problems++;

	return 0;
}

static int
saip_conf_check(const char *path)
{
	saip_conf_check_t cc;
	unsigned char buf[512];
	struct lejp_ctx ctx;
	int n, m = LEJP_CONTINUE, fd;

	memset(&cc, 0, sizeof(cc));

	fd = lws_open(path, O_RDONLY);
	if (fd < 0) {
		lwsl_err("%s: cannot open %s\n", __func__, path);
		return 1;
	}

	lejp_construct(&ctx, saip_conf_check_cb, &cc, NULL, 0);
	sai_lejp_enable_comments(&ctx);

	do {
		n = (int)read(fd, buf, sizeof(buf));
		if (n <= 0)
			break;
		m = lejp_parse(&ctx, buf, n);
	} while (m == LEJP_CONTINUE);

	close(fd);

	if (m < 0) {
		lwsl_err("%s: %s line %d: not valid JSON: %s\n", __func__, path,
			 ctx.line, lejp_error_to_string(m));
		cc.problems++;
	} else if (!cc.schema_seen) {
		lwsl_err("%s: %s needs \"schema\": \"sai-push\"\n", __func__,
			 path);
		cc.problems++;
	}

	lejp_destruct(&ctx);

	if (cc.problems)
		lwsl_err("%s: %d problem%s in %s, not starting\n", __func__,
			 cc.problems, cc.problems == 1 ? "" : "s", path);

	return !!cc.problems;
}

static int
saip_url_is_http(const char *url)
{
	return !strncmp(url, "https://", 8) || !strncmp(url, "http://", 7);
}

int
saip_conf_load(const char *path)
{
	unsigned char buf[512];
	lws_struct_args_t a;
	struct lejp_ctx ctx;
	int n, m = LEJP_CONTINUE, fd;
	saip_conf_t *c;

	if (saip_conf_check(path))
		return 1;

	memset(&a, 0, sizeof(a));
	a.map_st[0]		= lsm_saip_schema;
	a.map_entries_st[0]	= LWS_ARRAY_SIZE(lsm_saip_schema);
	a.ac_block_size		= 1024;

	fd = lws_open(path, O_RDONLY);
	if (fd < 0) {
		lwsl_err("%s: cannot open %s\n", __func__, path);
		return 1;
	}

	lws_struct_json_init_parse(&ctx, NULL, &a);
	sai_lejp_enable_comments(&ctx);

	do {
		n = (int)read(fd, buf, sizeof(buf));
		if (n <= 0)
			break;
		m = lejp_parse(&ctx, buf, n);
	} while (m == LEJP_CONTINUE);

	close(fd);

	if (m < 0 || !a.dest) {
		lwsl_err("%s: %s line %d: JSON decode failed '%s'\n", __func__,
			 path, ctx.line, lejp_error_to_string(m));
		lejp_destruct(&ctx);
		goto bail;
	}
	lejp_destruct(&ctx);

	c = (saip_conf_t *)a.dest;

	if (!c->repo_cache || c->repo_cache[0] != '/') {
		lwsl_err("%s: \"repo-cache\" must be an absolute path\n",
			 __func__);
		goto bail;
	}

	if (!c->watches.count) {
		lwsl_err("%s: no \"watches\"\n", __func__);
		goto bail;
	}

	lws_start_foreach_dll(struct lws_dll2 *, p, c->watches.head) {
		saip_watch_t *w = lws_container_of(p, saip_watch_t, list);

		if (!w->feed || !w->fetchurl || !w->remote ||
		    !w->rules.count) {
			lwsl_err("%s: each watch needs \"feed\", \"fetchurl\", "
				 "\"remote\" and \"rules\"\n", __func__);
			goto bail;
		}

		if (saip_watch_feed_url(w))
			goto bail;

		lws_start_foreach_dll(struct lws_dll2 *, q, w->rules.head) {
			saip_rule_t *r = lws_container_of(q, saip_rule_t, list);

			if (!r->branch_suffix || !r->branch_suffix[0]) {
				lwsl_err("%s: each rule needs a "
					 "\"branch-suffix\"\n", __func__);
				goto bail;
			}
			if (!r->match)
				r->match = "*";

			lwsl_notice("%s: %s: branches matching '%s' ending "
				    "'%s' go to the branch without it%s\n",
				    __func__, w->fetchurl, r->match,
				    r->branch_suffix,
				    r->force ? ", force pushed" : "");
		} lws_end_foreach_dll(q);

		if (saip_url_has_credentials(w->remote)) {
			/* not logging the url, it has the secret in it */
			lwsl_err("%s: the remote url for %s has credentials in "
				 "it\n", __func__, w->fetchurl);
			goto bail;
		}

		/*
		 * git won't be asked anything interactively, so over http(s)
		 * it can only push with credentials it already has from the
		 * user's own git config, or a mirror's token-file
		 */
		if (saip_url_is_http(w->remote))
			lwsl_warn("%s: %s: remote %s is http(s), which can't "
				  "push unless the user's git config has "
				  "credentials for it: use ssh\n", __func__,
				  w->fetchurl, w->remote);

		lwsl_notice("%s: %s: pushing to %s\n", __func__, w->fetchurl,
			    w->remote);

		lws_start_foreach_dll(struct lws_dll2 *, q, w->mirrors.head) {
			saip_mirror_t *mi = lws_container_of(q, saip_mirror_t,
							     list);

			if (saip_mirror_check(mi))
				goto bail;

			if (!mi->token_file && saip_url_is_http(mi->url))
				lwsl_warn("%s: %s: mirror %s is http(s) with no "
					  "\"token-file\", it can't push unless "
					  "the user's git config has "
					  "credentials for it: for github, use "
					  "ssh and a deploy key\n", __func__,
					  w->fetchurl, mi->url);

			lwsl_notice("%s: %s: mirrored to %s%s\n", __func__,
				    w->fetchurl, mi->url,
				    mi->token_file ? " (with token)" : "");
		} lws_end_foreach_dll(q);

		if (!w->mirrors.count)
			lwsl_notice("%s: %s: no mirrors\n", __func__,
				    w->fetchurl);

	} lws_end_foreach_dll(p);

	/* the parsed conf lives in its lwsac for as long as we run */

	saip.conf	= c;
	saip.ac_conf	= a.ac;

	return 0;

bail:
	lwsac_free(&a.ac);

	return 1;
}

/*
 * While we're still root: find the user we'll become, and make sure the repo
 * cache dir exists and belongs to them
 */
static int
saip_prepare_user(struct lws_context_creation_info *info)
{
	struct passwd *pw;

	if (geteuid()) {
		/* eg, testing by hand: we just carry on as whoever we are */
		pw = getpwuid(geteuid());
		if (saip.conf->user && (!pw || strcmp(pw->pw_name, saip.conf->user)))
			lwsl_warn("%s: not root, so staying as uid %u, not "
				  "becoming \"%s\"\n", __func__,
				  (unsigned int)geteuid(), saip.conf->user);
	} else {
		if (!saip.conf->user) {
			lwsl_err("%s: started as root, the conf must give the "
				 "\"user\" to run as\n", __func__);
			return 1;
		}

		pw = getpwnam(saip.conf->user);
		if (!pw || !pw->pw_uid) {
			lwsl_err("%s: user \"%s\" unknown, or is root\n",
				 __func__, saip.conf->user);
			return 1;
		}

		/* lws drops to this in lws_create_context() */
		info->username = saip.conf->user;
	}

	if (!pw) {
		lwsl_err("%s: can't find our own user\n", __func__);
		return 1;
	}

	/* git and ssh in the children find config and keys under here */
	lws_strncpy(saip.home, pw->pw_dir, sizeof(saip.home));

	if (mkdir(saip.conf->repo_cache, 0700) && errno != EEXIST) {
		lwsl_err("%s: can't create %s: %s\n", __func__,
			 saip.conf->repo_cache, strerror(errno));
		return 1;
	}

	if (!geteuid() && chown(saip.conf->repo_cache, pw->pw_uid, pw->pw_gid)) {
		lwsl_err("%s: can't chown %s: %s\n", __func__,
			 saip.conf->repo_cache, strerror(errno));
		return 1;
	}

	return 0;
}

static void
sigint_handler(int sig)
{
	interrupted = 1;
}

/*
 * git runs us as its GIT_ASKPASS for a mirror with a token file, with the
 * prompt as the argument and SAI_PUSH_TOKEN_FILE in the environment: we
 * answer a username prompt with a placeholder (github ignores it for token
 * auth) and a password prompt with the token, on stdout.
 */
int
saip_askpass(const char *prompt)
{
	const char *path = getenv("SAI_PUSH_TOKEN_FILE");
	char tok[512], *t = tok;
	ssize_t r;
	size_t n;
	int fd;

	if (!strncmp(prompt, "Username", 8)) {
		if (write(1, "x-access-token\n", 15) != 15)
			return 1;
		return 0;
	}

	fd = lws_open(path, O_RDONLY);
	if (fd < 0)
		return 1;
	r = read(fd, tok, sizeof(tok) - 1);
	close(fd);
	if (r <= 0)
		return 1;
	n = (size_t)r;	/* leaves room for the '\n' */

	/* just the token, whatever whitespace was around it in the file */
	while (n && (tok[n - 1] == '\n' || tok[n - 1] == '\r' ||
		     tok[n - 1] == ' ' || tok[n - 1] == '\t'))
		n--;
	while (n && (*t == '\n' || *t == '\r' || *t == ' ' || *t == '\t')) {
		t++;
		n--;
	}
	if (!n)
		return 1;
	t[n++] = '\n';

	return write(1, t, n) != (ssize_t)n;
}

static int
saip_any_token_files(void)
{
	lws_start_foreach_dll(struct lws_dll2 *, q, saip.conf->watches.head) {
		saip_watch_t *w = lws_container_of(q, saip_watch_t, list);

		lws_start_foreach_dll(struct lws_dll2 *, p, w->mirrors.head) {
			if (lws_container_of(p, saip_mirror_t,
					     list)->token_file)
				return 1;
		} lws_end_foreach_dll(p);
	} lws_end_foreach_dll(q);

	return 0;
}

/* now we're the push user, it must be able to read its tokens */

static int
saip_check_token_access(void)
{
	lws_start_foreach_dll(struct lws_dll2 *, q, saip.conf->watches.head) {
		saip_watch_t *w = lws_container_of(q, saip_watch_t, list);

		lws_start_foreach_dll(struct lws_dll2 *, p, w->mirrors.head) {
			saip_mirror_t *m = lws_container_of(p, saip_mirror_t,
							    list);

			if (m->token_file && access(m->token_file, R_OK)) {
				lwsl_err("%s: can't read %s as uid %u\n",
					 __func__, m->token_file,
					 (unsigned int)getuid());
				return 1;
			}
		} lws_end_foreach_dll(p);
	} lws_end_foreach_dll(q);

	return 0;
}

int
main(int argc, const char **argv)
{
	const char *p, *conf = "/etc/sai/push/conf";
	struct lws_context_creation_info info;

	/* git asking us for a token: answer and go, before anything else */
	if (argc == 2 && getenv("SAI_PUSH_TOKEN_FILE"))
		return saip_askpass(argv[1]);

	memset(&info, 0, sizeof(info));
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	lwsl_user("Sai Push - Copyright (C) 2026 Andy Green <andy@warmcat.com>\n");
	lwsl_user("   sai-push [-c <conf file>]\n");

	if ((p = lws_cmdline_option(argc, argv, "-c")))
		conf = p;

	if (saip_conf_load(conf))
		return 1;

	if (saip_prepare_user(&info))
		goto bail;

	if (saip_state_load())
		goto bail;

	/* git runs us again as its askpass, it needs our full path */
	if (saip_any_token_files()) {
		char rp[PATH_MAX];

		if ((!realpath("/proc/self/exe", rp) &&
		     !realpath(argv[0], rp)) ||
		    strlen(rp) >= sizeof(saip.self)) {
			lwsl_err("%s: can't find our own path for "
				 "GIT_ASKPASS\n", __func__);
			goto bail;
		}
		lws_strncpy(saip.self, rp, sizeof(saip.self));
	}

	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

	/*
	 * Not explicit vhosts, so lws drops to info.username inside
	 * lws_create_context(), before we open any connection
	 */
	info.port		= CONTEXT_PORT_NO_LISTEN;
	info.pprotocols		= pprotocols;
	info.options		= LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	/*
	 * lws' own fds, a feed connection per watch, and the three stdio
	 * pipes of the one git child at a time
	 */
	info.fd_limit_per_thread = 32 + (unsigned int)saip.conf->watches.count;

	saip.cx = lws_create_context(&info);
	if (!saip.cx) {
		lwsl_err("%s: lws init failed\n", __func__);
		goto bail;
	}
	saip.vh = lws_get_vhost_by_name(saip.cx, "default");

	if (saip_check_token_access())
		goto bail_cx;

	lws_start_foreach_dll(struct lws_dll2 *, q, saip.conf->watches.head) {
		saip_feed_start(lws_container_of(q, saip_watch_t, list));
	} lws_end_foreach_dll(q);

	while (!lws_service(saip.cx, 0) && !interrupted)
		;

bail_cx:
	lws_context_destroy(saip.cx);

bail:
	lws_start_foreach_dll_safe(struct lws_dll2 *, q, q1, saip.jobs.head) {
		lws_dll2_remove(q);
		free(lws_container_of(q, saip_job_t, list));
	} lws_end_foreach_dll_safe(q, q1);

	lws_start_foreach_dll(struct lws_dll2 *, q, saip.conf->watches.head) {
		saip_watch_t *w = lws_container_of(q, saip_watch_t, list);

		lwsac_free(&w->a.ac);
		lws_start_foreach_dll_safe(struct lws_dll2 *, t, t1,
					   w->targets.head) {
			lws_dll2_remove(t);
			free(lws_container_of(t, saip_target_t, list));
		} lws_end_foreach_dll_safe(t, t1);
	} lws_end_foreach_dll(q);

	lwsac_free(&saip.ac_conf);

	return 0;
}
