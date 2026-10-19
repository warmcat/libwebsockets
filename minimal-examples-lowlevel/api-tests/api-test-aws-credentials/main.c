/*
 * lws-api-test-aws-credentials
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * lws_aws_filesystem_credentials_helper() reads an AWS key id and secret
 * access key from a credentials file.  Each case here writes a file, reads
 * it back with the helper and checks what comes out.  All the while every
 * log line is captured, at every level the build has: the secret must never
 * appear in one (G-345).
 */

#include <libwebsockets.h>
#include <string.h>

#define KID	"aws_access_key_id"
#define AK	"aws_secret_access_key"

/* the secrets in the files below all start with this */
#define SECRET_MARK "SeCrEt"

static const struct tcase {
	const char	*name;
	const char	*content;	/* NULL: no file at all */
	const char	*keyid;		/* NULL: the helper must fail */
	const char	*key;
} cases[] = {
	{ "plain",
	  "[default]\n"
	  KID " = AKIDPLAIN\n"
	  AK " = " SECRET_MARK "plain/+=0\n",
	  "AKIDPLAIN", SECRET_MARK "plain/+=0" },

	{ "crlf, padding, no final newline",
	  "[default]\r\n"
	  AK "=   " SECRET_MARK "crlf  \r\n"
	  KID "=AKIDCRLF  ",
	  "AKIDCRLF", SECRET_MARK "crlf" },

	{ "the first profile wins",
	  "[default]\n"
	  KID " = AKIDFIRST\n"
	  AK " = " SECRET_MARK "first\n"
	  "[other]\n"
	  KID " = AKIDSECOND\n"
	  AK " = " SECRET_MARK "second\n",
	  "AKIDFIRST", SECRET_MARK "first" },

	{ "no secret",
	  "[default]\n"
	  KID " = AKIDLONELY\n",
	  NULL, NULL },

	{ "no key id",
	  "[default]\n"
	  AK " = " SECRET_MARK "lonely\n",
	  NULL, NULL },

	{ "no '='",
	  "[default]\n"
	  KID " AKIDNOEQ\n"
	  AK " " SECRET_MARK "noeq\n",
	  NULL, NULL },

	{ "no file", NULL, NULL, NULL },
};

static int leaks;

static void
emit(int level, const char *line)
{
	if (strstr(line, SECRET_MARK)) {
		char m[64];

		/* don't emit it either: say which level, and that's all */
		lws_snprintf(m, sizeof(m), "LEAK: secret logged at level 0x%x\n",
			     level);
		lwsl_emit_stderr(LLL_ERR, m);
		leaks++;
		return;
	}

	lwsl_emit_stderr(level, line);
}

static int
check(const char *dir, const struct tcase *c)
{
	char path[256], *keyid = (char *)"x", *key = (char *)"x";
	int n, fail = 0;

	lws_snprintf(path, sizeof(path), "%s/aws-creds-%d", dir,
		     (int)(c - cases));

	if (c->content &&
	    lws_plat_write_file(path, (void *)c->content, strlen(c->content))) {
		lwsl_err("%s: can't write %s\n", __func__, path);
		return 1;
	}

	n = lws_aws_filesystem_credentials_helper(path, KID, AK, &keyid, &key);

	if (!c->keyid) {
		if (!n || keyid || key) {
			lwsl_err("%s: '%s': must fail and allocate nothing\n",
				 __func__, c->name);
			fail = 1;
		}
	} else if (n || !keyid || !key || strcmp(keyid, c->keyid) ||
		   strcmp(key, c->key)) {
		lwsl_err("%s: '%s': wrong result %d, key id '%s'\n", __func__,
			 c->name, n, keyid ? keyid : "(none)");
		fail = 1;
	}

	if (!n) {
		free(keyid);
		free(key);
	}

	lwsl_user("%s: '%s': %s\n", __func__, c->name, fail ? "FAIL" : "pass");

	return fail;
}

/* a file bigger than the helper reads is refused, not truncated */
static int
check_oversize(const char *dir)
{
	char path[256], *keyid = NULL, *key = NULL, *big;
	size_t len = 32768;
	int n;

	big = malloc(len);
	if (!big)
		return 1;

	memset(big, '#', len);
	/* real credentials at the start, so only the size can refuse it */
	memcpy(big, KID "=AKIDBIG\n" AK "=" SECRET_MARK "big\n",
	       strlen(KID "=AKIDBIG\n" AK "=" SECRET_MARK "big\n"));

	lws_snprintf(path, sizeof(path), "%s/aws-creds-big", dir);
	n = lws_plat_write_file(path, big, len);
	free(big);
	if (n) {
		lwsl_err("%s: can't write %s\n", __func__, path);
		return 1;
	}

	n = lws_aws_filesystem_credentials_helper(path, KID, AK, &keyid, &key);
	if (!n || keyid || key) {
		lwsl_err("%s: oversize file was accepted\n", __func__);
		if (!n) {
			free(keyid);
			free(key);
		}
		return 1;
	}

	lwsl_user("%s: 'oversize': pass\n", __func__);

	return 0;
}

/* a path the helper can't hold is refused, not truncated to another file */
static int
check_long_path(void)
{
	char path[1024], *keyid = NULL, *key = NULL;
	int n;

	memset(path, 'a', sizeof(path) - 1);
	path[sizeof(path) - 1] = '\0';

	n = lws_aws_filesystem_credentials_helper(path, KID, AK, &keyid, &key);
	if (!n || keyid || key) {
		lwsl_err("%s: overlong path was accepted\n", __func__);
		if (!n) {
			free(keyid);
			free(key);
		}
		return 1;
	}

	lwsl_user("%s: 'long path': pass\n", __func__);

	return 0;
}

int
main(int argc, const char **argv)
{
	const char *dir = ".";
	int fails = 0;
	size_t n;

	/* every level the build has, so a leak at any of them is caught */
	lws_set_log_level(LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE |
			  LLL_INFO | LLL_DEBUG, emit);

	if (lws_cmdline_option(argc, argv, "-h")) {
		lwsl_user("Usage: %s [--dir <writable dir>]\n", argv[0]);
		return 0;
	}

	if (lws_cmdline_option(argc, argv, "--dir"))
		dir = lws_cmdline_option(argc, argv, "--dir");

	lwsl_user("LWS API test: aws credentials file helper\n");

	for (n = 0; n < LWS_ARRAY_SIZE(cases); n++)
		fails += check(dir, &cases[n]);

	fails += check_oversize(dir);
	fails += check_long_path();

	if (leaks)
		lwsl_err("%d log lines carried the secret\n", leaks);

	lwsl_user("Completed: %s\n", fails || leaks ? "FAIL" : "PASS");

	return fails || leaks;
}
