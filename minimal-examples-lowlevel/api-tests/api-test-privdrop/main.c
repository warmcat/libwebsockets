/*
 * lws-api-test-privdrop
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Tests for dropping the process's privileges to the uid / gid given in the
 * context creation info.  Most of it runs as any user:
 *
 *  - a uid, gid, user or group that does not exist fails context creation,
 *    with or without LWS_SERVER_OPTION_EXPLICIT_VHOSTS (where the drop itself
 *    only happens later, so the target must be checked up front)
 *
 *  - asking to run as the uid / gid we already run as, unprivileged, is not
 *    a failure, and lws_finalize_startup() may be called more than once
 *
 *  - if the deferred drop of an EXPLICIT_VHOSTS context fails while it is
 *    being serviced, the process exits rather than carry on (forced with
 *    fault injection, so only in LWS_WITH_SYS_FAULT_INJECTION builds)
 *
 * Run as root, it also has a child really drop to "nobody" through the loop,
 * and confirm it has that user's credentials and cannot get root back.
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/wait.h>

enum {
	LWS_SW_D,
	LWS_SW_HELP,
};

static const struct lws_switches switches[] = {
	[LWS_SW_D]	= { "-d",		"Debug logs (e.g. -d 15)" },
	[LWS_SW_HELP]	= { "--help",		"Show this help information" },
};

#define PDT_CHILD_SERVICE_MS	3000

static lws_sorted_usec_list_t sul_deadline;
static struct lws_context *child_cx;
static int deadline_hit;

static void
init_info(struct lws_context_creation_info *info, int explicit_vhosts)
{
	if (explicit_vhosts)
		lws_context_info_defaults(info, NULL);
	else
		memset(info, 0, sizeof(*info));

	info->port = CONTEXT_PORT_NO_LISTEN;
}

/* a uid / gid nothing on this system is using */

static uid_t
missing_uid(void)
{
	uid_t u = (uid_t)3999999999u;

	while (getpwuid(u))
		u--;

	return u;
}

static gid_t
missing_gid(void)
{
	gid_t g = (gid_t)3999999999u;

	while (getgrgid(g))
		g--;

	return g;
}

/* context creation is expected to fail */

static int
expect_create_fails(const char *what, struct lws_context_creation_info *info)
{
	struct lws_context *cx = lws_create_context(info);

	if (!cx) {
		lwsl_user("%s: %s: creation failed as expected\n", __func__,
			  what);

		return 0;
	}

	lwsl_err("%s: %s: context created\n", __func__, what);
	lws_context_destroy(cx);

	return 1;
}

static int
test_missing_targets(void)
{
	struct lws_context_creation_info info;
	int e = 0, ev;

	for (ev = 0; ev < 2; ev++) {
		init_info(&info, ev);
		info.uid = missing_uid();
		e += expect_create_fails(ev ? "missing uid, explicit vhosts" :
					      "missing uid", &info);

		init_info(&info, ev);
		info.gid = missing_gid();
		e += expect_create_fails(ev ? "missing gid, explicit vhosts" :
					      "missing gid", &info);

		init_info(&info, ev);
		info.username = "lws-api-test-no-such-user";
		e += expect_create_fails(ev ? "missing user, explicit vhosts" :
					      "missing user", &info);

		init_info(&info, ev);
		info.groupname = "lws-api-test-no-such-group";
		e += expect_create_fails(ev ? "missing group, explicit vhosts" :
					      "missing group", &info);
	}

	return e;
}

/*
 * Unprivileged, asked to become who we already are: nothing to drop, and
 * that is not a failure
 */

static int
test_already_target(void)
{
	struct lws_context_creation_info info;
	struct lws_context *cx;
	uid_t u = getuid();
	gid_t g = getgid();
	int e = 0;

	if (!geteuid() || !u) {
		lwsl_user("%s: running as root, skipping\n", __func__);

		return 0;
	}

	if (!getpwuid(u) || !getgrgid(g)) {
		/* eg, a container run with an arbitrary numeric uid */
		lwsl_user("%s: our uid / gid has no entry, skipping\n",
			  __func__);

		return 0;
	}

	init_info(&info, 1);
	info.uid = u;
	info.gid = g;

	cx = lws_create_context(&info);
	if (!cx) {
		lwsl_err("%s: context creation failed\n", __func__);

		return 1;
	}

	/* the second call must find it done, not try it again */

	if (lws_finalize_startup(cx, __func__) ||
	    lws_finalize_startup(cx, __func__)) {
		lwsl_err("%s: lws_finalize_startup() failed\n", __func__);
		e = 1;
	}

	if (getuid() != u || geteuid() != u || getgid() != g ||
	    getegid() != g) {
		lwsl_err("%s: credentials changed\n", __func__);
		e = 1;
	}

	lws_context_destroy(cx);

	return e;
}

static void
deadline_cb(lws_sorted_usec_list_t *sul)
{
	(void)sul;

	deadline_hit = 1;
	lws_cancel_service(child_cx);
}

/*
 * In a child: create an EXPLICIT_VHOSTS context from info and service it for
 * a while, so its protocols init and the deferred privilege drop happens from
 * the loop, as it does in lwsws.  Returns only if the child survived that.
 */

static int
child_service(struct lws_context_creation_info *info)
{
	child_cx = lws_create_context(info);
	if (!child_cx) {
		lwsl_err("%s: child context creation failed\n", __func__);

		return 1;
	}

	lws_sul_schedule(child_cx, 0, &sul_deadline, deadline_cb,
			 PDT_CHILD_SERVICE_MS * LWS_US_PER_MS);

	while (!deadline_hit && lws_service(child_cx, 0) >= 0)
		;

	lws_sul_cancel(&sul_deadline);
	lws_context_destroy(child_cx);

	return 0;
}

static int
wait_child(pid_t pid, int *status)
{
	while (waitpid(pid, status, 0) < 0)
		if (errno != EINTR)
			return 1;

	return 0;
}

#if defined(LWS_WITH_SYS_FAULT_INJECTION)

/*
 * The deferred drop fails while the loop is running: the child must exit with
 * status 1 rather than carry on serving
 */

static int
test_deferred_failure_exits(void)
{
	struct lws_context_creation_info info;
	int status;
	pid_t pid;

	pid = fork();
	if (pid < 0)
		return 1;

	if (!pid) {
		lws_fi_t fi = { .name = "ctx_privdrop_finalize",
				.type = LWSFI_ALWAYS };

		init_info(&info, 1);
		lws_fi_add(&info.fic, &fi);

		child_service(&info);

		/* we should never get here */
		lwsl_err("%s: child survived failed drop\n", __func__);
		_exit(0);
	}

	if (wait_child(pid, &status))
		return 1;

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 1) {
		lwsl_err("%s: child status 0x%x, expected exit 1\n", __func__,
			 status);

		return 1;
	}

	lwsl_user("%s: child exited on failed drop as expected\n", __func__);

	return 0;
}
#endif

/*
 * Only as root: a child really drops to "nobody" from the loop, and must
 * end up with nobody's credentials and no way back to root
 */

static int
test_real_drop(void)
{
	struct lws_context_creation_info info;
	struct passwd *pw;
	int status;
	pid_t pid;

	if (geteuid()) {
		lwsl_user("%s: not root, skipping\n", __func__);

		return 0;
	}

	pw = getpwnam("nobody");
	if (!pw || !pw->pw_uid) {
		lwsl_user("%s: no user 'nobody', skipping\n", __func__);

		return 0;
	}

	pid = fork();
	if (pid < 0)
		return 1;

	if (!pid) {
		uid_t u = pw->pw_uid;
		gid_t g = pw->pw_gid, groups[64];
		int n, ng;

		init_info(&info, 1);
		info.username = "nobody";

		if (child_service(&info))
			_exit(2);

		if (getuid() != u || geteuid() != u ||
		    getgid() != g || getegid() != g) {
			lwsl_err("%s: child has uid %u / %u, gid %u / %u\n",
				 __func__, (unsigned int)getuid(),
				 (unsigned int)geteuid(),
				 (unsigned int)getgid(),
				 (unsigned int)getegid());
			_exit(3);
		}

		if (!setuid(0)) {
			lwsl_err("%s: child could get root back\n", __func__);
			_exit(4);
		}

		ng = getgroups((int)LWS_ARRAY_SIZE(groups), groups);
		if (ng < 0)
			_exit(5);

		for (n = 0; n < ng; n++)
			if (!groups[n] && g) {
				lwsl_err("%s: child kept group 0\n", __func__);
				_exit(6);
			}

		_exit(0);
	}

	if (wait_child(pid, &status))
		return 1;

	if (!WIFEXITED(status) || WEXITSTATUS(status)) {
		lwsl_err("%s: child status 0x%x\n", __func__, status);

		return 1;
	}

	lwsl_user("%s: child dropped to nobody\n", __func__);

	return 0;
}

int
main(int argc, const char **argv)
{
	const char *p;
	int e = 0;

	if (lws_cmdline_option(argc, argv, switches[LWS_SW_HELP].sw)) {
		lws_switches_print_help(argv[0], switches,
					LWS_ARRAY_SIZE(switches));
		return 0;
	}

	p = lws_cmdline_option(argc, argv, switches[LWS_SW_D].sw);
	lws_set_log_level(p ? atoi(p) : LLL_USER | LLL_ERR | LLL_WARN, NULL);

	lwsl_user("LWS API selftest: privilege drop\n");

	e += test_missing_targets();
	e += test_already_target();
#if defined(LWS_WITH_SYS_FAULT_INJECTION)
	e += test_deferred_failure_exits();
#else
	lwsl_user("no fault injection, skipping deferred failure test\n");
#endif
	e += test_real_drop();

	lwsl_user("Completed: %s\n", e ? "FAIL" : "PASS");

	return !!e;
}
