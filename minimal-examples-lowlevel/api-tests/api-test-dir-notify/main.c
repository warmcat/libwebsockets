/*
 * lws-api-test-dir-notify
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * A directory monitor must report a change made in the directory straight
 * after lws_dir_notify_create() returned, before the event loop has run at
 * all: a user, eg, the tls cert watch, may look at what is in the directory,
 * then start watching it, and must not miss a change made after that.
 *
 * Each step creates a new file in the watched directory (a new entry is a
 * change every platform's monitor reports, kqueue included), and must be told
 * about it within STEP_US:
 *
 *  - a file created before the loop has run, straight after the monitor was
 *    created
 *  - a file created from the loop, after the first was reported
 */

#include <libwebsockets.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <signal.h>

#if defined(WIN32)
#include <direct.h>
#define mkdir(x,y) _mkdir(x)
#define rmdir(x) _rmdir(x)
#else
#include <unistd.h>
#endif

#define WATCHED		"dir-notify-test"
#define STEP_US		(5 * LWS_US_PER_SEC)

static const char * const steps[] = {
	"created straight after the monitor",
	"created from the loop",
};

static struct lws_context *context;
static struct lws_dir_notify *dn;
static lws_sorted_usec_list_t sul_step, sul_timeout;
static int result = 1, cur, seen;

static void
sigint_handler(int sig)
{
	(void)sig;
	lws_default_loop_exit(context);
}

/* make the current step's file in the watched directory */

static int
step_write(void)
{
	char path[64], c = 'x';

	seen = 0;
	lws_snprintf(path, sizeof(path), WATCHED "/f%d", cur);
	if (lws_plat_write_file(path, &c, 1)) {
		lwsl_err("%s: can't write %s\n", __func__, path);
		return 1;
	}

	return 0;
}

static void
timeout_cb(lws_sorted_usec_list_t *sul)
{
	lwsl_err("--- %s: FAIL: not reported ---\n", steps[cur]);
	lws_default_loop_exit(context);
}

static void
next_step_cb(lws_sorted_usec_list_t *sul)
{
	if (++cur == (int)LWS_ARRAY_SIZE(steps)) {
		lwsl_user("--- all steps passed ---\n");
		result = 0;
		lws_sul_cancel(&sul_timeout);
		lws_default_loop_exit(context);
		return;
	}

	if (step_write()) {
		lws_default_loop_exit(context);
		return;
	}

	lws_sul_schedule(context, 0, &sul_timeout, timeout_cb, STEP_US);
}

static void
notify_cb(const char *name, int is_file, void *user)
{
	char want[8];

	(void)is_file;
	(void)user;

	/* where the platform can't say which entry changed, the name is "" */
	lws_snprintf(want, sizeof(want), "f%d", cur);
	if (seen || (*name && strcmp(name, want)))
		return;
	seen = 1;

	lwsl_user("--- %s: reported as '%s': PASS ---\n", steps[cur], name);

	/* the next step is made from the loop, not from inside the callback */
	lws_sul_schedule(context, 0, &sul_step, next_step_cb, 1);
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	int n = 0;

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	info.port = CONTEXT_PORT_NO_LISTEN;

	signal(SIGINT, sigint_handler);
	lwsl_user("LWS API selftest: dir notify\n");

	/* a previous run's files would be no change, empty the dir */
	lws_dir(WATCHED, NULL, lws_dir_rm_rf_cb);
	if (mkdir(WATCHED, 0700) && errno != EEXIST) {
		lwsl_err("can't make " WATCHED "\n");
		return 1;
	}

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	dn = lws_dir_notify_create(context, WATCHED, notify_cb, NULL);
	if (!dn) {
		lwsl_err("can't watch " WATCHED "\n");
		goto bail;
	}

	/* no chance for the loop to run before this change */
	if (step_write())
		goto bail;
	lws_sul_schedule(context, 0, &sul_timeout, timeout_cb, STEP_US);

	while (n >= 0)
		n = lws_service(context, 0);

bail:
	lws_sul_cancel(&sul_step);
	lws_sul_cancel(&sul_timeout);
	lws_dir_notify_destroy(&dn);
	lws_context_destroy(context);
	lws_dir(WATCHED, NULL, lws_dir_rm_rf_cb);
	rmdir(WATCHED);

	lwsl_user("Completed: %s\n", result ? "FAIL" : "PASS");

	return result;
}
