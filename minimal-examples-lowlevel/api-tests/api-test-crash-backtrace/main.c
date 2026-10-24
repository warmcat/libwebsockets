/*
 * lws-api-test-crash-backtrace
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * lws_crash_backtrace_install() makes a process that crashes write its call
 * stack to stderr, then still die of the signal.  Each case is a child that
 * crashes, with its stderr on a pipe we read:
 *
 *  - segv: raise(SIGSEGV) must print the backtrace and die of SIGSEGV
 *
 *  - abort: abort(), as a failed assert() does, the same with SIGABRT
 *
 *  - app: a SIGSEGV handler the application installed first must still be
 *    the one that runs, with nothing printed by lws
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#define CBT_MARK_START		"*** lws: fatal signal "
#define CBT_MARK_END		"*** lws: end of backtrace"
#define CBT_APP_EXIT		3

enum {
	CBT_SEGV,
	CBT_ABORT,
	CBT_APP,
};

static const char *cbt_names[] = { "segv", "abort", "app" };

static void
cbt_app_handler(int sig)
{
	static const char m[] = "app handler\n";

	(void)sig;

	if (write(2, m, sizeof(m) - 1) < 0)
		_exit(CBT_APP_EXIT + 1);
	_exit(CBT_APP_EXIT);
}

/* the child: never returns */

static void
cbt_crash(int c)
{
	if (c == CBT_APP)
		signal(SIGSEGV, cbt_app_handler);

	if (lws_crash_backtrace_install()) {
		fprintf(stderr, "install failed\n");
		_exit(1);
	}

	if (c == CBT_ABORT)
		abort();

	raise(SIGSEGV);

	_exit(1); /* SIGSEGV should not return here */
}

/*
 * Run case c in a child, collecting what it wrote to stderr in buf.  Returns
 * the child's wait status, or -1.
 */

static int
cbt_run(int c, char *buf, size_t len)
{
	size_t used = 0;
	int pfd[2], st;
	ssize_t r;
	pid_t pid;

	if (pipe(pfd))
		return -1;

	pid = fork();
	if (pid < 0) {
		close(pfd[0]);
		close(pfd[1]);
		return -1;
	}

	if (!pid) {
		close(pfd[0]);
		if (dup2(pfd[1], 2) < 0)
			_exit(1);
		close(pfd[1]);
		cbt_crash(c);
	}

	close(pfd[1]);
	while (used < len - 1) {
		r = read(pfd[0], buf + used, len - 1 - used);
		if (r <= 0)
			break;
		used += (size_t)r;
	}
	buf[used] = '\0';
	close(pfd[0]);

	if (waitpid(pid, &st, 0) != pid)
		return -1;

	return st;
}

/* the backtrace is there, for signal sig, with at least one frame in it */

static int
cbt_check_bt(const char *buf, int sig)
{
	const char *s, *e;
	char mark[48];

	lws_snprintf(mark, sizeof(mark), CBT_MARK_START "%d,", sig);
	s = strstr(buf, mark);
	e = strstr(buf, CBT_MARK_END);
	if (!s || !e || e < s) {
		lwsl_err("no backtrace for signal %d\n", sig);
		return 1;
	}

	s = strchr(s, '\n');
	if (!s || s + 1 >= e) {
		lwsl_err("a backtrace with no frames\n");
		return 1;
	}

	return 0;
}

int main(int argc, const char **argv)
{
	struct lws_context_creation_info info;
	int c, st, sig, fails = 0;
	char buf[16384];

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	lwsl_user("LWS API selftest: crash backtraces\n");

	for (c = CBT_SEGV; c <= CBT_APP; c++) {
		st = cbt_run(c, buf, sizeof(buf));
		lwsl_user("=== %s: the child wrote ===\n%s", cbt_names[c], buf);

		if (st < 0) {
			lwsl_err("%s: FAIL: couldn't run the child\n",
				 cbt_names[c]);
			fails++;
			continue;
		}

		if (c == CBT_APP) {
			if (!WIFEXITED(st) || WEXITSTATUS(st) != CBT_APP_EXIT ||
			    strstr(buf, CBT_MARK_START)) {
				lwsl_err("%s: FAIL: the app's handler didn't "
					 "have it to itself\n", cbt_names[c]);
				fails++;
				continue;
			}
			lwsl_user("%s: PASS\n", cbt_names[c]);
			continue;
		}

		sig = c == CBT_ABORT ? SIGABRT : SIGSEGV;
		if (!WIFSIGNALED(st) || WTERMSIG(st) != sig) {
			lwsl_err("%s: FAIL: didn't die of signal %d\n",
				 cbt_names[c], sig);
			fails++;
			continue;
		}
		if (cbt_check_bt(buf, sig)) {
			lwsl_err("%s: FAIL\n", cbt_names[c]);
			fails++;
			continue;
		}
		lwsl_user("%s: PASS\n", cbt_names[c]);
	}

	lwsl_user("Completed: %s\n", fails ? "FAIL" : "PASS");

	return !!fails;
}
