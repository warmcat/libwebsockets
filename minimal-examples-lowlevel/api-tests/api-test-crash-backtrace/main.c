/*
 * lws-api-test-crash-backtrace
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * lws_crash_backtrace_install() makes a process that crashes write its call
 * stack to stderr, then still die as it would have.  Each case runs us again
 * as a child, with --crash <case>, that crashes, with its stderr on a pipe we
 * read:
 *
 *  - segv: a fault must print the backtrace and still kill the child: on
 *    posix raise(SIGSEGV), on windows an access violation exception
 *
 *  - abort: abort(), as a failed assert() does, the same with SIGABRT, which
 *    on windows exits with code 3
 *
 *  - app: a handler the application installed first, for SIGSEGV on posix or
 *    the unhandled exception filter on windows, must still be the one that
 *    runs, with nothing printed by lws
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#if defined(WIN32)
#include <windows.h>
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#endif

#define CBT_MARK_START		"*** lws: fatal "
#define CBT_MARK_END		"*** lws: end of backtrace"
#define CBT_APP_EXIT		3

enum {
	CBT_SEGV,
	CBT_ABORT,
	CBT_APP,

	CBT_COUNT
};

static const char *cbt_names[] = { "segv", "abort", "app" };

/* how a child ended */

typedef struct {
	int		signalled;	/* posix: died of a signal */
	unsigned long	code;		/* the signal, or the exit code */
} cbt_end_t;

/* the child */

#if defined(WIN32)
static LONG WINAPI
cbt_app_filter(EXCEPTION_POINTERS *ep)
{
	(void)ep;
	fprintf(stderr, "app handler\n");
	fflush(stderr);
	_exit(CBT_APP_EXIT);
}
#else
static void
cbt_app_handler(int sig)
{
	static const char m[] = "app handler\n";

	(void)sig;

	if (write(2, m, sizeof(m) - 1) < 0)
		_exit(CBT_APP_EXIT + 1);
	_exit(CBT_APP_EXIT);
}
#endif

static int
cbt_crash(int c)
{
#if defined(WIN32)
	/* no error dialogs, no waiting for anybody to see them */
	SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
#if defined(_MSC_VER)
	_set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#endif
	if (c == CBT_APP)
		SetUnhandledExceptionFilter(cbt_app_filter);
#else
	if (c == CBT_APP)
		signal(SIGSEGV, cbt_app_handler);
	else {
		/*
		 * Start from the default actions, as a plain process does.
		 * A sanitizer's runtime has already put its own handler on
		 * SIGSEGV, which lws must leave alone like the application's
		 * one in CBT_APP, and the child would die of its report
		 */
		signal(SIGSEGV, SIG_DFL);
		signal(SIGABRT, SIG_DFL);
	}
#endif

	if (lws_crash_backtrace_install()) {
		fprintf(stderr, "install failed\n");
		return 1;
	}

	if (c == CBT_ABORT)
		abort();

#if defined(WIN32)
	RaiseException(EXCEPTION_ACCESS_VIOLATION, EXCEPTION_NONCONTINUABLE,
		       0, NULL);
#else
	raise(SIGSEGV);
#endif

	return 1; /* the crash should not return here */
}

/*
 * Run us again as a child for case c, collecting what it wrote to stderr in
 * buf, and how it ended in *end.  Returns 0, or 1 if it couldn't be run.
 */

#if defined(WIN32)
static int
cbt_run(const char *self, int c, char *buf, size_t len, cbt_end_t *end)
{
	SECURITY_ATTRIBUTES sa = { (DWORD)sizeof(sa), NULL, TRUE };
	PROCESS_INFORMATION pi;
	HANDLE rd, wr;
	STARTUPINFOA si;
	char cmd[1024];
	size_t used = 0;
	DWORD r, code;

	if (!CreatePipe(&rd, &wr, &sa, 0))
		return 1;
	/* only the child's end is inherited */
	SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

	lws_snprintf(cmd, sizeof(cmd), "\"%s\" --crash %d", self, c);

	memset(&si, 0, sizeof(si));
	si.cb		= (DWORD)sizeof(si);
	si.dwFlags	= STARTF_USESTDHANDLES;
	si.hStdInput	= GetStdHandle(STD_INPUT_HANDLE);
	si.hStdOutput	= wr;
	si.hStdError	= wr;

	if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si,
			    &pi)) {
		CloseHandle(rd);
		CloseHandle(wr);
		return 1;
	}
	CloseHandle(wr);
	CloseHandle(pi.hThread);

	while (used < len - 1 &&
	       ReadFile(rd, buf + used, (DWORD)(len - 1 - used), &r, NULL) &&
	       r)
		used += r;
	buf[used] = '\0';
	CloseHandle(rd);

	WaitForSingleObject(pi.hProcess, INFINITE);
	if (!GetExitCodeProcess(pi.hProcess, &code)) {
		CloseHandle(pi.hProcess);
		return 1;
	}
	CloseHandle(pi.hProcess);

	end->signalled	= 0;
	end->code	= code;

	return 0;
}
#else
static int
cbt_run(const char *self, int c, char *buf, size_t len, cbt_end_t *end)
{
	char cs[8], *args[4];
	size_t used = 0;
	int pfd[2], st;
	ssize_t r;
	pid_t pid;

	lws_snprintf(cs, sizeof(cs), "%d", c);
	args[0] = (char *)self;
	args[1] = (char *)"--crash";
	args[2] = cs;
	args[3] = NULL;

	if (pipe(pfd))
		return 1;

	pid = fork();
	if (pid < 0) {
		close(pfd[0]);
		close(pfd[1]);
		return 1;
	}

	if (!pid) {
		close(pfd[0]);
		if (dup2(pfd[1], 2) < 0)
			_exit(1);
		close(pfd[1]);
		execv(self, args);
		_exit(1);
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
		return 1;

	end->signalled = WIFSIGNALED(st);
	end->code = (unsigned long)(end->signalled ? WTERMSIG(st) :
				    (WIFEXITED(st) ? WEXITSTATUS(st) : 255));

	return 0;
}
#endif

/* how case c's child must end, and what its backtrace must start with */

static void
cbt_expect(int c, cbt_end_t *end, char *mark, size_t len)
{
	switch (c) {
	case CBT_SEGV:
#if defined(WIN32)
		end->signalled	= 0;
		end->code	= (unsigned long)EXCEPTION_ACCESS_VIOLATION;
		lws_snprintf(mark, len, CBT_MARK_START "exception 0x%08lx,",
			     end->code);
#else
		end->signalled	= 1;
		end->code	= SIGSEGV;
		lws_snprintf(mark, len, CBT_MARK_START "signal %d,", SIGSEGV);
#endif
		break;
	case CBT_ABORT:
#if defined(WIN32)
		end->signalled	= 0;
		end->code	= 3;
#else
		end->signalled	= 1;
		end->code	= SIGABRT;
#endif
		lws_snprintf(mark, len, CBT_MARK_START "signal %d,", SIGABRT);
		break;
	default:
		end->signalled	= 0;
		end->code	= CBT_APP_EXIT;
		mark[0]		= '\0';
		break;
	}
}

/* the backtrace is there, starting with mark, with at least one frame */

static int
cbt_check_bt(const char *buf, const char *mark)
{
	const char *s, *e;

	if (!mark[0]) {
		if (strstr(buf, CBT_MARK_START)) {
			lwsl_err("lws printed a backtrace\n");
			return 1;
		}
		return 0;
	}

	s = strstr(buf, mark);
	e = strstr(buf, CBT_MARK_END);
	if (!s || !e || e < s) {
		lwsl_err("no backtrace starting \"%s\"\n", mark);
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
	cbt_end_t end, want;
	int c, fails = 0;
	char buf[16384], mark[64];
	const char *p;

	p = lws_cmdline_option(argc, argv, "--crash");
	if (p) {
		c = atoi(p);
		return c >= 0 && c < CBT_COUNT ? cbt_crash(c) : 1;
	}

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

	lwsl_user("LWS API selftest: crash backtraces\n");

	for (c = 0; c < CBT_COUNT; c++) {
		if (cbt_run(argv[0], c, buf, sizeof(buf), &end)) {
			lwsl_err("%s: FAIL: couldn't run the child\n",
				 cbt_names[c]);
			fails++;
			continue;
		}
		lwsl_user("=== %s: the child wrote ===\n%s", cbt_names[c], buf);

		cbt_expect(c, &want, mark, sizeof(mark));
		if (end.signalled != want.signalled || end.code != want.code) {
			lwsl_err("%s: FAIL: the child %s %lu, not %s %lu\n",
				 cbt_names[c],
				 end.signalled ? "died of signal" : "exited",
				 end.code,
				 want.signalled ? "died of signal" : "exited",
				 want.code);
			fails++;
			continue;
		}
		if (cbt_check_bt(buf, mark)) {
			lwsl_err("%s: FAIL\n", cbt_names[c]);
			fails++;
			continue;
		}
		lwsl_user("%s: PASS\n", cbt_names[c]);
	}

	lwsl_user("Completed: %s\n", fails ? "FAIL" : "PASS");

	return !!fails;
}
