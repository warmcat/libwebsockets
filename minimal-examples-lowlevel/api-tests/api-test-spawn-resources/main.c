/*
 * lws-api-test-spawn-resources
 *
 * Written in 2010-2026 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * Checks what lws_spawn_piped() reports a spawned process used, in its
 * lws_spawn_resource_us_t: that it's in bytes and uS on every platform, and
 * that it's for the whole process tree, not only the process lws started.
 *
 * The spawned processes are this program again, run as helpers:
 *
 *   --exit		says it started, and exits
 *
 *   --hog		allocates HOG_MIB and touches all of it so it's
 *			resident, uses HOG_CPU_US of cpu, then holds the memory
 *			for HOG_HOLD_MS
 *
 *   --tree		starts TREE_HOGS hogs at once and waits for them
 *
 * The legs are
 *
 *  - an exit, without and then with info.res: the helper is spawned, goes,
 *    and is reaped, and lws keeping track of its tree's memory while it
 *    runs doesn't change that
 *
 *  - one hog: the peak is about HOG_MIB, which also catches it being in
 *    other units than bytes, and the cpu is at least HOG_CPU_US
 *
 *  - a tree of hogs: the peak is about TREE_HOGS x HOG_MIB, all of them at
 *    once rather than the biggest one, and the cpu is theirs too, not the
 *    --tree process's that only waited for them
 *
 * So that a leg that goes wrong says where, the helpers say on their stdout
 * how far they got, which we log as it comes, and every HEARTBEAT_S while a
 * leg runs we say whether its helper is still there and how many of its
 * stdio pipes are still open.  A leg still going after LEG_MAX_S is given up
 * on, with a summary, before ctest's timeout kills us with nothing said.
 *
 * Reading the helpers' stdout is also our job as the pipes' protocol: on the
 * BSDs and macOS the end of a pipe is POLLIN as well as POLLHUP, and it's the
 * read finding nothing more that closes it.  Leaving it unread, the pipe
 * stays readable for ever, and the reap waits for it for ever.
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#if defined(WIN32)
#include <process.h>
#include <io.h>
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <signal.h>
#include <time.h>
#endif

#define HOG_MIB		48
#define HOG_CPU_US	(250 * LWS_US_PER_MS)
#define HOG_HOLD_MS	2000
#define TREE_HOGS	3
#define MIB		(1024ull * 1024ull)
#define HEARTBEAT_S	5
#define LEG_MAX_S	55

typedef enum {
	LEG_EXIT,
	LEG_EXIT_RES,
	LEG_HOG,
	LEG_TREE,
	LEG_DONE
} test_leg_t;

static const char * const leg_names[] = {
	"exit", "exit, tracking its resources", "one hog", "tree of hogs"
};

static struct lws_context *context;
static struct lws_vhost *vhost;
static struct lws_spawn_piped *lsp;
static lws_spawn_resource_us_t res;
static char argv0[1024];
static lws_sorted_usec_list_t sul_heartbeat;
static lws_usec_t leg_start;
static test_leg_t leg;
static int fails, helper_pid;

/*
 * Helper side
 */

/* the cpu this process has had so far */

static uint64_t
cpu_us(void)
{
#if defined(WIN32)
	FILETIME c, e, k, u;
	ULARGE_INTEGER ku, uu;

	if (!GetProcessTimes(GetCurrentProcess(), &c, &e, &k, &u))
		return 0;

	ku.LowPart = k.dwLowDateTime;
	ku.HighPart = k.dwHighDateTime;
	uu.LowPart = u.dwLowDateTime;
	uu.HighPart = u.dwHighDateTime;

	return (ku.QuadPart + uu.QuadPart) / 10;
#else
	struct rusage ru;

	if (getrusage(RUSAGE_SELF, &ru))
		return 0;

	return ((uint64_t)ru.ru_utime.tv_sec * LWS_US_PER_SEC) +
	       (uint64_t)ru.ru_utime.tv_usec +
	       ((uint64_t)ru.ru_stime.tv_sec * LWS_US_PER_SEC) +
	       (uint64_t)ru.ru_stime.tv_usec;
#endif
}

static void
sleep_ms(unsigned int ms)
{
#if defined(WIN32)
	Sleep(ms);
#else
	/* usleep() may refuse a second or more */
	struct timespec ts = { (time_t)(ms / 1000),
			       (long)(ms % 1000) * 1000000l };

	while (nanosleep(&ts, &ts) && errno == EINTR)
		;
#endif
}

/* the helper tells the test how far it got, on its stdout */

static void
say(const char *what)
{
	char buf[96];
	int n;

#if defined(WIN32)
	n = lws_snprintf(buf, sizeof(buf), "helper %d: %s\n", _getpid(), what);
	(void)!_write(1, buf, (unsigned int)n);
#else
	n = lws_snprintf(buf, sizeof(buf), "helper %d: %s\n", (int)getpid(),
			 what);
	(void)!write(1, buf, (size_t)n);
#endif
}

static int
hog(void)
{
	size_t len = HOG_MIB * MIB, n;
	lws_usec_t t0 = lws_now_usecs();
	volatile uint8_t *p;
	unsigned int sum = 0;
	uint8_t *mem;

	say("hog started");

	mem = malloc(len);
	if (!mem)
		return 2;
	p = mem;

	/* touch every page, so it's resident, not just reserved */
	for (n = 0; n < len; n += 4096)
		p[n] = (uint8_t)n;

	say("hog resident");

	/*
	 * Use our cpu by what we were given of it, not by the time it took:
	 * on a busy machine those are very different
	 */
	while (cpu_us() < HOG_CPU_US &&
	       lws_now_usecs() - t0 < 20 * LWS_US_PER_SEC)
		for (n = 0; n < len; n += 4096)
			sum += p[n];

	say("hog used its cpu");

	/* stay resident long enough to be seen alongside the other hogs */
	sleep_ms(HOG_HOLD_MS);

	for (n = 0; n < len; n += 4096)
		sum += p[n];

	free(mem);
	say("hog exiting");

	/* so the work can't be optimized away */
	return sum == 0xffffffffu ? 3 : 0;
}

static int
tree(void)
{
	int n, ret = 0, st;
#if defined(WIN32)
	intptr_t h[TREE_HOGS];
	char path[MAX_PATH];
#else
	pid_t pid[TREE_HOGS];
#endif

	say("tree started");

#if defined(WIN32)
	if (!GetModuleFileNameA(NULL, path, (DWORD)sizeof(path)))
		return 4;

	for (n = 0; n < TREE_HOGS; n++) {
		h[n] = _spawnl(_P_NOWAIT, path, path, "--hog", NULL);
		if (h[n] == -1)
			return 5;
	}

	for (n = 0; n < TREE_HOGS; n++)
		if (_cwait(&st, h[n], 0) == -1 || st)
			ret = 6;
#else
	for (n = 0; n < TREE_HOGS; n++) {
		pid[n] = fork();
		if (pid[n] < 0)
			return 5;
		if (!pid[n])
			_exit(hog());
	}

	for (n = 0; n < TREE_HOGS; n++)
		if (waitpid(pid[n], &st, 0) != pid[n] || !WIFEXITED(st) ||
		    WEXITSTATUS(st))
			ret = 6;
#endif

	say("tree's hogs are done");

	return ret;
}

/*
 * Test side
 */

static int
spawn_leg(void);

static int
check(int ok, const char *what)
{
	lwsl_user("  %s: %s\n", what, ok ? "ok" : "FAIL");
	if (!ok)
		fails++;

	return ok;
}

static void
reap_cb(void *opaque, const lws_spawn_resource_us_t *r, siginfo_t *si,
	int we_killed_him)
{
	uint64_t cpu = r->us_cpu_user + r->us_cpu_sys,
		 want_mib = leg == LEG_TREE ? TREE_HOGS * HOG_MIB : HOG_MIB,
		 want_cpu = leg == LEG_TREE ? TREE_HOGS * HOG_CPU_US :
					      HOG_CPU_US;
	int code;

	lws_sul_cancel(&sul_heartbeat);

#if defined(WIN32)
	code = si->retcode & 0xff;
#else
	code = si->si_status;
#endif

	lwsl_user("%s: %s: after %dms, exit %d, cpu %llums (user %llums, "
		  "sys %llums), peak %lluMiB\n", __func__, leg_names[leg],
		  (int)((lws_now_usecs() - leg_start) / LWS_US_PER_MS), code,
		  (unsigned long long)(cpu / 1000),
		  (unsigned long long)(r->us_cpu_user / 1000),
		  (unsigned long long)(r->us_cpu_sys / 1000),
		  (unsigned long long)(r->peak_mem_rss / MIB));

	check(!we_killed_him && !code, "the helper finished by itself, OK");

	if (leg == LEG_HOG || leg == LEG_TREE) {
		/* the helper made sure it had at least this much */
		check(cpu >= want_cpu, "cpu is of everything it ran");

		/*
		 * Each hog also has its program, libraries and heap, so above
		 * the least, leave room for those, and for what counting
		 * shared memory in each process adds.  Anything in KiB or
		 * pages instead of bytes is wildly outside this either way.
		 */
		check(r->peak_mem_rss >= (want_mib * MIB * 9) / 10,
		      "peak is of everything resident at once");
		check(r->peak_mem_rss <= (want_mib + 256 * (want_mib / HOG_MIB)) *
					 MIB, "peak is in bytes");
	}

	if (leg != LEG_EXIT)
		/* the same results are in the info's .res */
		check(!memcmp(&res, r, sizeof(res)),
		      "info .res has the results");

	helper_pid = 0;
	leg++;
	if (leg == LEG_DONE || spawn_leg())
		lws_default_loop_exit(context);
}

/*
 * What a helper said on its stdout or stderr, a line at a time.  Its first
 * line, "helper <pid>: ...", tells us the pid of the process we spawned.
 */

static void
helper_said(int std_idx, char *buf)
{
	char *nl;

	while (*buf) {
		nl = strchr(buf, '\n');
		if (nl)
			*nl = '\0';

		if (!helper_pid && !strncmp(buf, "helper ", 7))
			helper_pid = atoi(buf + 7);

		if (*buf)
			lwsl_user("  %s> %s\n", std_idx == LWS_STDERR ?
						 "stderr" : "stdout", buf);
		if (!nl)
			break;
		buf = nl + 1;
	}
}

/*
 * While a leg runs, say every HEARTBEAT_S whether its helper is still there
 * and how many of its stdio pipes are still open, and give up on it after
 * LEG_MAX_S
 */

static void
heartbeat_cb(lws_sorted_usec_list_t *sul)
{
	int secs = (int)((lws_now_usecs() - leg_start) / LWS_US_PER_SEC);
	const char *state = "not heard from";

	if (helper_pid > 0) {
#if defined(WIN32)
		state = "?";
#else
		/* a zombie is there too, until it's reaped */
		state = kill(helper_pid, 0) && errno == ESRCH ? "gone" :
							       "there";
#endif
	}

	lwsl_user("  %s: %ds in, helper %d %s, %d of its stdio pipes open\n",
		  leg_names[leg], secs, helper_pid, state,
		  lsp ? lws_spawn_get_stdwsi_open_count(lsp) : -1);

	if (secs >= LEG_MAX_S) {
		lwsl_err("%s: %s still not over after %ds, giving up\n",
			 __func__, leg_names[leg], secs);
		fails++;
		lws_default_loop_exit(context);

		return;
	}

	lws_sul_schedule(context, 0, &sul_heartbeat, heartbeat_cb,
			 HEARTBEAT_S * LWS_US_PER_SEC);
}

static int
callback_spawn(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	       void *in, size_t len)
{
	char buf[256];
	int n;

	switch (reason) {
	case LWS_CALLBACK_RAW_RX_FILE:
#if defined(WIN32)
		/* lws read the pipe for us, the pipe is a HANDLE here */
		n = (int)(len < sizeof(buf) - 1 ? len : sizeof(buf) - 1);
		if (n)
			memcpy(buf, in, (size_t)n);
#else
		/*
		 * Reading is ours to do.  At the end of the pipe, the BSDs and
		 * macOS say POLLIN as well as POLLHUP: reading nothing is what
		 * tells us it's over, and we close it
		 */
		n = (int)read(lws_get_socket_fd(wsi), buf, sizeof(buf) - 1);
		if (n <= 0)
			return -1;
#endif
		buf[n] = '\0';
		helper_said(lws_spawn_get_stdfd(wsi), buf);

		return 0;

	case LWS_CALLBACK_RAW_CLOSE_FILE:
		if (lsp)
			lws_spawn_stdwsi_closed(lsp, wsi);
		break;
	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols[] = {
	{ "spawn-resources", callback_spawn, 0, 0, 0, NULL, 0 },
	LWS_PROTOCOL_LIST_TERM
};

static int
spawn_leg(void)
{
	static const char * const helpers[] = {
		"--exit", "--exit", "--hog", "--tree"
	};
	const char *ea[] = { argv0, helpers[leg], NULL };
	struct lws_spawn_piped_info info;

	lwsl_user("--- %s ---\n", leg_names[leg]);

	memset(&res, 0, sizeof(res));
	memset(&info, 0, sizeof(info));
	info.vh			= vhost;
	info.exec_array		= ea;
	info.protocol_name	= "spawn-resources";
	info.reap_cb		= reap_cb;
	info.plsp		= &lsp;
	if (leg != LEG_EXIT)
		info.res	= &res;
	info.timeout_us		= 40 * LWS_US_PER_SEC;

	leg_start = lws_now_usecs();
	lsp = lws_spawn_piped(&info);
	if (!lsp) {
		lwsl_err("%s: spawn failed\n", __func__);
		fails++;

		return 1;
	}

	lws_sul_schedule(context, 0, &sul_heartbeat, heartbeat_cb,
			 HEARTBEAT_S * LWS_US_PER_SEC);

	return 0;
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;

	if (lws_cmdline_option(argc, argv, "--exit")) {
		say("started, exiting");
		return 0;
	}
	if (lws_cmdline_option(argc, argv, "--hog"))
		return hog();
	if (lws_cmdline_option(argc, argv, "--tree"))
		return tree();

	/*
	 * The helpers are us again.  The spawned child starts somewhere else,
	 * so a path to us relative to here won't find us from there.
	 */
#if defined(WIN32)
	if (!_fullpath(argv0, argv[0], sizeof(argv0)))
#else
	if (!strchr(argv[0], '/'))
		/* we were found on the PATH, and will be again */
		lws_strncpy(argv0, argv[0], sizeof(argv0));
	else if (!realpath(argv[0], argv0))
#endif
	{
		lwsl_err("%s: can't find ourselves\n", __func__);
		return 1;
	}

	lws_context_info_defaults(&info, NULL);
	lws_cmdline_option_handle_builtin(argc, argv, &info);
	info.options |= LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.protocols = protocols;

	lwsl_user("LWS API selftest: spawned process tree resources\n");

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

	vhost = lws_create_vhost(context, &info);
	if (vhost && !spawn_leg())
		lws_context_default_loop_run_destroy(context);
	else {
		fails++;
		lws_context_destroy(context);
	}

	if (leg != LEG_DONE)
		fails++;

	lwsl_user("Completed: %s\n", fails ? "FAIL" : "PASS");

	return !!fails;
}
