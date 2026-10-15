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
 *   --hog		allocates HOG_MIB and touches all of it so it's
 *			resident, uses HOG_CPU_US of cpu, then holds the memory
 *			for HOG_HOLD_MS
 *
 *   --tree		starts TREE_HOGS hogs at once and waits for them
 *
 * The legs are
 *
 *  - one hog: the peak is about HOG_MIB, which also catches it being in
 *    other units than bytes, and the cpu is at least HOG_CPU_US
 *
 *  - a tree of hogs: the peak is about TREE_HOGS x HOG_MIB, all of them at
 *    once rather than the biggest one, and the cpu is theirs too, not the
 *    --tree process's that only waited for them
 */

#include <libwebsockets.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#if defined(WIN32)
#include <process.h>
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/resource.h>
#endif

#define HOG_MIB		48
#define HOG_CPU_US	(250 * LWS_US_PER_MS)
#define HOG_HOLD_MS	2000
#define TREE_HOGS	3
#define MIB		(1024ull * 1024ull)

typedef enum {
	LEG_HOG,
	LEG_TREE,
	LEG_DONE
} test_leg_t;

static const char * const leg_names[] = { "one hog", "tree of hogs" };

static struct lws_context *context;
static struct lws_vhost *vhost;
static struct lws_spawn_piped *lsp;
static lws_spawn_resource_us_t res;
static char argv0[1024];
static test_leg_t leg;
static int fails;

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
	usleep(ms * 1000);
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

	mem = malloc(len);
	if (!mem)
		return 2;
	p = mem;

	/* touch every page, so it's resident, not just reserved */
	for (n = 0; n < len; n += 4096)
		p[n] = (uint8_t)n;

	/*
	 * Use our cpu by what we were given of it, not by the time it took:
	 * on a busy machine those are very different
	 */
	while (cpu_us() < HOG_CPU_US &&
	       lws_now_usecs() - t0 < 20 * LWS_US_PER_SEC)
		for (n = 0; n < len; n += 4096)
			sum += p[n];

	/* stay resident long enough to be seen alongside the other hogs */
	sleep_ms(HOG_HOLD_MS);

	for (n = 0; n < len; n += 4096)
		sum += p[n];

	free(mem);

	/* so the work can't be optimized away */
	return sum == 0xffffffffu ? 3 : 0;
}

static int
tree(void)
{
	int n, ret = 0;
#if defined(WIN32)
	intptr_t h[TREE_HOGS];
	char path[MAX_PATH];
	int st;

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
	pid_t pid[TREE_HOGS];
	int st;

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

#if defined(WIN32)
	code = si->retcode & 0xff;
#else
	code = si->si_status;
#endif

	lwsl_user("%s: %s: exit %d, cpu %llums (user %llums, sys %llums), "
		  "peak %lluMiB\n", __func__, leg_names[leg], code,
		  (unsigned long long)(cpu / 1000),
		  (unsigned long long)(r->us_cpu_user / 1000),
		  (unsigned long long)(r->us_cpu_sys / 1000),
		  (unsigned long long)(r->peak_mem_rss / MIB));

	check(!we_killed_him && !code, "the helper finished by itself, OK");

	/* the helper made sure it had at least this much */
	check(cpu >= want_cpu, "cpu is of everything it ran");

	/*
	 * Each hog also has its program, libraries and heap, so above the
	 * least, leave room for those, and for what counting shared memory
	 * in each process adds.  Anything in KiB or pages instead of bytes
	 * is wildly outside this either way.
	 */
	check(r->peak_mem_rss >= (want_mib * MIB * 9) / 10,
	      "peak is of everything resident at once");
	check(r->peak_mem_rss <= (want_mib + 256 * (want_mib / HOG_MIB)) * MIB,
	      "peak is in bytes");

	/* the same results are in the info's .res */
	check(!memcmp(&res, r, sizeof(res)), "info .res has the results");

	leg++;
	if (leg == LEG_DONE || spawn_leg())
		lws_default_loop_exit(context);
}

static int
callback_spawn(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	       void *in, size_t len)
{
	switch (reason) {
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
	const char *ea[] = { argv0, leg == LEG_TREE ? "--tree" : "--hog", NULL };
	struct lws_spawn_piped_info info;

	lwsl_user("--- %s ---\n", leg_names[leg]);

	memset(&res, 0, sizeof(res));
	memset(&info, 0, sizeof(info));
	info.vh			= vhost;
	info.exec_array		= ea;
	info.protocol_name	= "spawn-resources";
	info.reap_cb		= reap_cb;
	info.plsp		= &lsp;
	info.res		= &res;
	info.timeout_us		= 40 * LWS_US_PER_SEC;

	lsp = lws_spawn_piped(&info);
	if (!lsp) {
		lwsl_err("%s: spawn failed\n", __func__);
		fails++;

		return 1;
	}

	return 0;
}

int
main(int argc, const char **argv)
{
	struct lws_context_creation_info info;

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
