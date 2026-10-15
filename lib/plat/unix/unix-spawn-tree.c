/*
 * libwebsockets - small server side websockets and web server implementation
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
 * The memory a spawned process tree has resident, all together
 *
 * What the kernel tells us when we reap the child, ru_maxrss, is the peak of
 * the biggest single process: the child, or one of the descendants it waited
 * for.  A make -j4 has four compilers resident at once, and that counts as
 * one of them.  So while a child whose caller asked for its resource usage
 * runs, we add up the resident memory of it and all its descendants every
 * so often, and keep the peak.
 *
 * It's sampled, so a peak shorter than the interval can be missed; at reap,
 * the result is never less than ru_maxrss either way.  Pages shared between
 * processes, eg, libc, are counted in each of them, so it errs high.
 *
 * On Linux, a child in its own cgroup is measured by the cgroup's members,
 * which also catches anything it left running outside its process tree.
 * Elsewhere the tree is found by parent pid.
 */

#include "private-lib-core.h"

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>

#if defined(__linux__)
#include <dirent.h>
#elif defined(__APPLE__)
#include <libproc.h>
#elif defined(__FreeBSD__)
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#elif defined(__NetBSD__) || defined(__OpenBSD__)
#include <sys/param.h>
#include <sys/sysctl.h>
#endif

/* a busy tree, eg, make -j with its shells and compilers, is well inside this */
#define LWS_SPAWN_TREE_MAX_PROCS	4096

#if defined(__linux__) || defined(__FreeBSD__) || defined(__NetBSD__) || \
    defined(__OpenBSD__)

/*
 * One process on the system, while we work out which are in the tree: the
 * listings we have give everything, with each one's parent
 */

typedef struct {
	pid_t		pid;
	pid_t		ppid;
	uint64_t	rss;	/* bytes */
	char		in;
} lws_spawn_proc_t;

static int
proc_cmp(const void *a, const void *b)
{
	const lws_spawn_proc_t *pa = (const lws_spawn_proc_t *)a,
			       *pb = (const lws_spawn_proc_t *)b;

	return pa->pid < pb->pid ? -1 : pa->pid > pb->pid;
}

static lws_spawn_proc_t *
proc_find(lws_spawn_proc_t *p, size_t n, pid_t pid)
{
	lws_spawn_proc_t k;

	k.pid = pid;

	return (lws_spawn_proc_t *)bsearch(&k, p, n, sizeof(*p), proc_cmp);
}

/*
 * The resident memory of root and everything descended from it, out of a
 * listing of all the processes
 */

static uint64_t
proc_tree_sum(lws_spawn_proc_t *p, size_t n, pid_t root)
{
	uint64_t sum = 0;
	int more = 1;
	size_t m;

	qsort(p, n, sizeof(*p), proc_cmp);

	for (m = 0; m < n; m++)
		p[m].in = p[m].pid == root;

	/*
	 * Each pass takes in the children of what's in so far, so it's done
	 * in as many passes as the tree is deep
	 */

	while (more) {
		more = 0;
		for (m = 0; m < n; m++) {
			lws_spawn_proc_t *pp;

			if (p[m].in || p[m].ppid == p[m].pid)
				continue;

			pp = proc_find(p, n, p[m].ppid);
			if (pp && pp->in) {
				p[m].in = 1;
				more = 1;
			}
		}
	}

	for (m = 0; m < n; m++)
		if (p[m].in)
			sum += p[m].rss;

	return sum;
}

#endif

#if defined(__linux__)

/* the contents of a small /proc file, NUL-terminated, or -1 */

static int
read_small(const char *path, char *buf, size_t len)
{
	ssize_t r;
	int fd;

	fd = lws_open(path, O_RDONLY);
	if (fd < 0)
		return -1;

	r = read(fd, buf, len - 1);
	close(fd);
	if (r <= 0)
		return -1;

	buf[r] = '\0';

	return (int)r;
}

/*
 * The parent and resident pages of a process, from /proc/<pid>/stat.  Its
 * second field is the command name in brackets, which may contain anything,
 * spaces and brackets too, so the fields we count start after the last ')'
 */

static int
proc_stat(pid_t pid, pid_t *ppid, uint64_t *rss_pages)
{
	char path[48], buf[512], *p;
	int field = 2;

	lws_snprintf(path, sizeof(path), "/proc/%d/stat", (int)pid);
	if (read_small(path, buf, sizeof(buf)) < 0)
		return -1;

	p = strrchr(buf, ')');
	if (!p)
		return -1;
	p++;

	while (*p) {
		while (*p == ' ')
			p++;
		if (!*p)
			break;

		field++;
		if (field == 4)
			*ppid = (pid_t)atoi(p);
		if (field == 24) {
			*rss_pages = strtoull(p, NULL, 10);
			return 0;
		}

		while (*p && *p != ' ')
			p++;
	}

	return -1;
}

/* what one process has resident, from /proc/<pid>/statm: size, then resident */

static uint64_t
pid_rss(pid_t pid, uint64_t page)
{
	char pth[48], sm[128], *p;

	lws_snprintf(pth, sizeof(pth), "/proc/%d/statm", (int)pid);
	if (read_small(pth, sm, sizeof(sm)) <= 0)
		return 0; /* it went while we were looking */

	p = strchr(sm, ' ');

	return p ? strtoull(p + 1, NULL, 10) * page : 0;
}

/* the resident memory of everything in the cgroup, or -1 if we can't read it */

static int
cgroup_rss(const char *cgpath, uint64_t page, uint64_t *rss)
{
	char path[300], buf[1024];
	uint64_t sum = 0;
	pid_t pid = 0;
	int fd, any = 0;
	ssize_t r, m;

	lws_snprintf(path, sizeof(path), "%s/cgroup.procs", cgpath);
	fd = lws_open(path, O_RDONLY);
	if (fd < 0)
		return -1;

	/* one pid a line: the digits of one may straddle two reads */

	while ((r = read(fd, buf, sizeof(buf))) > 0)
		for (m = 0; m < r; m++) {
			if (buf[m] >= '0' && buf[m] <= '9') {
				pid = (pid * 10) + (buf[m] - '0');
				any = 1;
				continue;
			}

			if (any)
				sum += pid_rss(pid, page);
			pid = 0;
			any = 0;
		}

	if (any) /* the last one had no newline after it */
		sum += pid_rss(pid, page);

	close(fd);
	*rss = sum;

	return 0;
}

int
lws_spawn_tree_rss(struct lws_spawn_piped *lsp, uint64_t *rss)
{
	uint64_t page = (uint64_t)sysconf(_SC_PAGESIZE), pages;
	lws_spawn_proc_t *p = NULL, *p1;
	size_t n = 0, alloc = 0;
	struct dirent *de;
	pid_t ppid;
	DIR *d;

	if (lsp->cgroup_path[0] && !cgroup_rss(lsp->cgroup_path, page, rss))
		return 0;

	d = opendir("/proc");
	if (!d)
		return -1;

	while ((de = readdir(d)) && n < LWS_SPAWN_TREE_MAX_PROCS) {
		pid_t pid;

		if (de->d_name[0] < '1' || de->d_name[0] > '9')
			continue;

		pid = (pid_t)atoi(de->d_name);
		if (proc_stat(pid, &ppid, &pages))
			continue; /* it went while we were looking */

		if (n == alloc) {
			alloc = alloc ? alloc * 2 : 256;
			p1 = lws_realloc(p, alloc * sizeof(*p), __func__);
			if (!p1)
				break;
			p = p1;
		}

		p[n].pid	= pid;
		p[n].ppid	= ppid;
		p[n].rss	= pages * page;
		n++;
	}

	closedir(d);

	if (!p)
		return -1;

	*rss = proc_tree_sum(p, n, lsp->child_pid);
	lws_free(p);

	return 0;
}

/*
 * The cpu time of everything that ran in the child's cgroup, which includes
 * what it left running outside its process tree, eg, a background server
 * that was never waited for.  Returns -1 if there's no cgroup or no stat.
 */

int
lws_spawn_cgroup_cpu(struct lws_spawn_piped *lsp, uint64_t *us_user,
		     uint64_t *us_sys)
{
	char path[300], buf[512], *p;
	int got = 0;

	if (!lsp->cgroup_path[0])
		return -1;

	lws_snprintf(path, sizeof(path), "%s/cpu.stat", lsp->cgroup_path);
	if (read_small(path, buf, sizeof(buf)) < 0)
		return -1;

	p = strstr(buf, "user_usec ");
	if (p) {
		*us_user = strtoull(p + 10, NULL, 10);
		got++;
	}
	p = strstr(buf, "system_usec ");
	if (p) {
		*us_sys = strtoull(p + 12, NULL, 10);
		got++;
	}

	return got == 2 ? 0 : -1;
}

#elif defined(__APPLE__)

/*
 * libproc can list a process's children directly, so walk down the tree from
 * the child, a level at a time
 */

int
lws_spawn_tree_rss(struct lws_spawn_piped *lsp, uint64_t *rss)
{
	struct proc_taskinfo ti;
	uint64_t sum = 0;
	size_t head = 0, tail = 0;
	pid_t *q, kids[256];
	int n, m;

	q = lws_malloc(LWS_SPAWN_TREE_MAX_PROCS * sizeof(*q), __func__);
	if (!q)
		return -1;

	q[tail++] = lsp->child_pid;

	while (head < tail) {
		pid_t pid = q[head++];

		if (proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &ti, sizeof(ti)) ==
							(int)sizeof(ti))
			sum += ti.pti_resident_size;

		/* it gives the size of what it listed, in bytes */
		n = proc_listpids(PROC_PPID_ONLY, (uint32_t)pid, kids,
				  (int)sizeof(kids));
		if (n <= 0)
			continue;

		n /= (int)sizeof(kids[0]);
		for (m = 0; m < n && tail < LWS_SPAWN_TREE_MAX_PROCS; m++)
			if (kids[m] > 0)
				q[tail++] = kids[m];
	}

	lws_free(q);
	*rss = sum;

	return 0;
}

#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)

/*
 * The kernel lists every process with its parent and resident pages in one
 * sysctl, the struct being the BSD's own
 */

#if defined(__FreeBSD__)
typedef struct kinfo_proc lws_kp_t;
#define KP_PID(k)	((k)->ki_pid)
#define KP_PPID(k)	((k)->ki_ppid)
#define KP_RSS(k)	((uint64_t)(k)->ki_rssize)
#elif defined(__NetBSD__)
typedef struct kinfo_proc2 lws_kp_t;
#define KP_PID(k)	((pid_t)(k)->p_pid)
#define KP_PPID(k)	((pid_t)(k)->p_ppid)
#define KP_RSS(k)	((uint64_t)(k)->p_vm_rssize)
#else
typedef struct kinfo_proc lws_kp_t;
#define KP_PID(k)	((pid_t)(k)->p_pid)
#define KP_PPID(k)	((pid_t)(k)->p_ppid)
#define KP_RSS(k)	((uint64_t)(k)->p_vm_rssize)
#endif

int
lws_spawn_tree_rss(struct lws_spawn_piped *lsp, uint64_t *rss)
{
	uint64_t page = (uint64_t)sysconf(_SC_PAGESIZE);
	lws_spawn_proc_t *p;
	lws_kp_t *kp = NULL;
	size_t len = 0, n, m;
#if defined(__FreeBSD__)
	int mib[3] = { CTL_KERN, KERN_PROC, KERN_PROC_PROC };
	u_int miblen = 3;
#elif defined(__NetBSD__)
	int mib[6] = { CTL_KERN, KERN_PROC2, KERN_PROC_ALL, 0,
		       (int)sizeof(lws_kp_t), 0 };
	u_int miblen = 6;
#else
	int mib[6] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0,
		       (int)sizeof(lws_kp_t), 0 };
	u_int miblen = 6;
#endif

	if (sysctl(mib, miblen, NULL, &len, NULL, 0) < 0 || !len)
		return -1;

	/* there may be more by the time we ask again */
	len += len / 4;
	if (len > LWS_SPAWN_TREE_MAX_PROCS * sizeof(lws_kp_t))
		len = LWS_SPAWN_TREE_MAX_PROCS * sizeof(lws_kp_t);

	kp = lws_malloc(len, __func__);
	if (!kp)
		return -1;

#if defined(__NetBSD__) || defined(__OpenBSD__)
	/* these also take how many structs we have room for */
	mib[5] = (int)(len / sizeof(lws_kp_t));
#endif

	if (sysctl(mib, miblen, kp, &len, NULL, 0) < 0 && errno != ENOMEM) {
		lws_free(kp);
		return -1;
	}

	n = len / sizeof(lws_kp_t);
	p = lws_malloc((n ? n : 1) * sizeof(*p), __func__);
	if (!p) {
		lws_free(kp);
		return -1;
	}

	for (m = 0; m < n; m++) {
		p[m].pid	= KP_PID(&kp[m]);
		p[m].ppid	= KP_PPID(&kp[m]);
		p[m].rss	= KP_RSS(&kp[m]) * page;
	}

	lws_free(kp);

	*rss = proc_tree_sum(p, n, lsp->child_pid);
	lws_free(p);

	return 0;
}

#else

int
lws_spawn_tree_rss(struct lws_spawn_piped *lsp, uint64_t *rss)
{
	/* nothing to measure the tree with here, ru_maxrss is all there is */

	(void)lsp;
	(void)rss;

	return -1;
}

#endif

#if !defined(__linux__)
int
lws_spawn_cgroup_cpu(struct lws_spawn_piped *lsp, uint64_t *us_user,
		     uint64_t *us_sys)
{
	(void)lsp;
	(void)us_user;
	(void)us_sys;

	return -1;
}
#endif

/*
 * While the child runs, keep the peak of what its tree has resident, in
 * lsp->res.peak_mem_rss
 */

void
lws_spawn_tree_sample_cb(lws_sorted_usec_list_t *sul)
{
	struct lws_spawn_piped *lsp = lws_container_of(sul,
					struct lws_spawn_piped, sul_mem);
	uint64_t rss;

	if (lsp->child_pid <= 0 || lsp->reaped)
		return;

	if (lws_spawn_tree_rss(lsp, &rss))
		return; /* we can't measure it here, don't keep trying */

	if (rss > lsp->res.peak_mem_rss)
		lsp->res.peak_mem_rss = rss;

	lws_sul_schedule(lsp->info.vh->context, lsp->info.tsi, &lsp->sul_mem,
			 lws_spawn_tree_sample_cb, LWS_SPAWN_TREE_SAMPLE_US);
}
