/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2020 Andy Green <andy@warmcat.com>
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
 */

#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include "private-lib-core.h"
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>

#if defined(__linux__)
#include <sys/stat.h>
#endif

#if defined(__OpenBSD__) || defined(__NetBSD__)
#include <sys/resource.h>
#include <sys/wait.h>
#endif

void
lws_spawn_timeout(struct lws_sorted_usec_list *sul)
{
	struct lws_spawn_piped *lsp = lws_container_of(sul,
					struct lws_spawn_piped, sul);

	lwsl_warn("%s: spawn exceeded timeout, killing\n", __func__);

	lws_spawn_piped_kill_child_process(lsp);
}

void
lws_spawn_sul_reap(struct lws_sorted_usec_list *sul)
{
	struct lws_spawn_piped *lsp = lws_container_of(sul,
					struct lws_spawn_piped, sul_reap);

	lwsl_info("%s: reaping spawn after last stdpipe, tries left %d\n",
		    __func__, lsp->reap_retry_budget);
	if (!lws_spawn_reap(lsp) && !lsp->pipes_alive) {
		if (--lsp->reap_retry_budget) {
			lws_sul_schedule(lsp->info.vh->context, lsp->info.tsi,
					 &lsp->sul_reap, lws_spawn_sul_reap,
					 250 * LWS_US_PER_MS);
		} else {
			lwsl_err("%s: Unable to reap lsp %p, killing\n",
				 __func__, lsp);
			lsp->reap_retry_budget = 20;
			lws_spawn_piped_kill_child_process(lsp);
		}
	}
}

static struct lws *
lws_create_stdwsi(struct lws_context *context, int tsi,
		     const struct lws_role_ops *ops)
{
	struct lws_context_per_thread *pt = &context->pt[tsi];
	struct lws *new_wsi;

	if (!context->vhost_list)
		return NULL;

	if ((unsigned int)pt->fds_count == context->fd_limit_per_thread - 1) {
		lwsl_err("no space for new conn\n");
		return NULL;
	}

	lws_context_lock(context, __func__);
	new_wsi = __lws_wsi_create_with_role(context, tsi, ops, NULL);
	lws_context_unlock(context);
	if (new_wsi == NULL) {
		lwsl_err("Out of memory for new connection\n");
		return NULL;
	}

	new_wsi->rxflow_change_to = LWS_RXFLOW_ALLOW;

	/* initialize the instance struct */

	lws_role_transition(new_wsi, 0, LRS_ESTABLISHED, ops);

	new_wsi->hdr_parsing_completed = 0;

	/*
	 * these can only be set once the protocol is known
	 * we set an unestablished connection's protocol pointer
	 * to the start of the defauly vhost supported list, so it can look
	 * for matching ones during the handshake
	 */

	new_wsi->user_space = NULL;

	return new_wsi;
}

void
lws_spawn_piped_destroy(struct lws_spawn_piped **_lsp)
{
	struct lws_spawn_piped *lsp = *_lsp;
	int n;

	if (!lsp)
		return;

	lws_dll2_remove(&lsp->dll);

	lws_sul_cancel(&lsp->sul);
	lws_sul_cancel(&lsp->sul_reap);

	for (n = 0; n < 3; n++) {
#if 0
		if (lsp->pipe_fds[n][!!(n == 0)] == 0)
			lwsl_err("ZERO FD IN CGI CLOSE");

		if (lsp->pipe_fds[n][!!(n == 0)] >= 0) {
			close(lsp->pipe_fds[n][!!(n == 0)]);
			lsp->pipe_fds[n][!!(n == 0)] = LWS_SOCK_INVALID;
		}
#endif
		if (lsp->stdwsi[n]) {
			lws_set_timeout(lsp->stdwsi[n], 1, LWS_TO_KILL_ASYNC);
			lsp->stdwsi[n] = NULL;
		}
	}

	lws_free_set_NULL((*_lsp));
}

int
lws_spawn_reap(struct lws_spawn_piped *lsp)
{
	void *opaque = lsp->info.opaque;
	lsp_cb_t cb = lsp->info.reap_cb;
	lws_spawn_resource_us_t res;
	struct rusage ru;
	siginfo_t si;
	int n, status;

	if (lsp->child_pid < 1)
		return 0;

	/* check if exited, do not reap yet */

	memset(&lsp->si, 0, sizeof(lsp->si));
	n = wait4(lsp->child_pid, &status, WNOHANG, &ru);
	if (n < 0) {
		lwsl_info("%s: child %d still running (errno %d)\n", __func__,
			  lsp->child_pid, errno);
		return 0;
	}

	if (!n)
		return 0;

	lsp->si.si_code = WIFEXITED(status);
	lsp->si.si_status = WEXITSTATUS(status);

	/* his process has exited... */

	if (!lsp->reaped) {
		/* mark the earliest time we knew he had gone */
		lsp->reaped = lws_now_usecs();

		/*
		 * Switch the timeout to restrict the amount of grace time
		 * to drain stdwsi
		 */

		lws_sul_schedule(lsp->info.vh->context, lsp->info.tsi,
				 &lsp->sul, lws_spawn_timeout,
				 5 * LWS_US_PER_SEC);
	}

	/*
	 * Stage finalizing our reaction to the process going down until the
	 * stdwsi flushed whatever is in flight and all noticed they were
	 * closed.  For that reason, each stdwsi close must call lws_spawn_reap
	 * to check if that was the last one and we can proceed with the reap.
	 */

	if (!lsp->ungraceful && lsp->pipes_alive) {
		lwsl_info("%s: %d stdwsi alive, not reaping\n", __func__,
				lsp->pipes_alive);
		return 0;
	}

	/* we reached the reap point, no need for timeout wait */

	lws_sul_cancel(&lsp->sul);

#if defined(__linux__)
	if (lsp->cgroup_path[0]) {
		/*
		 * The child has been reaped, we can remove the cgroup dir.
		 * This will only work if the cgroup is empty, which it should
		 * be now.
		 */
		if (rmdir(lsp->cgroup_path))
			lwsl_warn("%s: unable to rmdir cgroup %s, errno %d\n",
				  __func__, lsp->cgroup_path, errno);
		else
			lwsl_info("%s: reaped cgroup %s\n", __func__, lsp->cgroup_path);
	}
#endif

	/*
	 * All the stdwsi went down, nothing more is coming... it's over
	 * Collect the final information and then reap the dead process
	 */

	lsp->res.us_cpu_user =
		((uint64_t)ru.ru_utime.tv_sec * 1000000) + (uint64_t)ru.ru_utime.tv_usec;
	lsp->res.us_cpu_sys =
		((uint64_t)ru.ru_stime.tv_sec * 1000000) + (uint64_t)ru.ru_stime.tv_usec;

	/* ru_maxrss is in KB */
	lsp->res.peak_mem_rss = (uint64_t)ru.ru_maxrss * 1024;

#if 0
	if (getrusage(RUSAGE_CHILDREN, &ru) == 0) {
		lsp->res.us_cpu_user +=
			((uint64_t)ru.ru_utime.tv_sec * 1000000) + (uint64_t)ru.ru_utime.tv_usec;
		lsp->res.us_cpu_sys +=
			((uint64_t)ru.ru_stime.tv_sec * 1000000) + (uint64_t)ru.ru_stime.tv_usec;
		/* ru_maxrss is in KB */
		lsp->res.peak_mem_rss += (uint64_t)ru.ru_maxrss * 1024;
	} else
		lwsl_err("%s: getrusage failed\n", __func__);
#endif

	n = waitpid(lsp->child_pid, &status, WNOHANG);
	if (n < 0) {
		lwsl_info("%s: child %d vanished\n", __func__, lsp->child_pid);
	}

	lwsl_info("%s: waitd says %d, process exit %d\n",
		    __func__, n, lsp->si.si_status);

	lsp->child_pid		= -1;
	si			= lsp->si;
	res			= lsp->res;
	n			= lsp->we_killed_him_timeout |
					(lsp->we_killed_him_spew << 1);

	/* destroy the lsp itself first (it's freed and plsp set NULL */

	if (lsp->info.plsp)
		lws_spawn_piped_destroy(lsp->info.plsp);

	/* then do the parent callback informing it's destroyed */

	if (cb)
		cb(opaque, &res, &si, n);

	return 1; /* was reaped */
}

/*
 * We send the child a SIGTERM, that's all.
 *
 * The process should terminate, closing the stdwsi.  The stdwsi pipes on
 * our side should indicate they need handling and CLOSE.  When the last
 * one CLOSEs, the lws_spawn_stdwsi_closed() api should do the reap.
 */

int
lws_spawn_piped_kill_child_process(struct lws_spawn_piped *lsp)
{
	int status, n;

	if (lsp->child_pid <= 0)
		return 1;

	lsp->ungraceful = 1; /* don't wait for flushing, just kill it */

	/* kill the process group */
	n = kill(-lsp->child_pid, SIGTERM);
	lwsl_debug("%s: SIGTERM child PID %d says %d (errno %d)\n", __func__,
		   lsp->child_pid, n, errno);
	if (n < 0) {
		/*
		 * hum seen errno=3 when process is listed in ps,
		 * it seems we don't always retain process grouping
		 *
		 * Direct these fallback attempt to the exact child
		 */
		n = kill(lsp->child_pid, SIGTERM);
		if (n < 0) {
			n = kill(lsp->child_pid, SIGPIPE);
			if (n < 0) {
				n = kill(lsp->child_pid, SIGKILL);
				if (n < 0)
					lwsl_info("%s: SIGKILL PID %d "
						 "failed errno %d "
						 "(maybe zombie)\n", __func__,
						 lsp->child_pid, errno);
			}
		}
	}

	/* He could be unkillable because he's a zombie */

	n = 1;
	while (n > 0) {
		n = waitpid(-lsp->child_pid, &status, WNOHANG);
		if (n > 0)
			lwsl_debug("%s: reaped PID %d\n", __func__, n);
		if (n <= 0) {
			n = waitpid(lsp->child_pid, &status, WNOHANG);
			if (n > 0)
				lwsl_debug("%s: reaped PID %d\n", __func__, n);
		}
	}

	return 0;
}

int
lws_spawn_get_self_cgroup(char *cgroup, size_t max)
{
#if defined(__linux__)
	int fd = open("/proc/self/cgroup", O_RDONLY);
	char *p, s[256], *end = &s[sizeof(s) - 1];
	ssize_t r;
	size_t ur;

	if (fd < 0) {
		lwsl_err("%s: unable to open /proc/self/cgroup\n", __func__);
		return 1;
	}

	r = read(fd, s, sizeof(s) - 2);
	close(fd);
	if (r < 0) {
		lwsl_err("%s: unable to read from /proc/self/cgroup\n", __func__);

		return 1;
	}
	ur = (size_t)r;

	s[ur] = '\0'; 
	p = strchr(s, ':');

	if (!p) {
		lwsl_err("%s: unable to find first :  '%s'\n", __func__, s);
		return 1;
	}

	p = strchr(p + 1, ':');
	if (!p || lws_ptr_diff_size_t(end, p) < 3) {
		lwsl_err("%s: unable to find second :  '%s'\n", __func__, s);

		return 1;
	}
	p++;

	/* name starts from p to NUL */

	ur = strlen(p);

	if (p[ur - 1] == '\n')
		p[--ur] = '\0';

	if (ur > max - 1) {
		lwsl_err("%s: cgroup name too large :  '%s'\n", __func__, s);

		return 1;
	}

	memcpy(cgroup, p, ur + 1u);

	return 0;
#else
	return 1;
#endif
}

/*
 * Deals with spawning a subprocess and executing it securely with stdin/out/err
 * diverted into pipes
 */

struct lws_spawn_piped *
lws_spawn_piped(const struct lws_spawn_piped_info *i)
{
	const struct lws_protocols *pcol = i->vh->context->vhost_list->protocols;
	struct lws_context *context = i->vh->context;
	struct lws_spawn_piped *lsp;
#if defined(__linux__)
	int do_cgroup = 0;
#endif
	const char *wd;
	int n, m;

	if (i->protocol_name)
		pcol = lws_vhost_name_to_protocol(i->vh, i->protocol_name);
	if (!pcol) {
		lwsl_err("%s: unknown protocol %s\n", __func__,
			 i->protocol_name ? i->protocol_name : "default");

		return NULL;
	}

	lsp = lws_zalloc(sizeof(*lsp), __func__);
	if (!lsp)
		return NULL;

	/* wholesale take a copy of info */
	lsp->info = *i;
	lsp->reap_retry_budget = 20;

#if defined(__linux__)
	lsp->cgroup_path[0] = '\0';
#endif

	if (i->p_cgroup_ret)
		*i->p_cgroup_ret = 1; /* Default to cgroup failed */

	/*
	 * Prepare the stdin / out / err pipes
	 */

	for (n = 0; n < 3; n++) {
		lsp->pipe_fds[n][0] = -1;
		lsp->pipe_fds[n][1] = -1;
	}

	/* create pipes for [stdin|stdout] and [stderr] */

	for (n = 0; n < 3; n++) {
		if (pipe(lsp->pipe_fds[n]) == -1)
			goto bail1;
		if (lws_plat_apply_FD_CLOEXEC(lsp->pipe_fds[n][n == 0]))
			lwsl_info("%s: FD_CLOEXEC didn't stick\n", __func__);
	}

	/*
	 * At this point, we have 6 pipe fds open on lws side and no wsis
	 * bound to them
	 */

	/* create wsis for each stdin/out/err fd */

	for (n = 0; n < 3; n++) {
		lsp->stdwsi[n] = lws_create_stdwsi(i->vh->context, i->tsi,
					  i->ops ? i->ops : &role_ops_raw_file);
		if (!lsp->stdwsi[n]) {
			lwsl_err("%s: unable to create lsp stdwsi\n", __func__);
			goto bail2;
		}

                __lws_lc_tag(i->vh->context, &i->vh->context->lcg[LWSLCG_WSI],
                	     &lsp->stdwsi[n]->lc, "nspawn-stdwsi-%d", n);

		lsp->stdwsi[n]->lsp_channel = (uint8_t)n;
		lws_vhost_bind_wsi(i->vh, lsp->stdwsi[n]);
		lsp->stdwsi[n]->a.protocol = pcol;
		lsp->stdwsi[n]->a.opaque_user_data = i->opaque;

		lwsl_debug("%s: lsp stdwsi %p: pipe idx %d -> fd %d / %d\n", __func__,
			   lsp->stdwsi[n], n, lsp->pipe_fds[n][n == 0],
			   lsp->pipe_fds[n][n != 0]);

		/* read side is 0, stdin we want the write side, others read */

		lsp->stdwsi[n]->desc.sockfd = lsp->pipe_fds[n][n == 0];
		if (fcntl(lsp->pipe_fds[n][n == 0], F_SETFL, O_NONBLOCK) < 0) {
			lwsl_err("%s: setting NONBLOCK failed\n", __func__);
			goto bail2;
		}

		/*
		 * We have bound 3 x pipe fds to wsis, wr side of stdin and rd
		 * side of stdout / stderr... those are marked CLOEXEC so they
		 * won't go through the fork
		 *
		 * rd side of stdin and wr side of stdout / stderr are open but
		 * not bound to anything on lws side.
		 */
	}

	/*
	 * Stitch the wsi fd into the poll wait
	 */

	for (n = 0; n < 3; n++) {
		if (context->event_loop_ops->sock_accept)
			if (context->event_loop_ops->sock_accept(lsp->stdwsi[n]))
				goto bail3;

		if (__insert_wsi_socket_into_fds(context, lsp->stdwsi[n]))
			goto bail3;

		lws_dll2_remove(&lsp->stdwsi[n]->pre_natal);

		if (i->opt_parent) {
			lsp->stdwsi[n]->parent = i->opt_parent;
			lsp->stdwsi[n]->sibling_list = i->opt_parent->child_list;
			i->opt_parent->child_list = lsp->stdwsi[n];
		}
	}

	if (lws_change_pollfd(lsp->stdwsi[LWS_STDIN], LWS_POLLIN, LWS_POLLOUT))
		goto bail3;
	if (lws_change_pollfd(lsp->stdwsi[LWS_STDOUT], LWS_POLLOUT, LWS_POLLIN))
		goto bail3;
	if (lws_change_pollfd(lsp->stdwsi[LWS_STDERR], LWS_POLLOUT, LWS_POLLIN))
		goto bail3;

	lwsl_info("%s: fds in %d, out %d, err %d\n", __func__,
		   lsp->stdwsi[LWS_STDIN]->desc.sockfd,
		   lsp->stdwsi[LWS_STDOUT]->desc.sockfd,
		   lsp->stdwsi[LWS_STDERR]->desc.sockfd);
 
#if defined(__linux__)
	if (i->cgroup_name_suffix && i->cgroup_name_suffix[0]) {
		char self_cg[256];

		if (lws_spawn_get_self_cgroup(self_cg, sizeof(self_cg) - 1))
			lwsl_err("%s: failed to get self cgroup\n", __func__);
		else {
			lws_snprintf(lsp->cgroup_path, sizeof(lsp->cgroup_path),
			     "/sys/fs/cgroup%s/%s", self_cg, i->cgroup_name_suffix);

			if (mkdir(lsp->cgroup_path, 0755)) {
				lwsl_warn("%s: failed to generate cgroup dir %s: errno %d\n",
						__func__, lsp->cgroup_path, errno);
				lsp->cgroup_path[0] = '\0';
			} else {
				char pth[300];
				int cfd;

				lws_snprintf(pth, sizeof(pth), "%s/cgroup.type", lsp->cgroup_path);
				cfd = lws_open(pth, LWS_O_WRONLY);
				if (cfd >= 0) {
					if (write(cfd, "threaded", 8) != 8)
						lwsl_warn("%s: failed to write threaded\n", __func__);

					close(cfd);
				}

				lwsl_info("%s: created cgroup %s\n", __func__, lsp->cgroup_path);
				lws_snprintf(pth, sizeof(pth), "%s/pids.max", lsp->cgroup_path);
				cfd = lws_open(pth, LWS_O_WRONLY);
				if (cfd >= 0) {
					if (write(cfd, "max", 3) != 3)
						lwsl_warn("%s: failed to write max\n", __func__);

					close(cfd);
				}

				do_cgroup = 1;
			}
		}
	}

	if (i->p_cgroup_ret)
		/* Report cgroup success to caller */
		*i->p_cgroup_ret = !do_cgroup;

#endif

	/* we are ready with the redirection pipes... do the (v)fork */
#if defined(__sun) || !defined(LWS_HAVE_VFORK) || !defined(LWS_HAVE_EXECVPE)
	lsp->child_pid = fork();
#else
	lsp->child_pid = vfork();
#endif
	if (lsp->child_pid < 0) {
		lwsl_err("%s: fork failed, errno %d", __func__, errno);
		goto bail3;
	}

#if defined(__linux__)
	if (!lsp->child_pid)
		prctl(PR_SET_PDEATHSIG, SIGTERM);
#endif

	if (lsp->info.disable_ctrlc)
		/* stops non-daemonized main processess getting SIGINT
		 * from TTY */
#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
		setpgid(0, 0);
#else
		setpgrp();
#endif

	if (lsp->child_pid) {

		/*
		 * We are the parent process.  We can close our copy of the
		 * "other" side of the pipe fds, ie, rd for stdin and wr for
		 * stdout / stderr.
		 */
		for (n = 0; n < 3; n++)
			/* these guys didn't have any wsi footprint */
			close(lsp->pipe_fds[n][n != 0]);

		lsp->pipes_alive = 3;
		lsp->created = lws_now_usecs();

		lwsl_info("%s: lsp %p spawned PID %d\n", __func__, lsp,
			  lsp->child_pid);

		if (i->timeout_us)
			lws_sul_schedule(context, i->tsi, &lsp->sul, lws_spawn_timeout,
					 i->timeout_us);

		if (i->owner)
			lws_dll2_add_head(&lsp->dll, i->owner);

		if (i->timeout_us)
			lws_sul_schedule(context, i->tsi, &lsp->sul,
					 lws_spawn_timeout, i->timeout_us);

               if (i->plsp)
                       *i->plsp = lsp;

		return lsp;
	}

	/*
	 * We are the forked process, redirect and kill inherited things.
	 *
	 * Because of vfork(), we cannot do anything that changes pages in
	 * the parent environment.  Stuff that changes kernel state for the
	 * process is OK.  Stuff that happens after the execvpe() is OK.
	 */

#if defined(__linux__)
	if (lsp->cgroup_path[0]) {
		char path[300], pid_str[20];
		int fd, len;

		/*
		 * We are the new child process. We must move ourselves into
		 * the cgroup created for us by the parent.
		 */
		lws_snprintf(path, sizeof(path) - 1, "%s/cgroup.procs", lsp->cgroup_path);
		fd = open(path, O_WRONLY);
		if (fd >= 0) {
			len = lws_snprintf(pid_str, sizeof(pid_str) - 1, "%d", (int)getpid());
			if (write(fd, pid_str, (size_t)len) != (ssize_t)len) {
				/*
				 * using lwsl_err here is unsafe in vfork()
				 * child, just exit with a special code
				 */
				_exit(121);
			}
			close(fd);
		} else
			_exit(122);
	}
#endif

	if (i->chroot_path && chroot(i->chroot_path)) {
		lwsl_err("%s: child chroot %s failed, errno %d\n",
			 __func__, i->chroot_path, errno);

		exit(2);
	}

	if (chdir("/")) /* cov */
		lwsl_notice("%s: Failed to cd to /\n", __func__);

	/* cwd: somewhere we can at least read things and enter it */

	wd = i->wd;
	if (!wd)
		wd = "/tmp";
	if (chdir(wd))
		lwsl_notice("%s: Failed to cd to %s\n", __func__, wd);

	/*
	 * Bind the child's stdin / out / err to its side of our pipes
	 */

	for (m = 0; m < 3; m++) {
		if (dup2(lsp->pipe_fds[m][m != 0], m) < 0) {
			lwsl_err("%s: stdin dup2 failed\n", __func__);
			goto bail3;
		}
		/*
		 * CLOEXEC on the lws-side of the pipe fds should have already
		 * dealt with closing those for the child perspective.
		 *
		 * Now it has done the dup, the child should close its original
		 * copies of its side of the pipes.
		 */

		close(lsp->pipe_fds[m][m != 0]);
	}

#if defined(__sun) || !defined(LWS_HAVE_VFORK) || !defined(LWS_HAVE_EXECVPE)
#if defined(__linux__) || defined(__APPLE__) || defined(__sun)
	m = 0;
	while (i->env_array[m]){
		const char *p = strchr(i->env_array[m], '=');
		int naml = lws_ptr_diff(p, i->env_array[m]);
		char enam[32];

		if (p) {
			lws_strnncpy(enam, i->env_array[m], naml, sizeof(enam));
			setenv(enam, p + 1, 1);
		}
		m++;
	}
#endif
	execvp(i->exec_array[0], (char * const *)&i->exec_array[0]);
#else
	execvpe(i->exec_array[0], (char * const *)&i->exec_array[0],
		(char **)&i->env_array[0]);
#endif

	lwsl_err("%s: child exec of %s failed %d\n", __func__, i->exec_array[0],
		 LWS_ERRNO);

	_exit(1);

bail3:

	while (--n >= 0)
		__remove_wsi_socket_from_fds(lsp->stdwsi[n]);
bail2:
	for (n = 0; n < 3; n++)
		if (lsp->stdwsi[n])
			__lws_free_wsi(lsp->stdwsi[n]);

bail1:
	for (n = 0; n < 3; n++) {
		if (lsp->pipe_fds[n][0] >= 0)
			close(lsp->pipe_fds[n][0]);
		if (lsp->pipe_fds[n][1] >= 0)
			close(lsp->pipe_fds[n][1]);
	}

	lws_free(lsp);

	lwsl_err("%s: failed\n", __func__);

	return NULL;
}

void
lws_spawn_closedown_stdwsis(struct lws_spawn_piped *lsp)
{
	int n;

	for (n = 0; n < 3; n++)
		if (lsp->stdwsi[n])
			lws_wsi_close(lsp->stdwsi[n], LWS_TO_KILL_ASYNC);
}

int
lws_spawn_stdwsi_closed(struct lws_spawn_piped *lsp, struct lws *wsi)
{
	int n;

	/*
	 * This is part of the normal cleanup path, check if the lsp has already
	 * been destroyed by a timeout or other error path. If the stdwsi that
	 * is closing has already been nulled out, we have already been through
	 * destroy.
	 */
	for (n = 0; n < 3; n++)
		if (lsp->stdwsi[n] == wsi)
			goto found;

	/* Not found, so must have been destroyed already */
	// lwsl_warn("%s: ----------------- didn't find stdwsi on lsp\n", __func__);

	return 0;

found:
 
	assert(lsp);
	lsp->pipes_alive--;
	lwsl_debug("%s: pipes alive %d\n", __func__, lsp->pipes_alive);
	if (!lsp->pipes_alive)
		lws_sul_schedule(lsp->info.vh->context, lsp->info.tsi,
				 &lsp->sul_reap, lws_spawn_sul_reap, 1);

	for (n = 0; n < 3; n++)
		if (lsp->stdwsi[n] == wsi)
			lsp->stdwsi[n] = NULL;

	return !lsp->pipes_alive;
}

int
lws_spawn_get_stdwsi_open_count(struct lws_spawn_piped *lsp)
{
	return lsp->pipes_alive;
}

int
lws_spawn_get_stdfd(struct lws *wsi)
{
	return wsi->lsp_channel;
}

int
lws_spawn_prepare_self_cgroup(const char *user, const char *group)
{
#if defined(__linux__)
	uid_t uid = (uid_t)-1;
	gid_t gid = (gid_t)-1;
	char path[256], self_cgroup[256];
	int fd;

	if (lws_spawn_get_self_cgroup(self_cgroup, sizeof(self_cgroup) - 1)) {
		lwsl_err("%s: unable to get self cgroup\n", __func__);

		return 1;
	}

	lws_snprintf(path, sizeof(path), "/sys/fs/cgroup%s/cgroup.subtree_control",
			self_cgroup);

	fd = lws_open(path, LWS_O_WRONLY);
	if (fd < 0) {
		/* May fail if user doesn't own the file, that's okay */
		lwsl_notice("%s: cannot open subtree_control: %s\n",
			    __func__, strerror(errno));
		return 0; /* Still a success if dir exists */
	}

	if (write(fd, "+cpu +memory +pids +io", 22) != 22)
		/* ignore, may be there already or fail due to perms */
		lwsl_debug("%s: setting admin cgroup options failed\n", __func__);
	close(fd);

	lws_snprintf(path, sizeof(path), "/sys/fs/cgroup%s", self_cgroup);

	if (user) {
		struct passwd *pwd;

		pwd = getpwnam(user);
		if (pwd)
			uid = pwd->pw_uid;
		else
			lwsl_warn("%s: user '%s' not found\n", __func__, user);
	}
	if (group) {
		struct group *grp;
 
		grp = getgrnam(group);
		if (grp)
			gid = grp->gr_gid;
		else
			lwsl_warn("%s: group '%s' not found\n", __func__, group);
	}

	if (uid != (uid_t)-1 || gid != (gid_t)-1) {

		lwsl_notice("%s: switching %s to %d:%d\n",
				__func__, path, uid, gid);

		if (chown(path, uid, gid) < 0)
			lwsl_warn("%s: failed to chown %s: %s\n",
				  __func__, path, strerror(errno));
		/* 2. ALSO change ownership of the critical control files inside it */
		lws_snprintf(path, sizeof(path), "/sys/fs/cgroup%s/cgroup.procs", self_cgroup);
		if (chown(path, uid, gid) < 0)
			lwsl_warn("%s: failed to chown %s: %s\n",
				  __func__, path, strerror(errno));

		lws_snprintf(path, sizeof(path), "/sys/fs/cgroup%s/cgroup.subtree_control", self_cgroup);
		if (chown(path, uid, gid) < 0)
			lwsl_warn("%s: failed to chown %s: %s\n",
				  __func__, path, strerror(errno));
 	}
	lws_snprintf(path, sizeof(path), "/sys/fs/cgroup%s/lws", self_cgroup);
	if (mkdir(path, 0775) < 0)
		lwsl_err("%s: unable to mkdir %s\n", __func__, path);
	if (uid != (uid_t)-1 || gid != (gid_t)-1) {

		lwsl_notice("%s: switching %s to %d:%d\n",
				__func__, path, uid, gid);

		if (chown(path, uid, gid) < 0)
			lwsl_warn("%s: failed to chown %s: %s\n",
				  __func__, path, strerror(errno));
		/* 2. ALSO change ownership of the critical control files inside it */
		lws_snprintf(path, sizeof(path), "/sys/fs/cgroup%s/cgroup.procs", self_cgroup);
		if (chown(path, uid, gid) < 0)
			lwsl_warn("%s: failed to chown %s: %s\n",
				  __func__, path, strerror(errno));

		lws_snprintf(path, sizeof(path), "/sys/fs/cgroup%s/cgroup.subtree_control", self_cgroup);
		if (chown(path, uid, gid) < 0)
			lwsl_warn("%s: failed to chown %s: %s\n",
				  __func__, path, strerror(errno));
 	}


	lwsl_notice("%s: lws cgroup parent configured: %s\n", __func__, path);

	return 0;
#endif
	return 1; /* Not supported on this platform */
}

int
lws_spawn_get_fd_stdxxx(struct lws_spawn_piped *lsp, int std_idx)
{
	assert(std_idx >= 0 && std_idx < 3);

	return lsp->pipe_fds[std_idx][!!(std_idx == 0)];
}
