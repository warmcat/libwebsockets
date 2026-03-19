/*
 * sai-builder
 *
 * Copyright (C) 2019 - 2025 Andy Green <andy@warmcat.com>
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
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#include <limits.h>
#include <stdlib.h>
#include <fcntl.h>

#include <sys/types.h>
#if !defined(WIN32)
#include <pwd.h>
#include <grp.h>
#endif

#if defined(__linux__) || defined(__APPLE__)
#include <unistd.h>
#endif

#if defined(__APPLE__)
#include <sys/stat.h>	/* for mkdir() */
#endif

#if defined(WIN32)
#include <initguid.h>
#include <KnownFolders.h>
#include <Shlobj.h>
#include <processthreadsapi.h>
#include <handleapi.h>


#if !defined(PATH_MAX)
#define PATH_MAX MAX_PATH
#endif
#endif

#include "b-private.h"

int
sai_deletion_worker(const char *home_dir)
{
	char *p, line[PATH_MAX], buf[4096];
	ssize_t n, len = 0;
	char *nl;

	lwsl_notice("%s: deletion worker started\n", __func__);

#if defined(WIN32)
	/*
	 * On Windows, stdin is not a pipe from the parent but a handle
	 * value passed on the commandline
	 */
	FreeConsole();
#endif

	do {
		n = read(0, buf + len, (sizeof(buf) - 1) - (unsigned int)len);
		if (n <= 0) {
			lwsl_notice("%s: pipe closed, exiting\n", __func__);
			return 0;
		}
		len += n;

		do {
			nl = memchr(buf, '\n', (unsigned int)len);
			if (!nl)
				break;

			*nl = '\0';
			lws_strncpy(line, buf, sizeof(line));

			len -= (nl - buf) + 1;
			memmove(buf, nl + 1, (unsigned int)len);

			p = line;
			/* sanitize: no .. or / or \ */
			while (*p) {
				if (*p == '.' || *p == '/' || *p == '\\') {
					lwsl_err("%s: invalid chars in delete path '%s'\n",
						 __func__, line);
					p = NULL;
					break;
				}
				p++;
			}
			if (!p)
				continue;

			lwsl_info("%s: received delete request for '%s'\n", __func__, line);

			{
				struct lws_dir_info di;
				char full_path[PATH_MAX];
				struct stat st;

				lws_snprintf(full_path, sizeof(full_path),
					     "%s/jobs/%s", home_dir, line);

				if (stat(full_path, &st)) {
					// lwsl_notice("%s: %s already gone or inaccessible\n", __func__, full_path);
					continue;
				}

				memset(&di, 0, sizeof(di));
				di.dirpath = full_path;
				di.cb = lws_dir_rm_rf_cb;
				di.do_toplevel_cb = 1;

				lwsl_info("%s: performing rm -rf %s\n", __func__, full_path);

				if (lws_dir_via_info(&di))
					lwsl_err("%s: failed to delete %s: %s\n",
						 __func__, full_path, strerror(errno));
			}
		} while (1);

	} while (1);

	return 0;
}

/*
 * Periodically (eg, once per hour) we walk the jobs dir and find subdirs
 * that are older than a day.
 *
 * These represent failed jobs that were left for inspection, but should now
 * be cleaned up.
 *
 * We are careful not to delete anything that is part of an ongoing job.
 */

struct active_job_uuids {
	lws_dll2_owner_t owner;
};

struct active_job_uuid {
	lws_dll2_t list;
	char uuid[65];
};

int
scan_jobs_dir_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	struct active_job_uuids *active = (struct active_job_uuids *)user;
	char path[512];
	struct stat sb;

	if (lde->name[0] == '.')
		return 0;

	lws_start_foreach_dll(struct lws_dll2 *, p, active->owner.head) {
		struct active_job_uuid *aj = lws_container_of(p, struct active_job_uuid, list);

		if (!strcmp(aj->uuid, lde->name)) {
			/* it's an active job, leave it alone */
			lwsl_info("%s: %s is active\n", __func__, lde->name);
			return 0;
		}

	} lws_end_foreach_dll(p);

	lws_snprintf(path, sizeof(path), "%s/%s", dirpath, lde->name);
	if (stat(path, &sb)) {
		lwsl_notice("%s: stat failed %s\n", __func__, path);
		return 0;
	}

	if (!S_ISDIR(sb.st_mode)) {
		lwsl_notice("%s: %s is not a dir\n", __func__, path);
		return 0;
	}

	/* older than 24h? */

	if (((uint64_t)lws_now_secs() - (uint64_t)sb.st_mtime) > SAI_CLEANUP_JOB_DIR_MIN_AGE_SECS) {
		char temp[128];
		size_t len = (size_t)lws_snprintf(temp, sizeof(temp), "%s\n", lde->name);
#if defined(WIN32)
		DWORD written;
#endif

		lwsl_info("%s: requesting removal of old job dir %s (age %llus)\n",
			    __func__, path, (unsigned long long)
			    ((uint64_t)lws_now_secs() - (uint64_t)sb.st_mtime));

#if !defined(WIN32)
		if (write(builder.pipe_master_wr, temp, LWS_POSIX_LENGTH_CAST(len)) != (ssize_t)len)
#else
		if (!WriteFile(builder.pipe_master_wr_win, temp, (DWORD)len,
				&written, NULL) || written != (DWORD)len)
#endif
			lwsl_err("%s: failed to write to deletion worker\n",
			 __func__);
	} else {
		lwsl_info("%s: %s is only %llus old\n", __func__, path,
			    (unsigned long long)
			    ((uint64_t)lws_now_secs() - (uint64_t)sb.st_mtime));
	}

	return 0;
}

void
sul_cleanup_jobs_cb(lws_sorted_usec_list_t *sul)
{
	struct sai_builder *b = lws_container_of(sul, struct sai_builder,
						 sul_cleanup_jobs);
	struct active_job_uuids active;
	struct lwsac *ac = NULL;
	char path[256];

	lwsl_info("%s: starting periodic cleanup\n", __func__);

	memset(&active, 0, sizeof(active));

	/*
	 * We must not delete any active job directories, find out the uuids
	 * of any active jobs
	 */
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   b->sai_plat_owner.head) {
		struct sai_plat *sp = lws_container_of(d,
					struct sai_plat, sai_plat_list);
		lws_start_foreach_dll_safe(struct lws_dll2 *, d2, d3,
					   sp->nspawn_owner.head) {
			struct sai_nspawn *ns = lws_container_of(d2,
						struct sai_nspawn, list);
			struct active_job_uuid *aj;

			if (!ns->task)
				continue;

			aj = lwsac_use_zero(&ac, sizeof(*aj), 64);
			if (!aj)
				continue;

			lws_strncpy(aj->uuid, ns->task->uuid, sizeof(aj->uuid));
			lws_dll2_add_tail(&aj->list, &active.owner);
		} lws_end_foreach_dll_safe(d2, d3);
	} lws_end_foreach_dll_safe(d, d1);

	/*
	 * Now we have the active job uuids, scan the jobs dir and check
	 * for old, inactive job dirs to reap
	 */

	lws_snprintf(path, sizeof(path), "%s/jobs", b->home);
	lws_dir(path, &active, scan_jobs_dir_cb);

	lwsac_free(&ac);

	lws_sul_schedule(b->context, 0, &b->sul_cleanup_jobs,
			 sul_cleanup_jobs_cb, SAI_CLEANUP_JOBS_INTERVAL_US);
}

int
saib_deletion_init(const char *argv0)
{
#if !defined(WIN32)
	{
		int pfd[2];
		pid_t pid;

		if (pipe(pfd) == -1) {
			lwsl_err("pipe() failed\n");
			return 1;
		}

		fcntl(pfd[0], F_SETFD, FD_CLOEXEC);
		fcntl(pfd[1], F_SETFD, FD_CLOEXEC);

		pid = fork();
		if (pid == -1) {
			lwsl_err("fork() failed\n");
			return 1;
		}

		if (!pid) {
			/* child: deletion worker */
			char home_arg[256];

			lws_snprintf(home_arg, sizeof(home_arg), "--home=%s",
				     builder.home);
			close(pfd[1]); /* wr */
			if (dup2(pfd[0], 0) < 0)
				return 1;
			close(pfd[0]);

			execlp(argv0, argv0, home_arg, "--delete-worker", (char *)NULL);
			lwsl_err("execlp failed\n");
			return 1;
		}

		/* parent */
		close(pfd[0]); /* rd */
		builder.pipe_master_wr = pfd[1];
	}
#else
	{
		char cmdline[512];
		HANDLE hChildStd_IN_Rd = NULL;
		HANDLE hChildStd_IN_Wr = NULL;
		SECURITY_ATTRIBUTES sa;
		PROCESS_INFORMATION pi;
		STARTUPINFOA si;

		sa.nLength = sizeof(SECURITY_ATTRIBUTES);
		sa.bInheritHandle = TRUE;
		sa.lpSecurityDescriptor = NULL;

		if (!CreatePipe(&hChildStd_IN_Rd, &hChildStd_IN_Wr, &sa, 0)) {
			lwsl_err("CreatePipe failed\n");
			return 1;
		}
		if (!SetHandleInformation(hChildStd_IN_Wr, HANDLE_FLAG_INHERIT, 0)) {
			lwsl_err("SetHandleInformation failed\n");
			return 1;
		}

		memset(&pi, 0, sizeof(pi));
		memset(&si, 0, sizeof(si));
		si.cb = sizeof(si);
		si.hStdInput = hChildStd_IN_Rd;
		si.dwFlags |= STARTF_USESTDHANDLES;

		lws_snprintf(cmdline, sizeof(cmdline), "%s --delete-worker --home=%s",
			     argv0, builder.home);

		if (!CreateProcessA(NULL, cmdline, NULL, NULL, TRUE, 0,
				    NULL, NULL, &si, &pi)) {
			lwsl_err("CreateProcess failed\n");
			return 1;
		}

		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		CloseHandle(hChildStd_IN_Rd);
		builder.pipe_master_wr_win = hChildStd_IN_Wr;
	}
#endif
	return 0;
}

