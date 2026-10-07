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

#if !defined(_CRT_SECURE_NO_WARNINGS)
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <libwebsockets.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <limits.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#if !defined(WIN32)
#include <pwd.h>
#include <grp.h>
#endif

#if defined(__linux__) || defined(__APPLE__)
#include <unistd.h>
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

#ifndef S_ISDIR
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#endif

#include "b-private.h"
#if defined(LWS_WITH_STUB)
#include <libwebsockets/lws-stub.h>
#endif

#if defined(LWS_WITH_STUB)

static int
sai_rm_rf_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	char path[PATH_MAX];

	if (lde->name[0] == '.' && lde->name[1] == '\0')
		return 0;
	if (lde->name[0] == '.' && lde->name[1] == '.' && lde->name[2] == '\0')
		return 0;

	lws_snprintf(path, sizeof(path), "%s/%s", dirpath, lde->name);

	if (lde->type == LDOT_DIR) {
		lws_dir(path, user, sai_rm_rf_cb);
#if defined(WIN32)
		SetFileAttributesA(path, FILE_ATTRIBUTE_NORMAL);
#endif
		if (rmdir(path))
			lwsl_notice("%s: rmdir %s failed: errno %d (%s)\n", __func__, path, errno, strerror(errno));
	} else {
		if (unlink(path)) {
#if defined(WIN32)
			SetFileAttributesA(path, FILE_ATTRIBUTE_NORMAL);
			if (unlink(path))
#endif
				lwsl_notice("%s: unlink %s failed: errno %d (%s)\n", __func__, path, errno, strerror(errno));
		}
	}

	return 0;
}

/*
 * Shared between sai_deletion_worker() (whose frame never returns while the
 * stub lives) and the UDS protocol via the vhost user pointer.
 */
struct deletion_worker_state {
	const char	*home_dir;
	const char	*secret;
};

struct child_conn {
	struct lejp_ctx jctx;
	const char *secret;		/* the stub secret, from stdin */
	char home_dir[PATH_MAX];
	unsigned int authenticated:1;
};

static signed char
child_lejp_cb(struct lejp_ctx *ctx, char reason)
{
	struct child_conn *conn = (struct child_conn *)ctx->user;

	if (reason == LEJPCB_VAL_STR_END && !strcmp(ctx->path, "secret")) {
		/*
		 * Every request must carry the exact 128-char stub secret.
		 * The socket is owner-only as well, but this is the gate that
		 * distinguishes the parent from anything else running as our
		 * uid.  Compare in constant time and fixed length.
		 */
		if (strlen(ctx->buf) != 128 ||
		    lws_timingsafe_bcmp(ctx->buf, conn->secret, 128)) {
			lwsl_warn("%s: bad stub secret, dropping connection\n",
				  __func__);
			return -1;
		}

		conn->authenticated = 1;

		return 0;
	}

	if (reason == LEJPCB_VAL_STR_END && !strcmp(ctx->path, "delete")) {
		struct lws_dir_info di;
		char full_path[PATH_MAX];
		struct stat st;

		if (!conn->authenticated) {
			lwsl_warn("%s: delete request without secret, ignoring\n",
				  __func__);
			return -1;
		}

		lwsl_notice("%s: received delete request for '%s'\n", __func__, ctx->buf);

		/*
		 * Security: ctx->buf is the JSON "delete" field received over
		 * the deletion UDS.  It is joined into a path and recursively
		 * unlinked below.  Reject anything that could escape the
		 * intended <home>/jobs/ tree: absolute paths, parent-dir
		 * traversal, and shell/path metacharacters.  Also apply
		 * lws_filename_purify_inplace as defense-in-depth (this scrubs
		 * .., :, \, $, % but not / so we check that explicitly above).
		 */
		if (ctx->buf[0] == '/' || strstr(ctx->buf, "..") ||
		    strchr(ctx->buf, '\\')) {
			lwsl_warn("%s: rejecting unsafe delete path '%s'\n",
				  __func__, ctx->buf);
			return -1;
		}
		lws_filename_purify_inplace(ctx->buf);

		lws_snprintf(full_path, sizeof(full_path), "%s/jobs/%s", conn->home_dir, ctx->buf);

		/*
		 * Don't stat the path first: the sanitizing above is the
		 * actual security gate, a stat-then-act is a TOCTOU race
		 * (CID 505638), and lws_dir_via_info() returns 1 whether or
		 * not the dir could be opened anyway.  So just attempt the
		 * removal directly and report a missing job dir from the
		 * rmdir() errno instead.
		 */
		memset(&di, 0, sizeof(di));
		di.dirpath = full_path;
		di.cb = sai_rm_rf_cb;
		di.do_toplevel_cb = 1;

		lwsl_notice("%s: performing rm -rf %s\n", __func__, full_path);

		/* Errors are logged by sai_rm_rf_cb. */
		lws_dir_via_info(&di);
#if defined(WIN32)
		SetFileAttributesA(full_path, FILE_ATTRIBUTE_NORMAL);
#endif
		if (rmdir(full_path) && errno == ENOENT)
			lwsl_notice("%s: job dir %s not found (errno %d)\n",
				    __func__, full_path, errno);

		if (!stat(full_path, &st))
			lwsl_notice("%s: top level dir %s still exists\n", __func__, full_path);
	}
	return 0;
}

static const char * const child_paths[] = { "secret", "delete" };

static int
callback_sai_deletion_uds(struct lws *wsi, enum lws_callback_reasons reason,
		    void *user, void *in, size_t len)
{
	struct child_conn *conn = (struct child_conn *)user;

	switch (reason) {
	case LWS_CALLBACK_RAW_ADOPT:
		/* Get home_dir + secret from vhost user data */
		{
			struct deletion_worker_state *vuser =
				(struct deletion_worker_state *)
					lws_get_vhost_user(lws_get_vhost(wsi));

			if (!vuser) {
				lwsl_err("%s: ADOPT: no vhost user data\n", __func__);
				return -1;
			}
			lws_strncpy(conn->home_dir, vuser->home_dir,
				    sizeof(conn->home_dir));
			conn->secret = vuser->secret;
		}
		lejp_construct(&conn->jctx, child_lejp_cb, conn, child_paths,
			       LWS_ARRAY_SIZE(child_paths));
		break;

	case LWS_CALLBACK_RAW_RX: {
		uint8_t *p = (uint8_t *)in;
		while (len) {
			int m = lejp_parse(&conn->jctx, p, 1);
			if (m < 0 && m != LEJP_CONTINUE) {
				/* 
				 * We hit the end of a JSON object and the start of the next one,
				 * which lejp rejects as trailing garbage. Reset the parser and 
				 * retry this byte! 
				 */
				lejp_destruct(&conn->jctx);
				lejp_construct(&conn->jctx, child_lejp_cb, conn, child_paths, LWS_ARRAY_SIZE(child_paths));
				continue;
			}
			p++;
			len--;
		}
		break;
	}

	case LWS_CALLBACK_RAW_CLOSE:
		lejp_destruct(&conn->jctx);
		lwsl_notice("%s: parent connection closed, stub exiting\\n", __func__);
		lws_cancel_service(lws_get_context(wsi));
		break;

	default:
		break;
	}
	return 0;
}

static struct lws_protocols protocol_deletion_uds[] = {
	{
		.name			= "sai-deletion-uds",
		.callback		= callback_sai_deletion_uds,
		.per_session_data_size	= sizeof(struct child_conn),
		.rx_buffer_size		= 0,
	},
	{ NULL, NULL, 0, 0 }
};

#if defined(__linux__) || defined(__APPLE__)
extern void crash_handler(int signum);
#endif

int
sai_deletion_worker(const char *home_dir_unused)
{
	struct deletion_worker_state wstate;
	struct lws_context_creation_info info;
	struct lws_context *cx;
	struct lws_vhost *vh_uds;
#if !defined(WIN32)
	mode_t om;
#endif
	char uds[256];
	char secret[129];
	char home_dir[PATH_MAX];
	size_t rx = 0;

#if defined(__linux__) || defined(__APPLE__)
	signal(SIGSEGV, crash_handler);
	signal(SIGABRT, crash_handler);
	signal(SIGBUS, crash_handler);
	signal(SIGILL, crash_handler);
	signal(SIGFPE, crash_handler);
#endif

	lwsl_notice("%s: deletion worker (stub) started\n", __func__);

	/* 1. Read secret from stdin */
#if defined(WIN32)
	_setmode(0, _O_BINARY);
#endif

	while (rx < 128) {
		ssize_t n = read(0, secret + rx, 128 - (unsigned int)rx);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			break;
		rx += (size_t)n;
	}

	if (rx < 64) {
		lwsl_err("%s: Failed to read secret from stdin\n", __func__);
		return 1;
	}
	secret[128] = '\0';

	/* 2. Read home_dir from stdin */
	{
		ssize_t n;
		do {
			n = read(0, home_dir, sizeof(home_dir) - 1);
		} while (n < 0 && errno == EINTR);
		
		if (n <= 0) {
			lwsl_err("%s: Failed to read home_dir\n", __func__);
			return 1;
		}
		home_dir[n] = '\0';
	}

	/* 3. Setup context */
	memset(&info, 0, sizeof(info));
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
	cx = lws_create_context(&info);
	if (!cx)
		return 1;

	lws_snprintf(uds, sizeof(uds), "%s/sai-deletion.sock", home_dir);

	wstate.home_dir = home_dir;
	wstate.secret = secret;

	/* 4. Create UDS server vhost */
	memset(&info, 0, sizeof(info));
	info.options = LWS_SERVER_OPTION_UNIX_SOCK | LWS_SERVER_OPTION_ONLY_RAW;
	info.iface = uds;
	info.protocols = protocol_deletion_uds;
	info.vhost_name = "sai-deletion";
	info.user = &wstate;

	/*
	 * bind() inside lws_create_vhost() creates the socket file with its
	 * mode masked by the process umask, so that is the only place the
	 * mode can be decided without a window where it is wrong: a chmod()
	 * afterwards leaves a window where the socket is connectable by more
	 * than our own uid.  So bind under a tightened umask instead and do
	 * not chmod the path at all (mirrors lws_stub_server_init()).
	 */

#if !defined(WIN32)
	om = umask(0077);
#endif
	unlink(info.iface);
	vh_uds = lws_create_vhost(cx, &info);
#if !defined(WIN32)
	umask(om);
#endif

	if (!vh_uds) {
		lwsl_err("%s: Failed to create UDS vhost\n", __func__);
		return 1;
	}

	lwsl_notice("STUB-READY (sai-deletion)\n");

	while (lws_service(cx, 0) >= 0)
		;

	lws_context_destroy(cx);
	return 0;
}

#endif

/*
 * Periodically (eg, once per hour) we walk the jobs dir and find subdirs
 * that are older than a day.
 *
 * These represent failed jobs that were left for inspection, but should now
 * be cleaned up.
 *
 * We are careful not to delete anything that is part of an ongoing job.
 */

/*
 * Wall clock step detection
 *
 * A builder VM commonly boots with a nonsense date and has ntp correct it a
 * moment later.  Job dir ages are wall clock now minus the dir's mtime, so a
 * forward step makes every dir written before it look exactly that much older
 * than it is -- a job dir created seconds ago looks a day and a half old, is
 * past the 24h threshold, and gets deleted while its task is still building.
 * A backward step is worse: the mtimes are then in the future, and the age
 * subtraction below used to wrap to an enormous number, so everything went.
 *
 * We cannot tell a pre-step mtime from a genuinely old one, so once a step is
 * seen we simply stop deciding anything from ages for a while.  Removing old
 * job dirs is housekeeping and the next pass will do it.
 */

void
saib_clock_baseline(void)
{
	builder.mono_at_base		= lws_now_usecs();
	builder.wall_at_base		= (uint64_t)lws_now_secs();
	builder.mono_last_clock_step	= 0;
}

int
saib_clock_ages_trustworthy(void)
{
	lws_usec_t mono = lws_now_usecs();
	uint64_t wall = (uint64_t)lws_now_secs(), expect;
	int64_t delta;

	if (!builder.wall_at_base) {
		/* nothing has baselined us yet, so this is the baseline */
		saib_clock_baseline();

		return 1;
	}

	expect = builder.wall_at_base +
		 (uint64_t)((mono - builder.mono_at_base) / LWS_US_PER_SEC);

	delta = (int64_t)wall - (int64_t)expect;

	if (delta > SAI_CLOCK_STEP_TOLERANCE_SECS ||
	    delta < -SAI_CLOCK_STEP_TOLERANCE_SECS) {

		lwsl_warn("%s: wall clock stepped by %llds (ntp on a VM that "
			  "booted with the wrong date?): not trusting job dir "
			  "ages for the next %ds\n", __func__,
			  (long long)delta, SAI_CLOCK_STEP_SETTLE_SECS);

		/*
		 * Tell anything we are building, since this also explains the
		 * jump it is about to see in its own log timestamps
		 */

		lws_start_foreach_dll(struct lws_dll2 *, d,
				      builder.sai_plat_owner.head) {
			sai_plat_t *sp = lws_container_of(d, sai_plat_t,
							 sai_plat_list);

			lws_start_foreach_dll(struct lws_dll2 *, d2,
					      sp->nspawn_owner.head) {
				struct sai_nspawn *ns = lws_container_of(d2,
						struct sai_nspawn, list);

				saib_task_logf(ns->spm, ns, NULL,
					"the builder's wall clock just stepped "
					"by %llds, most likely ntp correcting a "
					"VM that booted with the wrong date",
					(long long)delta);

			} lws_end_foreach_dll(d2);
		} lws_end_foreach_dll(d);

		/* rebase, so a single step is only reported once */

		builder.wall_at_base		= wall;
		builder.mono_at_base		= mono;
		builder.mono_last_clock_step	= mono;

		return 0;
	}

	if (!builder.mono_last_clock_step)
		return 1;

	if (mono - builder.mono_last_clock_step <
			(lws_usec_t)SAI_CLOCK_STEP_SETTLE_SECS * LWS_US_PER_SEC)
		return 0;

	builder.mono_last_clock_step = 0;

	return 1;
}

/*
 * Job dir holds
 *
 * A task's build steps are each offered, run and destroyed separately, so
 * between one step finishing and the next being offered there is no nspawn
 * pointing at the job dir.  The live-nspawn scan below is therefore not enough
 * to protect a job dir of a build that is still going: a hold covers the gap.
 *
 * Holds are renewed at every step and dropped when the task finishes or fails,
 * with a generous expiry as a backstop for a task that vanished server-side.
 */

static saib_jobdir_hold_t *
saib_jobdir_hold_find(const char *vn)
{
	lws_start_foreach_dll(struct lws_dll2 *, p, builder.jobdir_hold_owner.head) {
		saib_jobdir_hold_t *h = lws_container_of(p, saib_jobdir_hold_t, list);

		if (!strcmp(h->vn, vn))
			return h;

	} lws_end_foreach_dll(p);

	return NULL;
}

void
saib_jobdir_hold(const char *vn)
{
	saib_jobdir_hold_t *h;

	if (!vn || !vn[0])
		return;

	h = saib_jobdir_hold_find(vn);
	if (!h) {
		h = malloc(sizeof(*h));
		if (!h)
			return;
		memset(h, 0, sizeof(*h));
		lws_strncpy(h->vn, vn, sizeof(h->vn));
		lws_dll2_add_tail(&h->list, &builder.jobdir_hold_owner);
		lwsl_info("%s: holding job dir %s\n", __func__, vn);
	}

	h->renewed = (uint64_t)lws_now_secs();
}

void
saib_jobdir_release(const char *vn)
{
	saib_jobdir_hold_t *h;

	if (!vn || !vn[0])
		return;

	h = saib_jobdir_hold_find(vn);
	if (!h)
		return;

	lwsl_info("%s: releasing job dir %s\n", __func__, vn);
	lws_dll2_remove(&h->list);
	free(h);
}

int
saib_jobdir_is_held(const char *vn)
{
	saib_jobdir_hold_t *h = saib_jobdir_hold_find(vn);
	uint64_t now;

	if (!h)
		return 0;

	now = (uint64_t)lws_now_secs();

	if (now > h->renewed &&
	    now - h->renewed > SAI_JOBDIR_HOLD_MAX_SECS) {
		lwsl_notice("%s: hold on job dir %s expired after %llus\n",
			    __func__, vn,
			    (unsigned long long)(now - h->renewed));
		lws_dll2_remove(&h->list);
		free(h);

		return 0;
	}

	return 1;
}

/*
 * How many job dirs are held for tasks we are still building... expired holds
 * are dropped on the way
 */

unsigned int
saib_jobdir_holds_live(void)
{
	unsigned int n = 0;

	lws_start_foreach_dll_safe(struct lws_dll2 *, p, p1,
				   builder.jobdir_hold_owner.head) {
		saib_jobdir_hold_t *h = lws_container_of(p, saib_jobdir_hold_t, list);

		if (saib_jobdir_is_held(h->vn))
			n++;

	} lws_end_foreach_dll_safe(p, p1);

	return n;
}

void
saib_jobdir_holds_destroy(void)
{
	lws_start_foreach_dll_safe(struct lws_dll2 *, p, p1,
				   builder.jobdir_hold_owner.head) {
		saib_jobdir_hold_t *h = lws_container_of(p, saib_jobdir_hold_t, list);

		lws_dll2_remove(&h->list);
		free(h);

	} lws_end_foreach_dll_safe(p, p1);
}

struct inactive_job {
	struct inactive_job *next;
	char name[32];
	uint64_t age;
};

struct cleanup_ctx {
	lws_dll2_owner_t active_owner;
	struct lwsac *ac;
	struct inactive_job *inactive_head;
	int inactive_count;
	/* may we believe wall-clock-derived file ages on this pass? */
	char ages_trustworthy;
	/* ask again about dirs moved aside for deletion still lying around */
	char reap_aside;
};

struct active_job_uuid {
	lws_dll2_t list;
	char uuid[65];
};

#if defined(LWS_WITH_STUB)
static int
saib_deletion_request_name(const char *name);
#endif

static int
compare_age(const void *a, const void *b)
{
	const struct inactive_job *ia = *(const struct inactive_job **)a;
	const struct inactive_job *ib = *(const struct inactive_job **)b;

	if (ia->age > ib->age)
		return -1;
	if (ia->age < ib->age)
		return 1;
	return 0;
}

int
scan_jobs_dir_cb(const char *dirpath, void *user, struct lws_dir_entry *lde)
{
	struct cleanup_ctx *ctx = (struct cleanup_ctx *)user;
	char path[512], path2[512];
	struct stat sb, sb2;
	uint64_t age;

	if (lde->name[0] == '.') {
#if defined(LWS_WITH_STUB)
		/*
		 * A job dir we moved aside to delete and is still here: the
		 * stub went away before it got to it, or we did
		 */
		if (ctx->reap_aside && builder.mgr_deletion &&
		    !strncmp(lde->name, SAIB_JOBDIR_DELETING_PREFIX,
			     strlen(SAIB_JOBDIR_DELETING_PREFIX))) {
			lwsl_notice("%s: %s left over, deleting it\n",
				    __func__, lde->name);
			saib_deletion_request_name(lde->name);
		}
#endif
		return 0;
	}

	lws_start_foreach_dll(struct lws_dll2 *, p, ctx->active_owner.head) {
		struct active_job_uuid *aj = lws_container_of(p, struct active_job_uuid, list);

		if (!strcmp(aj->uuid, lde->name)) {
			/* it's an active job, leave it alone */
			lwsl_info("%s: %s is active\n", __func__, lde->name);
			return 0;
		}

	} lws_end_foreach_dll(p);

	/*
	 * A task between two of its steps has no live nspawn, so it will not be
	 * on the active list above... but its job dir still holds the tree the
	 * next step is going to build in
	 */

	if (saib_jobdir_is_held(lde->name)) {
		lwsl_info("%s: %s is held (task still building)\n", __func__,
			  lde->name);
		return 0;
	}

	lws_snprintf(path, sizeof(path), "%s/%s", dirpath, lde->name);
	if (stat(path, &sb)) {
		lwsl_notice("%s: stat failed %s: errno %d (%s)\n", __func__, path, errno, strerror(errno));
		return 0;
	}

	if (!S_ISDIR(sb.st_mode)) {
		lwsl_notice("%s: %s is not a dir\n", __func__, path);
		return 0;
	}

#if !defined(WIN32)
	lws_snprintf(path2, sizeof(path2), "%s/git_helper.sh", path);
#else
	lws_snprintf(path2, sizeof(path2), "%s/git_helper.bat", path);
#endif
	if (!stat(path2, &sb2)) {
		sb.st_mtime = sb2.st_mtime;
	}

	/* older than 24h? */

	{
		uint64_t now = (uint64_t)lws_now_secs();

		/*
		 * An mtime in the future means the clock went backwards since
		 * the dir was written; it does not mean the dir is older than
		 * the epoch, which is what the unsigned subtraction used to
		 * produce
		 */
		age = now > (uint64_t)sb.st_mtime ?
				now - (uint64_t)sb.st_mtime : 0;
	}

	if (age > SAI_CLEANUP_JOB_DIR_MIN_AGE_SECS && ctx->ages_trustworthy) {
		lwsl_info("%s: requesting removal of old job dir %s (age %llus)\n",
			    __func__, path, (unsigned long long)age);

#if defined(LWS_WITH_STUB)
					if (builder.mgr_deletion)
						saib_deletion_request(lde->name);
#endif
	} else {
		struct inactive_job *ij = lwsac_use_zero(&ctx->ac, sizeof(*ij), 0);
		if (ij) {
			lws_strncpy(ij->name, lde->name, sizeof(ij->name));
			ij->age = age;
			ij->next = ctx->inactive_head;
			ctx->inactive_head = ij;
			ctx->inactive_count++;
		}
		lwsl_info("%s: %s is only %llus old\n", __func__, path,
			    (unsigned long long)age);
	}

	return 0;
}

/*
 * Try to get \p needed_kib available under <home>/jobs by removing job dirs.
 *
 * \p protect_vn, if given, is the job dir of the task this is being done on
 * behalf of: it must survive even though it has no live nspawn, since its
 * earlier steps' output is what the next step builds on.
 */

int
saib_deletion_free_kib(unsigned int needed_kib, const char *protect_vn)
{
	struct sai_builder *b = &builder;
	struct cleanup_ctx ctx;
	char path[256];
	unsigned int free_kib = saib_get_free_disk_kib(b->home);

	if (free_kib >= needed_kib)
		return 0;

	memset(&ctx, 0, sizeof(ctx));
	ctx.ages_trustworthy = (char)saib_clock_ages_trustworthy();

	/* find out the uuids of any active jobs */
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, b->sai_plat_owner.head) {
		struct sai_plat *sp = lws_container_of(d, struct sai_plat, sai_plat_list);
		lws_start_foreach_dll_safe(struct lws_dll2 *, d2, d3, sp->nspawn_owner.head) {
			struct sai_nspawn *ns = lws_container_of(d2, struct sai_nspawn, list);
			struct active_job_uuid *aj;

			if (!ns->task) continue;

			aj = lwsac_use_zero(&ctx.ac, sizeof(*aj), 64);
			if (aj) {
				lws_strncpy(aj->uuid, ns->inp_vn, sizeof(aj->uuid));
				lws_dll2_add_tail(&aj->list, &ctx.active_owner);
			}
		} lws_end_foreach_dll_safe(d2, d3);
	} lws_end_foreach_dll_safe(d, d1);

	/*
	 * Add the dir we must not touch to the active list: the scan spares
	 * anything on it, and it needs no other special-casing
	 */

	if (protect_vn && protect_vn[0]) {
		struct active_job_uuid *aj = lwsac_use_zero(&ctx.ac, sizeof(*aj), 64);

		if (aj) {
			lws_strncpy(aj->uuid, protect_vn, sizeof(aj->uuid));
			lws_dll2_add_tail(&aj->list, &ctx.active_owner);
		}
	}

	lws_snprintf(path, sizeof(path), "%s/jobs", b->home);
	lws_dir(path, &ctx, scan_jobs_dir_cb);

	if (ctx.inactive_count) {
		int n, to_delete = 1, candidates = 0;
		struct inactive_job **sorted, *ij;

		sorted = lwsac_use(&ctx.ac, sizeof(*sorted) * (unsigned int)ctx.inactive_count, 0);
		if (sorted) {
			ij = ctx.inactive_head;
			while (ij) {
				/*
				 * Unlike the periodic cleanup, we delete dirs
				 * that are not yet a day old, so we need our
				 * own floor: something this fresh belongs to a
				 * build that is still going on (a task waiting
				 * for its next step to be offered, say) and
				 * taking it just breaks that build instead of
				 * fixing our disk problem.
				 */
				if (ctx.ages_trustworthy &&
				    ij->age >= SAI_FREEKIB_JOB_DIR_MIN_AGE_SECS)
					sorted[candidates++] = ij;
				else
					lwsl_info("%s: sparing %s, only %llus old\n",
						  __func__, ij->name,
						  (unsigned long long)ij->age);
				ij = ij->next;
			}

			if (!candidates) {
				lwsl_warn("%s: need %uMiB, only %uMiB free, but "
					  "no job dir is old enough to remove%s\n",
					  __func__, needed_kib / 1024,
					  free_kib / 1024,
					  ctx.ages_trustworthy ? "" :
					    " (and the wall clock stepped "
					    "recently, so their ages cannot be "
					    "believed)");
				goto done;
			}

			/* Assume each job frees roughly 100MB to reduce ping-ponging */
			to_delete = (int)(needed_kib - free_kib) / (100 * 1024);
			if (to_delete < 1) to_delete = 1;
			if (to_delete > candidates) to_delete = candidates;

			qsort(sorted, (size_t)candidates, sizeof(*sorted), compare_age);

			for (n = 0; n < to_delete; n++) {
				lwsl_notice("%s: out of space (need %uMiB, free %uMiB): requesting removal of %s (age %llus)\n",
					__func__, needed_kib / 1024, free_kib / 1024, sorted[n]->name, (unsigned long long)sorted[n]->age);

#if defined(LWS_WITH_STUB)
				if (builder.mgr_deletion)
					saib_deletion_request(sorted[n]->name);
#endif
			}
		}
	}

done:

	lwsac_free(&ctx.ac);
	return 0;
}

void
sul_cleanup_jobs_cb(lws_sorted_usec_list_t *sul)
{
	struct sai_builder *b = lws_container_of(sul, struct sai_builder,
						 sul_cleanup_jobs);
	struct cleanup_ctx ctx;
	char path[256];

	lwsl_info("%s: starting periodic cleanup\n", __func__);

	memset(&ctx, 0, sizeof(ctx));
	ctx.ages_trustworthy = (char)saib_clock_ages_trustworthy();
	/*
	 * We run when the stub (re)connects as well as periodically, so this
	 * is the time to finish deletions it may have lost
	 */
	ctx.reap_aside = 1;

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

			aj = lwsac_use_zero(&ctx.ac, sizeof(*aj), 64);
			if (!aj)
				continue;

			lws_strncpy(aj->uuid, ns->inp_vn, sizeof(aj->uuid));
			lws_dll2_add_tail(&aj->list, &ctx.active_owner);
		} lws_end_foreach_dll_safe(d2, d3);
	} lws_end_foreach_dll_safe(d, d1);

	/*
	 * Now we have the active job uuids, scan the jobs dir and check
	 * for old, inactive job dirs to reap
	 */

	lws_snprintf(path, sizeof(path), "%s/jobs", b->home);
	lws_dir(path, &ctx, scan_jobs_dir_cb);



	lwsac_free(&ctx.ac);

	lws_sul_schedule(b->context, 0, &b->sul_cleanup_jobs,
			 sul_cleanup_jobs_cb, SAI_CLEANUP_JOBS_INTERVAL_US);
}



#if defined(LWS_WITH_STUB)
static void sul_deletion_respawn_cb(lws_sorted_usec_list_t *sul);
#endif

static int
callback_sai_deletion_stdwsi(struct lws *wsi, enum lws_callback_reasons reason,
			    void *user, void *in, size_t len)
{
	uint8_t buf[256];
	int ilen;

	switch (reason) {

	case LWS_CALLBACK_RAW_CLOSE_FILE:
#if defined(LWS_WITH_STUB)
		/*
		 * The lws_stub parent_protocol_name contract requires us to
		 * notify the spawn object its stdwsi went away, so it can
		 * track remaining pipes and reap the child.  When the stub
		 * manager is being torn down, builder.mgr_deletion is already
		 * NULL and lws_spawn_piped_destroy() handles its own stdwsi.
		 */
		if (builder.mgr_deletion)
			lws_spawn_stdwsi_closed(
				lws_stub_get_lsp(builder.mgr_deletion), wsi);

		/*
		 * The stub child's stdio pipes going away means it died, for
		 * whatever reason.  Unless we respawn it, nothing will ever
		 * service deletion requests again until the service is
		 * restarted.  Come back in a moment (away from the close
		 * processing) and get a new one.
		 */
		if (!interrupted && !builder.sul_deletion_respawn.list.owner)
			lws_sul_schedule(builder.context, 0,
					 &builder.sul_deletion_respawn,
					 sul_deletion_respawn_cb,
					 10 * LWS_US_PER_SEC);
#endif
		break;


	case LWS_CALLBACK_RAW_RX_FILE:
#if defined(WIN32)
		/*
		 * lws spawn reads the pipe itself on windows, up to 4KB at a
		 * time, and delivers the data in in / len; the wsi has no
		 * readable fd for us.  Log the whole delivery, a piece at a
		 * time: keeping only the first sizeof(buf) - 1 bytes used to
		 * lose the rest of every larger read.
		 */
		while (len) {
			ilen = (int)len;
			if (ilen > (int)sizeof(buf) - 1)
				ilen = (int)sizeof(buf) - 1;
			memcpy(buf, in, (size_t)ilen);
			buf[ilen] = '\0';
			lwsl_notice("[DELETION] %s", (const char *)buf);
			in = (uint8_t *)in + ilen;
			len -= (size_t)ilen;
		}
#else
		ilen = (int)read((int)(intptr_t)lws_get_socket_fd(wsi), buf, sizeof(buf) - 1);
		if (ilen < 1) {
			return -1;
		}
		buf[ilen] = '\0';
		lwsl_notice("[DELETION] %s", (const char *)buf);
#endif
		break;

	default:
		break;
	}

	return 0;
}

struct lws_protocols protocol_deletion_stdxxx[] = {
	{
		.name			= "sai-deletion-stdxxx",
		.callback		= callback_sai_deletion_stdwsi,
		.per_session_data_size	= 0,
		.rx_buffer_size		= 0,
	},
	{ NULL, NULL, 0, 0 }
};

#if defined(LWS_WITH_STUB)
static void
sai_deletion_connected_cb(struct lws_stub_manager *mgr)
{
	lwsl_notice("%s: scheduling initial cleanup immediately upon connection\n", __func__);
	lws_sul_schedule(builder.context, 0, &builder.sul_cleanup_jobs,
			 sul_cleanup_jobs_cb, 1);
}

/*
 * Queue a fire-and-forget deletion of \p name (a dir under <home>/jobs/) with
 * the deletion stub.  Every request embeds the stub's 128-char secret: the
 * stub refuses any delete that did not prove it, which is what distinguishes
 * us from anything else that managed to connect to the owner-only UDS.
 */
static int
saib_deletion_request_name(const char *name)
{
	const char *secret;
	char json[384];

	if (!builder.mgr_deletion)
		return -1;

	secret = lws_stub_get_secret(builder.mgr_deletion);
	if (!secret)
		return -1;

	lws_snprintf(json, sizeof(json),
		     "{\"secret\":\"%s\",\"delete\":\"%s\"}", secret, name);

	return lws_stub_request(builder.mgr_deletion, json, NULL, 0,
				NULL, NULL, NULL);
}

/*
 * Delete job dir \p job (a name under <home>/jobs/).
 *
 * The stub gets to it some time after we ask, and finds it by name.  But the
 * name is only the task uuid's, so the next run of the same task (the next
 * slice of an idle lane, or a rebuild) uses it again, and may well already
 * have started in it by then: the deletion then removes what that run just put
 * there, eg, its git_helper.sh.  So move the dir aside under a name nothing
 * else uses before asking, which frees the job dir name at once.
 */
int
saib_deletion_request(const char *job)
{
	char from[PATH_MAX], to[PATH_MAX], aside[96];

	if (!builder.mgr_deletion)
		return -1;

	lws_snprintf(aside, sizeof(aside), SAIB_JOBDIR_DELETING_PREFIX "%s.%llx",
		     job, (unsigned long long)lws_now_usecs());
	lws_snprintf(from, sizeof(from), "%s/jobs/%s", builder.home, job);
	lws_snprintf(to, sizeof(to), "%s/jobs/%s", builder.home, aside);

	if (!rename(from, to))
		return saib_deletion_request_name(aside);

	if (errno == ENOENT)
		/* there's nothing to delete */
		return 0;

	lwsl_warn("%s: unable to move %s aside (errno %d), deleting it in "
		  "place\n", __func__, from, errno);

	return saib_deletion_request_name(job);
}

static int
saib_deletion_spawn(void)
{
	struct lws_stub_config config;
	char uds_path[256];

	memset(&config, 0, sizeof(config));

	lws_snprintf(uds_path, sizeof(uds_path), "%s/sai-deletion.sock", builder.home);

	if (!builder.vhost) {
		lwsl_err("%s: builder.vhost is NULL\n", __func__);
		return 1;
	}

	config.cx = builder.context;
	config.vh = builder.vhost;
	config.stub_name = "sai-deletion";
	config.uds_path = uds_path;
	/* protocol_deletion_stdxxx is in the global array pprotocols, but we pass it as a single element array for lws_stub_spawn */
	config.protocols = protocol_deletion_stdxxx;
	config.user = (void *)builder.home;
	config.extra_payload = builder.home;
	config.extra_payload_len = strlen(builder.home) + 1;
	config.connected_cb = sai_deletion_connected_cb;
	config.parent_protocol_name = "sai-deletion-stdxxx";

	builder.mgr_deletion = lws_stub_spawn(&config);
	if (!builder.mgr_deletion) {
		lwsl_err("%s: stub spawn failed\n", __func__);
		return 1;
	}

	return 0;
}

/*
 * The deletion stub child died.  If we leave things as they are, every
 * subsequent lws_stub_request() on the dead manager just queues JSON and
 * retries connects to the orphaned UDS path forever; no job dirs will ever be
 * removed again until the service is restarted.  So destroy the dead stub
 * manager (dropping anything queued on it) and get a new one; the fresh
 * child's connected cb also triggers an immediate cleanup pass.
 */
static void
sul_deletion_respawn_cb(lws_sorted_usec_list_t *sul)
{
	struct sai_builder *b = lws_container_of(sul, struct sai_builder,
						 sul_deletion_respawn);

	if (interrupted)
		return;

	lwsl_notice("%s: deletion stub child died, respawning\n", __func__);

	if (b->mgr_deletion)
		lws_stub_destroy(&b->mgr_deletion);

	/*
	 * Closing the dead child's stdwsi during the destroy re-arms us from
	 * the RAW_CLOSE_FILE handler, but we are already handling it
	 */
	lws_sul_cancel(&b->sul_deletion_respawn);

	if (saib_deletion_spawn()) {
		lwsl_err("%s: failed to respawn deletion stub, will retry\n",
			 __func__);
		lws_sul_schedule(b->context, 0, &b->sul_deletion_respawn,
				 sul_deletion_respawn_cb, 30 * LWS_US_PER_SEC);
	}
}

int
saib_deletion_init(const char *argv0)
{
	return saib_deletion_spawn();
}
#else
int
saib_deletion_init(const char *argv0)
{
	lwsl_err("%s: lws_stub disabled\n", __func__);
	return 0;
}
#endif
