/*
 * sai-builder task acquisition
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
#include <sys/stat.h>
#include <assert.h>
#include <fcntl.h>

#include "b-private.h"

const char *git_helper_sh =
	"#!/bin/bash\n"
	"export PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/sbin:/usr/sbin\n"
	"set -e\n"
	"echo \"git_helper_sh: starting\"\n"
	"OPERATION=$1\n"
	"shift\n"
	"if [ \"$OPERATION\" == \"mirror\" ]; then\n"
	"    REMOTE_URL=$1\n"
	"    REF=$2\n"
	"    HASH=$3\n"
	"    MIRROR_PATH=\"$HOME/git-mirror/$4\"\n"
	"    mkdir -p \"$HOME/git-mirror\"\n"
	"    for i in $(seq 1 60); do\n"
	"        if [ -d \"$MIRROR_PATH/.git\" ]; then\n"
	"            if git -C \"$MIRROR_PATH\" rev-parse -q --verify \"ref-$HASH\" > /dev/null; then\n"
	"                exit 0\n"
	"            fi\n"
	"        fi\n"
	"        if mkdir \"$MIRROR_PATH.lock\" 2>/dev/null; then\n"
	"            trap 'rm -rf \"$MIRROR_PATH.lock\"' EXIT\n"
	"            if [ -d \"$MIRROR_PATH/.git\" ]; then\n"
	"                if git -C \"$MIRROR_PATH\" rev-parse -q --verify \"ref-$HASH\" > /dev/null; then\n"
	"                    exit 0\n"
	"                fi\n"
	"            fi\n"
	"            mkdir -p \"$MIRROR_PATH\"\n"
	"            if [ ! -d \"$MIRROR_PATH/.git\" ]; then\n"
	"                git init --bare \"$MIRROR_PATH\"\n"
	"            fi\n"
	"            REFSPEC=\"$REF:ref-$HASH\"\n"
	"            git -C \"$MIRROR_PATH\" fetch \"$REMOTE_URL\" \"+$REFSPEC\"\n"
	"            exit 0\n"
	"        fi\n"
	"        echo \"git mirror locked, waiting...\"\n"
	"        sleep 1\n"
	"    done\n"
	"    exit 1\n"
	"elif [ \"$OPERATION\" == \"checkout\" ]; then\n"
	"    MIRROR_PATH=\"$HOME/git-mirror/$1\"\n"
	"    BUILD_DIR=$2\n"
	"    HASH=$3\n"
	"    if [ ! -d \"$BUILD_DIR/.git\" ]; then\n"
	"        rm -rf \"$BUILD_DIR\"\n"
	"        mkdir -p \"$BUILD_DIR\"\n"
	"        git -C \"$BUILD_DIR\" init\n"
	"    fi\n"
	"    if ! git -C \"$BUILD_DIR\" fetch \"$MIRROR_PATH\" \"ref-$HASH\"; then\n"
	"        exit 2\n"
	"    fi\n"
	"    git -C \"$BUILD_DIR\" checkout -f \"$HASH\"\n"
	"    git -C \"$BUILD_DIR\" clean -fdx\n"
	"else\n"
	"    exit 1\n"
	"fi\n"
	"echo \">>> Git helper script finished.\"\n"
	"exit 0\n"
;

const char *git_helper_bat =
	"@echo on\n"
	"setlocal EnableDelayedExpansion\n"
	"set \"PATH=%PATH%;C:\\Program Files\\Git\\cmd;C:\\Windows\\System32;C:\\Windows\"\n"
	"echo \"git_helper_bat: starting\"\n"
	"set \"OPERATION=%~1\"\n"
	"echo \"OPERATION: !OPERATION!\"\n"
	"if /i \"!OPERATION!\"==\"mirror\" (\n"
	"    set \"REMOTE_URL=%~2\"\n"
	"    set \"REF=%~3\"\n"
	"    set \"HASH=%~4\"\n"
	"    set \"MIRROR_PATH=%HOME%\\\\git-mirror\\\\%~5\"\n"
	"    echo \"REMOTE_URL: !REMOTE_URL!\"\n"
	"    echo \"REF: !REF!\"\n"
	"    echo \"HASH: !HASH!\"\n"
	"    echo \"MIRROR_PATH: !MIRROR_PATH!\"\n"
	"    :lock_wait\n"
	"    mkdir \"!MIRROR_PATH!.lock\"\n"
	"    if errorlevel 1 (\n"
	"        echo \"git mirror locked, waiting...\"\n"
	"        ping -n 2 127.0.0.1 >nul\n"
	"        goto :lock_wait\n"
	"    )\n"
	"    if exist \"!MIRROR_PATH!\\\\.git\" (\n"
	"        git -C \"!MIRROR_PATH!\" rev-parse -q --verify \"ref-!HASH!\" > nul 2> nul\n"
	"        if exist !MIRROR_PATH!\\\\.git if not errorlevel 1 (\n"
	"            rmdir \"!MIRROR_PATH!.lock\"\n"
	"            exit /b 0\n"
	"        )\n"
	"    )\n"
	"    if not exist \"!MIRROR_PATH!\\\\.\" (\n"
	"    mkdir \"!MIRROR_PATH!\"\n"
	"    )\n"
	"    if not exist \"!MIRROR_PATH!\\\\.git\" (\n"
	"        git init --bare \"!MIRROR_PATH!\"\n"
	"        if errorlevel 1 (\n"
	"            rmdir \"!MIRROR_PATH!.lock\"\n"
	"            exit /b 1\n"
	"        )\n"
	"    )\n"
	"    set \"REFSPEC=!REF!:ref-!HASH!\"\n"
	"    echo \"REFSPEC: !REFSPEC!\"\n"
	"    git -C \"!MIRROR_PATH!\" fetch \"!REMOTE_URL!\" \"!REFSPEC!\" 2>&1\n"
	"    if !ERRORLEVEL! neq 0 (\n"
	"        echo \"git fetch failed with errorlevel !ERRORLEVEL!\"\n"
	"        rmdir \"!MIRROR_PATH!.lock\"\n"
	"        exit /b 1\n"
	"    )\n"
	"    rmdir \"!MIRROR_PATH!.lock\"\n"
	"    exit /b 0\n"
	")\n"
	"if /i \"!OPERATION!\"==\"checkout\" (\n"
	"    set \"MIRROR_PATH=%HOME%\\\\git-mirror\\\\%~2\"\n"
	"    set \"BUILD_DIR=%~3\"\n"
	"    set \"HASH=%~4\"\n"
	"    echo \"MIRROR_PATH: !MIRROR_PATH!\"\n"
	"    echo \"BUILD_DIR: !BUILD_DIR!\"\n"
	"    echo \"HASH: !HASH!\"\n"
	"    if not exist \"!BUILD_DIR!\\\\.git\" (\n"
	"        if exist \"!BUILD_DIR!\\\\\" rmdir /s /q \"!BUILD_DIR!\"\n"
	"        mkdir \"!BUILD_DIR!\"\n"
	"        git -C \"!BUILD_DIR!\" init\n"
	"        if errorlevel 1 exit /b 1\n"
	"    )\n"
	"    git -C \"!BUILD_DIR!\" fetch \"!MIRROR_PATH!\" \"ref-!HASH!\"\n"
	"    if errorlevel 1 exit /b 2\n"
	"    git -C \"!BUILD_DIR!\" checkout -f \"!HASH!\"\n"
	"    if errorlevel 1 exit /b 1\n"
	"    echo \">>> Git helper script finished.\"\n"
	"    exit /b 0\n"
	")\n"
	"exit /b 1\n"
;



static int
saib_can_accept_task(sai_task_t *task, sai_plat_t *sp)
{
	unsigned int tc = sp->job_limit ? sp->job_limit : 6u;
#if 0
	unsigned int free_ram = saib_get_free_ram_kib();
	unsigned int total_ram = saib_get_total_ram_kib();
	unsigned int free_disk = saib_get_free_disk_kib(builder.home);
	unsigned int total_disk = saib_get_total_disk_kib(builder.home);
//	int cpu_load = saib_get_system_cpu(&builder);
#endif

	if ((((builder.ram_limit_kib * 4) / 3) - builder.ram_reserved_kib) < task->est_peak_mem_kib) {
		lwsl_notice("%s: reject task %s: not enough RAM: task %u vs %u lim - %u res\n", __func__,
			    task->uuid, (unsigned int)task->est_peak_mem_kib, (unsigned int)builder.ram_limit_kib, (unsigned int)builder.ram_reserved_kib);
		return 1;
	}

	if ((((builder.disk_total_kib * 7) / 8) - builder.disk_reserved_kib) < task->est_disk_kib) {
		lwsl_notice("%s: reject task %s: not enough disk: total %u, res %u, needed %u\n", __func__,
			    task->uuid, (unsigned int)builder.disk_total_kib, (unsigned int)builder.disk_reserved_kib, (unsigned int)task->est_disk_kib);
		return 1;
	}

       if (sp->nspawn_owner.count >= tc) {
		lwsl_notice("%s: reject task %s: already running %u tasks\n",
			    __func__, task->uuid, tc);
               return 1; /* nope */
       }

	return 0; /* acceptable */
}

#if !defined(WIN32)
static char csep = '/';
#else
static char csep = '\\';
#endif

static void saib_start_artifact_upload(struct sai_nspawn *ns);


int
saib_set_ns_state(struct sai_nspawn *ns, int state)
{
	ns->state		= (uint8_t)state;
	ns->state_changed	= 1;

	switch (state) {
	case NSSTATE_EXECUTING_STEPS:
	    if (ns->spm && !ns->spm->sul_load_report.list.owner)
		lws_sul_schedule(ns->builder->context, 0,
				 &ns->spm->sul_load_report,
				 saib_sul_load_report_cb, 1);
	    break;

	case NSSTATE_UPLOADING_ARTIFACTS:
		saib_start_artifact_upload(ns);
		break;

	case NSSTATE_FAILED:
		ns->retcode = SAISPRF_EXIT | 254;
		saib_task_grace(ns);
		break;
	default:
		break;
	}

	if (!ns->spm || !ns->spm->ss)
		return 0;

	return lws_ss_request_tx(ns->spm->ss) ? -1 : 0;
}

/*
 * update all servers we're connected to about builder status / optional reject
 */

int
saib_queue_task_status_update(sai_plat_t *sp, struct sai_plat_server *spm,
			      const char *rej_task_uuid, unsigned int ecode,
			      unsigned int reason)
{
	struct sai_rejection rej;

	if (!spm)
		return -1;

	if (!spm->ss)
		return 0;

	memset(&rej, 0, sizeof(rej));

	/*
	 * Queue a builder task status update
	 */

	if (rej_task_uuid)
		lws_strncpy(rej.task_uuid, rej_task_uuid,
				sizeof(rej.task_uuid));

	lws_snprintf(rej.host_platform, sizeof(rej.host_platform), "%s", sp->name);

	rej.ecode		= ecode;
	rej.reason		= (uint8_t)reason;

	if (saib_srv_queue_json_fragments_helper(spm->ss, lsm_schema_json_task_rej,
				LWS_ARRAY_SIZE(lsm_schema_json_task_rej), &rej))
		return -1;

	return 0;
}

void
saib_task_destroy(struct sai_nspawn *ns)
{
	int n;

	lwsl_notice("%s: destroying task %s\n", __func__,
		    ns->task ? ns->task->uuid : "null");

	lws_sul_cancel(&ns->sul_cleaner);
	lws_sul_cancel(&ns->sul_task_cancel);

	/*
	 * If able, builder should reintroduce himself to get
	 * another task
	 */

	if (ns->spm) {

		if (saib_srv_queue_json_fragments_helper(ns->spm->ss,
				lsm_schema_map_plat,
				LWS_ARRAY_SIZE(lsm_schema_map_plat),
				&builder.sai_plat_owner))
			return;

               /*
                * If spm is holding on to us as the last reference point,
                * we can't be used any more since we are goneski
                */
               if (ns->spm->last_logging_nspawn == &ns->list)
                       ns->spm->last_logging_nspawn = NULL;
	}

	if (ns->list.owner && ns->list.owner->count == 1) {
		int m = 0;

		/*
		 * Is it the case that none of the platforms have
		 * any ongoing jobs then?  We don't any more.
		 *
		 * If nobody does, start the grace time for suspend.
		 */

		lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
			   builder.sai_plat_owner.head) {
			struct sai_plat *sp = lws_container_of(d,
				  struct sai_plat, sai_plat_list);
			if (sp->nspawn_owner.count)
				m++;
		} lws_end_foreach_dll_safe(d, d1);

		/*
		 * Schedule informing all the servers we're connected to
		 */

		if (!m) {
#if defined(__APPLE__)
			if (!saib_need_wakelock()) {
				lwsl_notice("%s: last task finished, scheduling wakelock release\n", __func__);
				lws_sul_schedule(builder.context, 0,
					 &builder.sul_release_wakelock,
					 sul_release_wakelock_cb,
					 30 * LWS_US_PER_SEC);
			}
#else
			lws_sul_schedule(builder.context, 0,
					 &builder.sul_idle, sul_idle_cb,
					SAI_IDLE_GRACE_US);
#endif
		}
	}

	if (ns->task && ns->task->ac_task_container) {
		 /* contains the task object */
		lwsac_free(&ns->task->ac_task_container);
		ns->task = NULL;
	}

	if (ns->script_path[0])
		unlink(ns->script_path);

	for (n = 0; n < (int)LWS_ARRAY_SIZE(ns->vhosts); n++)
		if (ns->vhosts[n]) {
			lws_vhost_destroy(ns->vhosts[n]);
			ns->vhosts[n] = NULL;
		}

	if (ns->slp_control.sockpath[0])
		unlink(ns->slp_control.sockpath);
	for (n = 0; n < (int)LWS_ARRAY_SIZE(ns->slp); n++)
		if (ns->slp[n].sockpath[0])
			unlink(ns->slp[n].sockpath);

	/*
	 * If stdwsi are lurking around, we can't destroy the ns,
	 * since they will touch it during their close handling.
	 */

	if (ns->task && (ns->retcode & SAISPRF_EXIT) &&
	    (ns->retcode & 0xff) == 0) {
		/* Task succeeded, so clean up the directory. */

		lwsl_notice("%s: task %s succeeded, requesting deletion of job dir %s\n",
			    __func__, ns->task->uuid, ns->inp);
#if !defined(WIN32)
		if (write(builder.pipe_master_wr, ns->task->uuid,
			  LWS_POSIX_LENGTH_CAST(strlen(ns->task->uuid))) != (ssize_t)strlen(ns->task->uuid))
			lwsl_err("%s: failed to write to deletion worker\n",
				 __func__);
#else
		{
			DWORD written;
			if (!WriteFile(builder.pipe_master_wr_win, ns->task->uuid,
				       (DWORD)strlen(ns->task->uuid), &written, NULL))
				lwsl_err("%s: failed to write to deletion worker\n",
					 __func__);
		}
#endif
	}

	lws_dll2_remove(&ns->list);
	lwsl_user("%s: free(ns) %p\n", __func__, (void *)ns);
	free(ns);
}

static void
saib_sub_cleaner_cb(lws_sorted_usec_list_t *sul)
{
	struct sai_nspawn *ns = lws_container_of(sul, struct sai_nspawn,
						 sul_cleaner);
	lwsl_warn("%s: +++++ Task completion grace period ended with ns alive\n", __func__);


	if (ns->op && ns->op->lsp) {
		lwsl_notice("%s: +++++++++++ killing child process (budget %d)\n", __func__, ns->term_budget);
		lws_spawn_piped_kill_child_process(ns->op->lsp);

		if (!ns->term_budget)
			ns->term_budget = 10;

		/* give it a few goes to react to the signal */
		if (--ns->term_budget) {
			lws_sul_schedule(builder.context, 0, &ns->sul_cleaner,
					 saib_sub_cleaner_cb, 250 * LWS_US_PER_MS);
			return;
		}

		lwsl_err("%s: ============= unable to kill child process -> destroying ns forcibly\n", __func__);
		/*
		 * It refused to die after a few seconds... we are giving up on it.
		 * Break the link between the op and the ns, so if the op and its
		 * process ever do die, the reap callback will see ns is NULL and
		 * just free the op.
		 */
		ns->op->ns = NULL;
		/*
		 * And lose our link to the op, so saib_task_destroy() doesn't
		 * try to kill it again.  Because op->ns is NULL, we are leaving
		 * responsibility for freeing op to the eventual reap action.
		 */
		ns->op = NULL;
	}

	saib_task_destroy(ns);
}

void
saib_task_grace(struct sai_nspawn *ns)
{
	lwsl_err("%s: +++++ starting task %s grace wait\n", __func__, ns->task ? ns->task->uuid : "null");
	lws_sul_schedule(builder.context, 0, &ns->sul_cleaner,
			 saib_sub_cleaner_cb, 20 * LWS_USEC_PER_SEC);
}


static int
artifact_glob_cb(void *data, const char *path)
{
	struct sai_nspawn *ns = (struct sai_nspawn *)data;
	const char *p, *ph = NULL;
	struct lws_ss_handle *h;
	char upp[256], s[384];
	sai_artifact_t *ap = NULL;
	int n;

	/*
	 * "path" passed the filter...
	 *
	 * In order that we can maximize usage of the CI builder, first mv
	 * the artifact from path to ns->inp + "uploads/"
	 * + filename part
	 */

	p = path;
	while (*p) {
		if (*p == '/' || *p == '\\')
			ph = p + 1;
		p++;
	}

	if (!ph)
		return 1;

	/*
	 * This builder might complete another task that happens to create the
	 * same- named artifact before we finish uploading this one, trashing
	 * the temp copy on disk.  So we add the timestamp in the temp upload
	 * copy filename that this can't happen.
	 */

	lws_snprintf(upp, sizeof(upp), "%s../.sai-uploads/%llu-%s", ns->inp,
		     (unsigned long long)lws_now_usecs(), ph);

	n = lws_snprintf(s, sizeof(s), ">saib> Artifact: %s\n", upp);
	saib_log_chunk_create(ns, s, (size_t)n, 3);

	lwsl_notice("%s: moving %s -> %s\n", __func__, path, upp);
	if (rename(path, upp)) {
		lwsl_err("%s: mv artifact %s %s failed\n", __func__, path, upp);
		return 1;
	}

	/* pass upp in as the opaque data... we use it during CREATING */

	if (lws_ss_create(builder.context, 0, &ssi_sai_artifact, upp, &h,
			  NULL, NULL)) {
		lwsl_err("%s: failed to create secure stream\n",
			 __func__);
		return -1;
	}

	ap = lws_ss_to_user_object(h);
	/* take a copy so we can unlink the path later */
	lws_strncpy(ap->path, upp, sizeof(ap->path));

	lwsl_notice("%s: artifact ss created '%s'\n", __func__, ap->path);
	ns->count_artifacts++;

	lws_strncpy(ap->task_uuid, ns->task->uuid, sizeof(ap->task_uuid));
	lws_strncpy(ap->artifact_up_nonce, ns->task->art_up_nonce,
		    sizeof(ap->artifact_up_nonce));
	lws_strncpy(ap->blob_filename, ph, sizeof(ap->blob_filename));
	ap->timestamp = (uint64_t)lws_now_usecs();

	/*
	 * We need to set the metadata items for the post urlargs.  spm->url is
	 * something like "wss://warmcat.com/sai/builder"... we will send JSON
	 * on this connection first and that will be understood by the server
	 * as meaning the bulk data follows.
	 */

	if (lws_ss_set_metadata(h, "url", ns->spm->url, strlen(ns->spm->url)))
		lwsl_warn("%s: unable to set metadata\n", __func__);

	return lws_ss_client_connect(h) ? -1 : 0;
}

/*
 * We're finished with the nspawn / task one way or the other, specifically
 * all the stdwsi are closed and we reaped the lws_spawn_piped, but there's
 * still stuff we need to send out.  Give it some time then force destruction
 * of the task and reset the nspawn.
 */

static void
saib_start_artifact_upload(struct sai_nspawn *ns)
{
	char filt[32], scandir[256];
	struct lws_tokenize ts;
	uint8_t *p, *p1, *ps;
	lws_dir_glob_t g;
	int m;

	if (!ns->spm)
		return;

	/*
	 * Let's look for any artifacts the saifile lists...
	 * they're done as globs so the package filenames or
	 * whatever may contain substrings like git commit hash
	 * without having to know it in the saifile.
	 *
	 * The file search context is ns->inp, which is where
	 * the instance and platform-specific build takes place.
	 *
	 * We get a comma-separated list of globs possibly each
	 * with a path offset like "build/\*.rpm".  Let's parse
	 * out each in turn, and do an lws_dir at any path
	 * offset, matching on the remaining glob.
	 */

	lws_tokenize_init(&ts, ns->task->artifacts,
			  LWS_TOKENIZE_F_NO_INTEGERS |
			  LWS_TOKENIZE_F_NO_FLOATS |
			  LWS_TOKENIZE_F_SLASH_NONTERM |
			  LWS_TOKENIZE_F_DOT_NONTERM |
			  LWS_TOKENIZE_F_MINUS_NONTERM);

	m = 0;
	filt[0] = '\0';
	while ((ts.e = (int8_t)lws_tokenize(&ts)) >= 0) {
		switch (ts.e) {
		case LWS_TOKZE_ENDED:
			if (filt[0])
				goto scan;
			break;
		case LWS_TOKZE_DELIMITER:
			if (*ts.token == ',')
				goto scan;
			else
				filt[m++] = *ts.token;
			break;
		case LWS_TOKZE_TOKEN:
			lws_strnncpy(&filt[m], ts.token, ts.token_len,
				     sizeof(filt) - 1u - (unsigned int)m);
			m = (int)strlen(filt);
			break;
		}
		if (ts.e == LWS_TOKZE_ENDED)
			break;
		continue;
scan:
		lws_strncpy(scandir, ns->inp, sizeof(scandir));
		m = (int)strlen(scandir);

		/*
		 * if the filter has a fully-defined subdir,
		 * append it to the start path
		 */

		ps = p1 = p = (uint8_t *)filt;
		while (*p) {
			if (*p == '/') {
				if (lws_ptr_diff(p, p1) + 2 <
					  (int)sizeof(scandir) - m) {
					memcpy(scandir + m, p1,
					   lws_ptr_diff_size_t(p, p1));
					m += lws_ptr_diff(p, p1);
					scandir[m] = '\0';
				} else
					break;
				p1 = p;
				ps = p + 1;
			}
			if (*p == '*')
				break;
			p++;
		}

		lwsl_notice("%s: scan path %s, filter %s\n", __func__,
				scandir, (const char *)ps);

		g.filter = (char *)ps;
		g.user = (void *)ns;
		g.cb = artifact_glob_cb;

		lws_dir(scandir, &g, lws_dir_glob_cb);

		filt[0] = '\0';
		m = 0;

		if (ts.e == LWS_TOKZE_ENDED)
			break;
	}

	if (!ns->count_artifacts) {
		lwsl_notice("%s: no artifacts, destroying ns now\n", __func__);
		/* no artifacts to hang around for... nuke the ns now */
        	lws_sul_schedule(builder.context, 0, &ns->sul_cleaner,
                         saib_sub_cleaner_cb, 1);
	} else
		lwsl_notice("%s: created / waiting on %d artifact uploads\n",
				__func__, ns->count_artifacts);
}

void
saib_sul_task_cancel(struct lws_sorted_usec_list *sul)
{
	struct sai_nspawn *ns = lws_container_of(sul,
					struct sai_nspawn, sul_task_cancel);
	char s[64];
	int n;

	if (!ns->op || !ns->op->lsp)
		return;

	n = lws_snprintf(s, sizeof(s), ">saib> Cancelling...\n");
	saib_log_chunk_create(ns, s, (size_t)n, 3);

	lws_spawn_piped_kill_child_process(ns->op->lsp);
	if (!--ns->term_budget)
		return;

	lws_sul_schedule(ns->builder->context, 0, &ns->sul_task_cancel,
			 saib_sul_task_cancel, 500 * LWS_US_PER_MS);
}

int
saib_consider_allocating_task(struct sai_plat_server *spm, lws_struct_args_t *a,
			      const uint8_t *in, size_t len, int flags)
{
	char *p, mb[96], pur[128], ordinal_acc[SAI_BUILDER_INSTANCE_LIMIT],
		script_path[512];
	sai_plat_t *sp = NULL;
	struct sai_nspawn *ns;
	int n, en, ml, fd;
	sai_task_t *task;

	task = (sai_task_t *)a->dest;
	task->ac_task_container = a->ac; /* bequeath lwsac responsibility */

	/*
	 * Server is requesting that a platform adopt a task...
	 *
	 * Multiple platforms may be using this connection to a given
	 * server so we have to disambiguate which platform he's
	 * tasking first.
	 */

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
			builder.sai_plat_owner.head) {
	       sp = lws_container_of(d, sai_plat_t, sai_plat_list);

	       if (!strcmp(sp->platform, task->platform))
		       break;
	       sp = NULL;
	} lws_end_foreach_dll_safe(d, d1);

	if (!sp) {
		lwsl_err("%s: can't identify req task plat '%s'\n",
				__func__, task->platform);

		return 1;
	}

	/*
	 * For debugging, it's good to see what tasks are ongoing
	 */

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, sp->nspawn_owner.head) {
		struct sai_nspawn *xns = lws_container_of(d, struct sai_nspawn, list);

		lwsl_notice("%s: nspawn_census: %s\n", __func__, xns->task->uuid);

	} lws_end_foreach_dll_safe(d, d1);
	lwsl_notice("%s:\n", __func__);

	/*
	 * store a copy of the toplevel ac used for the deserialization
	 * into the outer part of the c builder wrapper
	 */

	sp->deserialization_ac = a->ac;

	/*
	 * Are we willing to take this task step on?
	 *
	 * We may connect to multiple servers and it's asynchronous
	 * which server may have tasked us first, so it's not that
	 * unusual to reject a task the server thought we could have
	 * taken
	 */

	n = 0;
	ns = NULL;
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, sp->nspawn_owner.head) {
		struct sai_nspawn *xns = lws_container_of(d, struct sai_nspawn, list);

		if (xns->task && !strcmp(xns->task->uuid, task->uuid)) {
			lwsl_warn("%s: server offered task that's already running. State %d, artifacts %d, op %p\n",
				__func__, xns->state, xns->count_artifacts, xns->op);
			saib_queue_task_status_update(sp, spm, task->uuid, 0,
						      SAI_TASK_REASON_DUPE);
			saib_reassess_idle_situation();

			return 0;
		}

	} lws_end_foreach_dll_safe(d, d1);

	/*
	 * We're not already running it, let's consider accepting it
	 */

	if (saib_can_accept_task(task, sp)) {
		lwsl_warn("%s: builder rejects offered task\n", __func__);
		if (saib_queue_task_status_update(sp, spm, task->uuid, 0,
						  SAI_TASK_REASON_BUSY))
			return -1;
		saib_reassess_idle_situation();

		return 0;
	}

	/*
	 * We're going to accept the task.  Create the nspawn.
	 */

	ns = malloc(sizeof(*ns));
	if (!ns)
		return -1;

	memset(ns, 0, sizeof(*ns));
	ns->builder	= &builder;
	ns->sp		= sp;

	/*
	 * Find the lowest free ordinal and use that.  It doesn't
	 * have any meaning for us, but the project being built needs
	 * it in SAI_INSTANCE_IDX so ctest can use, eg, test ports
	 * that don't conflict with any other running instance.
	 */

	memset(ordinal_acc, 0, sizeof(ordinal_acc));
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1, sp->nspawn_owner.head) {
		struct sai_nspawn *xns = lws_container_of(d, struct sai_nspawn, list);

		assert(xns->instance_ordinal < (int)sizeof(ordinal_acc));
		ordinal_acc[xns->instance_ordinal] = 1;
	} lws_end_foreach_dll_safe(d, d1);

	for (n = 0; n < (int)sizeof(ordinal_acc); n++)
		if (ordinal_acc[n] == 0) {
			ns->instance_ordinal = n;
			break;
		}


	lws_dll2_add_tail(&ns->list, &sp->nspawn_owner);
	saib_reassess_idle_situation();

	/*
	 * If we're using sai-device, sort out the log proxy
	 * information
	 */

	if (strstr(task->script, "sai-device")) {
		lws_strncpy(pur, sp->name, sizeof(pur));
		lws_filename_purify_inplace(pur);
		p = pur;
		while ((p = strchr(p, '/')))
			*p = '_';

		lws_snprintf(ns->slp_control.sockpath,
				sizeof(ns->slp_control.sockpath),
#if defined(__linux__)
				UDS_PATHNAME_LOGPROXY".%s.saib",
#else
				UDS_PATHNAME_LOGPROXY"/%s.saib",
#endif
				task->uuid);

		ns->slp_control.ns = ns;
		ns->slp_control.log_channel_idx = 3;

		if (saib_create_listen_uds(builder.context, &ns->slp_control,
					&ns->vhosts[0])) {
			lwsl_err("%s: Failed to create ctl log proxy listen UDS %s\n",
					__func__, ns->slp_control.sockpath);
			return -1;
		}

		for (n = 0; n < (int)LWS_ARRAY_SIZE(ns->slp); n++) {
			lws_snprintf(ns->slp[n].sockpath,
					sizeof(ns->slp[n].sockpath),
#if defined(__linux__)
					UDS_PATHNAME_LOGPROXY".%s.tty%d",
#else
					UDS_PATHNAME_LOGPROXY"/%s.tty%d",
#endif
					task->uuid, n);

			ns->slp[n].ns = ns;
			ns->slp[n].log_channel_idx = n + 4;

			if (saib_create_listen_uds(builder.context, &ns->slp[n],
						&ns->vhosts[n + 1])) {
				lwsl_err("%s: Failed to create log proxy listen UDS %s\n",
						__func__, ns->slp[n].sockpath);
				return -1;
			}
		}
	}

	lws_strncpy(ns->fsm.distro, task->platform,
		    sizeof(ns->fsm.distro));
	lws_filename_purify_inplace(ns->fsm.distro);
	p = ns->fsm.distro;
	while ((p = strchr(p, '/')))
		*p = '_';

	/*
	 * unique for remote server name ("warmcat"),
	 * project name ("libwebsockets")
	 */

	ns->server_name		= spm->name;
	ns->project_name	= task->repo_name;
	ns->ref			= sai_get_ref(task->git_ref);
	ns->hash		= task->git_hash;
	ns->git_repo_url	= task->git_repo_url;

	if (ns->task && ns->task->ac_task_container)
		lwsac_free(&ns->task->ac_task_container);

	ns->task		= task; /* we are owning this nspawn for the duration */
	ns->spm			= spm; /* bind this task to the spm the req came in on */

	if (!ns->task->build_step) {
		ns->spins	= 0;
		ns->user_cancel = 0;
		ns->us_cpu_user = 0;
		ns->us_cpu_sys	= 0;
		ns->worst_mem	= 0;
		ns->worst_stg	= 0;


		/*
		 * If it's the first step, log some preamble info
		 */
		saib_log_chunk_create(ns, ">saib>\n", 7, 3);
		saib_log_chunk_create(ns, ">saib>\n", 7, 3);
		saib_log_chunk_create(ns, ">saib>\n", 7, 3);

		ml = lws_snprintf(mb, sizeof(mb),
				  ">saib> Sai Builder Version: %s, lws: %s\n",
				  BUILD_INFO, LWS_BUILD_HASH);
		saib_log_chunk_create(ns, mb, (unsigned int)ml, 3);
	}

	saib_log_chunk_create(ns, ">saib>\n", 7, 3);
	ml = lws_snprintf(mb, sizeof(mb),
			  ">saib> Starting task step %d ===>\n",
			  ns->task->build_step + 1);

	saib_log_chunk_create(ns, mb, (unsigned int)ml, 3);

	saib_set_ns_state(ns, NSSTATE_INIT);

#if defined(__linux__)
	ns->fsm.layers[0] = "base";
	ns->fsm.layers[1] = "env";
#endif

	lws_snprintf(ns->fsm.ovname, sizeof(ns->fsm.ovname), "%s", task->uuid);

	n = lws_snprintf(ns->inp, sizeof(ns->inp), "%s%c",
			 builder.home, csep);

	n += lws_snprintf(ns->inp + n, sizeof(ns->inp) - (unsigned int)n, "jobs%c",
			csep);
	lws_filename_purify_inplace(ns->inp);

	if (mkdir(ns->inp, 0755) && errno != EEXIST) {
		en = errno;
		lwsl_err("%s: mkdir %s -> errno %d\n", __func__, ns->inp, en);
		goto ebail;
	}

	memcpy(ns->inp_vn, ns->fsm.ovname, 4);
	memcpy(ns->inp_vn + 4, ns->fsm.ovname + strlen(ns->fsm.ovname) - 4, 4);
	ns->inp_vn[8] = '\0';

	n += lws_snprintf(ns->inp + n, sizeof(ns->inp) - (unsigned int)n, "%s%c",
			  ns->inp_vn, csep);
	lws_filename_purify_inplace(ns->inp);
	if (mkdir(ns->inp, 0755) && errno != EEXIST) {
		en = errno;
		lwsl_err("%s: mkdir %s -> errno %d\n", __func__, ns->inp, en);

		goto ebail;
	}

	/*
	 * Create a pending upload dir to mv artifacts into while
	 * we get on with the next job.
	 */
	lws_snprintf(ns->inp + n, sizeof(ns->inp) - (unsigned int)n,
			"../.sai-uploads");

	if (mkdir(ns->inp, 0755) && errno != EEXIST) {
		en = errno;
		lwsl_err("%s: mkdir %s -> errno %d\n", __func__, ns->inp, en);

		goto ebail;
	}

	/*
	 * Snip that last bit off so ns->inp is the fully qualified
	 * builder instance base dir
	 */

	ns->inp[n] = '\0';


#if !defined(WIN32)
	/* create git_helper.sh */
	lws_snprintf(script_path, sizeof(script_path), "%s%cgit_helper.sh",
			ns->inp, csep);
	fd = open(script_path, O_CREAT | O_TRUNC | O_WRONLY, 0755);
	if (fd < 0) {
		lwsl_warn("%s: failed to open git script for write %s\n",
			  __func__, script_path);
		goto bail;
	}

	if ((size_t)write(fd, git_helper_sh, strlen(git_helper_sh)) != strlen(git_helper_sh)) {
		lwsl_warn("%s: failed to write git script %s\n", __func__, script_path);
		close(fd);
		goto bail;
	}
	close(fd);
#else
	/* create git_helper.bat */
	lws_snprintf(script_path, sizeof(script_path), "%s%cgit_helper.bat",
			ns->inp, csep);
	if (_sopen_s(&fd, script_path, _O_CREAT | _O_TRUNC | _O_WRONLY,
			_SH_DENYNO, _S_IWRITE))
		fd = -1;
	if (fd < 0) {
		lwsl_warn("%s: failed to open git script for write %s\n", __func__, script_path);
		goto bail;
	}

	if ((size_t)write(fd, git_helper_bat, (unsigned int)strlen(git_helper_bat)) != strlen(git_helper_bat)) {
		lwsl_warn("%s: failed to write git script %s\n", __func__, script_path);
		close(fd);
		goto bail;
	}
	close(fd);
#endif

	saib_set_ns_state(ns, NSSTATE_EXECUTING_STEPS);

	ns->user_cancel		= 0;
	ns->spins		= 0;

	if (saib_spawn_script(ns)) {
		lwsl_err("%s: saib_spawn_script failed\n", __func__);
		goto bail;
	}

	/* we're busy, we're not in the mood for suspending */

	lws_sul_cancel(&ns->builder->sul_idle);

	/*
	 * We accepted the task
	 */

	task->started = (uint64_t)lws_now_secs();

	builder.ram_reserved_kib += task->est_peak_mem_kib;
	builder.disk_reserved_kib += task->est_disk_kib;

	if (saib_queue_task_status_update(sp, spm, task->uuid, 0, SAI_TASK_REASON_ACCEPTED))
		goto bail;

#if defined(__APPLE__)
	saib_wakelock();
#endif

	return 0;

ebail:
	lwsl_err("%s: unable to create %s\n", __func__, ns->inp);

bail:
	lwsl_notice("%s: failing spawn cleanly\n", __func__);
	saib_set_ns_state(ns, NSSTATE_FAILED);
	saib_task_grace(ns);

	return 1;
}
