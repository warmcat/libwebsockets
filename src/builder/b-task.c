/*
 * sai-builder task acquisition
 *
 * Copyright (C) 2019 - 2026 Andy Green <andy@warmcat.com>
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
#include <errno.h>
#include <stdlib.h> /* realpath() on posix */

#include "sai-git-hash.h"
#include "b-private.h"

const char *git_helper_sh =
	"#!/usr/bin/env bash\n"
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
	"        if [ -d \"$MIRROR_PATH\" ]; then\n"
	"            if git -C \"$MIRROR_PATH\" rev-parse -q --verify \"ref-$HASH\" > /dev/null 2>&1; then\n"
	"                exit 0\n"
	"            fi\n"
	"        fi\n"
	"        if mkdir \"$MIRROR_PATH.lock\" 2>/dev/null; then\n"
	"            trap 'rm -rf \"$MIRROR_PATH.lock\"' EXIT\n"
	"            if [ -d \"$MIRROR_PATH\" ]; then\n"
	"                if git -C \"$MIRROR_PATH\" rev-parse -q --verify \"ref-$HASH\" > /dev/null 2>&1; then\n"
	"                    exit 0\n"
	"                fi\n"
	"            fi\n"
	"            mkdir -p \"$MIRROR_PATH\"\n"
	"            if [ ! -f \"$MIRROR_PATH/HEAD\" ]; then\n"
	"                git init --bare \"$MIRROR_PATH\"\n"
	"            fi\n"
	"            REFSPEC=\"$REF:ref-$HASH\"\n"
	"            git -C \"$MIRROR_PATH\" fetch -q \"$REMOTE_URL\" \"+$REFSPEC\"\n"
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
	"@echo off\n"
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
	"    if exist \"!MIRROR_PATH!\\\\.\" (\n"
	"        git -C \"!MIRROR_PATH!\" rev-parse -q --verify \"ref-!HASH!\" > nul 2> nul\n"
	"        if not errorlevel 1 (\n"
	"            rmdir \"!MIRROR_PATH!.lock\"\n"
	"            exit /b 0\n"
	"        )\n"
	"    )\n"
	"    if not exist \"!MIRROR_PATH!\\\\.\" (\n"
	"    mkdir \"!MIRROR_PATH!\"\n"
	"    )\n"
	"    if not exist \"!MIRROR_PATH!\\\\HEAD\" (\n"
	"        git init --bare \"!MIRROR_PATH!\"\n"
	"        if errorlevel 1 (\n"
	"            rmdir \"!MIRROR_PATH!.lock\"\n"
	"            exit /b 1\n"
	"        )\n"
	"    )\n"
	"    set \"REFSPEC=!REF!:ref-!HASH!\"\n"
	"    echo \"REFSPEC: !REFSPEC!\"\n"
	"    git -C \"!MIRROR_PATH!\" fetch -q \"!REMOTE_URL!\" \"!REFSPEC!\" 2>&1\n"
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
	"        if exist \"!BUILD_DIR!\\\\\" (\n"
	"            del /f /s /q \"!BUILD_DIR!\" > nul 2>&1\n"
	"            rmdir /s /q \"!BUILD_DIR!\"\n"
	"        )\n"
	"        mkdir \"!BUILD_DIR!\"\n"
	"        git -C \"!BUILD_DIR!\" init\n"
	"        if errorlevel 1 exit /b 1\n"
	"    )\n"
	"    git -C \"!BUILD_DIR!\" fetch \"!MIRROR_PATH!\" \"ref-!HASH!\"\n"
	"    if errorlevel 1 exit /b 2\n"
	"    git -C \"!BUILD_DIR!\" checkout -f \"!HASH!\"\n"
	"    if errorlevel 1 exit /b 1\n"
	"    git -C \"!BUILD_DIR!\" clean -fdx\n"
	"    echo \">>> Git helper script finished.\"\n"
	"    exit /b 0\n"
	")\n"
	"exit /b 1\n"
;



/*
 * The job dir for a task is named from the first 4 and last 4 chars of its
 * uuid.  Both the acceptance path (which has to protect the dir before any
 * nspawn exists) and the nspawn setup need it.
 */

void
saib_task_jobdir_vn(char *dest, size_t dest_len, const char *task_uuid)
{
	size_t l = strlen(task_uuid);

	if (dest_len < 9 || l < 8) {
		lws_strncpy(dest, task_uuid, dest_len);
		return;
	}

	memcpy(dest, task_uuid, 4);
	memcpy(dest + 4, task_uuid + l - 4, 4);
	dest[8] = '\0';
}

/*
 * The server keeps re-offering a task we refused, so an explanation of the
 * refusal has to be rate-limited or it becomes the task's log.  One line per
 * task per minute is enough to see why a task sat around.
 */

static int
saib_refusal_loggable(const char *task_uuid)
{
	static char last_uuid[65];
	static lws_usec_t last_us;
	lws_usec_t now = lws_now_usecs();

	if (!strcmp(last_uuid, task_uuid) &&
	    now - last_us < 60 * LWS_US_PER_SEC)
		return 0;

	lws_strncpy(last_uuid, task_uuid, sizeof(last_uuid));
	last_us = now;

	return 1;
}

/*
 * What the idle slices we are stopping still have reserved: it's as good as
 * free for the real work that we are stopping them for
 */

static void
saib_idletask_yielding_res(uint64_t *ram_kib, uint64_t *disk_kib)
{
	*ram_kib = *disk_kib = 0;

	lws_start_foreach_dll(struct lws_dll2 *, mp, builder.sai_plat_owner.head) {
		struct sai_plat *xsp = lws_container_of(mp, struct sai_plat,
							sai_plat_list);

		lws_start_foreach_dll(struct lws_dll2 *, p, xsp->nspawn_owner.head) {
			struct sai_nspawn *xns = lws_container_of(p,
						struct sai_nspawn, list);

			if (xns->idle_yield) {
				*ram_kib += xns->res_ram_kib;
				*disk_kib += xns->res_disk_kib;
			}

		} lws_end_foreach_dll(p);

	} lws_end_foreach_dll(mp);
}

static int
saib_can_accept_task(struct sai_plat_server *spm, sai_task_t *task,
		     sai_plat_t *sp)
{
	uint64_t yield_ram_kib, yield_disk_kib, ram_reserved_kib,
		 disk_reserved_kib;
	unsigned int tc = sp->job_limit ? sp->job_limit : 6u;
#if 0
	unsigned int free_ram = saib_get_free_ram_kib();
	unsigned int total_ram = saib_get_total_ram_kib();
	unsigned int free_disk = saib_get_free_disk_kib(builder.home);
	unsigned int total_disk = saib_get_total_disk_kib(builder.home);
//	int cpu_load = saib_get_system_cpu(&builder);
#endif

	unsigned int executing = 0;

	if (builder.one_shot_active) {
		if (!builder.one_shot_task_uuid[0]) {
			lws_strncpy(builder.one_shot_task_uuid, task->uuid,
				    sizeof(builder.one_shot_task_uuid));
			lwsl_notice("%s: locked one-shot affinity to task %s\n",
				    __func__, builder.one_shot_task_uuid);
		} else if (strcmp(builder.one_shot_task_uuid, task->uuid)) {
			lwsl_notice("%s: reject task %s: one-shot affinity locked to %s\n",
				    __func__, task->uuid, builder.one_shot_task_uuid);
			return 1;
		}
	}

	if (sp->powering_down) {
		lwsl_notice("%s: reject task %s: powering down\n", __func__,
			    task->uuid);
		return 1;
	}

	if (builder.event_affinity_active) {
		if (!builder.event_affinity[0]) {
			lws_strncpy(builder.event_affinity, task->event_uuid,
				    sizeof(builder.event_affinity));
			lwsl_notice("%s: locked affinity to event %s\n",
				    __func__, builder.event_affinity);
		} else if (strcmp(builder.event_affinity, task->event_uuid)) {
			lwsl_notice("%s: reject task %s: affinity locked to %s\n",
				    __func__, task->uuid, builder.event_affinity);
			return 1;
		}
	}

	saib_idletask_yielding_res(&yield_ram_kib, &yield_disk_kib);
	ram_reserved_kib = builder.ram_reserved_kib > yield_ram_kib ?
				builder.ram_reserved_kib - yield_ram_kib : 0;
	disk_reserved_kib = builder.disk_reserved_kib > yield_disk_kib ?
				builder.disk_reserved_kib - yield_disk_kib : 0;

	{
		uint64_t budget = (builder.ram_limit_kib * 4) / 3;

		budget = ram_reserved_kib > budget ? 0 :
					budget - ram_reserved_kib;

		if (budget < task->est_peak_mem_kib) {
			if (saib_refusal_loggable(task->uuid))
				saib_task_logf(spm, NULL, task->uuid,
					"Builder %s can't take this step yet: "
					"needs %uMiB RAM, %lluMiB of its "
					"%lluMiB budget left", sp->name,
					(unsigned int)(task->est_peak_mem_kib / 1024),
					(unsigned long long)(budget / 1024),
					(unsigned long long)((builder.ram_limit_kib * 4) / 3 / 1024));
			return 1;
		}
	}

	{
		uint64_t free_disk = saib_get_free_disk_kib(builder.home);
		uint64_t needed_disk = (uint64_t)task->est_disk_kib +
						disk_reserved_kib;
		char vn[16];

		/* leave 12.5% of free space as a safety margin */
		if (free_disk < needed_disk + (free_disk / 8)) {
			uint64_t want = needed_disk + (free_disk / 8);

			if (saib_refusal_loggable(task->uuid))
				saib_task_logf(spm, NULL, task->uuid,
					"Builder %s can't take this step yet: "
					"needs %lluMiB (step %uMiB + %lluMiB "
					"reserved by other steps), only %lluMiB "
					"free on %s", sp->name,
					(unsigned long long)(needed_disk / 1024),
					(unsigned int)(task->est_disk_kib / 1024),
					(unsigned long long)(disk_reserved_kib / 1024),
					(unsigned long long)(free_disk / 1024),
					builder.home);

			/*
			 * Try to make room, but never at the cost of the job
			 * dir of the very task we are being offered: its
			 * earlier steps' output is in there
			 */

			saib_task_jobdir_vn(vn, sizeof(vn), task->uuid);

			if (want > 0xffffffffull)
				want = 0xffffffffull;

			saib_deletion_free_kib((unsigned int)want, vn);

			return 1;
		}
	}

	lws_start_foreach_dll(struct lws_dll2 *, p, sp->nspawn_owner.head) {
		struct sai_nspawn *xns = lws_container_of(p, struct sai_nspawn, list);
		if (!xns->idle_yield && /* going away to make room */
		    (xns->state == NSSTATE_INIT ||
		     xns->state == NSSTATE_MOUNTING ||
		     xns->state == NSSTATE_EXECUTING_STEPS))
			executing++;
	} lws_end_foreach_dll(p);

	if (executing >= tc) {
		lwsl_notice("%s: reject task %s: already running %u tasks\n",
			    __func__, task->uuid, tc);
		return 1; /* nope */
	}

	return 0; /* acceptable */
}

/*
 * Idle tasks
 *
 * The server only offers us idle tasks for a platform when it has nothing real
 * for that platform, and when the platform's conf share of idle time allows.
 * But "idle" is about this whole builder: we don't take idle work while any of
 * our platforms has real work, or had it within the settle time, and when real
 * work is offered to any of them, we stop all our idle slices to make way.
 */

static int
saib_idletask_should_decline(sai_plat_t *sp)
{
	lws_usec_t now = lws_now_usecs();
	unsigned int ours = 0;

	if (!sp->idle_share) {
		lwsl_notice("%s: %s: no idle share\n", __func__, sp->name);
		return 1;
	}

	/* these modes are for a builder that exists for one real thing */
	if (builder.one_shot_active || builder.event_affinity_active)
		return 1;

	if (builder.last_real_us &&
	    now - builder.last_real_us <
			(lws_usec_t)sp->idle_settle_secs * LWS_US_PER_SEC) {
		lwsl_notice("%s: %s: real work too recently\n", __func__,
			    sp->name);
		return 1;
	}

	lws_start_foreach_dll(struct lws_dll2 *, mp, builder.sai_plat_owner.head) {
		struct sai_plat *xsp = lws_container_of(mp, struct sai_plat,
							sai_plat_list);

		lws_start_foreach_dll(struct lws_dll2 *, p, xsp->nspawn_owner.head) {
			struct sai_nspawn *xns = lws_container_of(p,
						struct sai_nspawn, list);

			if (!xns->task)
				continue;

			if (!xns->task->idle) {
				lwsl_notice("%s: %s: has real work\n",
					    __func__, sp->name);
				return 1;
			}

			if (xsp == sp && !xns->idle_yield)
				ours++;

		} lws_end_foreach_dll(p);

	} lws_end_foreach_dll(mp);

	if (ours >= sp->idle_instances) {
		lwsl_notice("%s: %s: already running %u idle tasks\n",
			    __func__, sp->name, ours);
		return 1;
	}

	return 0;
}

/* real work is coming... stop every idle slice we have to make way for it */

static void
saib_idletask_yield_all(void)
{
	lws_start_foreach_dll(struct lws_dll2 *, mp, builder.sai_plat_owner.head) {
		struct sai_plat *xsp = lws_container_of(mp, struct sai_plat,
							sai_plat_list);

		lws_start_foreach_dll(struct lws_dll2 *, p, xsp->nspawn_owner.head) {
			struct sai_nspawn *xns = lws_container_of(p,
						struct sai_nspawn, list);

			if (!xns->task || !xns->task->idle || xns->idle_yield)
				continue;

			lwsl_notice("%s: yielding idle task %s\n", __func__,
				    xns->task->uuid);

			xns->idle_yield = 1;

			if (saib_pool_waiter_abort(xns))
				/* it hadn't started, waiting for its pool */
				continue;

			if (!xns->op || !xns->op->lsp)
				/*
				 * Nothing running to stop, eg, between
				 * spawning and uploading; it reports as
				 * yielded when it's destroyed
				 */
				continue;

			xns->user_cancel = 1;
			xns->term_budget = 5;
			lws_sul_schedule(builder.context, 0,
					 &xns->sul_task_cancel,
					 saib_sul_task_cancel, 1);

		} lws_end_foreach_dll(p);

	} lws_end_foreach_dll(mp);
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
	struct sai_plat_server *spm;

	if (!ns)
		return -1;

	spm = ns->spm;

	lwsl_notice("%s: ns=%p (%s) changing state from %d to %d\n", __func__, 
		(void*)ns, ns->task ? ns->task->uuid : "null", ns->state, state);

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

	if (!spm || !spm->ss)
		return 0;

	int ret = lws_ss_request_tx(spm->ss) ? -1 : 0;
	if (ret)
		lwsl_notice("TRAP: saib_set_ns_state lws_ss_request_tx failed\n");
	return ret;
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
				LWS_ARRAY_SIZE(lsm_schema_json_task_rej), &rej)) {
		lwsl_notice("TRAP: saib_queue_task_status_update saib_srv_queue_json_fragments_helper failed\n");
		return -1;
	}

	return 0;
}

void
saib_task_destroy(struct sai_nspawn *ns)
{
	int n;

	/*
	 * The last in-flight artifact upload calls this from its own
	 * DESTROYING; if we got here first via the cleaner or cancel paths, the
	 * outstanding artifact destroys below would otherwise call us back
	 * reentrantly.
	 */

	if (ns->destroying)
		return;
	ns->destroying = 1;

	lwsl_notice("====== saib_task_destroy START (ns=%p, uuid=%s, spm=%p) ======\n",
		(void*)ns, ns->task ? ns->task->uuid : "null", (void*)ns->spm);

	lwsl_notice("%s: destroying task %s\n", __func__,
		    ns->task ? ns->task->uuid : "null");

	lws_sul_cancel(&ns->sul_cleaner);
	lws_sul_cancel(&ns->sul_task_cancel);

	/* sync what the task left in its pool, if it has one */
	saib_pool_detach(ns);

	/*
	 * Any artifact uploads still referencing us must go first... their
	 * DESTROYING unlinks their temp file and accounts against
	 * ns->count_artifacts, but skips the recursive destroy since we are
	 * already destroying.
	 */

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   ns->artifact_owner.head) {
		sai_artifact_t *ap = lws_container_of(d, sai_artifact_t, list);
		struct lws_ss_handle *h = ap->ss;

		lwsl_notice("%s: destroying in-flight artifact %s\n", __func__,
			    ap->path);

		lws_ss_destroy(&h);
	} lws_end_foreach_dll_safe(d, d1);

	/*
	 * If able, builder should reintroduce himself to get
	 * another task
	 */

	if (ns->spm) {

		saib_srv_queue_json_fragments_helper(ns->spm->ss,
				lsm_schema_map_plat,
				LWS_ARRAY_SIZE(lsm_schema_map_plat),
				&builder.sai_plat_owner);

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

		if (!m && !builder.shell_owner.head) {
#if defined(__APPLE__)
			if (!saib_need_wakelock()) {
				lwsl_notice("%s: last task finished, scheduling wakelock release\n", __func__);
				lws_sul_schedule(builder.context, 0,
					 &builder.sul_release_wakelock,
					 sul_release_wakelock_cb,
					 30 * LWS_US_PER_SEC);
			}
#endif
			/*
			 * the reassess at the end of the destroy starts the
			 * idle grace time
			 */
		}
	}

	if (ns->task) {
		unsigned int ecode = (unsigned int)ns->retcode;

		if (ns->idle_yield)
			/*
			 * We stopped this idle slice, it's not a failure
			 * whatever the process had to say about it
			 */
			ecode = SAISPRF_TERMINATED | SAISPRF_YIELDED;

		if (!ns->task->idle)
			/* real work idles us only after the settle time */
			builder.last_real_us = lws_now_usecs();

		saib_queue_task_status_update(ns->sp, ns->spm, ns->task->uuid,
					      ecode, SAI_TASK_REASON_DESTROYED);

		/*
		 * Only ever give back what this ns took.  Giving back the
		 * task's estimate for an ns that never reserved anything (it
		 * failed during setup) underflowed these, after which every
		 * offered task looked disk-starved and the deletion path
		 * purged job dirs to try to make room that was never missing.
		 */

		builder.ram_reserved_kib  -= builder.ram_reserved_kib < ns->res_ram_kib ?
					builder.ram_reserved_kib : ns->res_ram_kib;
		builder.disk_reserved_kib -= builder.disk_reserved_kib < ns->res_disk_kib ?
					builder.disk_reserved_kib : ns->res_disk_kib;
		ns->res_ram_kib = 0;
		ns->res_disk_kib = 0;
		if (ns->spm)
			lws_sul_schedule(builder.context, 0,
					 &ns->spm->sul_load_report,
					 saib_sul_load_report_cb, 1);
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

	if (ns->task && ns->inp_vn[0]) {
		int step_ok = (ns->retcode & SAISPRF_EXIT) &&
			      !(ns->retcode & 0xff);
		int last_step = ns->task->build_step ==
					ns->task->build_step_count - 1;

		if (step_ok && !last_step) {
			/*
			 * More steps of this task are coming, but each step is
			 * its own nspawn: from here until the next step is
			 * offered there is no live nspawn pointing at the job
			 * dir, and the deletion paths only spare dirs that
			 * have one.  Hold it over the gap, or the next step
			 * finds its src/ tree gone.
			 */
			saib_jobdir_hold(ns->inp_vn);
		} else {
			/*
			 * Either we're done or we failed.  Failed job dirs are
			 * deliberately left for inspection, so just drop the
			 * hold and let the normal age / disk pressure rules
			 * decide when they go.
			 */
			saib_jobdir_release(ns->inp_vn);

			if (step_ok) {
				/* Task succeeded completely, clean up the dir */

				lwsl_notice("%s: task %s succeeded (all %d steps), requesting deletion of job dir %s\n",
					    __func__, ns->task->uuid,
					    ns->task->build_step_count, ns->inp);
#if defined(LWS_WITH_STUB)
				if (builder.mgr_deletion &&
				    saib_deletion_request(ns->inp_vn) < 0)
					lwsl_err("%s: failed to queue deletion\n",
						 __func__);
#endif
			}
		}
	}

	if (ns->task && ns->task->ac_task_container) {
		struct lwsac *ac = ns->task->ac_task_container;
		 /* contains the task object */
		lwsac_free(&ac);
		ns->task = NULL;
	}

	lws_dll2_remove(&ns->list);
	lwsl_user("%s: free(ns) %p\n", __func__, (void *)ns);
	free(ns);

	saib_reassess_idle_situation();
	lwsl_notice("====== saib_task_destroy completely finished ======\n");
}

static void
saib_sub_cleaner_cb(lws_sorted_usec_list_t *sul)
{
	struct sai_nspawn *ns = lws_container_of(sul, struct sai_nspawn,
						 sul_cleaner);
	lwsl_warn("%s: +++++ Task completion grace period ended with ns alive\n", __func__);

	if (ns->op && ns->op->lsp) {
		if (!ns->term_budget)
			saib_task_logf(ns->spm, ns, NULL,
				       "Step %d completed but its process is "
				       "still alive after the grace period, "
				       "terminating it",
				       ns->task ? ns->task->build_step + 1 : 0);

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

		saib_task_logf(ns->spm, ns, NULL,
			       "Unable to terminate the step process, "
			       "abandoning it: the builder may have a stray "
			       "process left behind");

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

#if !defined(WIN32)
	{
		char rp[384], rip[384];
		size_t rl;

		/*
		 * The glob came from repo-controlled .sai.json, so before we
		 * rename the match away, make sure the resolved path really
		 * sits under the instance dir: a symlink planted in the build
		 * dir points the scan at host files outside it even when the
		 * pattern itself looked clean.
		 */

		if (!realpath(path, rp) || !realpath(ns->inp, rip))
			return 1;

		rl = strlen(rip);
		if (strncmp(rp, rip, rl) || (rp[rl] && rp[rl] != '/')) {
			lwsl_err("%s: artifact '%s' resolves outside the "
				 "instance dir, skipping\n", __func__, path);
			return 1;
		}
	}
#endif

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

	/*
	 * The upload outlives the task's own steps and must know its ns, so
	 * DESTROYING can account for it and destroy the ns when the last one
	 * finishes; and saib_task_destroy() can find and kill in-flight uploads
	 * if it goes first.  The SS user object is zalloc'd, so without this
	 * ap->ns is NULL.
	 */

	ap->ns = ns;
	lws_dll2_add_tail(&ap->list, &ns->artifact_owner);

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

/* cap on how long we let artifact uploads hold the ns alive */
#define SAIB_ARTIFACT_UPLOAD_MAX_US (10 * 60 * LWS_USEC_PER_SEC)

static void
saib_start_artifact_upload(struct sai_nspawn *ns)
{
	char filt[32], scandir[256];
	struct lws_tokenize ts;
	uint8_t *p, *p1, *ps;
	lws_dir_glob_t g;
	int m;

	lwsl_notice("====== saib_start_artifact_upload START (ns=%p, uuid=%s, spm=%p) ======\n", 
		(void*)ns, ns->task ? ns->task->uuid : "null", (void*)ns->spm);

	if (!ns->spm) {
		lwsl_notice("%s: ns->spm is NULL, calling saib_task_destroy\n", __func__);
		saib_task_destroy(ns);
		return;
	}

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
		/*
		 * The glob is repo-controlled all the way from .sai.json:
		 * its path part decides where we scan from, so it must stay
		 * inside the instance dir (no ".." components, absolute
		 * patterns, or windows drive / UNC shapes).
		 */

		if (!sai_artifacts_pattern_safe(filt)) {
			lwsl_err("%s: ignoring artifact glob '%s' that escapes "
				 "the build dir\n", __func__, filt);
			filt[0] = '\0';
			m = 0;

			if (ts.e == LWS_TOKZE_ENDED)
				break;
			continue;
		}

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
		lws_sul_cancel(&ns->sul_cleaner);
		saib_task_destroy(ns);
	} else {
		lwsl_notice("%s: created / waiting on %d artifact uploads\n",
				__func__, ns->count_artifacts);

		/*
		 * The ns now lives until the last upload destroys it, not the
		 * 20s task grace timer... but keep a much longer hard cap so
		 * a stream stuck retrying can't pin the ns (and the builder's
		 * idle / power state) forever.
		 */

		lws_sul_schedule(builder.context, 0, &ns->sul_cleaner,
				 saib_sub_cleaner_cb,
				 SAIB_ARTIFACT_UPLOAD_MAX_US);
	}
}

void
saib_sul_task_cancel(struct lws_sorted_usec_list *sul)
{
	struct sai_nspawn *ns = lws_container_of(sul,
					struct sai_nspawn, sul_task_cancel);
	char s[64];
	int n;

	if (saib_pool_waiter_abort(ns))
		/* it never started, it was waiting for its pool */
		return;

	if (!ns->op || !ns->op->lsp)
		return;

	if (ns->user_killed)
		n = lws_snprintf(s, sizeof(s), "\xe2\x96\xa0 >saib> Build was manually killed\n");
	else
		if (ns->idle_yield)
			n = lws_snprintf(s, sizeof(s), ">saib> Stopping idle task...\n");
		else
			n = lws_snprintf(s, sizeof(s), ">saib> Cancelling...\n");
	saib_log_chunk_create(ns, s, (size_t)n, 3);

	lws_spawn_piped_kill_child_process(ns->op->lsp);
	if (!--ns->term_budget) {
		lwsl_err("%s: unable to kill child process -> destroying ns forcibly\n", __func__);
		ns->op->ns = NULL;
		ns->op = NULL;
		saib_task_destroy(ns);
		return;
	}

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
	int n, en = 0, ml, fd;
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

		lwsl_notice("%s: nspawn_census: %s\n", __func__,
			    xns->task ? xns->task->uuid : "(no task)");

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
			if (saib_queue_task_status_update(sp, spm, task->uuid, 0,
						      SAI_TASK_REASON_DUPE)) {
				lwsl_notice("TRAP: saib_queue_task_status_update failed (DUPE)\n");
				return -1;
			}
			saib_reassess_idle_situation();

			return 0;
		}

	} lws_end_foreach_dll_safe(d, d1);

	/*
	 * We're not already running it, let's consider accepting it
	 */

	if (task->idle) {
		if (saib_idletask_should_decline(sp))
			goto idle_decline;
	} else {
		/*
		 * Real work has been offered, so we're not idle: make way for
		 * it by stopping any idle tasks, whatever platform they're on
		 */
		builder.last_real_us = lws_now_usecs();
		saib_idletask_yield_all();
	}

	if (saib_can_accept_task(spm, task, sp)) {
		if (task->idle)
			goto idle_decline;

		lwsl_warn("%s: builder rejects offered task\n", __func__);
		if (saib_queue_task_status_update(sp, spm, task->uuid, 0,
						  SAI_TASK_REASON_BUSY)) {
			lwsl_notice("TRAP: saib_queue_task_status_update failed (BUSY)\n");
			return -1;
		}
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
	 * Bind the task and the server connection immediately: every failure
	 * path from here on wants to be able to say what went wrong in the
	 * task's own log, and nothing should ever see an nspawn on the list
	 * with no task.
	 */
	ns->task	= task;
	ns->spm		= spm;

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
			saib_task_logf(spm, ns, NULL,
				       "Unable to create the sai-device control "
				       "log proxy socket %s",
				       ns->slp_control.sockpath);
			goto bail;
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
				saib_task_logf(spm, ns, NULL,
					       "Unable to create the sai-device "
					       "tty%d log proxy socket %s",
					       n, ns->slp[n].sockpath);
				goto bail;
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

	/* ns->task / ns->spm were bound when the nspawn was created */

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
				  SAI_BUILD_INFO, LWS_BUILD_HASH);
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

	saib_task_jobdir_vn(ns->inp_vn, sizeof(ns->inp_vn), ns->fsm.ovname);

	/*
	 * Renew the hold on the job dir for as long as this task has steps
	 * running or pending on us
	 */
	saib_jobdir_hold(ns->inp_vn);

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
		saib_task_logf(spm, ns, NULL,
			       "Unable to create %s: errno %d (%s)",
			       script_path, errno, strerror(errno));
		goto bail;
	}

	if ((size_t)write(fd, git_helper_sh, strlen(git_helper_sh)) != strlen(git_helper_sh)) {
		en = errno;
		close(fd);
		saib_task_logf(spm, ns, NULL,
			       "Unable to write %s: errno %d (%s)",
			       script_path, en, strerror(en));
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
		saib_task_logf(spm, ns, NULL,
			       "Unable to create %s: errno %d (%s)",
			       script_path, errno, strerror(errno));
		goto bail;
	}

	if ((size_t)write(fd, git_helper_bat, (unsigned int)strlen(git_helper_bat)) != strlen(git_helper_bat)) {
		en = errno;
		close(fd);
		saib_task_logf(spm, ns, NULL,
			       "Unable to write %s: errno %d (%s)",
			       script_path, en, strerror(en));
		goto bail;
	}
	close(fd);
#endif

	saib_set_ns_state(ns, NSSTATE_EXECUTING_STEPS);

	ns->user_cancel		= 0;
	ns->spins		= 0;

	if (saib_pool_attach(ns))
		goto bail;

	/*
	 * If the task has a pool we haven't pulled lately, the step is spawned
	 * once we did (or gave up), see b-pool.c
	 */

	if (!saib_pool_defer_spawn(ns) && saib_spawn_script(ns)) {
		lwsl_err("%s: saib_spawn_script failed\n", __func__);
		goto bail;
	}

	/*
	 * We accepted the task
	 */

	task->started = (uint64_t)lws_now_secs();

	/*
	 * Remember what we reserved on the ns itself, so the destroy gives back
	 * exactly this and nothing at all for an ns that failed before getting
	 * here
	 */

	ns->res_ram_kib			 = task->est_peak_mem_kib;
	ns->res_disk_kib		 = task->est_disk_kib;
	builder.ram_reserved_kib	+= ns->res_ram_kib;
	builder.disk_reserved_kib	+= ns->res_disk_kib;

	if (saib_queue_task_status_update(sp, spm, task->uuid, 0, SAI_TASK_REASON_ACCEPTED))
		goto bail;

#if defined(__APPLE__)
	saib_wakelock();
#endif

	return 0;

idle_decline:
	/*
	 * Unlike BUSY, this doesn't tell the server we can't take real tasks
	 */
	lwsl_notice("%s: declining idle task %s\n", __func__, task->uuid);
	if (saib_queue_task_status_update(sp, spm, task->uuid, 0,
					  SAI_TASK_REASON_IDLE_DECLINED))
		return -1;
	saib_reassess_idle_situation();

	return 0;

ebail:
	saib_task_logf(spm, ns, NULL,
		       "Unable to create the job dir %s: errno %d (%s)",
		       ns->inp, en, strerror(en));

bail:
	/*
	 * We are about to report this step as failed with nothing in the log to
	 * say why, unless one of the paths that got us here already did.  These
	 * builders are often transient VMs, so the local log is no help after
	 * the fact.
	 */
	saib_task_logf(spm, ns, NULL,
		       "Builder %s could not start step %d, failing the task",
		       sp->name, ns->task ? ns->task->build_step + 1 : 0);

	saib_set_ns_state(ns, NSSTATE_FAILED);
	saib_task_grace(ns);

	return 1;
}
