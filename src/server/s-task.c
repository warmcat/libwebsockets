/*
 * Sai server
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

#include <assert.h>

#include "s-private.h"



/*
 * Checks if a given event db contains any tasks for a given platform
 */
static int
sais_event_check_for_plat_tasks(struct vhd *vhd, const char *event_uuid,
				const char *platform)
{
	sqlite3 *check_pdb = NULL;
	char query[256];
	unsigned int count = 0;

	if (sai_event_db_ensure_open(vhd->context, &vhd->sqlite3_cache,
			      vhd->sqlite3_path_lhs, event_uuid, 1, &check_pdb))
		return 0;

	lws_snprintf(query, sizeof(query),
		     "select count(state) from tasks where platform = '%s' and idle=0",
		     platform);

	if (sqlite3_exec(check_pdb, query, sql3_get_integer_cb, &count,
			 NULL) != SQLITE_OK)
		count = 0;

	sai_event_db_close(&vhd->sqlite3_cache, &check_pdb);

	lwsl_info("%s: event %s, platform %s: count %u\n", __func__, event_uuid,
		  platform, count);

	return count > 0;
}

/*
 * On the server's builder-platform, we keep a list of tasks we have offered it.
 *
 * If the builder accepted the task, then we change the task's state in sqlite and
 * remove it from this list.
 *
 * Inbetweentimes, we know to avoid re-offering or cancelling the task by seeing
 * if the task is already listed as "inflight".
 */

int
sais_is_task_inflight(struct vhd *vhd, sai_plat_t *build, const char *uuid,
		      sai_uuid_list_t **hit)
{
	assert(strlen(uuid) == 64);

	if (build) {
		lws_start_foreach_dll(struct lws_dll2 *, pif,
				      build->inflight_owner.head) {
			sai_uuid_list_t *ul = lws_container_of(pif, sai_uuid_list_t, list);

			if (!strcmp(uuid, ul->uuid)) {
				if (hit)
					*hit = ul;

				lwsl_info("%s: %s is inflight on %s (of %d)\n", __func__,
						uuid, build->name, build->inflight_owner.count);

				return 1;
			}

		} lws_end_foreach_dll(pif);

		return 0;
	}

	/*
	 * lookup a uuid across all builder / plats
	 * to see if it is inflight
	 */

	lws_start_foreach_dll(struct lws_dll2 *, pb,
			      vhd->server.builder_owner.head) {
		build = lws_container_of(pb, sai_plat_t, sai_plat_list);

		if (sais_is_task_inflight(vhd, build, uuid, hit))
			return 1;

	} lws_end_foreach_dll(pb);

	return 0;
}

int
sais_add_to_inflight_list_if_absent(struct vhd *vhd, sai_plat_t *sp,
				    const char *uuid, int idle)
{
	sai_uuid_list_t *uuid_list;

	if (sais_is_task_inflight(vhd, NULL, uuid, NULL))
		return 0;

	uuid_list = malloc(sizeof(*uuid_list));
	if (!uuid_list)
		return 1;

	memset(uuid_list, 0, sizeof(*uuid_list));
	lws_strncpy(uuid_list->uuid, uuid, sizeof(uuid_list->uuid));
	uuid_list->us_time_listed = lws_now_usecs();
	uuid_list->idle = (char)!!idle;

	lws_dll2_add_tail(&uuid_list->list, &sp->inflight_owner);

	lwsl_info("%s: created uuid_list entry for %s\n", __func__, uuid_list->uuid);
	assert(sais_is_task_inflight(vhd, NULL, uuid, NULL));
	return 0;
}

void
sais_inflight_entry_destroy(sai_uuid_list_t *ul)
{
	lwsl_info("%s: removing uuid_list entry for %s\n", __func__, ul->uuid);

	lws_dll2_remove(&ul->list);
	free(ul);
}

void
sais_prune_inflight_list(struct vhd *vhd)
{
	lws_usec_t t = lws_now_usecs();

	lws_start_foreach_dll(struct lws_dll2 *, p, vhd->server.builder_owner.head) {
		sai_plat_t *sp = lws_container_of(p, sai_plat_t, sai_plat_list);

		lws_start_foreach_dll_safe(struct lws_dll2 *, p1, p2, sp->inflight_owner.head) {
			sai_uuid_list_t *u = lws_container_of(p1, sai_uuid_list_t, list);

			if (!u->started && (t - u->us_time_listed) > 30 * 1000 * 1000)
				sais_inflight_entry_destroy(u);

		} lws_end_foreach_dll_safe(p1, p2);

	} lws_end_foreach_dll(p);
}


/*
 * Helper to identify and fix stale corrupted legacy tasks
 */
static int
sais_check_and_fix_stale_task(sqlite3 *pdb, sai_task_t *t)
{
	int max_run = -1;
	char q[200], esc[100];

	lws_sql_purify(esc, t->uuid, sizeof(esc));
	lws_snprintf(q, sizeof(q), "select max(run) from tasks where uuid='%s'", esc);

	if (sqlite3_exec(pdb, q, sql3_get_integer_cb, &max_run, NULL) == SQLITE_OK) {
		if (max_run >= 0 && (int)t->run < max_run) {
			lwsl_err("%s: task %s run %d is stale (max %d), marking deleted\n", __func__, esc, t->run, max_run);
			lws_snprintf(q, sizeof(q), "update tasks set state=7 where uuid='%s' and run=%d", esc, t->run);
			sqlite3_exec(pdb, q, NULL, NULL, NULL);
			return 1;
		}
	}
	return 0;
}

/*
 * How many of the newest unfinished events we look through for one with
 * something startable on the platform.  Each repo's newest event with work for
 * the platform competes for its turn, so this has to reach back past a burst
 * of pushes on one busy repo to whatever else is pending
 */
#define SAIS_PENDING_EVENTS		32
/* forget a repo's turn on a platform if it hasn't been served for this long */
#define SAIS_REPO_TURN_EXPIRY_US	(24ll * 3600 * LWS_US_PER_SEC)

static sais_repo_turn_t *
sais_repo_turn_find(struct vhd *vhd, const char *platform, const char *repo)
{
	lws_usec_t now = lws_now_usecs();
	sais_repo_turn_t *found = NULL;

	lws_start_foreach_dll_safe(struct lws_dll2 *, p, p1,
				   vhd->repo_turns.head) {
		sais_repo_turn_t *rt = lws_container_of(p, sais_repo_turn_t,
							list);

		if (now - rt->last_served > SAIS_REPO_TURN_EXPIRY_US) {
			lws_dll2_remove(&rt->list);
			free(rt);
			continue;
		}

		if (!strcmp(rt->platform, platform) &&
		    !strcmp(rt->repo_name, repo))
			found = rt;

	} lws_end_foreach_dll_safe(p, p1);

	return found;
}

/*
 * When did platform last get a task from repo... 0 if not recently, which
 * puts it at the front of the queue
 */

static lws_usec_t
sais_repo_turn_last_served(struct vhd *vhd, const char *platform,
			   const char *repo)
{
	sais_repo_turn_t *rt = sais_repo_turn_find(vhd, platform, repo);

	return rt ? rt->last_served : 0;
}

/*
 * The platform was just given a task from repo, so it goes to the back of the
 * queue for that platform
 */

static void
sais_repo_turn_served(struct vhd *vhd, const char *platform, const char *repo)
{
	sais_repo_turn_t *rt = sais_repo_turn_find(vhd, platform, repo);

	if (!rt) {
		rt = malloc(sizeof(*rt));
		if (!rt)
			return;
		memset(rt, 0, sizeof(*rt));
		lws_strncpy(rt->platform, platform, sizeof(rt->platform));
		lws_strncpy(rt->repo_name, repo, sizeof(rt->repo_name));
		lws_dll2_add_tail(&rt->list, &vhd->repo_turns);
	}

	rt->last_served = lws_now_usecs();
}

void
sais_repo_turns_destroy(struct vhd *vhd)
{
	lws_start_foreach_dll_safe(struct lws_dll2 *, p, p1,
				   vhd->repo_turns.head) {
		sais_repo_turn_t *rt = lws_container_of(p, sais_repo_turn_t,
							list);

		lws_dll2_remove(&rt->list);
		free(rt);

	} lws_end_foreach_dll_safe(p, p1);
}

/*
 * Pick a startable task for platform from event e, preferring ones that failed
 * the last time this repo / ref was built on the platform.
 *
 * Returns 0 with the task in pss->alloc_task, 1 if nothing startable, or -1 if
 * we found and cleaned up a stale task, and the caller should give up this
 * time around.
 */

static int
sais_task_pending_on_event(struct vhd *vhd, struct pss *pss,
			   const sai_event_t *e, const char *esc_plat,
			   const char *esc_bname)
{
	typedef struct sai_failed_task_info {
		lws_dll2_t      list;
		/* over-allocated */
		const char      *taskname;
	} sai_failed_task_info_t;
	char prev_event_uuid[33] = "", checked_uuid[33] = "";
	char esc_repo[96], esc_ref[96], pf[2048], query[384];
	sqlite3 *pdb = NULL, *prev_pdb = NULL;
	lws_dll2_owner_t failed_tasks_owner, owner;
	struct lwsac *failed_ac = NULL;
	uint64_t last_created;
	sai_task_t *t;
	int n, r = 1;

	if (sai_event_db_ensure_open(vhd->context, &vhd->sqlite3_cache,
			      vhd->sqlite3_path_lhs, e->uuid, 0, &pdb))
		return 1;

	lws_dll2_owner_clear(&failed_tasks_owner);

	lws_sql_purify(esc_repo, e->repo_name, sizeof(esc_repo));
	lws_sql_purify(esc_ref, e->ref, sizeof(esc_ref));
	last_created = e->created;

	do {
		sqlite3_stmt *sm;
		int pr;

		prev_event_uuid[0] = '\0';
		lws_snprintf(query, sizeof(query),
			 "select uuid, created from events where repo_name='%s' and "
			 "ref='%s' and created < %llu "
			 "order by created desc limit 1",
			 esc_repo, esc_ref, (unsigned long long)last_created);

		/*
		 * ... this is the 32-char EVENT uuid coming,
		 * not a compound (64 char) task one
		 */

		pr = sqlite3_prepare_v2(vhd->server.pdb, query, -1, &sm, NULL);
		if (pr != SQLITE_OK) {
			lwsl_warn("%s: sq3 prep returned %d instead of SQLITE_OK\n", __func__, pr);
			break;
		}
		if (sqlite3_step(sm) == SQLITE_ROW) {
			const char *u = (const char *)sqlite3_column_text(sm, 0);

			if (u)
				lws_strncpy(prev_event_uuid, (const char *)u, sizeof(prev_event_uuid));

			last_created = (uint64_t)sqlite3_column_int64(sm, 1);
		} else
			lwsl_notice("%s: no results from event check %s %s\n", __func__, esc_repo, esc_ref);

		sqlite3_finalize(sm);

		if (!prev_event_uuid[0]) {
			lwsl_notice("%s: breaking due to NUL prev_event_uuid\n", __func__);
			break;
		}

		if (!sais_event_check_for_plat_tasks(vhd, prev_event_uuid, esc_plat)) {
			lwsl_notice("%s: continuing due to event_ran_platform 0\n", __func__);
			continue;
		}

		lws_strncpy(checked_uuid, prev_event_uuid, sizeof(checked_uuid));
		break;
	} while (1);

	if (checked_uuid[0] &&
	    !sai_event_db_ensure_open(vhd->context, &vhd->sqlite3_cache,
			      vhd->sqlite3_path_lhs, checked_uuid, 1, &prev_pdb)) {
		sqlite3_stmt *sm;

		/* we are looking for failed tasks here */

		lws_snprintf(query, sizeof(query),
			     "select taskname from tasks t1 where "
			     "state = 4 and idle=0 and platform = ?"
			     " and run = (select max(run) from tasks t2 where t1.uuid = t2.uuid)");

		if (sqlite3_prepare_v2(prev_pdb, query, -1, &sm, NULL) == SQLITE_OK) {
			const unsigned char *tn;
			sai_failed_task_info_t *fti;

			sqlite3_bind_text(sm, 1, esc_plat, -1, SQLITE_TRANSIENT);

			while (1) {
				int nn = sqlite3_step(sm);

				if (nn != SQLITE_ROW)
					break;

				tn = sqlite3_column_text(sm, 0);
				if (!tn)
					continue;

				/*
				 * We found errored tasks in the previous event for this
				 * repo / branch / platform.  Let's record them in a temp
				 * lwsac and condsider if we should use this info to
				 * prioritize running the corresponding task in the current
				 * event first
				 */

				fti = lwsac_use_zero(&failed_ac, sizeof(*fti) +
						strlen((const char *)tn) + 1, 256);
				if (fti) {
					fti->taskname = (const char *)&fti[1];
					memcpy((char *)fti->taskname, tn,
					       strlen((const char *)tn) + 1);
					lws_dll2_add_tail(&fti->list, &failed_tasks_owner);
				}
			}
			sqlite3_finalize(sm);
		} else
			lwsl_err("%s: query fail 1\n", __func__);

		sai_event_db_close(&vhd->sqlite3_cache, &prev_pdb);
	}

	/*
	 * Let's go through the tasks that failed last time we built this repo / branch, and see
	 * if we can find the analagous task in the current event.
	 */

	lws_start_foreach_dll(struct lws_dll2 *, p_fail, failed_tasks_owner.head) {
		sai_failed_task_info_t *fti = lws_container_of(p_fail, sai_failed_task_info_t, list);
		char esc_taskname[256];

		lws_sql_purify(esc_taskname, fti->taskname, sizeof(esc_taskname));
		lws_snprintf(pf, sizeof(pf),
			     " and state IN(0,9) and idle=0 and platform='%s' and taskname='%s' and "
			     "(builder_name IS NULL or builder_name IN('','%s'))"
			     " and run = (select max(run) from tasks t2 where tasks.uuid = t2.uuid)",
			     esc_plat, esc_taskname, esc_bname);

		lwsac_free(&pss->ac_alloc_task);
		lws_dll2_owner_clear(&owner);
		n = lws_struct_sq3_deserialize(pdb, pf, NULL,
					       lsm_schema_sq3_map_task,
					       &owner, &pss->ac_alloc_task, 0, 1);
		if (n < 0 || !owner.count)
			continue;

		// lwsl_notice("%s: Prioritizing failed task for %s ('%s')\n",
		//	    __func__, esc_plat, fti->taskname);

		goto found;

	} lws_end_foreach_dll(p_fail);

	lwsl_info("%s: no priority\n", __func__);

	/* We have fallen back to doing tasks earliest-first */

	lws_snprintf(pf, sizeof(pf),
		     " and state IN(0,9) and idle=0 and platform='%s' and "
		     "(builder_name IS NULL or builder_name IN('','%s'))"
		     " and run = (select max(run) from tasks t2 where tasks.uuid = t2.uuid)",
		     esc_plat, esc_bname);

	lwsac_free(&pss->ac_alloc_task);
	lws_dll2_owner_clear(&owner);
	n = lws_struct_sq3_deserialize(pdb, pf, "taskname asc, uid asc ",
				       lsm_schema_sq3_map_task,
				       &owner, &pss->ac_alloc_task, 0, 1);
	// lwsl_notice("%s: deser returned %d\n", __func__, n);
	if (n < 0 || !owner.count || !pss->ac_alloc_task)
		goto bail;

found:
	t = lws_container_of(owner.head, sai_task_t, list);
	if (sais_check_and_fix_stale_task(pdb, t)) {
		r = -1;
		goto bail;
	}

	memcpy(&pss->alloc_task, t, sizeof(pss->alloc_task));
	lws_strncpy(pss->alloc_repo, e->repo_name, sizeof(pss->alloc_repo));
	r = 0;

bail:
	sai_event_db_close(&vhd->sqlite3_cache, &pdb);
	lwsac_free(&failed_ac);

	return r;
}

/*
 * Find a task that still needs doing for platform, on any event.
 *
 * A task the builder already started and that is waiting for its next step
 * comes first.  Otherwise, each repo with something startable for the
 * platform puts forward its newest event that has some, and the repos take
 * turns: the one the platform was least recently given a task from goes
 * first.  So a big push on one repo doesn't hold up a push on another until
 * every one of its tasks is done.
 */
static const sai_task_t *
sais_task_pending(struct vhd *vhd, struct pss *pss, sai_plat_t *cb,
		  const char *platform)
{
	const sai_event_t *cand[SAIS_PENDING_EVENTS];
	lws_usec_t cand_served[SAIS_PENDING_EVENTS];
	char esc_plat[96], esc_bname[128], pf[512], query[384];
	struct lwsac *ac = NULL;
	unsigned int pending_count;
	int n, m, i, cands = 0;
	lws_dll2_owner_t o;

	lws_sql_purify(esc_plat, platform, sizeof(esc_plat));
	lws_sql_purify(esc_bname, cb->name, sizeof(esc_bname));
	assert(platform);

	/* 
	 * this is looking at the state of *events*
	 *
	 *      SAIES_WAITING                           = 0,
         *	SAIES_PASSED_TO_BUILDER                 = 1,
         *	SAIES_BEING_BUILT                       = 2,
         *	SAIES_SUCCESS                           = 3,
         *	SAIES_FAIL                              = 4,
         *	SAIES_CANCELLED                         = 5,
         *	SAIES_BEING_BUILT_HAS_FAILURES          = 6,
         *	SAIES_DELETED                           = 7,
	 */
	lws_snprintf(pf, sizeof(pf)," and (state != 3 and state != 4 and state != 5 and state != 7) and (created < %llu)",
			(unsigned long long)(lws_now_secs() - 10));

	n = lws_struct_sq3_deserialize(vhd->server.pdb, pf, "created desc ",
				       lsm_schema_sq3_map_event, &o, &ac, 0,
				       SAIS_PENDING_EVENTS);
	if (n < 0 || !o.count) {
		lwsl_notice("%s: platform %s: bail1: n %d count %d\n", __func__, platform, n, o.count);

		goto bail;
	}

	lwsl_info("%s: plat %s, toplevel results %d\n", __func__, platform, o.count);

	/*
	 * Newest first, find each repo's newest event with startable tasks for
	 * this platform
	 */

	lws_start_foreach_dll(struct lws_dll2 *, p, o.head) {
		sai_event_t *e = lws_container_of(p, sai_event_t, list);
		lws_dll2_owner_t owner;
		sqlite3 *pdb = NULL;

		if (sai_event_db_ensure_open(vhd->context, &vhd->sqlite3_cache,
				      vhd->sqlite3_path_lhs, e->uuid, 0, &pdb))
			continue;

		/*
		 * A task this builder already started, waiting for its next
		 * step, comes before anything new whatever repo it is from.
		 * Its earlier steps' work is sitting in our job dir, which is
		 * only safe from being reclaimed for a while, and starting new
		 * tasks instead just eats more of the disk it is waiting for.
		 */

		lws_snprintf(pf, sizeof(pf),
			     " and state=%d and idle=0 and platform='%s' and "
			     "builder_name='%s' and run = (select max(run) "
			     "from tasks t2 where tasks.uuid = t2.uuid)",
			     SAIES_STEP_SUCCESS, esc_plat, esc_bname);

		lwsac_free(&pss->ac_alloc_task);
		lws_dll2_owner_clear(&owner);
		n = lws_struct_sq3_deserialize(pdb, pf, "uid asc ",
					       lsm_schema_sq3_map_task,
					       &owner, &pss->ac_alloc_task, 0, 1);
		if (n >= 0 && owner.count) {
			sai_task_t *t = lws_container_of(owner.head,
							 sai_task_t, list);

			if (sais_check_and_fix_stale_task(pdb, t)) {
				sai_event_db_close(&vhd->sqlite3_cache, &pdb);
				goto bail;
			}

			lwsl_info("%s: plat %s: continuing %s\n", __func__,
				  platform, t->uuid);

			memcpy(&pss->alloc_task, t, sizeof(pss->alloc_task));
			lws_strncpy(pss->alloc_repo, e->repo_name,
				    sizeof(pss->alloc_repo));
			sai_event_db_close(&vhd->sqlite3_cache, &pdb);
			lwsac_free(&ac);

			return &pss->alloc_task;
		}

		for (i = 0; i < cands; i++)
			if (!strcmp(cand[i]->repo_name, e->repo_name))
				break;
		if (i != cands) {
			/* this repo already has a newer candidate */
			sai_event_db_close(&vhd->sqlite3_cache, &pdb);
			continue;
		}

		/*
		 * Find out how many tasks in startable state for this platform,
		 * on this event
		 */

		lws_snprintf(query, sizeof(query), "select count(state) from tasks t1 where "
						   "state IN(0,9) and idle=0 and platform='%s' and "
						   "(builder_name IS NULL or builder_name IN('','%s'))"
						   " and run = (select max(run) from tasks t2 where t1.uuid = t2.uuid)",
						   esc_plat, esc_bname);
		m = sqlite3_exec(pdb, query, sql3_get_integer_cb, &pending_count, NULL);
		sai_event_db_close(&vhd->sqlite3_cache, &pdb);

		if (m != SQLITE_OK) {
			pending_count = 0;
			lwsl_err("%s: query failed: %d\n", __func__, m);
		}

		// lwsl_notice("%s: %s: platform: '%s' startable tasks: %d\n", __func__, e->uuid, esc_plat, pending_count);

		if (pending_count <= 0)
			continue;

		cand_served[cands] = sais_repo_turn_last_served(vhd, platform,
								e->repo_name);
		cand[cands++] = e;

	} lws_end_foreach_dll(p);

	if (!cands) {
		lwsl_info("%s: platform %s: no pending count\n", __func__, platform);
		goto bail;
	}

	/*
	 * Try the candidates least recently served first, ties going to the
	 * newer event
	 */

	while (cands) {
		int best = 0;

		for (i = 1; i < cands; i++)
			if (cand_served[i] < cand_served[best])
				best = i;

		lwsl_info("%s: plat %s: trying repo %s, event %s\n", __func__,
			  platform, cand[best]->repo_name, cand[best]->uuid);

		n = sais_task_pending_on_event(vhd, pss, cand[best], esc_plat,
					       esc_bname);
		if (n < 0)
			/* we cleaned up something stale, try again later */
			goto bail;

		if (!n) {
			lwsac_free(&ac);

			return &pss->alloc_task;
		}

		/* nothing usable after all, drop it, keeping the order */

		cands--;
		memmove(&cand[best], &cand[best + 1],
			(size_t)(cands - best) * sizeof(cand[0]));
		memmove(&cand_served[best], &cand_served[best + 1],
			(size_t)(cands - best) * sizeof(cand_served[0]));
	}

bail:
	lwsac_free(&ac);

	lwsl_info("%s: leaving by bail\n", __func__);

	return NULL;
}

/*
 * If the plat name is already listed, just return with 1.
 * Otherwise add to the ac and linked-list for unique startable plat names and
 * return 0.
 */

static int
sais_find_or_add_pending_plat(struct vhd *vhd, const char *name, int count, int unmet)
{
	sais_plat_t *sp;

	lws_start_foreach_dll(struct lws_dll2 *, p, vhd->pending_plats.head) {
		sais_plat_t *pl = lws_container_of(p, sais_plat_t, list);

		if (!strcmp(pl->plat, name)) {
			pl->pending_count += count;
			pl->unmet_count += unmet;
			return 1;
		}

	} lws_end_foreach_dll(p);

	/* platform name is new, make an entry in the ac */

	sp = lwsac_use_zero(&vhd->ac_plats, sizeof(sais_plat_t) + strlen(name) + 1, 512);

	sp->plat = (const char *)&sp[1]; /* start of overcommit */
	memcpy(&sp[1], name, strlen(name) + 1);
	sp->pending_count = count;
	sp->unmet_count = unmet;

	lws_dll2_add_tail(&sp->list, &vhd->pending_plats);

	return 0;
}

void
sais_add_pending_plat(struct vhd *vhd, const char *name, int count, int unmet)
{
	sais_find_or_add_pending_plat(vhd, name, count, unmet);
}

static void
sais_destroy_pending_plat_list(struct vhd *vhd)
{
	/*
	 * We can just drop everything in the owner and drop the ac to destroy
	 */
	lws_dll2_owner_clear(&vhd->pending_plats);
	lwsac_free(&vhd->ac_plats);
}

static void
sais_notify_all_sai_power(struct vhd *vhd)
{
	lws_start_foreach_dll(struct lws_dll2 *, p, vhd->sai_powers.head) {
		struct pss *pss = lws_container_of(p, struct pss, same);

		lws_callback_on_writable(pss->wsi);

	} lws_end_foreach_dll(p);
}

/*
 * Find out which platforms on this server have pending tasks
 */

int
sais_platforms_with_tasks_pending(struct vhd *vhd)
{
	struct lwsac *ac = NULL;
	char pf[128];
	lws_dll2_owner_t o;
	int n;

	/* lose everything we were holding on to from last time */
	sais_destroy_pending_plat_list(vhd);

	/*
	 * Collect a list of *events* (not tasks) that still have any open tasks
	 */

	lws_snprintf(pf, sizeof(pf)," and (state != 3 and state != 4 and state != 5 and state != 7) and (created < %llu)",
			(unsigned long long)(lws_now_secs() - 10));

	n = lws_struct_sq3_deserialize(vhd->server.pdb, pf, "created desc ",
				       lsm_schema_sq3_map_event, &o, &ac, 0, 20);

	if (n < 0)
		goto bail;

	/*
	 * If there are no events that aren't complete, we carry on: idle
	 * tasks live on completed events, and sai-power still needs telling
	 * that nothing is pending any more
	 */

	/*
	 * Iterate through the events looking at his event-specific database
	 * for platforms that have pending or ongoing tasks...
	 */

	lws_start_foreach_dll(struct lws_dll2 *, p, o.head) {
		sai_event_t *e = lws_container_of(p, sai_event_t, list);
		sqlite3 *pdb = NULL;
		sqlite3_stmt *sm;
		int n;

		if (!sai_event_db_ensure_open(vhd->context, &vhd->sqlite3_cache,
				      vhd->sqlite3_path_lhs, e->uuid, 0, &pdb)) {

			if (sqlite3_prepare_v2(pdb, "select platform, count(*), "
						    "sum(case when (state = 0 or state = 9) and (builder_name IS NULL or builder_name = '') then 1 else 0 end) "
						    "from tasks t1 where idle=0 and "
						    "run = (select max(run) from tasks t2 where t1.uuid = t2.uuid) and "
						    "(state = 0 or state = 1 or state = 2 or state = 9) group by platform", -1, &sm,
							   NULL) != SQLITE_OK) {
				lwsl_err("%s: Unable to %s\n",
					 __func__, sqlite3_errmsg(pdb));

				goto bail;
			}

			do {
				n = sqlite3_step(sm);
				if (n == SQLITE_ROW)
					sais_find_or_add_pending_plat(vhd,
						(const char *)sqlite3_column_text(sm, 0),
						sqlite3_column_int(sm, 1),
						sqlite3_column_int(sm, 2));
			} while (n == SQLITE_ROW);

			sqlite3_reset(sm);
			sqlite3_finalize(sm);

			if (n != SQLITE_DONE) {
				n = sqlite3_extended_errcode(pdb);
				if (!n)
					lwsl_info("%s: failed\n", __func__);

				lwsl_err("%s: %d: Unable to perform: %s\n",
					 __func__, n, sqlite3_errmsg(pdb));
			}

			sai_event_db_close(&vhd->sqlite3_cache, &pdb);
		}

	} lws_end_foreach_dll(p);

	/*
	 * Idle tasks that builders are due to be working on count as pending
	 * too, so sai-power brings those builders up for them
	 */
	sais_idle_add_pending_plats(vhd);

	/*
	 * Also account for any in-memory interactive shell sessions
	 */
	lws_start_foreach_dll(struct lws_dll2 *, p_sh, vhd->shell_sessions.head) {
		sai_shell_session_t *sh = lws_container_of(p_sh, sai_shell_session_t, list);
		const char *plat = strchr(sh->builder_name, '.');
		if (plat)
			sais_find_or_add_pending_plat(vhd, plat + 1, 1, 1);
		else
			sais_find_or_add_pending_plat(vhd, sh->builder_name, 1, 1);
	} lws_end_foreach_dll(p_sh);

	sais_notify_all_sai_power(vhd);

	/*
	 * Wake up any builders that are slacking, since there are new tasks
	 */
	lws_start_foreach_dll(struct lws_dll2 *, p, vhd->server.builder_owner.head) {
		sai_plat_t *sp = lws_container_of(p, sai_plat_t, sai_plat_list);

		if (!sp->busy)
			sais_plat_busy(sp, 0);

	} lws_end_foreach_dll(p);

	lwsac_free(&ac);

	return 0;

bail:
	lwsac_free(&ac);

	return 1;
}

/*
 * Look for any task on any event that needs building on platform_name, if found
 * the caller must take responsibility to free pss->a.ac
 */

int
sais_allocate_task(struct vhd *vhd, struct pss *pss, sai_plat_t *sp,
		   const char *platform_name)
{
	const sai_task_t *task_template;
	sai_task_t temp_task;

	if (sp->busy) {
		lwsl_wsi_warn(pss->wsi, "::::::::::::: ABORTING task alloc due to BUSY on %s", sp->name);
		return 1;
	}

	/*
	 * Look for a task for this platform, on any event that needs building
	 */

	task_template = sais_task_pending(vhd, pss, sp, platform_name);
	if (!task_template) {
		lwsl_info("%s: %s: can't identify pending task\n",
			    __func__, sp->name);
		/*
		 * Nothing real for this builder platform to do... it may
		 * be willing to spend the time on an idle task
		 */
		return sais_idle_allocate(vhd, pss, sp);
	}

	/*
	 * We have a candidate task, check if the builder has enough
	 * resources for it
	 */
	memcpy(&temp_task, task_template, sizeof(temp_task));
	sais_get_task_metrics_estimates(vhd, &temp_task);

	if (temp_task.est_peak_mem_kib > sp->avail_mem_kib ||
	    temp_task.est_disk_kib > sp->avail_sto_kib) {
		lwsl_notice("%s: builder %s lacks resources for task %s "
			    "(mem %uk/%uk, sto %uk/%uk), trying another\n",
			    __func__, sp->name, temp_task.uuid,
			    temp_task.est_peak_mem_kib, sp->avail_mem_kib,
			    temp_task.est_disk_kib, sp->avail_sto_kib);
		return 1;
	}

	if (sais_is_task_inflight(vhd, NULL, task_template->uuid, NULL)) {
		lwsl_info("%s: ~~~~~~~~ skipping %s as listed on inflight\n",
				__func__, task_template->uuid);
		return 1;
	}

	/*
	 * This marks the sqlite task as being bound to builder sp->name
	 */

	sais_bind_task_to_builder(vhd, sp->name, sp->name, task_template->uuid);

	lwsl_info("%s: %s: task %s found for %s\n", __func__,
		    platform_name, task_template->uuid, sp->name);

	if (sais_create_and_offer_task_step(vhd, task_template->uuid))
		return 1;

	/* the platform's next task should come from a different repo, if any */

	sais_repo_turn_served(vhd, platform_name, pss->alloc_repo);

	/* yes, we will offer it to him */

	sais_list_builders(vhd);

	/* advance the task state first time we get logs */
	pss->mark_started = 1;

	return 0;
}

#define MAX_BLOB 1024

void
sais_activity_cb(lws_sorted_usec_list_t *sul)
{
	struct vhd *vhd = lws_container_of(sul, struct vhd, sul_activity);
	struct lwsac *ac_events = NULL, *ac_tasks = NULL;
	lws_dll2_owner_t o_events, o_tasks;
	char *p, *start, *end, *ast, s = 1;
	lws_wsmsg_info_t info;
	int cat, first = 1;
	lws_usec_t now;

	ast = malloc(MAX_BLOB + LWS_PRE);
	if (!ast)
		return;

	start = ast + LWS_PRE;
	end = start + MAX_BLOB;
	p = start;

	p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
			  "{\"schema\":\"com.warmcat.sai.taskactivity\","
			  "\"activity\":[");

	now = lws_now_usecs();

	if (lws_struct_sq3_deserialize(vhd->server.pdb,
			" and state != 3 and state != 4 and state != 5 and state != 7",
			NULL, lsm_schema_sq3_map_event, &o_events, &ac_events, 0, 100) < 0 ||
			!o_events.head)
		goto nope;

	lws_start_foreach_dll(struct lws_dll2 *, d, o_events.head) {
		sai_event_t *e = lws_container_of(d, sai_event_t, list);
		sqlite3 *pdb = NULL;

		if (sai_event_db_ensure_open(vhd->context, &vhd->sqlite3_cache,
				      vhd->sqlite3_path_lhs, e->uuid, 0, &pdb))
			goto next;

		if (lws_struct_sq3_deserialize(pdb,
                                " and (state = 1 or state = 2) and run = (select max(run) from tasks t2 where tasks.uuid = t2.uuid)",
				NULL, lsm_schema_sq3_map_task, &o_tasks,
				&ac_tasks, 0, 100) < 0 || !o_tasks.head)
			goto next1;

		lws_start_foreach_dll(struct lws_dll2 *, dt, o_tasks.head) {
			sai_task_t *t = lws_container_of(dt, sai_task_t, list);

			if (lws_ptr_diff_size_t(end, p) < 100)
				break;

			if (now - (lws_usec_t)(t->last_updated * LWS_US_PER_SEC) > 10 * LWS_US_PER_SEC)
				cat = 1;
			else if (now - (lws_usec_t)(t->last_updated * LWS_US_PER_SEC) > 3 * LWS_US_PER_SEC)
				cat = 2;
			else
				cat = 3;

			if (!first)
				*p++ = ',';

			p += lws_snprintf(p, lws_ptr_diff_size_t(end, p),
					  "{\"uuid\":\"%s\",\"cat\":%d}", t->uuid, cat);
			first = 0;

			if (lws_ptr_diff_size_t(end, p) < 100) {
				memset(&info, 0, sizeof(info));
				info.private_source_idx	= SAI_WEBSRV_PB__ACTIVITY;
				info.buf		= (uint8_t *)start;
				info.len		= lws_ptr_diff_size_t(p, start);
				info.ss_flags		= s ? LWSSS_FLAG_SOM : 0;
				/*
				 * We might start it, but it won't be the final
				 * frag here since we have JSON closure to do
				 */
				sais_websrv_broadcast_REQUIRES_LWS_PRE(vhd->h_ss_websrv, &info);
				p = start;
				s = 0;
			}
		} lws_end_foreach_dll(dt);

next1:
		lwsac_free(&ac_tasks);
		sai_event_db_close(&vhd->sqlite3_cache, &pdb);

next: ;
	} lws_end_foreach_dll(d);

nope:
	lwsac_free(&ac_events);

	*p++ = ']';
	*p++ = '}';

	if (!s) { /* ie, if we sent something, send the closing part of the JSON */
		memset(&info, 0, sizeof(info));

		info.private_source_idx		= SAI_WEBSRV_PB__ACTIVITY;
		info.buf			= (uint8_t *)start;
		info.len			= lws_ptr_diff_size_t(p, start);
		info.ss_flags			= LWSSS_FLAG_EOM;
		sais_websrv_broadcast_REQUIRES_LWS_PRE(vhd->h_ss_websrv, &info);

		lws_sul_schedule(vhd->context, 0, &vhd->sul_activity,
				 sais_activity_cb, 3 * LWS_US_PER_SEC);
	}

	free(ast);
}

int
sais_create_and_offer_task_step(struct vhd *vhd, const char *task_uuid)
{
	char event_uuid[33], esc_uuid[129], *p, *start, url[128],
	     mirror_path[256], update[128];
	sai_task_t *temp_task = NULL, *task_template;
	lws_dll2_owner_t o, o_event;
	struct lwsac *ac = NULL;
	sai_uuid_list_t *ul;
	sqlite3 *pdb = NULL;
	sai_event_t *event;
	int n, build_step;
	struct pss *pss;
	sai_plat_t *sp;
	int inflight;
	int ret = -1;

	inflight = sais_is_task_inflight(vhd, NULL, task_uuid, &ul);
       
	if (inflight) {
		if (!ul->started) {
			lwsl_notice("%s: ~~~ not continuing %s as listed on inflight\n",
				    __func__, task_uuid);
			return 1;
		}
		/*
		 * We're about to offer its next step, and from here until the
		 * builder accepts it the prune is allowed to decide the offer
		 * got lost.  The entry was listed when step 1 was offered, so
		 * unless the clock restarts now, any task more than 30s old
		 * loses its entry the moment the prune runs in this gap, and
		 * the next scan for pending work offers the same step again.
		 */
		ul->started = 0;
		ul->us_time_listed = lws_now_usecs();
	}

	event_uuid[0] = '\0';
	sai_task_uuid_to_event_uuid(event_uuid, task_uuid);

	if (sai_event_db_ensure_open(vhd->context, &vhd->sqlite3_cache,
			      vhd->sqlite3_path_lhs, event_uuid, 0, &pdb) || !pdb)
		return -1;

	// lwsl_notice("%s: task_uuid %s, pdb %p\n", __func__, task_uuid, pdb);

	lws_sql_purify(esc_uuid, task_uuid, sizeof(esc_uuid));
	lws_snprintf(update, sizeof(update), " and uuid='%s'", esc_uuid);
	n = lws_struct_sq3_deserialize(pdb, update, "run desc",
				       lsm_schema_sq3_map_task, &o, &ac, 0, 1);
	if (n < 0 || !o.head) {
		lwsl_warn("%s: bailing as no task %s\n", __func__, task_uuid);
		sai_event_db_close(&vhd->sqlite3_cache, &pdb);
		lwsac_free(&ac);
		return -1;
	}

	task_template = lws_container_of(o.head, sai_task_t, list);

	switch (task_template->state) {
	case SAIES_YIELDED:
		/*
		 * The builder stopped this idle task's slice, it has no
		 * more steps to offer until s-idle.c starts a new slice
		 */
		sai_event_db_close(&vhd->sqlite3_cache, &pdb);
		lwsac_free(&ac);
		return 0;

	case SAIES_SUCCESS:
	case SAIES_FAIL:
	case SAIES_CANCELLED:
	case SAIES_DELETED:
	case SAIES_PAUSED:
		/*
		 * Its latest run isn't going anywhere, whatever build_step
		 * says.  Nothing is in flight for it any more, either.
		 */
		lwsl_notice("%s: not offering %s in state %d\n", __func__,
			    task_uuid, task_template->state);
		if (inflight)
			sais_inflight_entry_destroy(ul);
		sai_event_db_close(&vhd->sqlite3_cache, &pdb);
		lwsac_free(&ac);
		return 1;

	default:
		break;
	}

	/*
	 * Make a copy of the lws_struct allocation in the lwsac,
	 * but we must retain the lwsac because the copied task_template
	 * still contains pointers into it!
	 */

	temp_task = malloc(sizeof(sai_task_t));
	if (!temp_task) {
		lwsac_free(&ac);
		sai_event_db_close(&vhd->sqlite3_cache, &pdb);
		return -1;
	}

	memset(temp_task, 0, sizeof(*temp_task));
	*temp_task = *task_template;
	temp_task->ac_task_container = ac;

	sais_get_task_metrics_estimates(vhd, temp_task);

	build_step = temp_task->build_step;

	/* get the event */
	lws_sql_purify(esc_uuid, event_uuid, sizeof(esc_uuid));
	lws_snprintf(update, sizeof(update), " and uuid='%s'", esc_uuid);
	n = lws_struct_sq3_deserialize(vhd->server.pdb, update, NULL,
				       lsm_schema_sq3_map_event, &o_event,
				       &temp_task->ac_task_container, 0, 1);
	if (n < 0 || !o_event.head) {
		lwsl_warn("%s: bailing as nothing with uuid %s\n", __func__, esc_uuid);
		sai_event_db_close(&vhd->sqlite3_cache, &pdb);
		free(temp_task);
		return -1;
	}

	event = lws_container_of(o_event.head, sai_event_t, list);

	temp_task->one_event		= event;
	temp_task->repo_name		= event->repo_name;
	temp_task->git_ref		= event->ref;
	temp_task->git_hash		= event->hash;
	temp_task->git_repo_url		= event->repo_fetchurl;

	/* find builder */

	sp = sais_builder_from_uuid(vhd, temp_task->builder_name);
	if (!sp) {
		lwsl_warn("%s: bailing as can't find builder from %s\n",
			  __func__, temp_task->builder_name);
		goto bail;
	}

	if (!inflight) {
		if (sais_add_to_inflight_list_if_absent(vhd, sp, task_uuid,
							temp_task->idle)) {
			lwsl_warn("%s: bailing as can't add to inflight %s\n", __func__, task_uuid);
			sais_task_clear_build_and_logs(vhd, task_uuid, 0);
			goto bail;
		}
	}

	lws_strncpy(url, temp_task->one_event->repo_fetchurl, sizeof(url));
	lws_filename_purify_inplace(url);
	char *q = url;
	while (*q) {
		if (*q == '/') *q = '_';
		if (*q == '.') *q = '_';
		q++;
	}
	lws_snprintf(mirror_path, sizeof(mirror_path), "%s", url);

	/*
	 * Defense-in-depth: the notification lejp callback (s-notification.c)
	 * already validates git_ref / git_hash at the only ingress point.  We
	 * re-check here before interpolating them unquoted into the shell
	 * script line, in case a task is created or mutated via another path.
	 * See sai_is_safe_ref / sai_is_git_hash in src/common/c-utils.c.
	 */
	if (build_step <= 1 &&
	    (!sai_is_safe_ref(temp_task->git_ref) ||
	     !sai_is_git_hash(temp_task->git_hash))) {
		lwsl_warn("%s: refusing to offer task %s step %d: unsafe ref "
			  "'%s' or hash '%s'\n", __func__, task_uuid,
			  build_step, temp_task->git_ref, temp_task->git_hash);
		goto bail;
	}

	switch (build_step) {
	case 0: /* git mirror */
		if (sp->windows)
			lws_snprintf(temp_task->script, sizeof(temp_task->script),
				".\\git_helper.bat mirror \"%s\" %s %s %s",
				temp_task->git_repo_url, temp_task->git_ref, temp_task->git_hash,
				mirror_path);
		else
			lws_snprintf(temp_task->script, sizeof(temp_task->script),
				"./git_helper.sh mirror \"%s\" %s %s %s",
				temp_task->git_repo_url, temp_task->git_ref, temp_task->git_hash,
				mirror_path);
		break;
	case 1: /* git checkout */
		if (sp->windows)
			lws_snprintf(temp_task->script, sizeof(temp_task->script),
				".\\git_helper.bat checkout \"%s\" src %s",
				mirror_path, temp_task->git_hash);
		else
			lws_snprintf(temp_task->script, sizeof(temp_task->script),
				"./git_helper.sh checkout \"%s\" src %s",
				mirror_path, temp_task->git_hash);
		break;
	default:
		p = start = temp_task->build;
		n = 0;
		while (n < build_step - 2 && (p = strchr(p, '\n'))) {
			p++;
			n++;
		}

		/*
		 * A build ending in '\n' leaves us at an empty string after
		 * its last line rather than NULL; that isn't a step, and
		 * sais_task_build_step_count() doesn't count it as one either
		 */
		if (!p || !*p) { /* no more steps */
			sai_uuid_list_t *u;

			lwsl_info("%s: no more steps after "
				  "build_step %d for task %s, setting SAIES_SUCCESS\n",
				  __func__, build_step, temp_task->uuid);
			sais_task_logf(vhd, temp_task->uuid,
				       "all %d steps completed, task succeeded",
				       build_step);
			sais_set_task_state(vhd, temp_task->uuid, SAIES_SUCCESS, 0, 0);

			if (sais_is_task_inflight(vhd, sp, temp_task->uuid, &u))
				sais_inflight_entry_destroy(u);
			ret = 0;
			goto bail;
		}

		start = p;
		p = strchr(start, '\n');
		if (p)
			*p = '\0';

		lws_strncpy(temp_task->script, start, sizeof(temp_task->script));
		break;
	}

	/* find builder pss */

	pss = NULL;
	lws_start_foreach_dll(struct lws_dll2 *, d, vhd->builders.head) {
		struct pss *pss_ = lws_container_of(d, struct pss, same);
		if (pss_->wsi == sp->wsi) {
			pss = pss_;
			break;
		}
	} lws_end_foreach_dll(d);

	if (!pss)
		goto bail;

	temp_task->server_name = pss->server_name;

	if (!inflight) {
		if (sais_add_to_inflight_list_if_absent(vhd, sp, temp_task->uuid,
							temp_task->idle)) {
			lwsl_warn("%s: bailing as can't add to inflight %s\n", __func__, task_uuid);
			sais_task_clear_build_and_logs(vhd, temp_task->uuid, 0);
			goto bail;
		}
	}

	/*
	 * Offer this task step to the builder
	 */

	lws_dll2_add_tail(&temp_task->pending_assign_list, &pss->issue_task_owner);
	lws_callback_on_writable(pss->wsi);

	sai_event_db_close(&vhd->sqlite3_cache, &pdb);

	return 0;

bail:
sai_event_db_close(&vhd->sqlite3_cache, &pdb);
	lwsac_free(&temp_task->ac_task_container);
	free(temp_task);

	return ret;
}



void
sais_plat_find_jobs_cb(lws_sorted_usec_list_t *sul)
{
	sai_plat_t *sp = lws_container_of(sul, sai_plat_t, sul_find_jobs);

	lwsl_info("%s: %s: sp->busy: %d\n", __func__, sp->name, sp->busy);

	if (!sp->busy && sp->wsi && lws_wsi_user(sp->wsi) &&
		/*
		 * try to bind outstanding task to specific builder
		 * instance
		 */
	    !sais_allocate_task((struct vhd *)sp->vhd,
				(struct pss *)lws_wsi_user(sp->wsi),
				sp, sp->platform))
		/*
		 * Only look again if we ended this try successfully
		 */
		lws_sul_schedule(sp->cx, 0, &sp->sul_find_jobs,
				sais_plat_find_jobs_cb, 50 * LWS_US_PER_MS);
}

void
sais_plat_busy(sai_plat_t *sp, char set)
{
	if (set) {
		lwsl_notice("%s: %s: SETTING BUSY\n", __func__, sp->name);
		lws_sul_cancel(&sp->sul_find_jobs);
		sp->busy = 1;
		return;
	}

	sp->busy = 0;
	lwsl_info("%s: %s: CLEARING BUSY\n", __func__, sp->name);

	lws_sul_schedule(sp->cx, 0, &sp->sul_find_jobs,
			 sais_plat_find_jobs_cb, 1);
}
