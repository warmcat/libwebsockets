/*
 * Sai server - ./src/server/s-idle.c
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
 *
 * Idle tasks
 *
 * A .sai.json configuration with "idle": N gets N idle tasks ("lanes") per
 * platform in each event, besides its normal task.  Lanes don't count towards
 * the event's state, and they are only offered to a builder platform that has
 * nothing real to do, and whose builder conf gave it an "idle" share.
 *
 * The lanes of the newest event on a repo + ref whose real tasks have all
 * finished (the "host" event for that ref) are the ones that run: the event
 * stays the one being worked on in idle time after it completed, until a newer
 * push on the ref completes.  Each time a lane runs is a "slice", which is a
 * new run of the lane task; old runs are pruned.
 *
 * How much idle time a builder platform gives to lanes is its builder conf
 * share, eg 50%.  The active period (from the first of its slices starting to
 * the last one ending) puts it in debt: it has to rest for the period *
 * (100 - share) / share before it can start another.  The debt is only paid
 * off while that platform has no real tasks pending, so it really is a share
 * of idle time.  The debt lives here, and survives the builder disconnecting,
 * so builders that sai-power turns off while resting are woken again when the
 * rest is over.
 *
 * Making way for real work when it appears is done by the builder, which
 * stops its slices and reports them YIELDED.
 */

#include <libwebsockets.h>
#include <string.h>

#include "s-private.h"

/* the host events are found again at least this often */
#define SAIS_IDLE_HOSTS_REFRESH_US	(10 * LWS_US_PER_SEC)
/* after a builder declines an idle task, don't offer it another for this */
#define SAIS_IDLE_DECLINE_BACKOFF_US	(60 * LWS_US_PER_SEC)
/* how many of a lane's most recent slices keep their task row and logs */
#define SAIS_IDLE_RUNS_KEPT		4
/*
 * The least an active period is charged as, so a lane that fails at once
 * every time (eg, it doesn't build on that platform) rests like one that ran
 * a while instead of being restarted over and over
 */
#define SAIS_IDLE_MIN_PERIOD_US		(120 * LWS_US_PER_SEC)
/* the most rest an active period can put a builder platform in debt for */
#define SAIS_IDLE_MAX_DEBT_US		(7ll * 24 * 3600 * LWS_US_PER_SEC)
/* how many recent events with lanes we consider as hosts */
#define SAIS_IDLE_HOST_EVENTS		64

static sais_idle_budget_t *
sais_idle_budget_find(struct vhd *vhd, const char *name)
{
	lws_start_foreach_dll(struct lws_dll2 *, p, vhd->idle_budgets.head) {
		sais_idle_budget_t *b = lws_container_of(p,
						sais_idle_budget_t, list);

		if (!strcmp(b->name, name))
			return b;

	} lws_end_foreach_dll(p);

	return NULL;
}

/*
 * A builder told us about one of its platforms, including what, if anything,
 * its conf says it should do with its idle time
 */

void
sais_idle_plat_update(struct vhd *vhd, const sai_plat_t *build)
{
	sais_idle_budget_t *b = sais_idle_budget_find(vhd, build->name);

	if (!b) {
		if (!build->idle_share)
			return;

		b = malloc(sizeof(*b));
		if (!b)
			return;
		memset(b, 0, sizeof(*b));
		lws_strncpy(b->name, build->name, sizeof(b->name));
		lws_strncpy(b->platform, build->platform, sizeof(b->platform));
		b->last_tick = lws_now_usecs();
		lws_dll2_add_tail(&b->list, &vhd->idle_budgets);
	}

	b->share	= build->idle_share > 100 ? 100 : build->idle_share;
	b->instances	= build->idle_instances ? build->idle_instances : 1;
	b->slice_secs	= build->idle_slice_secs;

	lwsl_notice("%s: %s: idle share %u%%, %u instances, slice %us\n",
		    __func__, b->name, b->share, b->instances, b->slice_secs);
}

void
sais_idle_destroy(struct vhd *vhd)
{
	lws_start_foreach_dll_safe(struct lws_dll2 *, p, p1,
				   vhd->idle_budgets.head) {
		sais_idle_budget_t *b = lws_container_of(p,
						sais_idle_budget_t, list);

		lws_dll2_remove(&b->list);
		free(b);

	} lws_end_foreach_dll_safe(p, p1);

	lws_dll2_owner_clear(&vhd->idle_hosts);
	lwsac_free(&vhd->ac_idle_hosts);
}

/* how many idle tasks the builder platform is working on right now */

static unsigned int
sais_idle_running(const sai_plat_t *sp, const char *except_uuid)
{
	unsigned int n = 0;

	if (!sp)
		return 0;

	lws_start_foreach_dll(struct lws_dll2 *, p, sp->inflight_owner.head) {
		sai_uuid_list_t *ul = lws_container_of(p, sai_uuid_list_t, list);

		if (ul->idle && (!except_uuid || strcmp(ul->uuid, except_uuid)))
			n++;

	} lws_end_foreach_dll(p);

	return n;
}

/*
 * Find the host events again: for each repo + ref, the newest event with lanes
 * whose real tasks have all finished.  For each platform it has lanes on, note
 * how many of them are not running a slice at the moment.
 */

static void
sais_idle_hosts_refresh(struct vhd *vhd)
{
	struct {
		char repo[65];
		char ref[65];
	} *seen;
	sqlite3_stmt *sm, *tsm;
	int nseen = 0, n;
	char q[384];

	lws_dll2_owner_clear(&vhd->idle_hosts);
	lwsac_free(&vhd->ac_idle_hosts);
	vhd->idle_hosts_refreshed = lws_now_usecs();
	vhd->idle_hosts_stale = 0;

	lws_snprintf(q, sizeof(q), "select uuid, repo_name, ref from events "
		     "where idle > 0 and adhoc = 0 and state != %d "
		     "order by created desc limit %d", SAIES_DELETED,
		     SAIS_IDLE_HOST_EVENTS);
	if (sqlite3_prepare_v2(vhd->server.pdb, q, -1, &sm, NULL) != SQLITE_OK) {
		lwsl_err("%s: %s\n", __func__, sqlite3_errmsg(vhd->server.pdb));
		return;
	}

	seen = malloc(sizeof(*seen) * SAIS_IDLE_HOST_EVENTS);
	if (!seen) {
		sqlite3_finalize(sm);
		return;
	}

	while (sqlite3_step(sm) == SQLITE_ROW) {
		const char *uuid = (const char *)sqlite3_column_text(sm, 0),
			   *repo = (const char *)sqlite3_column_text(sm, 1),
			   *ref = (const char *)sqlite3_column_text(sm, 2);
		unsigned int unfinished = 1;
		sqlite3 *pdb = NULL;

		if (!uuid || !repo || !ref)
			continue;

		for (n = 0; n < nseen; n++)
			if (!strcmp(seen[n].repo, repo) &&
			    !strcmp(seen[n].ref, ref))
				break;
		if (n != nseen)
			/* a newer event already hosts this repo + ref */
			continue;

		if (sai_event_db_ensure_open(vhd->context, &vhd->sqlite3_cache,
					     vhd->sqlite3_path_lhs, uuid, 0,
					     &pdb))
			continue;

		/*
		 * Have all its real tasks finished?  If not, an older event
		 * on the ref may still be the host until it does
		 */

		lws_snprintf(q, sizeof(q),
			     "select count(*) from tasks t1 where idle=0 and "
			     "state not in (%d,%d,%d) and run=(select max(run) "
			     "from tasks t2 where t2.uuid=t1.uuid)",
			     SAIES_SUCCESS, SAIES_FAIL, SAIES_CANCELLED);
		if (sqlite3_exec(pdb, q, sql3_get_integer_cb, &unfinished,
				 NULL) != SQLITE_OK || unfinished) {
			sai_event_db_close(&vhd->sqlite3_cache, &pdb);
			continue;
		}

		lws_strncpy(seen[nseen].repo, repo, sizeof(seen[nseen].repo));
		lws_strncpy(seen[nseen].ref, ref, sizeof(seen[nseen].ref));
		nseen++;

		/* a waiting lane that's bound has been offered to a builder */
		lws_snprintf(q, sizeof(q),
			     "select platform, sum(case when state in "
			     "(%d,%d,%d,%d) or (state in (%d,%d) and "
			     "ifnull(builder_name,'')='') then 1 else 0 end) "
			     "from tasks t1 where idle=1 and run=(select "
			     "max(run) from tasks t2 where t2.uuid=t1.uuid) "
			     "group by platform",
			     SAIES_SUCCESS, SAIES_FAIL, SAIES_CANCELLED,
			     SAIES_YIELDED, SAIES_WAITING,
			     SAIES_NOT_READY_FOR_BUILD);

		if (sqlite3_prepare_v2(pdb, q, -1, &tsm, NULL) == SQLITE_OK) {
			while (sqlite3_step(tsm) == SQLITE_ROW) {
				const char *plat = (const char *)
						sqlite3_column_text(tsm, 0);
				sais_idle_host_t *h;

				if (!plat)
					continue;

				h = lwsac_use_zero(&vhd->ac_idle_hosts,
						   sizeof(*h), 1024);
				if (!h)
					break;

				lws_strncpy(h->event_uuid, uuid,
					    sizeof(h->event_uuid));
				lws_strncpy(h->platform, plat,
					    sizeof(h->platform));
				h->free_lanes = sqlite3_column_int(tsm, 1);
				lws_dll2_add_tail(&h->list, &vhd->idle_hosts);
			}
			sqlite3_finalize(tsm);
		}

		sai_event_db_close(&vhd->sqlite3_cache, &pdb);

		if (nseen == SAIS_IDLE_HOST_EVENTS)
			break;
	}

	sqlite3_finalize(sm);
	free(seen);
}

static void
sais_idle_hosts_ensure_fresh(struct vhd *vhd)
{
	if (vhd->idle_hosts_stale ||
	    lws_now_usecs() - vhd->idle_hosts_refreshed >
						SAIS_IDLE_HOSTS_REFRESH_US)
		sais_idle_hosts_refresh(vhd);
}

/*
 * Called as part of recomputing the pending platforms, which happens at least
 * once a second.  At that point vhd->pending_plats holds just the platforms
 * with real tasks waiting or running.
 *
 * First, builder platforms with nothing real pending get to pay off some of
 * their rest.
 *
 * Then we add the idle tasks that are running, and those that builders are due
 * to start, to the pending platforms, so sai-power keeps up, or brings up, the
 * builders for them.  sai-power can only turn on platforms, not particular
 * builders; so we only ask it for a platform whose builders all take idle
 * tasks, or we would be waking builders that will decline them.
 */

void
sais_idle_add_pending_plats(struct vhd *vhd)
{
	lws_usec_t now = lws_now_usecs();

	if (!vhd->idle_budgets.count)
		return;

	lws_start_foreach_dll(struct lws_dll2 *, p, vhd->idle_budgets.head) {
		sais_idle_budget_t *b = lws_container_of(p,
						sais_idle_budget_t, list);
		lws_usec_t dt = now - b->last_tick;
		int real = 0;

		b->last_tick = now;

		lws_start_foreach_dll(struct lws_dll2 *, px,
				      vhd->pending_plats.head) {
			sais_plat_t *pl = lws_container_of(px, sais_plat_t, list);

			if (!strcmp(pl->plat, b->platform) && pl->pending_count)
				real = 1;

		} lws_end_foreach_dll(px);

		if (!real && b->debt_us)
			b->debt_us = b->debt_us > dt ? b->debt_us - dt : 0;

	} lws_end_foreach_dll(p);

	sais_idle_hosts_ensure_fresh(vhd);

	lws_start_foreach_dll(struct lws_dll2 *, p, vhd->idle_budgets.head) {
		sais_idle_budget_t *b = lws_container_of(p,
						sais_idle_budget_t, list);
		sai_plat_t *sp = sais_builder_from_uuid(vhd, b->name);
		unsigned int running = sais_idle_running(sp, NULL), due = 0,
			     lanes = 0, takers = 0, builders = 0;
		sqlite3_stmt *sm;

		if (b->share && !b->debt_us && running < b->instances) {
			lws_start_foreach_dll(struct lws_dll2 *, ph,
					      vhd->idle_hosts.head) {
				sais_idle_host_t *h = lws_container_of(ph,
							sais_idle_host_t, list);

				if (!strcmp(h->platform, b->platform))
					lanes += (unsigned int)h->free_lanes;

			} lws_end_foreach_dll(ph);

			due = b->instances - running;
			if (due > lanes)
				due = lanes;
		}

		if (due) {
			/* do all the builders of the platform take idle tasks? */

			lws_start_foreach_dll(struct lws_dll2 *, p1,
					      vhd->idle_budgets.head) {
				sais_idle_budget_t *b1 = lws_container_of(p1,
						sais_idle_budget_t, list);

				if (b1->share && !strcmp(b1->platform, b->platform))
					takers++;

			} lws_end_foreach_dll(p1);

			if (sqlite3_prepare_v2(vhd->server.pdb,
					"select count(*) from builders where "
					"platform=?", -1, &sm, NULL) == SQLITE_OK) {
				sqlite3_bind_text(sm, 1, b->platform, -1,
						  SQLITE_TRANSIENT);
				if (sqlite3_step(sm) == SQLITE_ROW)
					builders = (unsigned int)
						sqlite3_column_int(sm, 0);
				sqlite3_finalize(sm);
			}

			if (takers < builders)
				due = 0;
		}

		if (running || due)
			sais_add_pending_plat(vhd, b->platform,
					      (int)(running + due), (int)due);

	} lws_end_foreach_dll(p);
}

/*
 * Arm the next slice of an idle task whose last one is over: a new run, bound
 * to the builder platform that's going to do it.  The oldest runs beyond the
 * last few are pruned, with their logs and artifacts, since a lane runs
 * indefinitely.
 */

static int
sais_idle_new_run(struct vhd *vhd, sqlite3 *pdb, const char *task_uuid,
		  const sai_plat_t *sp)
{
	struct lwsac *ac = NULL;
	char esc[96], q[256];
	lws_dll2_owner_t o;
	sai_task_t *t;
	int n;

	lws_sql_purify(esc, task_uuid, sizeof(esc));
	lws_snprintf(q, sizeof(q), " and uuid='%s'", esc);

	n = lws_struct_sq3_deserialize(pdb, q, "run desc",
				       lsm_schema_sq3_map_task, &o, &ac, 0, 1);
	if (n < 0 || !o.head) {
		lwsac_free(&ac);
		return 1;
	}

	t = lws_container_of(o.head, sai_task_t, list);

	t->run++;
	t->state		= SAIES_WAITING;
	t->started		= 0;
	t->duration		= 0;
	t->build_step		= 0;
	t->last_updated		= (uint64_t)lws_now_secs();
	t->server_name		= "";
	lws_strncpy(t->builder, sp->name, sizeof(t->builder));
	lws_strncpy(t->builder_name, sp->name, sizeof(t->builder_name));

	n = lws_struct_sq3_serialize(pdb, lsm_schema_sq3_map_task, &o, 0);
	if (n < 0) {
		lwsl_err("%s: unable to add run %d of %s\n", __func__, t->run,
			 task_uuid);
		lwsac_free(&ac);
		return 1;
	}

	n = t->run - SAIS_IDLE_RUNS_KEPT;
	lwsac_free(&ac);

	if (n >= 0) {
		lws_snprintf(q, sizeof(q), "delete from logs where "
			     "task_uuid='%s' and run <= %d", esc, n);
		sqlite3_exec(pdb, q, NULL, NULL, NULL);
		lws_snprintf(q, sizeof(q), "delete from artifacts where "
			     "task_uuid='%s' and run <= %d", esc, n);
		sqlite3_exec(pdb, q, NULL, NULL, NULL);
		lws_snprintf(q, sizeof(q), "delete from tasks where "
			     "uuid='%s' and run <= %d", esc, n);
		sqlite3_exec(pdb, q, NULL, NULL, NULL);
	}

	return 0;
}

/*
 * Look for a lane on the host event for this platform that isn't running a
 * slice, arm it and offer it to the builder platform.  Returns 0 if we
 * offered one.
 */

static int
sais_idle_offer_lane(struct vhd *vhd, sai_plat_t *sp, const char *event_uuid)
{
	char task_uuid[65], q[384];
	sqlite3 *pdb = NULL;
	sqlite3_stmt *sm;
	int state = -1;

	if (sai_event_db_ensure_open(vhd->context, &vhd->sqlite3_cache,
				     vhd->sqlite3_path_lhs, event_uuid, 0, &pdb))
		return 1;

	lws_snprintf(q, sizeof(q),
		     "select uuid, state from tasks t1 where idle=1 and "
		     "platform=? and run=(select max(run) from tasks t2 where "
		     "t2.uuid=t1.uuid) and (state in (%d,%d,%d,%d) or "
		     "(state in (%d,%d) and (builder_name is null or "
		     "builder_name in ('', ?)))) order by uid",
		     SAIES_SUCCESS, SAIES_FAIL, SAIES_CANCELLED, SAIES_YIELDED,
		     SAIES_WAITING, SAIES_NOT_READY_FOR_BUILD);

	if (sqlite3_prepare_v2(pdb, q, -1, &sm, NULL) != SQLITE_OK) {
		lwsl_err("%s: %s\n", __func__, sqlite3_errmsg(pdb));
		sai_event_db_close(&vhd->sqlite3_cache, &pdb);
		return 1;
	}

	sqlite3_bind_text(sm, 1, sp->platform, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(sm, 2, sp->name, -1, SQLITE_TRANSIENT);

	task_uuid[0] = '\0';
	while (sqlite3_step(sm) == SQLITE_ROW) {
		const char *u = (const char *)sqlite3_column_text(sm, 0);

		if (!u || strlen(u) != SAI_TASKID_LEN ||
		    sais_is_task_inflight(vhd, NULL, u, NULL))
			continue;

		lws_strncpy(task_uuid, u, sizeof(task_uuid));
		state = sqlite3_column_int(sm, 1);
		break;
	}
	sqlite3_finalize(sm);

	if (!task_uuid[0]) {
		sai_event_db_close(&vhd->sqlite3_cache, &pdb);
		return 1;
	}

	if (state != SAIES_WAITING && state != SAIES_NOT_READY_FOR_BUILD) {
		/* its last slice is over, it needs a new run for the next */
		if (sais_idle_new_run(vhd, pdb, task_uuid, sp)) {
			sai_event_db_close(&vhd->sqlite3_cache, &pdb);
			return 1;
		}
		sai_event_db_close(&vhd->sqlite3_cache, &pdb);
		sais_taskchange(vhd->h_ss_websrv, task_uuid, SAIES_WAITING);
	} else {
		/* its first slice, the task as created */
		sai_event_db_close(&vhd->sqlite3_cache, &pdb);
		if (sais_bind_task_to_builder(vhd, sp->name, sp->name,
					      task_uuid))
			return 1;
		if (state == SAIES_NOT_READY_FOR_BUILD)
			sais_set_task_state(vhd, task_uuid, SAIES_WAITING, 0, 0);
	}

	lwsl_notice("%s: offering idle task %s to %s\n", __func__, task_uuid,
		    sp->name);

	if (sais_create_and_offer_task_step(vhd, task_uuid)) {
		sais_bind_task_to_builder(vhd, NULL, NULL, task_uuid);
		return 1;
	}

	return 0;
}

/*
 * The builder platform has nothing real to do... if it gives some of its idle
 * time to idle tasks and it's not resting, offer it one.  Returns 0 if we
 * offered it something.
 */

int
sais_idle_allocate(struct vhd *vhd, struct pss *pss, sai_plat_t *sp)
{
	sais_idle_budget_t *b = sais_idle_budget_find(vhd, sp->name);
	lws_usec_t now = lws_now_usecs();
	unsigned int running;

	if (!b || !b->share || b->debt_us || sp->idle_backoff_until > now)
		return 1;

	running = sais_idle_running(sp, NULL);
	if (running >= b->instances)
		return 1;

	/*
	 * A new slice can join the active period while it's younger than a
	 * slice, otherwise the period ends when the running slices do and the
	 * platform rests before starting any more
	 */
	if (running && b->slice_secs &&
	    now - b->period_start > (lws_usec_t)b->slice_secs * LWS_US_PER_SEC)
		return 1;

	sais_idle_hosts_ensure_fresh(vhd);

	lws_start_foreach_dll(struct lws_dll2 *, p, vhd->idle_hosts.head) {
		sais_idle_host_t *h = lws_container_of(p, sais_idle_host_t, list);

		if (h->free_lanes <= 0 || strcmp(h->platform, sp->platform))
			continue;

		if (!sais_idle_offer_lane(vhd, sp, h->event_uuid)) {
			h->free_lanes--;
			if (!running)
				b->period_start = now;

			sais_list_builders(vhd);
			pss->mark_started = 1;

			return 0;
		}

		/* nothing we could use there after all */
		h->free_lanes = 0;

	} lws_end_foreach_dll(p);

	return 1;
}

/*
 * An idle task's slice ended, one way or another.  If it was the last of the
 * builder platform's slices running, its active period is over and it owes
 * rest in proportion.
 */

void
sais_idle_slice_ended(struct vhd *vhd, sqlite3 *pdb, const char *task_uuid)
{
	char builder_name[96], q[192], esc[96];
	uint64_t started = 0;
	sais_idle_budget_t *b;
	lws_usec_t now, period;
	sqlite3_stmt *sm;

	vhd->idle_hosts_stale = 1;

	builder_name[0] = '\0';
	lws_sql_purify(esc, task_uuid, sizeof(esc));
	lws_snprintf(q, sizeof(q), "select builder_name, started from tasks "
		     "where uuid='%s' order by run desc limit 1", esc);
	if (sqlite3_prepare_v2(pdb, q, -1, &sm, NULL) != SQLITE_OK)
		return;
	if (sqlite3_step(sm) == SQLITE_ROW) {
		const char *bn = (const char *)sqlite3_column_text(sm, 0);

		if (bn)
			lws_strncpy(builder_name, bn, sizeof(builder_name));
		started = (uint64_t)sqlite3_column_int64(sm, 1);
	}
	sqlite3_finalize(sm);

	b = builder_name[0] ? sais_idle_budget_find(vhd, builder_name) : NULL;
	if (!b || !b->share)
		return;

	if (sais_idle_running(sais_builder_from_uuid(vhd, builder_name),
			      task_uuid))
		/* the builder platform's active period goes on */
		return;

	now = lws_now_usecs();
	if (b->period_start)
		period = now - b->period_start;
	else
		/* we restarted since it began, go by the slice itself */
		period = started ? ((lws_usec_t)lws_now_secs() -
				    (lws_usec_t)started) * LWS_US_PER_SEC : 0;
	if (period < SAIS_IDLE_MIN_PERIOD_US)
		period = SAIS_IDLE_MIN_PERIOD_US;

	b->debt_us += (period * (100 - (lws_usec_t)b->share)) / b->share;
	if (b->debt_us > SAIS_IDLE_MAX_DEBT_US)
		b->debt_us = SAIS_IDLE_MAX_DEBT_US;
	b->period_start = 0;

	lwsl_notice("%s: %s: active for %llds, resting for %llds\n", __func__,
		    b->name, (long long)(period / LWS_US_PER_SEC),
		    (long long)(b->debt_us / LWS_US_PER_SEC));
}

/*
 * The builder platform won't take the idle task we offered right now, eg,
 * it has real work, or had it recently.  Put the task back and don't offer it
 * idle tasks for a while.
 */

void
sais_idle_declined(struct vhd *vhd, sai_plat_t *sp, const char *task_uuid)
{
	char event_uuid[33], esc[96], q[160];
	sqlite3 *pdb = NULL;
	int state = -1;

	sp->idle_backoff_until = lws_now_usecs() + SAIS_IDLE_DECLINE_BACKOFF_US;
	vhd->idle_hosts_stale = 1;

	sai_task_uuid_to_event_uuid(event_uuid, task_uuid);
	if (!sai_event_db_ensure_open(vhd->context, &vhd->sqlite3_cache,
				      vhd->sqlite3_path_lhs, event_uuid, 0,
				      &pdb)) {
		lws_sql_purify(esc, task_uuid, sizeof(esc));
		lws_snprintf(q, sizeof(q), "select state from tasks where "
			     "uuid='%s' order by run desc limit 1", esc);
		if (sqlite3_exec(pdb, q, sql3_get_integer_cb, &state,
				 NULL) != SQLITE_OK)
			state = -1;
		sai_event_db_close(&vhd->sqlite3_cache, &pdb);
	}

	if (state == SAIES_STEP_SUCCESS) {
		/*
		 * It was offered a later step of a slice that had started,
		 * eg, real work turned up between its steps.  The steps have
		 * to happen in one place, so that's the end of the slice.
		 */
		sais_task_logf(vhd, task_uuid, "builder %s declined the next "
			       "step, so this idle slice is over", sp->name);
		sais_set_task_state(vhd, task_uuid, SAIES_YIELDED, 0, 0);
		return;
	}

	sais_bind_task_to_builder(vhd, NULL, NULL, task_uuid);
}

/*
 * The builder went away... any slices it had are over, and nothing else is
 * going to tell us.  Real tasks it had are dealt with separately, but they
 * only live on events that haven't completed, and idle tasks mostly live on
 * events that have.
 */

void
sais_idle_builder_gone(struct vhd *vhd, sai_plat_t *sp)
{
	sqlite3_stmt *sm, *tsm;
	char q[256];

	lws_snprintf(q, sizeof(q), "select uuid from events where idle > 0 "
		     "and state != %d order by created desc limit %d",
		     SAIES_DELETED, SAIS_IDLE_HOST_EVENTS);
	if (sqlite3_prepare_v2(vhd->server.pdb, q, -1, &sm, NULL) != SQLITE_OK)
		return;

	lws_snprintf(q, sizeof(q),
		     "select uuid, state from tasks t1 where idle=1 and "
		     "builder_name=? and state in (%d,%d,%d,%d) and "
		     "run=(select max(run) from tasks t2 where t2.uuid=t1.uuid)",
		     SAIES_WAITING, SAIES_PASSED_TO_BUILDER, SAIES_BEING_BUILT,
		     SAIES_STEP_SUCCESS);

	while (sqlite3_step(sm) == SQLITE_ROW) {
		const char *ev = (const char *)sqlite3_column_text(sm, 0);
		lws_dll2_owner_t owner;
		struct lwsac *ac = NULL;
		sqlite3 *pdb = NULL;

		if (!ev || sai_event_db_ensure_open(vhd->context,
				&vhd->sqlite3_cache, vhd->sqlite3_path_lhs,
				ev, 0, &pdb))
			continue;

		/*
		 * Collect them first, changing the task state reopens the db
		 */

		lws_dll2_owner_clear(&owner);
		if (sqlite3_prepare_v2(pdb, q, -1, &tsm, NULL) == SQLITE_OK) {
			sqlite3_bind_text(tsm, 1, sp->name, -1,
					  SQLITE_TRANSIENT);
			while (sqlite3_step(tsm) == SQLITE_ROW) {
				const char *u = (const char *)
						sqlite3_column_text(tsm, 0);
				sai_uuid_list_t *ul;

				if (!u)
					continue;
				ul = lwsac_use_zero(&ac, sizeof(*ul), 512);
				if (!ul)
					break;
				lws_strncpy(ul->uuid, u, sizeof(ul->uuid));
				/* reuse .started for "was it offered only" */
				ul->started = sqlite3_column_int(tsm, 1) ==
								SAIES_WAITING;
				lws_dll2_add_tail(&ul->list, &owner);
			}
			sqlite3_finalize(tsm);
		}
		sai_event_db_close(&vhd->sqlite3_cache, &pdb);

		lws_start_foreach_dll(struct lws_dll2 *, p, owner.head) {
			sai_uuid_list_t *ul = lws_container_of(p,
						sai_uuid_list_t, list);

			sai_uuid_list_t *inf;

			/*
			 * Drop it from what the builder platform is running
			 * first, so ending the last one ends its active period
			 */
			if (sais_is_task_inflight(vhd, sp, ul->uuid, &inf))
				sais_inflight_entry_destroy(inf);

			if (ul->started)
				sais_bind_task_to_builder(vhd, NULL, NULL,
							  ul->uuid);
			else {
				sais_task_logf(vhd, ul->uuid,
					"builder %s disconnected, so this idle "
					"slice is over", sp->name);
				sais_set_task_state(vhd, ul->uuid,
						    SAIES_YIELDED, 0, 0);
			}

		} lws_end_foreach_dll(p);

		lwsac_free(&ac);
	}

	sqlite3_finalize(sm);
}
