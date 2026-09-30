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
 *
 */

#include <libwebsockets.h>
#include <string.h>
#include <time.h>
#include <assert.h>

#include "s-private.h"


/*
 * This is the only path to send things from server -> web
 *
 * It will copy the incoming buffer fragment into a buflist in order.  So you
 * should dump all your fragments for a message in here one after the other
 * and the message will go out uninterrupted.  Having this as the only tx path
 * allows us to guarantee we won't interrupt the fragment sequencing.
 *
 * The fragment sizing does not have to be related to ss usage sizing, it can
 * be larger and it will be used from the buflist according to what SS wants.
 *
 *
 * This is a bit tricky because the per sai-web buflist may be in the middle of
 * a series of fragments for an existing message.  We can't snipe our way in
 * the middle and start dumping logs then.  And, each sai-web connection may
 * be in a different situation for ongoing existing messages.
 *
 * To solve this, we use lws_wsmsg_ apis to reassemble the various sources
 * of messages using private buflists before emptying them into the upstream
 * buflist.
 */

static void
_sais_websrv_broadcast(struct lws_ss_handle *h, void *arg)
{
	websrvss_srv_t *m	   = (websrvss_srv_t *)lws_ss_to_user_object(h);
	lws_wsmsg_info_t *info_in  = (lws_wsmsg_info_t *)arg;
	lws_wsmsg_info_t info	   = *info_in;
	unsigned int *pi	   = (unsigned int *)((const char *)info.buf - sizeof(int));

	info.head_upstream		= &m->bl_srv_to_web;
	info.private_heads		= m->private_heads;

	// lwsl_ss_notice(h, "Queueing %u bytes, ridx %d, ff_flags: %u",
	//	       (unsigned int)info.len, info.private_source_idx, info.ss_flags);

	/* sai-web might not be taking it.. */

	if (lws_buflist_total_len(&m->bl_srv_to_web) > (5u * 1024u * 1024u)) {
		lwsl_ss_warn(h, "server->web buflist reached 5MB");
		/* close the connection to the client then */
		lws_ss_start_timeout(h, 1);

		return;
	}

	*pi = info.ss_flags;

	info.buf	= info.buf - sizeof(int);
	info.len	= info.len + sizeof(int);

	if (lws_wsmsg_append(&info) < 0)
		lwsl_ss_err(h, "failed to append"); /* still ask to drain */

	if (lws_ss_request_tx(h))
		lwsl_ss_err(h, "failed to request tx");
}

int
sais_websrv_broadcast_REQUIRES_LWS_PRE(struct lws_ss_handle *hsrv,
				       lws_wsmsg_info_t *info)
{
	/* calls back for every connected client on server */
	lws_ss_server_foreach_client(hsrv, _sais_websrv_broadcast, info);

	return 0;
}


/*
 * We will copy the buflist bl on to every sai-web client connected to our
 * sai-server server, then empty bl.
 */

void
sais_websrv_broadcast_buflist(struct lws_ss_handle *hsrv, struct lws_buflist **bl)
{
	size_t total = 0, max_len;
	uint8_t *flat;
	lws_wsmsg_info_t info;

	if (!bl || !*bl)
		return;

	max_len = lws_buflist_total_len(bl);
	if (!max_len) {
		lws_buflist_destroy_all_segments(bl);
		return;
	}

	/*
	 * We flatten it into a single contiguous buffer so we can broadcast
	 * it as a single SOM | EOM message, which prevents other messages
	 * getting interleaved in the middle of it in the upstream buflist.
	 */

	flat = malloc(LWS_PRE + sizeof(int) + max_len);
	if (!flat) {
		lwsl_err("%s: OOM\n", __func__);
		lws_buflist_destroy_all_segments(bl);
		return;
	}

	while (*bl) {
		uint8_t *frag;
		size_t flen = lws_buflist_next_segment_len(bl, &frag);

		if (flen > sizeof(int)) {
			memcpy(flat + LWS_PRE + sizeof(int) + total,
			       frag + sizeof(int), flen - sizeof(int));
			total += flen - sizeof(int);
		}
		lws_buflist_use_segment(bl, flen);
	}

	if (!total) {
		free(flat);
		return;
	}

	memset(&info, 0, sizeof(info));
	info.private_source_idx = SAI_WEBSRV_PB__PROXIED_FROM_BUILDER_LR;
	info.buf = flat + LWS_PRE + sizeof(int);
	info.len = total;
	info.ss_flags = LWSSS_FLAG_SOM | LWSSS_FLAG_EOM;

	lws_ss_server_foreach_client(hsrv, _sais_websrv_broadcast, &info);

	free(flat);
}


void
sais_taskchange(struct lws_ss_handle *hsrv, const char *task_uuid, int state)
{
	char tc[LWS_PRE + 256], *start = tc + LWS_PRE, esc[256];
	lws_wsmsg_info_t info;
	int n;

	lwsl_ss_notice(hsrv, "%%%%%%%% sai-taskchange %s -> %d", task_uuid, state);

	n = lws_snprintf(start, sizeof(tc) - LWS_PRE,
			 "{\"schema\":\"sai-taskchange\", "
			 "\"event_hash\":\"%s\", \"state\":%d}",
			 lws_json_purify(esc, task_uuid, sizeof(esc) - 1, NULL),
			 state);

	memset(&info, 0, sizeof(info));
	info.private_source_idx		= SAI_WEBSRV_PB__GENERATED;
	info.buf			= (uint8_t *)start;
	info.len			= (size_t)n;
	info.ss_flags			= LWSSS_FLAG_SOM | LWSSS_FLAG_EOM;

	if (sais_websrv_broadcast_REQUIRES_LWS_PRE(hsrv, &info) < 0) {
		lwsl_warn("%s: buflist append failed\n", __func__);

		return;
	}
}

void
sais_eventchange(struct lws_ss_handle *hsrv, const char *event_uuid, int state)
{
	char tc[LWS_PRE + 256], *start = tc + LWS_PRE, esc[256];
	lws_wsmsg_info_t info;
	int n;

	lwsl_ss_notice(hsrv, "%%%%%%%% sai-eventchange %s -> %d", event_uuid, state);

	n = lws_snprintf(start, sizeof(tc) - LWS_PRE,
			 "{\"schema\":\"sai-eventchange\", "
			 "\"event_hash\":\"%s\", \"state\":%d}",
			 lws_json_purify(esc, event_uuid, sizeof(esc) - 1, NULL),
			 state);

	memset(&info, 0, sizeof(info));
	info.private_source_idx		= SAI_WEBSRV_PB__GENERATED;
	info.buf			= (uint8_t *)start;
	info.len			= (size_t)n;
	info.ss_flags			= LWSSS_FLAG_SOM | LWSSS_FLAG_EOM;

	if (sais_websrv_broadcast_REQUIRES_LWS_PRE(hsrv, &info) < 0) {
		lwsl_warn("%s: buflist append failed\n", __func__);

		return;
	}
}

/*
 * Remember the hash most recently pushed for (repo, ref).  Updated for every
 * authenticated hook notification, including scratch refs we don't CI, so an
 * ad-hoc build can be pointed at "the head of this branch as last pushed".
 */
int
sais_push_record(struct vhd *vhd, const char *repo_name, const char *ref,
		 const char *hash)
{
	sqlite3_stmt *stmt = NULL;
	int rc;

	if (sqlite3_prepare_v2(vhd->server.pdb,
			"INSERT OR REPLACE INTO pushes "
			"(repo_name, ref, hash, created) VALUES (?, ?, ?, ?)",
			-1, &stmt, NULL) != SQLITE_OK) {
		lwsl_err("%s: prepare failed: %s\n", __func__,
			 sqlite3_errmsg(vhd->server.pdb));
		return 1;
	}

	sqlite3_bind_text(stmt, 1, repo_name, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, ref, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 3, hash, -1, SQLITE_STATIC);
	sqlite3_bind_int64(stmt, 4, (sqlite3_int64)lws_now_secs());

	rc = sqlite3_step(stmt);
	sqlite3_finalize(stmt);

	if (rc != SQLITE_DONE) {
		lwsl_err("%s: insert failed: %s\n", __func__,
			 sqlite3_errmsg(vhd->server.pdb));
		return 1;
	}

	return 0;
}

/*
 * Resolve (repo, ref) to the hash we should build for it: the most recent
 * push we were notified about, or failing that (eg, an event predating the
 * pushes table) the newest non-deleted event on that ref.
 */
int
sais_push_lookup(struct vhd *vhd, const char *repo_name, const char *ref,
		 char *hash, size_t hash_len)
{
	static const char * const q[] = {
		"SELECT hash FROM pushes WHERE repo_name = ? AND ref = ?",
		"SELECT hash FROM events WHERE repo_name = ? AND ref = ? "
		"AND state != 7 ORDER BY created DESC LIMIT 1"
	};
	sqlite3_stmt *stmt = NULL;
	int n, ret = 1;

	for (n = 0; n < (int)LWS_ARRAY_SIZE(q) && ret; n++) {
		if (sqlite3_prepare_v2(vhd->server.pdb, q[n], -1, &stmt,
				       NULL) != SQLITE_OK) {
			lwsl_err("%s: prepare %d failed: %s\n", __func__, n,
				 sqlite3_errmsg(vhd->server.pdb));
			continue;
		}

		sqlite3_bind_text(stmt, 1, repo_name, -1, SQLITE_STATIC);
		sqlite3_bind_text(stmt, 2, ref, -1, SQLITE_STATIC);

		if (sqlite3_step(stmt) == SQLITE_ROW) {
			const char *h = (const char *)sqlite3_column_text(stmt, 0);

			if (h && sai_is_git_hash(h)) {
				lws_strncpy(hash, h, hash_len);
				ret = 0;
			}
		}

		sqlite3_finalize(stmt);
	}

	return ret;
}

/*
 * Create a new ad-hoc event holding a single task, seeded from an existing
 * task.
 *
 * The seed's event supplies the repo and its urls; the seed task supplies the
 * platform, build dimension name (taskname), packages, artifacts and log
 * limit, so the result looks like any other task of that dimension in the UI.
 * The caller supplies the ref to build, which is resolved here to the hash
 * last pushed for it, and the build script, which may have been edited.
 *
 * Everything else about the new task (uuids, nonces, state) is freshly
 * minted; it is not a "run" of the seed and does not touch the seed's event.
 */
sai_db_result_t
sais_event_clone_task(struct vhd *vhd, const sai_browse_rx_taskclone_t *tc)
{
	sai_db_result_t r = SAI_DB_RESULT_ERROR;
	struct lwsac *ac_ev = NULL, *ac_task = NULL;
	char seed_event_uuid[33], esc[96], filt[160];
	lws_dll2_owner_t o_ev, o_task, owner;
	sai_event_t *seed_e, ev;
	sai_task_t *seed_t, *t = NULL;
	sqlite3 *pdb = NULL;
	char *err = NULL;
	int n;

	if (sais_validate_id(tc->seed_uuid, SAI_TASKID_LEN)) {
		lwsl_notice("%s: bad seed uuid\n", __func__);
		return SAI_DB_RESULT_ERROR;
	}

	/*
	 * The ref is exported into the builder's git helper script; it has
	 * to be a full, safe refname.  strlen() == sizeof - 1 means lws_struct
	 * truncated it on the way in, so it can't be what the user meant.
	 */
	if (strncmp(tc->ref, "refs/", 5) || !sai_is_safe_ref(tc->ref) ||
	    strlen(tc->ref) >= sizeof(tc->ref) - 1) {
		lwsl_notice("%s: rejecting ref '%s'\n", __func__, tc->ref);
		return SAI_DB_RESULT_ERROR;
	}

	if (!tc->build[0] || strlen(tc->build) >= sizeof(tc->build) - 1) {
		lwsl_notice("%s: rejecting empty or overlong build\n", __func__);
		return SAI_DB_RESULT_ERROR;
	}

	sai_task_uuid_to_event_uuid(seed_event_uuid, tc->seed_uuid);

	/* the seed's event, from the main events db */

	lws_sql_purify(esc, seed_event_uuid, sizeof(esc));
	lws_snprintf(filt, sizeof(filt), " and uuid='%s'", esc);
	n = lws_struct_sq3_deserialize(vhd->server.pdb, filt, NULL,
				       lsm_schema_sq3_map_event, &o_ev,
				       &ac_ev, 0, 1);
	if (n < 0 || !o_ev.head) {
		lwsl_notice("%s: no seed event %s\n", __func__, seed_event_uuid);
		goto bail;
	}
	seed_e = lws_container_of(o_ev.head, sai_event_t, list);

	/* the seed task, latest run, from its event-specific db */

	if (sai_event_db_ensure_open(vhd->context, &vhd->sqlite3_cache,
				     vhd->sqlite3_path_lhs, seed_event_uuid,
				     0, &pdb)) {
		lwsl_notice("%s: unable to open seed event db\n", __func__);
		goto bail;
	}

	lws_sql_purify(esc, tc->seed_uuid, sizeof(esc));
	lws_snprintf(filt, sizeof(filt), " and uuid='%s'", esc);
	n = lws_struct_sq3_deserialize(pdb, filt, "run desc",
				       lsm_schema_sq3_map_task, &o_task,
				       &ac_task, 0, 1);
	sai_event_db_close(&vhd->sqlite3_cache, &pdb);
	if (n < 0 || !o_task.head) {
		lwsl_notice("%s: no seed task %s\n", __func__, tc->seed_uuid);
		goto bail;
	}
	seed_t = lws_container_of(o_task.head, sai_task_t, list);

	/* the new event: the seed's repo, but the requested ref's head */

	memset(&ev, 0, sizeof(ev));
	lws_strncpy(ev.repo_name, seed_e->repo_name, sizeof(ev.repo_name));
	lws_strncpy(ev.repo_fetchurl, seed_e->repo_fetchurl,
		    sizeof(ev.repo_fetchurl));
	lws_strncpy(ev.repo_weburl, seed_e->repo_weburl,
		    sizeof(ev.repo_weburl));
	lws_strncpy(ev.ref, tc->ref, sizeof(ev.ref));
	ev.sec = seed_e->sec;
	ev.adhoc = 1;

	if (sais_push_lookup(vhd, ev.repo_name, ev.ref, ev.hash,
			     sizeof(ev.hash))) {
		lwsl_notice("%s: no known push of %s for %s\n", __func__,
			    ev.ref, ev.repo_name);
		goto bail;
	}

	sai_uuid16_create(vhd->context, ev.uuid);
	ev.created = (unsigned long long)lws_now_secs();
	ev.state = SAIES_WAITING;

	lws_dll2_clear(&ev.list);
	lws_dll2_owner_clear(&owner);
	lws_dll2_add_head(&ev.list, &owner);

	if (lws_struct_sq3_serialize(vhd->server.pdb, lsm_schema_sq3_map_event,
				     &owner, 0) < 0) {
		lwsl_err("%s: unable to create event\n", __func__);
		goto bail;
	}

	/* the single task, in the new event's own db */

	t = malloc(sizeof(*t));
	if (!t)
		goto bail;
	memset(t, 0, sizeof(*t));

	lws_strncpy(t->platform, seed_t->platform, sizeof(t->platform));
	lws_strncpy(t->taskname, seed_t->taskname, sizeof(t->taskname));
	lws_strncpy(t->packages, seed_t->packages, sizeof(t->packages));
	lws_strncpy(t->artifacts, seed_t->artifacts, sizeof(t->artifacts));
	lws_strncpy(t->build, tc->build, sizeof(t->build));
	t->task_log_limit = seed_t->task_log_limit;
	t->state = SAIES_WAITING;

	if (sai_event_db_ensure_open(vhd->context, &vhd->sqlite3_cache,
				     vhd->sqlite3_path_lhs, ev.uuid, 1, &pdb)) {
		lwsl_err("%s: unable to create event db\n", __func__);
		goto bail;
	}

	sqlite3_exec(pdb, "BEGIN TRANSACTION", NULL, NULL, &err);
	if (err)
		sqlite3_free(err);

	n = sais_task_insert(vhd->context, pdb, &ev, t, 0);

	err = NULL;
	sqlite3_exec(pdb, "END TRANSACTION", NULL, NULL, &err);
	if (err)
		sqlite3_free(err);
	sai_event_db_close(&vhd->sqlite3_cache, &pdb);

	if (n < 0) {
		lwsl_err("%s: unable to create task\n", __func__);
		goto bail;
	}

	lwsl_notice("%s: ad-hoc event %s: %s %s on %s from %s\n", __func__,
		    ev.uuid, ev.repo_name, ev.ref, t->platform, tc->seed_uuid);

	/*
	 * Let sai-power / builders know there's something new, and let the
	 * sai-web instances (and so browsers) see the new event appear
	 */
	sais_platforms_with_tasks_pending(vhd);
	lws_sul_schedule(vhd->context, 0, &vhd->sul_central, sais_central_cb,
			 1 * LWS_US_PER_SEC);
	sais_eventchange(vhd->h_ss_websrv, ev.uuid, SAIES_WAITING);

	r = SAI_DB_RESULT_OK;

bail:
	free(t);
	lwsac_free(&ac_task);
	lwsac_free(&ac_ev);

	return r;
}

sai_db_result_t
sais_event_reset(struct vhd *vhd, const char *event_uuid)
{
	struct lwsac *ac = NULL;
	sqlite3 *pdb = NULL;
	lws_dll2_owner_t o;
	char *err = NULL;
	int ret;

	if (sai_event_db_ensure_open(vhd->context, &vhd->sqlite3_cache,
			      vhd->sqlite3_path_lhs, event_uuid, 0, &pdb))
		return SAI_DB_RESULT_ERROR;

	if (lws_struct_sq3_deserialize(pdb, " and run=(select max(run) from tasks t2 where t2.uuid=tasks.uuid)", NULL,
				       lsm_schema_sq3_map_task,
				       &o, &ac, 0, 999) >= 0) {

		ret = sqlite3_exec(pdb, "BEGIN TRANSACTION", NULL, NULL, &err);
		if (ret != SQLITE_OK) {
			sai_event_db_close(&vhd->sqlite3_cache, &pdb);
			lwsac_free(&ac);
			sqlite3_free(err);
			if (ret == SQLITE_BUSY)
				return SAI_DB_RESULT_BUSY;
			return SAI_DB_RESULT_ERROR;
		}
		sqlite3_free(err);

		lws_start_foreach_dll(struct lws_dll2 *, p, o.head) {
			sai_task_t *t = lws_container_of(p, sai_task_t, list);
			if (sais_task_clear_build_and_logs(vhd, t->uuid, 0) == SAI_DB_RESULT_BUSY) {
				sqlite3_exec(pdb, "END TRANSACTION", NULL, NULL, &err);
				sqlite3_free(err);
				sai_event_db_close(&vhd->sqlite3_cache, &pdb);
				lwsac_free(&ac);
				return SAI_DB_RESULT_BUSY;
			}
		} lws_end_foreach_dll(p);

		ret = sqlite3_exec(pdb, "END TRANSACTION", NULL, NULL, &err);
		if (ret != SQLITE_OK) {
			sai_event_db_close(&vhd->sqlite3_cache, &pdb);
			lwsac_free(&ac);
			sqlite3_free(err);
			if (ret == SQLITE_BUSY)
				return SAI_DB_RESULT_BUSY;
			return SAI_DB_RESULT_ERROR;
		}
		sqlite3_free(err);
	}

	sai_event_db_close(&vhd->sqlite3_cache, &pdb);
	lwsac_free(&ac);

	return SAI_DB_RESULT_OK;
}

sai_db_result_t
sais_event_delete(struct vhd *vhd, const char *event_uuid)
{
	char qu[128], esc[96], pre[LWS_PRE + 128];
	lws_wsmsg_info_t info;
	sqlite3 *pdb = NULL;
	char *err = NULL;
	sqlite3_stmt *sm;
	size_t len;
	int ret;

	lws_sql_purify(esc, event_uuid, sizeof(esc));

	/* 1. Mark event as SAIES_DELETED immediately so it disappears from UI */
	lws_snprintf(qu, sizeof(qu), "update events set state=%d where uuid='%s'", SAIES_DELETED, esc);
	ret = sqlite3_exec(vhd->server.pdb, qu, NULL, NULL, &err);
	if (ret != SQLITE_OK) {
		if (ret == SQLITE_BUSY) {
			sqlite3_free(err);
			return SAI_DB_RESULT_BUSY;
		}
		lwsl_err("%s: evdel mark uuid %s, sq3 err %s\n", __func__, esc, err);
		sqlite3_free(err);
		return SAI_DB_RESULT_ERROR;
	}

	/* 2. Broadcast change to UI */
	sais_eventchange(vhd->h_ss_websrv, event_uuid, SAIES_DELETED);

	len = (size_t)lws_snprintf(pre + LWS_PRE, sizeof(pre) - LWS_PRE,
			"{\"schema\":\"sai-overview\"}");

	memset(&info, 0, sizeof(info));
	info.private_source_idx		= SAI_WEBSRV_PB__GENERATED;
	info.buf			= (uint8_t *)pre + LWS_PRE;
	info.len			= len;
	info.ss_flags			= LWSSS_FLAG_SOM | LWSSS_FLAG_EOM;

	if (sais_websrv_broadcast_REQUIRES_LWS_PRE(vhd->h_ss_websrv, &info) < 0) {
		lwsl_err("%s: unable to broadcast\n", __func__);
		return SAI_DB_RESULT_ERROR;
	}

	/* 3. Drop active builders gracefully without loading huge JSON objects */
	if (sai_event_db_ensure_open(vhd->context, &vhd->sqlite3_cache,
			      vhd->sqlite3_path_lhs, event_uuid, 0, &pdb) == 0) {
		lws_snprintf(qu, sizeof(qu), "SELECT uuid FROM tasks WHERE state != 0 AND state != 3 AND state != 4 AND state != 5 AND state != 11 "
					     "AND run=(SELECT max(run) FROM tasks t2 WHERE t2.uuid = tasks.uuid)");
		if (sqlite3_prepare_v2(pdb, qu, -1, &sm, NULL) == SQLITE_OK) {
			while (sqlite3_step(sm) == SQLITE_ROW) {
				const unsigned char *task_uuid = sqlite3_column_text(sm, 0);
				if (task_uuid)
					sais_task_cancel(vhd, (const char *)task_uuid, 0, 1);
			}
			sqlite3_finalize(sm);
		}
		sai_event_db_close(&vhd->sqlite3_cache, &pdb);
	}

	/* 
	 * Incrementally garbage collect the tasks later in sais_central_cb, 
	 * which eventually drops the DB and erases the event row entirely.
	 */
	lws_sul_schedule(vhd->context, 0, &vhd->sul_gc_events,
			 sais_central_gc_deleted_events_cb, 1);

	/*
	 * Recompute startable task platforms and broadcast to all sai-power,
	 * after there has been a change in tasks
	 */
	sais_platforms_with_tasks_pending(vhd);

	return SAI_DB_RESULT_OK;
}

sai_db_result_t
sais_plat_reset(struct vhd *vhd, const char *event_uuid, const char *platform)
{
	char filt[256], esc[96];
	struct lwsac *ac = NULL;
	sqlite3 *pdb = NULL;
	lws_dll2_owner_t o;
	char *err = NULL;
	int ret;

	if (sai_event_db_ensure_open(vhd->context, &vhd->sqlite3_cache,
			      vhd->sqlite3_path_lhs, event_uuid, 0, &pdb))
		return SAI_DB_RESULT_ERROR;

	lws_sql_purify(esc, platform, sizeof(esc));
	lws_snprintf(filt, sizeof(filt), " and platform='%s' and run=(select max(run) from tasks t2 where t2.uuid=tasks.uuid)", esc);

	if (lws_struct_sq3_deserialize(pdb, filt, NULL,
				       lsm_schema_sq3_map_task,
				       &o, &ac, 0, 999) >= 0) {
		ret = sqlite3_exec(pdb, "BEGIN TRANSACTION", NULL, NULL, &err);
		if (ret != SQLITE_OK) {
			sai_event_db_close(&vhd->sqlite3_cache, &pdb);
			lwsac_free(&ac);
			sqlite3_free(err);
			if (ret == SQLITE_BUSY)
				return SAI_DB_RESULT_BUSY;
			return SAI_DB_RESULT_ERROR;
		}
		sqlite3_free(err);

		lws_start_foreach_dll(struct lws_dll2 *, p, o.head) {
			sai_task_t *t = lws_container_of(p, sai_task_t, list);
			if (sais_task_clear_build_and_logs(vhd, t->uuid, 0) == SAI_DB_RESULT_BUSY) {
				sqlite3_exec(pdb, "END TRANSACTION", NULL, NULL, &err);
				sqlite3_free(err);
				sai_event_db_close(&vhd->sqlite3_cache, &pdb);
				lwsac_free(&ac);
				return SAI_DB_RESULT_BUSY;
			}
		} lws_end_foreach_dll(p);

		ret = sqlite3_exec(pdb, "END TRANSACTION", NULL, NULL, &err);
		if (ret != SQLITE_OK) {
			sai_event_db_close(&vhd->sqlite3_cache, &pdb);
			lwsac_free(&ac);
			sqlite3_free(err);
			if (ret == SQLITE_BUSY)
				return SAI_DB_RESULT_BUSY;
			return SAI_DB_RESULT_ERROR;
		}
		sqlite3_free(err);
	}

	sai_event_db_close(&vhd->sqlite3_cache, &pdb);
	lwsac_free(&ac);

	return SAI_DB_RESULT_OK;
}



