/*
 * Sai server
 *
 * Copyright (C) 2019 - 2020 Andy Green <andy@warmcat.com>
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
#include <time.h>

#include "w-private.h"

void
sai_task_uuid_to_event_uuid(char *event_uuid33, const char *task_uuid65)
{
	memcpy(event_uuid33, task_uuid65, 32);
	event_uuid33[32] = '\0';
}

int
saiw_get_blob(struct vhd *vhd, const char *url, sqlite3 **pdb,
	      sqlite3_blob **blob, uint64_t *length)
{
	char task_uuid[66], event_uuid[34], nonce[34], qu[200],
	     esc[66], esc1[34];
	struct lwsac *ac = NULL;
	lws_dll2_owner_t o;
	sai_artifact_t *a;
	uint64_t rid = 0;
	const char *p;
	int n;

	/*
	 * We get passed the RHS of a URL string like
	 *
	 * <task_uuid>/<down_nonce>/filename
	 *
	 * filename is not used for matching, but make sure the client saves it
	 * using the name generated along with the link.
	 *
	 * Security model: artifact download is intentionally unauthenticated
	 * at the HTTP layer; access is gated by knowledge of the 32-char hex
	 * down_nonce (a capability token minted by sai_uuid16_create, 128 bits
	 * of CSPRNG entropy, see s-notification.c).  The length checks below
	 * enforce that both task_uuid (64 hex chars) and down_nonce (32 hex
	 * chars) are exactly the expected length, and both are passed through
	 * lws_sql_purify before SQL interpolation.  Treat the down_nonce with
	 * the same care as a credential: it is rendered into the build page
	 * for every viewer, so anyone who can view the build can fetch the
	 * artifact.
	 *
	 * Extract the pieces from the URL
	 */

	n = 0;
	p = url;
	while (*p && *p != '/' && n < (int)sizeof(task_uuid) - 1)
		task_uuid[n++] = *p++;

	if (n != sizeof(task_uuid) - 2 || *p != '/') {
		lwsl_notice("%s: url layout 1: %d %s\n", __func__, n, url);
		return -1;
	}

	task_uuid[n] = '\0';
	p++; /* skip the / */

	n = 0;
	while (*p && *p != '/' && n < (int)sizeof(nonce) - 1)
		nonce[n++] = *p++;

	if (n != sizeof(nonce) - 2 || *p != '/') {
		lwsl_notice("%s: url layout 2\n", __func__);
		return -1;
	}

	if (!saiw_event_visible(vhd, task_uuid)) {
		lwsl_info("%s: task's project not shown on this vhost\n",
			  __func__);
		return -1;
	}

	sai_task_uuid_to_event_uuid(event_uuid, task_uuid);

	/* open the event-specific database object */

	if (sai_event_db_ensure_open(vhd->context, &vhd->sqlite3_cache,
			      vhd->sqlite3_path_lhs, event_uuid, 0, pdb)) {
		lwsl_info("%s: unable to open event-specific database\n",
				__func__);

		return -1;
	}

	/*
	 * Query the artifact he's asking for
	 */

	lws_sql_purify(esc, task_uuid, sizeof(esc));
	lws_sql_purify(esc1, nonce, sizeof(esc1));
	lws_snprintf(qu, sizeof(qu),
		     " and task_uuid='%s' and artifact_down_nonce='%s'",
		     esc, esc1);
	n = lws_struct_sq3_deserialize(*pdb, qu, NULL,
				       lsm_schema_sq3_map_artifact,
				       &o, &ac, 0, 1);
	if (n < 0 || !o.head) {
		lwsl_err("%s: no result from %s\n", __func__, qu);
		goto fail;
	}

	a = (sai_artifact_t *)o.head;

	*length = a->len;

	/*
	 * recover the rowid the blob api requires
	 */

	lws_snprintf(qu, sizeof(qu), "select rowid from artifacts "
				     "where artifact_down_nonce='%s'", esc1);

	if (sqlite3_exec(*pdb, qu, sai_sql3_get_uint64_cb, &rid, NULL) != SQLITE_OK) {
		lwsl_err("%s: %s: %s: fail\n", __func__, qu, sqlite3_errmsg(*pdb));
		goto fail;
	}

	/*
	 * Get a read-only handle on the blob
	 */

	if (sqlite3_blob_open(*pdb, "main", "artifacts", "blob", (sqlite3_int64)rid, 0, blob) != SQLITE_OK) {
		lwsl_err("%s: unable to open blob, rid %d\n", __func__, (int)rid);
		goto fail;
	}

	lwsac_free(&ac); /* drop the lwsac holding that result */

	/*
	 * It was successful, *length was set, *pdb and *blob are live handles
	 * to the db and the blob itself.
	 */

	return 0;

fail:
	lwsac_free(&ac);
	sai_event_db_close(&vhd->sqlite3_cache, pdb);

	lwsl_notice("%s: couldn't find blob %s\n", __func__, url);

	return -1;
}
