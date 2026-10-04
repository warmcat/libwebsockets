/*
 * Sai web - ./src/web/w-visible.c
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
 * Which projects a vhost shows
 *
 * A sai-web vhost can be given a "projects" pvo listing the projects (repo
 * names) it shows, so the events of one sai-server can be offered as different
 * canned views, eg, on differently-named unix sockets for the front-end proxy
 * to mount.  Without the pvo, the vhost shows every project.
 *
 * The list is kept twice from the one parse: as a list for checks done in C,
 * and as a TEMP table on the vhd's own connection to the events db, so the sql
 * listing events can be scoped by a fixed fragment.  TEMP tables only exist on
 * the connection that made them, so each vhost's list is private to it.
 *
 * Everything that tells browsers about, or acts on, a project goes through
 * these, so that a restricted vhost behaves as if the other projects don't
 * exist.
 */

#include <libwebsockets.h>
#include <string.h>

#include "w-private.h"

#define SAIW_VISIBLE_SQL \
	" and repo_name in (select name from temp.saiw_visible)"

typedef struct saiw_visible_project {
	lws_dll2_t		list; /* vhd->visible_projects */

	/* name over-allocated here */
} saiw_visible_project_t;

static const char *
saiw_visible_name(const saiw_visible_project_t *vp)
{
	return (const char *)&vp[1];
}

static int
saiw_visible_listed(struct vhd *vhd, const char *project)
{
	lws_start_foreach_dll(struct lws_dll2 *, p,
			      vhd->visible_projects.head) {
		saiw_visible_project_t *vp = lws_container_of(p,
					saiw_visible_project_t, list);

		if (!strcmp(saiw_visible_name(vp), project))
			return 1;
	} lws_end_foreach_dll(p);

	return 0;
}

int
saiw_project_visible(struct vhd *vhd, const char *project)
{
	return !saiw_restricted(vhd) || saiw_visible_listed(vhd, project);
}

int
saiw_event_visible(struct vhd *vhd, const char *uuid)
{
	char event_uuid[33];
	sqlite3_stmt *sm;
	int r = 0;

	if (!saiw_restricted(vhd))
		return 1;

	/* a task uuid starts with its event's uuid */
	if (strlen(uuid) < 32)
		return 0;
	sai_task_uuid_to_event_uuid(event_uuid, uuid);

	if (sqlite3_prepare_v2(vhd->pdb, "SELECT 1 FROM events WHERE uuid = ?"
			       SAIW_VISIBLE_SQL, -1, &sm, NULL) != SQLITE_OK) {
		lwsl_err("%s: prepare failed: %s\n", __func__,
			 sqlite3_errmsg(vhd->pdb));
		return 0;
	}

	sqlite3_bind_text(sm, 1, event_uuid, -1, SQLITE_TRANSIENT);
	r = sqlite3_step(sm) == SQLITE_ROW;
	sqlite3_finalize(sm);

	return r;
}

const char *
saiw_visible_sql(struct vhd *vhd)
{
	return saiw_restricted(vhd) ? SAIW_VISIBLE_SQL : "";
}

static int
saiw_visible_add(struct vhd *vhd, const char *name)
{
	saiw_visible_project_t *vp;
	size_t len = strlen(name);
	sqlite3_stmt *sm;

	if (!len || saiw_visible_listed(vhd, name))
		/* listed twice is the same as once */
		return 0;

	vp = lwsac_use_zero(&vhd->ac_visible, sizeof(*vp) + len + 1, 512);
	if (!vp)
		return 1;
	memcpy((char *)&vp[1], name, len + 1);

	if (sqlite3_prepare_v2(vhd->pdb, "INSERT INTO temp.saiw_visible "
			       "(name) VALUES (?)", -1, &sm, NULL) != SQLITE_OK)
		return 1;
	sqlite3_bind_text(sm, 1, name, -1, SQLITE_TRANSIENT);
	if (sai_sqlite3_step_done(vhd->pdb, sm, "list visible project"))
		return 1;

	lws_dll2_add_tail(&vp->list, &vhd->visible_projects);

	return 0;
}

/*
 * Parse the "projects" pvo, a comma-separated list, eg,
 *
 *	"projects": "libwebsockets, sai",
 *
 * Whitespace around the names is ignored.  Names may use A-Z a-z 0-9 _ - and .
 *
 * Call after vhd->pdb is open.  Returns 0 if OK, including when there is no
 * pvo.  If there is one but it can't be understood or lists nothing, it fails
 * rather than show this vhost everything.
 */

int
saiw_visible_init(struct vhd *vhd, void *pvo)
{
	struct lws_tokenize ts;
	const char *list;
	char name[65];

	lws_dll2_owner_clear(&vhd->visible_projects);

	if (lws_pvo_get_str(pvo, "projects", &list))
		return 0;

	if (sai_sqlite3_statement(vhd->pdb, "CREATE TEMP TABLE IF NOT EXISTS "
				  "saiw_visible (name TEXT PRIMARY KEY);",
				  "create saiw_visible"))
		return 1;

	lws_tokenize_init(&ts, list, LWS_TOKENIZE_F_COMMA_SEP_LIST |
				     LWS_TOKENIZE_F_MINUS_NONTERM |
				     LWS_TOKENIZE_F_DOT_NONTERM |
				     LWS_TOKENIZE_F_NO_INTEGERS |
				     LWS_TOKENIZE_F_NO_FLOATS);

	do {
		ts.e = (int8_t)lws_tokenize(&ts);

		switch (ts.e) {
		case LWS_TOKZE_ENDED:
			break;

		case LWS_TOKZE_TOKEN:
			if (lws_tokenize_cstr(&ts, name, sizeof(name))) {
				lwsl_err("%s: project name too long\n",
					 __func__);
				goto bail;
			}
			if (saiw_visible_add(vhd, name))
				goto bail;
			break;

		case LWS_TOKZE_DELIMITER:
			/* COMMA_SEP_LIST makes sure commas are where they go */
			if (*ts.token == ',')
				break;
			goto bail;

		default:
			/* eg, missing or doubled commas, or bad characters */
			goto bail;
		}
	} while (ts.e > 0);

	if (!saiw_restricted(vhd)) {
		lwsl_err("%s: \"projects\" pvo lists no projects\n", __func__);
		return 1;
	}

	lwsl_notice("%s: vhost %s shows %u projects: %s\n", __func__,
		    lws_get_vhost_name(vhd->vhost),
		    (unsigned int)vhd->visible_projects.count, list);

	return 0;

bail:
	lwsl_err("%s: unable to use \"projects\" pvo '%s'\n", __func__, list);
	saiw_visible_destroy(vhd);

	return 1;
}

void
saiw_visible_destroy(struct vhd *vhd)
{
	/* the TEMP table goes with the db connection */
	lws_dll2_owner_clear(&vhd->visible_projects);
	lwsac_free(&vhd->ac_visible);
}
