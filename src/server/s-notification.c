/*
 * Sai server - src/server/notification.c
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
 * The same ws interface is connected-to by builders (on path /builder), and
 * provides the query transport for browsers (on path /browse).
 */

#include <libwebsockets.h>
#include "s-private.h"

/* starts from +1 of sai_notification_action_t */

static const char *notifaction_action_names[] = {
	"repo-update"
};

static const char * const paths[] = {
	"schema",
	"action",
	"repository.name",
	"repository.fetchurl",
	"ref",
	"hash",
	"nonce",
	"saifile_len",
	"saifile",
	"sec",
};

enum enum_paths {
	LEJPN_SCHEMA,
	LEJPN_ACTION,
	LEJPN_REPOSITORY_NAME,
	LEJPN_REPOSITORY_FETCHURL,
	LEJPN_REF,
	LEJPN_HASH,
	LEJPN_NONCE,
	LEJPN_SAIFILE_LEN,
	LEJPN_SAIFILE,
	LEJPN_SEC,
};

/*
 * Saifile parser
 */

static const char * const saifile_paths[] = {
	"schema",
	"platforms.*.build[]",
	"platforms.*.build",
	"platforms.*.build.*",
	"platforms.*.default",
	"platforms.*",
	"configurations.*.prep",
	"configurations.*.cmake",
	"configurations.*.deps",
	"configurations.*.platforms",
	"configurations.*.artifacts",
	"configurations.*.cpack",
	"configurations.*.branches",
	"configurations.*",
};

enum enum_saifile_paths {
	LEJPNSAIF_SCHEMA,
	LEJPNSAIF_PLAT_BUILD_STAGE,
	LEJPNSAIF_PLAT_BUILD,
	LEJPNSAIF_PLAT_BUILD_ELEMENT,
	LEJPNSAIF_PLAT_DEFAULT,
	LEJPNSAIF_PLAT_NAME,
	LEJPNSAIF_CONFIGURATIONS_PREP,
	LEJPNSAIF_CONFIGURATIONS_CMAKE,
	LEJPNSAIF_CONFIGURATIONS_DEPS,
	LEJPNSAIF_CONFIGURATIONS_PLATFORMS,
	LEJPNSAIF_CONFIGURATIONS_ARTIFACTS,
	LEJPNSAIF_CONFIGURATIONS_CPACK,
	LEJPNSAIF_CONFIGURATIONS_BRANCHES,
	LEJPNSAIF_CONFIGURATIONS_NAME,
};

/* do the string subst for ${cmake} etc */

static int
exp_cmake(void *priv, const char *name, char *out, size_t *pos, size_t olen,
	  size_t *exp_ofs)
{
	sai_notification_t *sn = (sai_notification_t *)priv;
	const char *replace = NULL;
	size_t replace_len, rem_out;

	if (!strcmp(name, "prep")) {
		replace = sn->t.prep;
		replace_len = strlen(sn->t.prep);
		goto expand;
	}

	if (!strcmp(name, "cmake")) {
		replace = sn->t.cmake;
		replace_len = strlen(sn->t.cmake);
		goto expand;
	}

	if (!strcmp(name, "cpack")) {
		replace = sn->t.cpack;
		replace_len = strlen(sn->t.cpack);
		goto expand;
	}

	return LSTRX_FATAL_NAME_UNKNOWN;

expand:
	rem_out = olen - *pos;		/* remaining rhs */
	replace_len -= *exp_ofs;
	if (replace_len < rem_out)
		rem_out = replace_len;

	memcpy(out + *pos, replace + (*exp_ofs), rem_out);
	*exp_ofs += rem_out;
	*pos += rem_out;

	if (rem_out == replace_len)
		return LSTRX_DONE;

	return LSTRX_FILLED_OUT;
}

static int
arg_to_bool(const char *s)
{
	static const char * const on[] = { "on", "yes", "true" };
	int n = atoi(s);

	if (n)
		return 1;

	for (n = 0; n < (int)LWS_ARRAY_SIZE(on); n++)
		if (!strcasecmp(s, on[n]))
			return 1;

	return 0;
}

static int
sai_tuple_element_compare(const char *e1, const char *e2)
{
	char *p;

	// lwsl_notice("%s: comp '%s' '%s'\n", __func__, e1, e2);

	if (strlen(e1) > strlen(e2))
		/* can't match if req is longer than plat */
		return -1;

	p = strchr(e2, '/');
	if (p && lws_ptr_diff(p, e2) < (int)strlen(e1))
		/* e2 contains a / section terminal inside e1 scope */
		return 1;

	return strncmp(e1, e2, strlen(e1));
}

static int
sai_tuple_compare(const char *req, size_t req_len, const char *plat)
{
	const char *pos = req;
	char e1[96];
	int n;

	do {
		n = 0;
		while (n < (int)sizeof(e1) - 1 && req_len && *pos != '/') {
			e1[n++] = *pos++;
			req_len--;
		}
		e1[n] = '\0';
		if (*pos == '/' && req_len) {
			req_len--;
			pos++;
		}

		if (n == sizeof(e1) - 1) {
			// lwsl_notice("%s: NOMATCH 3 '%s' '%s'\n", __func__, req, plat);
			/* element too long */
			return 1;
		}

		if (n && /* let it pass if empty match section, eg, linux//gcc */
		    sai_tuple_element_compare(e1, plat)) {
			// lwsl_notice("%s: NOMATCH 2 '%s' '%s'\n", __func__, req, plat);
			/* section does not match */
			return 1;
		}

		while (*plat && *plat != '/')
			plat++;
		if (*plat == '/')
			plat++;

		if (!*plat && req_len) {
			// lwsl_notice("%s: NOMATCH 1 '%s' '%s'\n", __func__, req, plat);
			/* FAIL: req had more than we had */
			return 1;
		}

		if (!req_len) {
			// lwsl_notice("%s: MATCH '%s' '%s'\n", __func__, req, plat);
			/* MATCH: we matched at least as far as we had */
			return 0;
		}

	} while (1);

	return 1;
}

/*
 * We parse the saifile JSON
 *
 * The backdrop of this is the remote's hook that's letting us know all this
 * won't update his refs to the push described here until he's finished
 * uploading the saifile POST.
 *
 * So although we are going to add the tasks as we parse them, in fact we
 * can't hand any of them out to builders until a short time after we got to
 * the end of the POST, otherwise the builders are not going to find the
 * right refs in the repo yet.
 */

static signed char
sai_saifile_lejp_cb(struct lejp_ctx *ctx, char reason)
{
	struct pss *pss = (struct pss *)ctx->user;
	sai_notification_t *sn = (sai_notification_t *)&pss->sn;
	sqlite3 *pdb = NULL;
	size_t n;

	// lwsl_notice("%s: reason %d, %s\n", __func__, reason, ctx->path);

	if (reason == LEJPCB_COMPLETE) {

		if (!pss->dry)
			lwsl_notice("%s: saifile decode completed\n", __func__);

		return 0;
	}

	if (reason == LEJPCB_OBJECT_START &&
	    ctx->path_match - 1 == LEJPNSAIF_CONFIGURATIONS_NAME) {
		/*
		 * We're at the testname part of "testname" : { }
		 */
		lws_strncpy(sn->t.taskname, &ctx->path[15],
			    sizeof(sn->t.taskname));
		sn->t.prep[0]			= '\0';
		sn->t.packages[0]		= '\0';
		sn->t.cmake[0]			= '\0';
		sn->t.cpack[0]			= '\0';
		sn->t.artifacts[0]		= '\0';
		sn->t.branches[0]		= '\0';
		sn->explicit_platforms[0]	= '\0';
		return 0;
	}

	if (reason == LEJPCB_OBJECT_END &&
	    ctx->path_match - 1 == LEJPNSAIF_CONFIGURATIONS_NAME &&
	    sn->t.taskname[0]) {
		lws_dll2_owner_t owner;
		char *err;

		/*
		 * We're at the testname part of "testname" : { }
		 */
		if (pss->dry) {
			sn->t.taskname[0] = '\0';

			return 0;
		}

		/*
		 * Iterate through each platform creating task entries for this
		 * configuration customized for each platform... first time just
		 * check the string subst for all of them is OK...
		 */

		lwsl_notice("%s: Creating task entries for notification\n", __func__);

		lws_start_foreach_dll(struct lws_dll2 *, p,
					   pss->platform_owner.head) {
			sai_platform_t *pl =
				lws_container_of(p, sai_platform_t, list);
			size_t used_in, used_out;
			struct lws_tokenize ts;
			int n, match = 0;
			lws_strexp_t sx;

			if (!pl->nondefault)
				/*
				 * If it's a default platform, then match
				 * by default
				 */
				match = 1;

			/*
			 * The configuration restricts itself to only
			 * existing on certain branches?
			 */

			if (sn->t.branches[0]) {
				char ref[256];

				lws_snprintf(ref, sizeof(ref), "refs/heads/%s", sn->t.branches);

				if (strcmp(ref, sn->e.ref)) {
					lwsl_notice("%s: config %s skipped as only applies to %s not %s\n",
							__func__, sn->t.taskname, ref, sn->e.ref);
					goto next_plat;
				}
			}

			if (sn->explicit_platforms[0]) {
				char not = 0;

				/*
				 * If the configuration gives explicit
				 * platforms, we have to filter the platform
				 * against the comma-separated list.
				 *
				 * "none" - don't match any plats just because
				 *	    they are default
				 *
				 * "not plat" - disallow specific plat "plat",
				 *		implies you're not using "none"
				 *
				 * "plat" - allow specific plat "plat"
				 */
				memset(&ts, 0, sizeof(ts));
				ts.start = (char *)sn->explicit_platforms;
				ts.len = strlen(ts.start);
				ts.flags = LWS_TOKENIZE_F_DOT_NONTERM |
					   LWS_TOKENIZE_F_SLASH_NONTERM |
					   LWS_TOKENIZE_F_MINUS_NONTERM;
				do {
					ts.e = (int8_t)lws_tokenize(&ts);
					if (ts.e != LWS_TOKZE_TOKEN)
						continue;

			//		lwsl_notice("%s: check %.*s\n", __func__,
			//			    (int)ts.token_len, ts.token);

					if (!strncmp(ts.token, "none",
						     ts.token_len)) {
						not = 0;
						match = 0;
						continue;
					}
					if (!strncmp(ts.token, "not",
						     ts.token_len)) {
						not = 1;
						continue;
					}
					/*
					 * We need to check with per-slash
					 * minimal matching, ie, "linux"
					 * matches "linux-ubuntu/x86_64/gcc"
					 */
					if (!sai_tuple_compare(ts.token,
						     ts.token_len, pl->name)) {
						match = !not;
						if (match)
							break;
					}
					not = 0;
				} while (ts.e > 0);
			}

			if (match) {

				/*
				 * The platform build string (pl->build) is the
				 * base, with optional entries like ${cmake}
				 * that are filled in with the corresponding
				 * info from the specific configuration's
				 * "cmake" entry (sn->t.cmake)...
				 *
				 * sn->t.build becomes the string-substituted
				 * copy that is serialized
				 */

				lws_strexp_init(&sx, sn, exp_cmake, sn->t.build,
						sizeof(sn->t.build));

				n = lws_strexp_expand(&sx, pl->build,
						      strlen(pl->build),
						      &used_in, &used_out);
				if (n != LSTRX_DONE) {
					lwsl_notice("%s: strsubst fail n=%d %s %s\n",
						    __func__, n, pl->build,
						    sn->t.cmake);
					return -1;
				}
			}

next_plat: ;

		} lws_end_foreach_dll(p);

		/*
		 * ...now we know the string handling will go well, create the
		 * event database file and create task entries in there for this
		 * configuration's tasks for each platform
		 */

		if (sai_event_db_ensure_open(pss->vhd->context, &pss->vhd->sqlite3_cache,
				      pss->vhd->sqlite3_path_lhs, pss->sn.e.uuid, 1, &pdb)) {
			lwsl_err("%s: unable to open event-specific db\n", __func__);
			return -1;
		}

		sqlite3_exec(pdb, "BEGIN TRANSACTION", NULL, NULL, &err);
		if (err)
			sqlite3_free(err);

		lws_start_foreach_dll(struct lws_dll2 *, p,
					   pss->platform_owner.head) {
			sai_platform_t *pl =
				lws_container_of(p, sai_platform_t, list);
			size_t used_in, used_out;
			struct lws_tokenize ts;
			int n, match = 0;
			lws_strexp_t sx;

			if (!pl->nondefault)
				/*
				 * If it's a nondefault platform, then match
				 * by default
				 */
				match = 1;

			if (sn->explicit_platforms[0]) {
				char not = 0;

				/*
				 * If the configuration gives explicit
				 * platforms, we have to filter the platform
				 * against the comma-separated list.
				 *
				 * "none" - don't match any plats just because
				 *	    they are default
				 *
				 * "not plat" - disallow specific plat "plat",
				 *		implies you're not using "none"
				 *
				 * "plat" - allow specific plat "plat"
				 */

				memset(&ts, 0, sizeof(ts));
				ts.start = (char *)sn->explicit_platforms;
				ts.len = strlen(ts.start);
				ts.flags = LWS_TOKENIZE_F_DOT_NONTERM |
					   LWS_TOKENIZE_F_SLASH_NONTERM |
					   LWS_TOKENIZE_F_MINUS_NONTERM;

				do {
					ts.e = (int8_t)lws_tokenize(&ts);
					if (ts.e != LWS_TOKZE_TOKEN)
						continue;

			//		lwsl_notice("%s: check %.*s\n", __func__,
			//			    (int)ts.token_len, ts.token);

					if (!strncmp(ts.token, "none",
						     ts.token_len)) {
						not = 0;
						match = 0;
						continue;
					}
					if (!strncmp(ts.token, "not",
						     ts.token_len)) {
						not = 1;
						continue;
					}
					if (!sai_tuple_compare(ts.token,
						     ts.token_len, pl->name)) {
						match = !not;
						if (match)
							break;
					}
					not = 0;
				} while (ts.e > 0);
			}

			if (match) {
				const char *p;
				int c;

				/*
				 * For this platform, we want to create a task
				 * associated with this event.  Tasks and logs
				 * associated with an event go in an event-
				 * specific database file for scalability.
				 */

				c = 2; /* git mirror and checkout */
				p = pl->build;
				while (*p)
					if (*p++ == '\n')
						c++;

				pss->sn.t.build_step_count = c;

				lws_strexp_init(&sx, sn, exp_cmake, sn->t.build,
						sizeof(sn->t.build));

				n = lws_strexp_expand(&sx, pl->build,
						      strlen(pl->build),
						      &used_in, &used_out);
				if (n != LSTRX_DONE) {
					lwsl_notice("%s: strsubst failed %s %s\n",
						    __func__, pl->build,
						    sn->t.cmake);
					sqlite3_exec(pdb, "END TRANSACTION", NULL, NULL, &err);
					if (err)
						sqlite3_free(err);
					sai_event_db_close(&pss->vhd->sqlite3_cache, &pdb);
					return -1;
				}


				/*
				 * Prepare a struct of the task object...
				 * task uuid is the event uuid and another
				 * random 32 chars, so you can always recover
				 * the related event uuid from the task uuid
				 */

				memcpy(pss->sn.t.uuid, pss->sn.e.uuid, 32);
				sai_uuid16_create(lws_get_context(pss->wsi),
						  pss->sn.t.uuid + 32);
				strcpy(pss->sn.t.event_uuid, pss->sn.e.uuid);
				pss->sn.t.uid = pss->sn.event_task_index++;

				/*
				 * This is basically a secret that anything
				 * trying to upload an artifact for the task
				 * must provide to authenticate.
				 */
				sai_uuid16_create(lws_get_context(pss->wsi),
						  pss->sn.t.art_up_nonce);
				/*
				 * An unrelated secret that anything
				 * trying to download an artifact for the task
				 * must provide to identify it.
				 */
				sai_uuid16_create(lws_get_context(pss->wsi),
						  pss->sn.t.art_down_nonce);

				pss->sn.t.git_repo_url =
						pss->sn.e.repo_fetchurl;
				pss->sn.e.last_updated =
					(unsigned long long)lws_now_secs();
				pss->sn.e.state = SAIES_WAITING;
				lws_strncpy(pss->sn.t.platform, pl->name,
					    sizeof(pss->sn.t.platform));

				// pss->sn.t.server_name	= ;
				pss->sn.t.repo_name	= pss->sn.e.repo_name;
				pss->sn.t.git_ref	= sn->e.ref;
				pss->sn.t.git_hash	= sn->e.hash;
				pss->sn.t.parallel	= 2;

				lws_dll2_clear(&pss->sn.t.list);
				lws_dll2_owner_clear(&owner);
				lws_dll2_add_head(&pss->sn.t.list, &owner);

				/*
				 * Create the task in event-specific database
				 */

				lws_struct_sq3_serialize(pdb,
							 lsm_schema_sq3_map_task,
							 &owner, (uint32_t)pss->sn.t.uid);
			}

		} lws_end_foreach_dll(p);

		sqlite3_exec(pdb, "END TRANSACTION", NULL, NULL, &err);
		if (err)
			sqlite3_free(err);

		sai_event_db_close(&pss->vhd->sqlite3_cache, &pdb);

		/*
		 * Recompute startable task platforms and broadcast to all sai-power,
		 * after there has been a change in tasks
		 */
		sais_platforms_with_tasks_pending(pss->vhd);

//		lwsl_notice("%s: New test '%s', '%s', '%s'\n", __func__,
//			    sn->t.taskname, sn->t.cmake, sn->t.packages);

		sn->t.taskname[0] = '\0';
		return 0;
	}

	if (reason == LEJPCB_OBJECT_START &&
	    ctx->path_match - 1 == LEJPNSAIF_PLAT_NAME) {
		/*
		 * We're at the platformname part of "platformname" : { }
		 */
		lws_strncpy(sn->platname, &ctx->path[10], sizeof(sn->platname));
		sn->t.prep[0] = '\0';
		sn->t.cmake[0] = '\0';
		sn->t.cpack[0] = '\0';
		sn->platbuild[0] = '\0';
		sn->nondefault = 0;
		return 0;
	}

	if (reason == LEJPCB_OBJECT_END &&
	    ctx->path_match - 1 == LEJPNSAIF_PLAT_NAME &&
	    sn->platname[0] && sn->platbuild[0]) {
		sai_platform_t *pl;
		uint8_t *plb;
		size_t pnl;

		if (pss->dry) {
			sn->t.platform[0] = '\0';
			return 0;
		}

		/*
		 * We create a platform object with space for its strings after
		 */

		pnl = strlen(sn->platname);
		pl = (sai_platform_t *)malloc(sizeof(*pl) + pnl +
					      strlen(sn->platbuild) + 2);
		if (!pl)
			return -1;

		memset(pl, 0, sizeof(*pl));
		plb = (uint8_t *)&pl[1];

		/*
		 * Platforms are malloc'd up and added to pss
		 * .platform_owner
		 */

		pl->name = (const char *)plb;
		memcpy(plb, sn->platname, pnl + 1);
		plb += pnl + 1;

		pl->build = (const char *)plb;
		memcpy(plb, sn->platbuild, strlen(sn->platbuild) + 1);

		pl->nondefault = sn->nondefault;

		lws_dll2_add_head(&pl->list, &pss->platform_owner);

//		lwsl_notice("%s: New platform '%s', build '%s', notdefault %d\n",
//			    __func__, pl->name, pl->build, pl->nondefault);

		sn->platbuild[0] = '\0';
		return 0;
	}

	if (ctx->path_match - 1 == LEJPNSAIF_PLAT_BUILD_STAGE &&
	    reason == LEJPCB_VAL_STR_START) {
		n = strlen(sn->platbuild);

		if (n && n < sizeof(sn->platbuild) - 2) {
			sn->platbuild[n++] = '\n';
			sn->platbuild[n] = '\0';
		}
		return 0;
	}

	/* we only match on the prepared path strings */
	if (!(reason & LEJP_FLAG_CB_IS_VALUE) || !ctx->path_match)
		return 0;

	/*
	 * Some of these will be long strings, accept all the string parts
	 * and accumilate them
	 */

	switch (ctx->path_match - 1) {
	case LEJPNSAIF_SCHEMA:
		sn->event_task_index = 0;
		return 0;

	case LEJPNSAIF_CONFIGURATIONS_PREP:
		/* the additional cmake options for this test configuration */
		n = strlen(sn->t.prep);
		if (n < sizeof(sn->t.prep) - 2)
			lws_strnncpy(sn->t.prep + n, ctx->buf, ctx->npos,
				     sizeof(sn->t.prep) - n);
		break;

	case LEJPNSAIF_CONFIGURATIONS_CMAKE:
		/* the additional cmake options for this test configuration */
		n = strlen(sn->t.cmake);
		if (n < sizeof(sn->t.cmake) - 2)
			lws_strnncpy(sn->t.cmake + n, ctx->buf, ctx->npos,
				     sizeof(sn->t.cmake) - n);
		break;

	case LEJPNSAIF_CONFIGURATIONS_DEPS:
		/* the necessary dependent package strings */
		n = strlen(sn->t.packages);
		if (n < sizeof(sn->t.packages) - 2) {
			if (n)
				sn->t.packages[n++] = ',';
			lws_strncpy(sn->t.packages + n, ctx->buf,
				    sizeof(sn->t.packages) - n);
		}
		break;

	case LEJPNSAIF_CONFIGURATIONS_PLATFORMS:
		/* the necessary dependent package strings... can be huge */
		n = strlen(sn->explicit_platforms);
		if (n < sizeof(sn->explicit_platforms) - 2)
			lws_strnncpy(sn->explicit_platforms + n, ctx->buf, ctx->npos,
				     sizeof(sn->explicit_platforms) - n);
		break;

	case LEJPNSAIF_CONFIGURATIONS_ARTIFACTS:
		lws_strncpy(sn->t.artifacts, ctx->buf, sizeof(sn->t.artifacts));
		break;

	case LEJPNSAIF_CONFIGURATIONS_CPACK:
		n = strlen(sn->t.cpack);
		if (n < sizeof(sn->t.cpack) - 2)
			lws_strnncpy(sn->t.cpack + n, ctx->buf, ctx->npos,
				     sizeof(sn->t.cpack) - n);
		break;

	case LEJPNSAIF_CONFIGURATIONS_BRANCHES:
		lws_strncpy(sn->t.branches, ctx->buf, sizeof(sn->t.branches));
		break;

	case LEJPNSAIF_PLAT_BUILD:
	case LEJPNSAIF_PLAT_BUILD_STAGE:
		/*
		 * The overall build script for this platform
		 * is appended into the temp sn.platbuild
		 */

		lwsl_err("%s: LEJPNSAIF_PLAT_BUILD_STAGE: %.*s\n", __func__, (int)ctx->npos, (const char *)ctx->buf);

		n = strlen(sn->platbuild);
		if (n < sizeof(sn->platbuild) - 2 && ctx->npos)
			lws_strnncpy(sn->platbuild + n, ctx->buf, ctx->npos,
				     sizeof(sn->platbuild) - n);
		break;

	case LEJPNSAIF_PLAT_BUILD_ELEMENT:
		n = strlen(sn->platbuild);
		if (n) {
			if (n > sizeof(sn->platbuild) - 2)
				break;
			sn->platbuild[n++] = '\n';
		}
		if (n < sizeof(sn->platbuild) - 2)
			lws_strnncpy(sn->platbuild + n, ctx->buf, ctx->npos,
				     sizeof(sn->platbuild) - n);
		break;

	case LEJPNSAIF_PLAT_DEFAULT:
		sn->nondefault = !arg_to_bool(ctx->buf);
		break;

	default:
		return 0;
	}

	return 0;
}

static signed char
sai_notification_lejp_cb(struct lejp_ctx *ctx, char reason)
{
	struct pss *pss = (struct pss *)ctx->user;
	sai_notification_t *sn = (sai_notification_t *)&pss->sn;
	size_t ile, ole;
	int n;

	/* we only match on the prepared path strings */
	if (!(reason & LEJP_FLAG_CB_IS_VALUE) || !ctx->path_match)
		return 0;

//	if (reason != LEJPCB_VAL_STR_END)
//		return 0;

	/* only the end part of the string, where we know the length */

	switch (ctx->path_match - 1) {
	case LEJPN_SCHEMA:
		if (strcmp(ctx->buf, "com-warmcat-sai-notification")) {
			lwsl_err("%s: unknown schema '%s'\n", __func__, ctx->buf);
			return -1;
		}
		return 0;

	case LEJPN_ACTION:
		for (n = 0; n < (int)LWS_ARRAY_SIZE(notifaction_action_names);n++)
			if (!strcmp(ctx->buf, notifaction_action_names[n])) {
				sn->action = (sai_notification_action_t)(n + 1);

				return 0;
			}
		lwsl_notice("%s: unknown action '%s' ignored\n",
			    __func__, ctx->buf);
		return -1;

	case LEJPN_REPOSITORY_NAME:
		lws_strncpy(sn->e.repo_name, ctx->buf, sizeof(sn->e.repo_name));
		break;

	case LEJPN_REPOSITORY_FETCHURL:
		lws_strncpy(sn->e.repo_fetchurl, ctx->buf, sizeof(sn->e.repo_fetchurl));
		break;

	case LEJPN_REF:
		lws_strncpy(sn->e.ref, ctx->buf, sizeof(sn->e.ref));
		break;

	case LEJPN_SEC:
		sn->e.sec = 1;
		break;

	case LEJPN_HASH:
		lws_strncpy(sn->e.hash, ctx->buf, sizeof(sn->e.hash));
		break;

	case LEJPN_NONCE:
		break;

	case LEJPN_SAIFILE_LEN:
		sn->saifile_in_len = (unsigned int)atoi(ctx->buf);
		/* only accept sane base64 size */
		if (sn->saifile_in_len < 8 || sn->saifile_in_len > 65536) {
			lwsl_err("%s: bad saifile_len %u\n", __func__,
					(unsigned int)sn->saifile_in_len);

			return -1;
		}
		sn->saifile_out_len = (sn->saifile_in_len * 3) / 4 + 4;
		sn->saifile = malloc(sn->saifile_out_len);
		if (!sn->saifile) {
			lwsl_err("%s: OOM\n", __func__);

			return -1;
		}
		/*
		 * Caller must take responsibility for sn->saifile allocation
		 */
		sn->saifile_in_seen = sn->saifile_out_pos = 0;
		lws_b64_decode_state_init(&sn->b64);
		break;

	case LEJPN_SAIFILE:
		/*
		 * Base64 encoding of the commit's .sai.json file contents... we
		 * have to treat this with caution since it can be anything,
		 * including unparsable JSON.
		 *
		 * Let's base64-decode it and collect it into an buffer first,
		 * before sn test parse and then sn second parse to extract the
		 * tasks
		 */

		sn->saifile_in_seen += ctx->npos;
		if (sn->saifile_in_seen > sn->saifile_in_len) {
			lwsl_err("%s: SAIFILE: too large in %u vs %u\n", __func__,
				 (unsigned int)sn->saifile_in_seen,
				 (unsigned int)sn->saifile_in_len);
			return -1;
		}
		ile = ctx->npos;
		ole = sn->saifile_out_len - sn->saifile_out_pos;
		lws_b64_decode_stateful(&sn->b64, ctx->buf, &ile,
				(uint8_t *)sn->saifile + sn->saifile_out_pos, &ole,
					sn->saifile_in_seen == sn->saifile_in_len);

		sn->saifile_out_pos += ole;
		break;

	default:
		return 0;
	}

	return 0;
}

int
sai_notification_file_upload_cb(void *data, const char *name,
				const char *filename, char *buf, int len,
				enum lws_spa_fileupload_states state)
{
	struct pss *pss = (struct pss *)data;
	struct lejp_ctx saictx;
	lws_dll2_owner_t owner;
	uint8_t result[64];
	int m;

	switch (state) {
	case LWS_UFS_OPEN:
		lwsl_notice("%s: LWS_UFS_OPEN\n", __func__);
		lejp_construct(&pss->ctx, sai_notification_lejp_cb,
			       pss, paths, LWS_ARRAY_SIZE(paths));

		if (lws_genhmac_init(&pss->hmac, pss->hmac_type,
				      (uint8_t *)pss->vhd->notification_key,
				      strlen(pss->vhd->notification_key))) {
			lwsl_err("%s: failed to init hmac\n", __func__);

			return -1;
		}
		break;
	case LWS_UFS_FINAL_CONTENT:
	case LWS_UFS_CONTENT:
		lwsl_notice("%s: LWS_UFS_[]CONTENT: %p %p, \n", __func__, pss, buf);
		if (len && lws_genhmac_update(&pss->hmac, buf, (unsigned int)len))
			return -1;

		printf("%.*s", (int)len, buf);

		m = lejp_parse(&pss->ctx, (uint8_t *)buf, len);
		if (m < 0 && m != LEJP_CONTINUE) {
			lwsl_notice("%s: notif JSON decode failed '%s' (%d)\n",
					__func__, lejp_error_to_string(m), m);
			return m;
		}

		lwsl_notice("%s: m = %d\n", __func__, m);

		if (m != 1)
			break;

		lws_genhmac_destroy(&pss->hmac, result);

		if (memcmp(result, pss->notification_sig,
			   lws_genhmac_size(pss->hmac_type))) {
			lwsl_err("%s: hmac mismatch\n", __func__);

			return -1;
		}
		lwsl_notice("%s: hmac OK\n", __func__);

		/*
		 * We have the notification metadata JSON parsed into pss->sn.e,
		 * eg, pss->sn->e.hash ... since it's common to, eg, push a tree
		 * in a branch and then later tag the same commit, we don't want
		 * to pointlessly repeat CI for the same tree multiple times,
		 * and need to basically dedupe.
		 */

		{
			uint64_t rid = 0;
			char qu[192];

			lws_snprintf(qu, sizeof(qu), "select rowid from events "
						     "where hash='%s'",
						     pss->sn.e.hash);

			if (sqlite3_exec(pss->vhd->server.pdb, qu,
					 sai_sql3_get_uint64_cb,
					 &rid, NULL) == SQLITE_OK && rid) {
				/* it already exists */
				lwsl_notice("%s: ignoring notification as "
					    "tree hash event exists\n",
					    __func__);

				return 0;
			}
		}

		if (!pss->sn.saifile)
			return -1;

		/*
		 * We processed the notification JSON, but we only decoded the
		 * base64'd copy of the .sai.json so far... now's the time we
		 * want to process that and break it down into tasks.
		 *
		 * We don't trust it since it's controlled by the guy who pushed
		 * the commit, there can be anything at all in there.  We made
		 * sure he can't attack us until now by base64-ing it at the
		 * server hook, so he's just dumb payload.
		 *
		 * Let's try to parse it in two passes, first without acting on
		 * the content to confirm it's going to succeed...
		 */

		sai_uuid16_create(lws_get_context(pss->wsi), pss->sn.e.uuid);
		m = sai_event_db_ensure_open(pss->vhd->context, &pss->vhd->sqlite3_cache,
				      pss->vhd->sqlite3_path_lhs, pss->sn.e.uuid, 1,
					      (sqlite3 **)&pss->sn.e.pdb);
		if (m) {
			lwsl_err("%s: XX %d unable to open event-specific database\n",
					__func__, m);

			goto saifile_bail;
		}

		pss->dry = 1;
		lejp_construct(&saictx, sai_saifile_lejp_cb, pss, saifile_paths,
			       LWS_ARRAY_SIZE(saifile_paths));
		m = lejp_parse(&saictx, (uint8_t *)pss->sn.saifile,
			       (int)pss->sn.saifile_out_pos);
		sai_event_db_close(&pss->vhd->sqlite3_cache, (sqlite3 **)&pss->sn.e.pdb);
		if (m < 0) {
			lwsl_notice("%s: saifile JSON 1 decode failed '%s' (%d)\n",
				    __func__, lejp_error_to_string(m), m);
			puts(pss->sn.saifile);
			goto saifile_bail;
		}

		/* ... then add the 32-char event object in the database ... */

		pss->sn.e.created = (unsigned long long)lws_now_secs();
		pss->sn.e.state = SAIES_WAITING;

		memset(&pss->sn.e.list, 0, sizeof(pss->sn.e.list));
		lws_dll2_owner_clear(&owner);
		lws_dll2_add_head(&pss->sn.e.list, &owner);

		/*
		 * This is our new event going into the event database...
		 */

		lws_struct_sq3_serialize(pss->vhd->server.pdb,
					 lsm_schema_sq3_map_event, &owner, 0);

		/*
		 * ... process the saifile JSON again creating tasks for each
		 * entry in the saifile, for each platform, against that event
		 * object...
		 */

		pss->dry = 0;
		lejp_construct(&saictx, sai_saifile_lejp_cb, pss, saifile_paths,
			       LWS_ARRAY_SIZE(saifile_paths));
		m = lejp_parse(&saictx, (uint8_t *)pss->sn.saifile,
			       (int)pss->sn.saifile_out_pos);
		free(pss->sn.saifile);
		pss->sn.saifile = NULL;
		if (m < 0) {
			lwsl_notice("%s: saifile JSON 2 decode failed '%s' (%d)\n",
				    __func__, lejp_error_to_string(m), m);
			puts(pss->sn.saifile);
			return m;
		}

		lwsl_notice("%s: notification inserted into db\n", __func__);

		/*
		 * The tasks are all in there but set to state
		 * NOT_READY_FOR_BUILD, the periodic central scan
		 * switch them over to WAITING when they have been like that
		 * for a short grace time (eg, 10s)
		 */

		lws_sul_schedule(pss->vhd->context, 0, &pss->vhd->sul_central,
				 sais_central_cb, 1 * LWS_US_PER_SEC);

		return 0;

saifile_bail:
		free(pss->sn.saifile);
		pss->sn.saifile = NULL;

		return -1;

	case LWS_UFS_CLOSE:
		// lwsl_info("%s: LWS_UFS_CLOSE\n", __func__);
		lejp_destruct(&pss->ctx);
		break;
	}

	return 0;
}


