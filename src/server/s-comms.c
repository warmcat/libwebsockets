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
 * The same ws interface is connected-to by builders (on path /builder), and
 * provides the query transport for browsers (on path /browse).
 *
 * There's a single server slite3 database containing events, and a separate
 * sqlite3 database file for each event, it only contains tasks and logs for
 * the event and can be deleted when the event record associated with it is
 * deleted.  This is to keep is scalable when there may be thousands of events
 * and related tasks and logs stored.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <stdio.h>
#include <fcntl.h>

#include "s-private.h"

extern const lws_struct_map_t lsm_schema_sq3_map_event[];
extern const lws_ss_info_t ssi_server;

/*
 * The vhost whose protocol instance serves the websrv control link.  All the
 * builder, power and task state sai-web sees over the link belongs to that
 * one vhd, so sai-server supports exactly one vhost carrying the
 * com-warmcat-sai protocol: a second one would bind its own link on the same
 * path, unlinking the first, and sai-web would then be talking to a vhd that
 * has no builders on it.
 */
static struct lws_vhost *sais_link_vhost;

typedef enum {
	SHMUT_NONE = -1,
	SHMUT_HOOK,
	SHMUT_BROWSE,
} sai_http_murl_t;

static const char * const well_known[] = {
	"/update-hook",
	"/sai/browse",
};

static const struct {
	const char *name;
	enum lws_genhmac_types type;
} hmac_names[] = {
	{ "sai sha256=", LWS_GENHMAC_TYPE_SHA256 },
	{ "sai sha384=", LWS_GENHMAC_TYPE_SHA384 },
	{ "sai sha512=", LWS_GENHMAC_TYPE_SHA512 },
};

/* paths of the link auth message's members we care about */
static const char * const link_auth_paths[] = { "secret" };

static signed char
sais_link_auth_lejp_cb(struct lejp_ctx *ctx, char reason)
{
	struct pss *pss = (struct pss *)ctx->user;
	struct vhd *vhd = pss->vhd;

	if (reason == LEJPCB_VAL_STR_END && ctx->path_match == 1) {
		size_t kl = strlen(vhd->link_key);

		if (strlen(ctx->buf) != kl ||
		    lws_timingsafe_bcmp(ctx->buf, vhd->link_key, (uint32_t)kl))
			/* wrong secret... kill the parse */
			return -1;

		pss->auth_secret_ok = 1;
	}

	return 0;
}

/*
 * The first ws message on a /builder or /power connection must prove the
 * fleet link secret ({"schema":"com.warmcat.sai.linkauth","secret":...}).
 * Nothing else from the peer is processed until it did: without this, any
 * internet peer that could reach the listener was a "builder", able to
 * register platforms, receive real task dispatches (with their build
 * scripts and artifact upload nonces) and forge task results.
 *
 * Returns 0 to keep waiting / on success, or -1 to drop the connection.
 */
static int
sais_link_auth_rx(struct vhd *vhd, struct pss *pss, uint8_t *buf, size_t bl,
		  unsigned int ss_flags)
{
	int n;

	if (ss_flags & LWSSS_FLAG_SOM) {
		lejp_construct(&pss->auth_ctx, sais_link_auth_lejp_cb, pss,
			       link_auth_paths,
			       LWS_ARRAY_SIZE(link_auth_paths));
		pss->auth_secret_ok = 0;
	}

	n = lejp_parse(&pss->auth_ctx, buf, (int)bl);
	if (n < 0 && n != LEJP_CONTINUE) {
		lwsl_notice("%s: link auth JSON invalid, dropping\n", __func__);
		return -1;
	}

	if (n == LEJP_CONTINUE) {
		/* the auth message is not complete yet */

		if (ss_flags & LWSSS_FLAG_EOM) {
			lwsl_notice("%s: link auth incomplete at EOM, dropping\n",
				  __func__);
			return -1;
		}

		return 0;
	}

	/* the auth JSON completed */

	if (!pss->auth_secret_ok) {
		lwsl_notice("%s: link secret mismatch, dropping\n", __func__);
		return -1;
	}

	pss->link_authed = 1;
	lwsl_notice("%s: peer authenticated on %s\n", __func__,
		    pss->is_power ? "/power" : "/builder");

	return 0;
}

int
sai_get_head_status(struct vhd *vhd, const char *projname)
{
	struct lwsac *ac = NULL;
	lws_dll2_owner_t o;
	sai_event_t *e;
	int state;

	if (lws_struct_sq3_deserialize(vhd->server.pdb, " and state != 7", "created ",
			lsm_schema_sq3_map_event, &o, &ac, 0, -1))
		return -1;

	if (!o.head)
		return -1;

	e = lws_container_of(o.head, sai_event_t, list);
	state = (int)e->state;

	lwsac_free(&ac);

	return state;
}

static int
s_callback_ws(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	    void *in, size_t len)
{
	struct vhd *vhd = (struct vhd *)lws_protocol_vh_priv_get(
				lws_get_vhost(wsi), lws_get_protocol(wsi));
	uint8_t buf[LWS_PRE + 8192], *start = &buf[LWS_PRE], *p = start,
		*end = &buf[sizeof(buf) - LWS_PRE - 1];
	struct pss *pss = (struct pss *)user;
	sai_http_murl_t mu = SHMUT_NONE;
	const char *pvo_resources, *num;
	lws_wsmsg_info_t info;
	unsigned int ssf;
	int n;

	(void)end;
	(void)p;

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT:
		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
						  lws_get_protocol(wsi),
						  sizeof(struct vhd));
		if (!vhd)
			return -1;

		vhd->context = lws_get_context(wsi);
		vhd->vhost = lws_get_vhost(wsi);

		if (sais_link_vhost) {
			lwsl_err("%s: com-warmcat-sai is already active on"
				 " vhost %s; only one sai-server vhost may"
				 " carry it (builders, hooks and the sai-web"
				 " control link all belong to that vhd)."
				 "  Remove the protocol from vhost %s\n",
				 __func__, lws_get_vhost_name(sais_link_vhost),
				 lws_get_vhost_name(vhd->vhost));
			return -1;
		}

		if (lws_pvo_get_str(in, "notification-key",
				    &vhd->notification_key)) {
			lwsl_warn("%s: notification_key pvo required\n", __func__);
			return -1;
		}

		/*
		 * The fleet-wide secret builders and sai-power daemons must
		 * present in their first ws message.  Required: without it
		 * the builder/power endpoints are unauthenticated.
		 */
		if (lws_pvo_get_str(in, "link-key", &vhd->link_key)) {
			lwsl_err("%s: link-key pvo required\n", __func__);
			return -1;
		}

		if (!lws_pvo_get_str(in, "task-abandoned-timeout-mins", &num))
			vhd->task_abandoned_timeout_mins = (unsigned int)atoi(num);
		else
			vhd->task_abandoned_timeout_mins = 8 * 60;

		/*
		 * X-Forwarded-For is only honored when explicitly opted-in.
		 * See the trust_xff comment in s-private.h.
		 */
		if (!lws_pvo_get_str(in, "trust-x-forwarded-for", &num))
			vhd->trust_xff = !strcmp(num, "1") ||
					 !strcasecmp(num, "true") ||
					 !strcasecmp(num, "yes");

		if (lws_pvo_get_str(in, "database", &vhd->sqlite3_path_lhs)) {
			lwsl_err("%s: database pvo required\n", __func__);
			return -1;
		}

		{
			const char *conf_dir = "/etc/sai/server";
			if (lws_pvo_get_str(in, "config-dir", &conf_dir)) {
				lwsl_info("%s: config-dir pvo not found, using default %s\n", __func__, conf_dir);
			}
			sais_config_watchers(vhd, conf_dir);
		}

		/*
		 * Create the listed well-known resources to be managed by the
		 * sai-server for the builders
		 */

		if (!lws_pvo_get_str(in, "resources", &pvo_resources)) {
			sai_resource_wellknown_t *wk;
			struct lws_tokenize ts;
			char wkname[32];

			wkname[0] = '\0';
			lws_tokenize_init(&ts, pvo_resources,
					  LWS_TOKENIZE_F_MINUS_NONTERM);
			do {

				ts.e = (int8_t)lws_tokenize(&ts);
				switch (ts.e) {
				case LWS_TOKZE_TOKEN_NAME_EQUALS:
					lws_strnncpy(wkname, ts.token, ts.token_len,
							sizeof(wkname));
					break;
				case LWS_TOKZE_INTEGER:

					/*
					 * Create a new well-known resource
					 */

					wk = malloc(sizeof(*wk) + strlen(wkname) + 1);
					if (!wk)
						return -1;

					memset(wk, 0, sizeof(*wk));
					wk->cx = lws_get_context(wsi);
					wk->name = (const char *)&wk[1];
					memcpy((char *)wk->name, wkname,
					       strlen(wkname) + 1);
					wk->budget = atol(ts.token);
					lwsl_notice("%s: well-known resource '%s' "
						    "initialized to %ld\n", __func__,
						    wk->name, wk->budget);
					lws_dll2_add_tail(&wk->list, &vhd->server.
							  resource_wellknown_owner);
					break;
				default:
					break;
				}
			} while (ts.e > 0);
		}

		lws_snprintf((char *)buf, sizeof(buf), "%s-events.sqlite3",
				vhd->sqlite3_path_lhs);

		if (lws_struct_sq3_open(vhd->context, (char *)buf, 1,
					&vhd->server.pdb)) {
			lwsl_err("%s: Unable to open session db %s: %s\n",
				 __func__, vhd->sqlite3_path_lhs, sqlite3_errmsg(
						 vhd->server.pdb));

			return -1;
		}

		/* the other daemon has this db open too */
		sqlite3_busy_timeout(vhd->server.pdb, SAI_SQLITE3_BUSY_TIMEOUT_MS);

		sai_sqlite3_statement(vhd->server.pdb,
				      "PRAGMA journal_mode=WAL;", "set WAL");

		if (lws_struct_sq3_create_table(vhd->server.pdb,
						lsm_schema_sq3_map_event)) {
			lwsl_err("%s: unable to create event table\n", __func__);
			return -1;
		}

		/*
		 * create_table() is "if not exists", so existing event tables
		 * lack later columns like weburl... try to add them (fails
		 * harmlessly if the column is already there)
		 */
		{
			char *err = NULL;

			sqlite3_exec(vhd->server.pdb,
				     "ALTER TABLE events ADD COLUMN weburl varchar;",
				     NULL, NULL, &err);
			if (err)
				sqlite3_free(err);

			err = NULL;
			sqlite3_exec(vhd->server.pdb,
				     "ALTER TABLE events ADD COLUMN adhoc integer;",
				     NULL, NULL, &err);
			if (err)
				sqlite3_free(err);
		}

		sai_sqlite3_statement(vhd->server.pdb, "CREATE UNIQUE INDEX IF NOT EXISTS idx_event_uuid ON events(uuid);", "create event index");

		/*
		 * The hash most recently pushed for each (repo, ref) we were
		 * notified about, including scratch "_" refs we don't CI.
		 * Ad-hoc builds resolve their target branch to a hash here.
		 */
		if (sai_sqlite3_statement(vhd->server.pdb,
			"CREATE TABLE IF NOT EXISTS pushes ("
			" repo_name varchar(64), ref varchar(64),"
			" hash varchar(64), created integer,"
			" PRIMARY KEY (repo_name, ref));",
			"create pushes table")) {
			lwsl_err("%s: unable to create pushes table\n", __func__);
			return -1;
		}

		if (lws_struct_sq3_create_table(vhd->server.pdb,
						lsm_schema_sq3_map_plat)) {
			lwsl_err("%s: unable to create builders table\n", __func__);
			return -1;
		}

 		sai_sqlite3_statement(vhd->server.pdb,
				"CREATE UNIQUE INDEX IF NOT EXISTS name_idx ON builders (name)",
				"create builder name index");

		/*
		 * Where we serve the websrv control link for sai-web... it is
		 * admin-equivalent, so it wants to be a path-based unix
		 * socket that filesystem permissions gate.  lws binds it
		 * during protocol init, before dropping privileges, and
		 * gives it the conf uid:gid with mode 0660: only that user
		 * and group can connect.  Without a conf sockpath, fall back
		 * to the legacy abstract-namespace name, which any local
		 * user can connect to.
		 */
		if (lws_pvo_get_str(in, "sockpath", &vhd->websrv_sockpath)) {
			vhd->websrv_sockpath = SAI_WEBSRV_UDS_DEFAULT;
			lwsl_warn("%s: no \"sockpath\" pvo: serving the"
				  " admin control link on abstract socket %s,"
				  " which any local user can connect to."
				  "  Set \"sockpath\" to a filesystem path"
				  " in both the sai-server and sai-web confs\n",
				  __func__, vhd->websrv_sockpath);
		} else {
			char pol[256];

			lws_snprintf(pol, sizeof(pol),
				     "{\"s\":[{\"websrv\":{\"endpoint\":\"+%s\"}}]}",
				     vhd->websrv_sockpath);

			if (lws_ss_policy_overlay(vhd->context, pol) < 0) {
				lwsl_err("%s: unable to apply sockpath %s\n",
					 __func__, vhd->websrv_sockpath);
				return -1;
			}
		}

		lwsl_notice("%s: creating server stream on %s\n", __func__,
			    vhd->websrv_sockpath);

		if (lws_ss_create(vhd->context, 0, &ssi_server, vhd,
				  &vhd->h_ss_websrv, NULL, NULL)) {
			lwsl_err("%s: failed to create secure stream\n",
				 __func__);
			return -1;
		}

		sais_link_vhost = vhd->vhost;

		lws_sul_schedule(vhd->context, 0, &vhd->sul_central,
				 sais_central_cb, 500 * LWS_US_PER_MS);

		lws_sul_schedule(vhd->context, 0, &vhd->sul_activity,
				 sais_activity_cb, 1 * LWS_US_PER_SEC);

		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		if (vhd && vhd->vhost == sais_link_vhost)
			sais_link_vhost = NULL;
		sais_server_destroy(vhd, &vhd->server);
		goto passthru;

	/*
	 * receive http hook notifications
	 */

	case LWS_CALLBACK_HTTP:

		pss->vhd = vhd;

		for (n = 0; n < (int)LWS_ARRAY_SIZE(well_known); n++) {

			size_t q = strlen(in), t = strlen(well_known[n]);
			if (q >= t && !strcmp((const char *)in + q - t, well_known[n])) {
				mu = n;
				break;
			}
		}

		pss->our_form = 0;

		// lwsl_notice("%s: HTTP: xmu = %d\n", __func__, n);

		switch (mu) {

		case SHMUT_NONE:
			goto passthru;

		case SHMUT_HOOK:
			if (!vhd)
				/* no db etc without completed protocol init */
				return -1;
			pss->our_form = 1;
			lwsl_notice("LWS_CALLBACK_HTTP: sees hook\n");
			return 0;

		default:
			lwsl_notice("%s: DEFAULT!!!\n", __func__);
			return 0;
		}


	/*
	 * Notifcation POSTs
	 */

	case LWS_CALLBACK_HTTP_BODY:

		if (!pss->our_form) {
			lwsl_notice("%s: not our form\n", __func__);
			goto passthru;
		}

		if (!vhd)
			return -1;

		/* create the POST argument parser if not already existing */

		if (!pss->spa) {
			pss->wsi = wsi;
			if (lws_hdr_copy(wsi, pss->notification_sig,
					 sizeof(pss->notification_sig),
					 WSI_TOKEN_HTTP_AUTHORIZATION) < 0) {
				lwsl_err("%s: failed to get signature hdr\n",
					 __func__);
				return -1;
			}

			/*
			 * Record the source IP of the notifier.  Prefer the
			 * real peer address; only consult X-Forwarded-For when
			 * the operator opted in via "trust-x-forwarded-for",
			 * since it is otherwise trivially spoofable.
			 */
			if (!vhd->trust_xff ||
			    lws_hdr_copy(wsi, pss->sn.e.source_ip,
					 sizeof(pss->sn.e.source_ip),
					 WSI_TOKEN_X_FORWARDED_FOR) < 0)
				lws_get_peer_simple(wsi, pss->sn.e.source_ip,
						sizeof(pss->sn.e.source_ip));

			pss->spa = lws_spa_create(wsi, NULL, 0, 1024,
					sai_notification_file_upload_cb, pss);
			if (!pss->spa) {
				lwsl_err("failed to create spa\n");
				return -1;
			}

			/* find out the hmac used to sign it */

			pss->hmac_type = LWS_GENHMAC_TYPE_UNKNOWN;
			for (n = 0; n < (int)LWS_ARRAY_SIZE(hmac_names); n++)
				if (!strncmp(pss->notification_sig,
					     hmac_names[n].name,
					     strlen(hmac_names[n].name))) {
					pss->hmac_type = hmac_names[n].type;
					break;
				}

			if (pss->hmac_type == LWS_GENHMAC_TYPE_UNKNOWN) {
				lwsl_notice("%s: unknown sig hash type\n",
						__func__);
				return -1;
			}

			/* convert it to binary */

			n = lws_hex_to_byte_array(
				pss->notification_sig + strlen(hmac_names[n].name),
				(uint8_t *)pss->notification_sig, 64);

			if (n != (int)lws_genhmac_size(pss->hmac_type)) {
				lwsl_notice("%s: notifcation hash bad length\n",
						__func__);

				return -1;
			}
		}

		/* let it parse the POST data */

		if (!pss->spa_failed &&
		    lws_spa_process(pss->spa, in, (int)len))
			/*
			 * mark it as failed, and continue taking body until
			 * completion, and return error there
			 */
			pss->spa_failed = 1;

		break;

	case LWS_CALLBACK_HTTP_BODY_COMPLETION:

		if (!pss->our_form) {
			lwsl_user("%s: no sai form\n", __func__);
			goto passthru;
		}

		if (!vhd)
			return -1;

		if (pss->spa) {
			lws_spa_finalize(pss->spa);
			lws_spa_destroy(pss->spa);
			pss->spa = NULL;
		}

		/*
		 * Inform sai-webs about notification processing, so
		 * they can update connected browsers to show the new
		 * event
		 */
		n = lws_snprintf((char *)start, sizeof(buf) - LWS_PRE,
				 "{\"schema\":\"sai-overview\"}");

		memset(&info, 0, sizeof(info));
		info.private_source_idx		= SAI_WEBSRV_PB__GENERATED;
		info.buf			= start;
		info.len			= (size_t)n;
		info.ss_flags			= LWSSS_FLAG_SOM | LWSSS_FLAG_EOM;

		if (sais_websrv_broadcast_REQUIRES_LWS_PRE(vhd->h_ss_websrv, &info) < 0)
			lwsl_warn("%s: buflist append failed\n", __func__);

		if (lws_return_http_status(wsi,
					pss->spa_failed ? HTTP_STATUS_FORBIDDEN :
							  HTTP_STATUS_OK,
							  NULL) < 0)
			return -1;

		return 0;

	/*
	 * ws connections from builders
	 */

	case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
		/*
		 * If PROTOCOL_INIT failed on this vhost (eg, it has the
		 * protocol bound but not the pvo set), lws frees the vhd
		 * yet keeps serving the protocol here: refuse the upgrade
		 * instead of letting a connection in that can only be torn
		 * down half-established.
		 */
		if (!vhd) {
			lwsl_wsi_err(wsi, "refusing conn: protocol init failed"
					" on this vhost\n");
			return -1;
		}
		return 0;

	case LWS_CALLBACK_ESTABLISHED:
		pss->wsi = wsi;
		pss->vhd = vhd;

		if (!vhd)
			return -1;

		if (lws_hdr_total_length(wsi, WSI_TOKEN_GET_URI)) {
			if (lws_hdr_copy(wsi, (char *)start, 64, WSI_TOKEN_GET_URI) < 0)
				return -1;
		}
#if defined(LWS_ROLE_H2)
		else
			if (lws_hdr_copy(wsi, (char *)start, 64, WSI_TOKEN_HTTP_COLON_PATH) < 0)
				return -1;
#endif

		if (!memcmp((char *)start, "/sai", 4))
			start += 4;

		if (!strcmp((char *)start, "/builder")) {
			lwsl_info("%s: ESTABLISHED: builder\n", __func__);
			pss->wsi = wsi;

			lws_get_peer_simple(wsi, pss->peer_ip, sizeof(pss->peer_ip));

			/*
			 * this adds our pss part, but not the logical builder
			 * yet, until we get the ws rx
			 */
			lws_dll2_add_head(&pss->same, &vhd->builders);

			/*
			 * If viewers are already present, tell this new builder to
			 * start reporting immediately.
			 */
			if (vhd->viewers_are_present) {
				sai_viewer_state_t *vsend = calloc(1, sizeof(*vsend));
				if (vsend) {
					vsend->viewers = 1; /* true */
					lws_dll2_add_tail(&vsend->list, &pss->viewer_state_owner);
					lws_callback_on_writable(pss->wsi);
				}
			}
			break;
		}

		if (!strcmp((char *)start, "/power")) {
			lwsl_notice("%s: ESTABLISHED: power connection\n", __func__);
			pss->is_power = 1;
			lws_dll2_add_head(&pss->same, &vhd->sai_powers);
			sais_platforms_with_tasks_pending(vhd);
			break;
		}

		lwsl_err("%s: unknown URL '%s'\n", __func__, start);

		return -1;

	case LWS_CALLBACK_CLOSED:
		/*
		 * This can also arrive for wsis that were never established
		 * as a builder or power conn, eg on a vhost where protocol
		 * init failed, or one dropped at the ESTABLISHED URL checks.
		 * Those were never added to a vhd conn list and have no
		 * teardown state, and may not even be in a ws condition:
		 * asking about the peer's close payload dereferences wsi->ws,
		 * which only exists on a conn that got that far.
		 */
		if (!pss || lws_dll2_is_detached(&pss->same))
			break;

		lwsac_free(&pss->query_ac);

		/* a conn closed mid-message must not leak its reassembly */
		lws_buflist_destroy_all_segments(&pss->power_rx_cache);
		lws_buflist_destroy_all_segments(&pss->onward_reassembly);

		{
			const unsigned char *cp = lws_get_close_payload(wsi);
			int clen = lws_get_close_length(wsi);
			if (clen)
				lwsl_wsi_user(wsi, "#### sai-server: CLOSED builder conn (reason: %.*s) ####", clen, cp);
			else
				lwsl_wsi_user(wsi, "#### sai-server: CLOSED builder conn (no close payload) ####");
		}
		/* remove pss from vhd->builders (active connection list) */
		lws_dll2_remove(&pss->same);

		sais_builder_disconnected(vhd, wsi);

		sais_resource_wellknown_remove_pss(&pss->vhd->server, pss);

		if (pss->blob_artifact) {
			sqlite3_blob_close(pss->blob_artifact);
			pss->blob_artifact = NULL;
		}

		if (pss->pdb_artifact) {
			sai_event_db_close(&pss->vhd->sqlite3_cache, &pss->pdb_artifact);
			pss->pdb_artifact = NULL;
		}

		/*
		 * Update the sai-webs about the builder removal, so they
		 * can update their connected browsers
		 */
		sais_list_builders(vhd);
		break;

	case LWS_CALLBACK_RECEIVE:

		if (!vhd)
			return -1;

		pss->wsi = wsi;
		ssf = (lws_is_first_fragment(wsi) ? LWSSS_FLAG_SOM : 0) |
                      (lws_is_final_fragment(wsi) ? LWSSS_FLAG_EOM : 0);

		lws_validity_confirmed(wsi);

		/*
		 * A ws client sent us something... it could be a builder or
		 * it could be sai-power. We can tell which by the `is_power`
		 * flag we set in the pss during ESTABLISHED.
		 *
		 * Either way, until it proved the link secret in its first
		 * message, nothing else it sends is processed.
		 */

		if (!pss->link_authed) {
			if (sais_link_auth_rx(vhd, pss, in, len, ssf) < 0)
				return -1;
			break;
		}

		if (pss->is_power) {
			if (sais_power_rx(vhd, pss, in, len, ssf)) {
				lwsl_err("%s: sais_power_rx returned error, dropping connection\n",
					 __func__);
				return -1;
			}
			break;
		}

		/*
		 * This is a message from a builder
		 */

		// lwsl_wsi_notice(wsi, "rx from builder, len %d, : ss_flags: %d\n", (int)len, ssf);

		if (sais_ws_json_rx_builder(vhd, pss, in, len, ssf)) {
			lwsl_err("%s: sais_ws_json_rx_builder returned error, dropping connection\n", __func__);
			return -1;
		}

		if (!pss->announced) {
			/*
			 * Update the sai-webs about the builder creation, so
			 * they can update their connected browsers
			 */
			sais_list_builders(vhd);

			pss->announced = 1;
		}
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		if (!vhd) {
			lwsl_notice("%s: no vhd\n", __func__);
			break;
		}

		if (pss->is_power || pss->stay_owner.head)
			return sais_power_tx(vhd, pss, buf, sizeof(buf));

		int ret = sais_ws_json_tx_builder(vhd, pss, buf, sizeof(buf));
		if (ret != 0) {
			lwsl_err("%s: sais_ws_json_tx_builder returned %d, dropping connection\n", __func__, ret);
		}
		return ret;

	default:
passthru:
			break;
	}

	int dummy_ret = lws_callback_http_dummy(wsi, reason, user, in, len);
	if (dummy_ret != 0 && reason != LWS_CALLBACK_CLOSED && reason != LWS_CALLBACK_WSI_DESTROY) {
		lwsl_err("%s: dummy returned %d for reason %d, dropping connection\n", __func__, dummy_ret, reason);
	}
	return dummy_ret;
}

const struct lws_protocols protocol_ws = {
	.name = "com-warmcat-sai",
	.callback = s_callback_ws,
	.per_session_data_size = sizeof(struct pss),
	.rx_buffer_size = 0,
};

static int
sais_config_watchers_cb(const char *dirpath, void *opaque, struct lws_dir_entry *lde)
{
	struct vhd *vhd = (struct vhd *)opaque;
	char path[256], *buf;
	sai_watcher_conf_t *wc;
	struct lwsac *ac = NULL;
	lws_dll2_owner_t o;
	int n, fd;
	struct stat st;
	struct lejp_ctx ctx;
	lws_struct_args_t args;

	memset(&o, 0, sizeof(o));

	if (lde->type != LDOT_FILE || !strstr(lde->name, ".json"))
		return 0;

	lws_snprintf(path, sizeof(path), "%s/%s", dirpath, lde->name);
	lwsl_notice("%s: parsing %s for watchers\n", __func__, path);

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return 0;

	if (fstat(fd, &st)) {
		close(fd);
		return 0;
	}

	buf = malloc((size_t)st.st_size);
	if (!buf) {
		close(fd);
		return 0;
	}

	if (read(fd, buf, (size_t)st.st_size) != (ssize_t)st.st_size) {
		free(buf);
		close(fd);
		return 0;
	}
	close(fd);

	memset(&args, 0, sizeof(args));
	args.map_st[0] = lsm_watcher_conf;
	args.map_entries_st[0] = LWS_ARRAY_SIZE(lsm_watcher_conf);
	args.dest = &o;
	args.dest_len = sizeof(o);

	lws_struct_json_init_parse(&ctx, lws_struct_default_lejp_cb, &args);
	n = lejp_parse(&ctx, (const uint8_t *)buf, (int)st.st_size);
	lejp_destruct(&ctx);
	ac = args.ac;

	free(buf);

	if (n < 0 || !o.head) {
		lwsac_free(&ac);
		return 0;
	}

	wc = lws_container_of(o.head, sai_watcher_conf_t, watchers);

	/* Move the parsed watcher services to our vhd list */
	lws_start_foreach_dll_safe(struct lws_dll2 *, p, p1, wc->watchers.head) {
		sai_watcher_service_t *ws = lws_container_of(p,
						sai_watcher_service_t, list);

		lwsl_notice("%s: added watcher service '%s'\n", __func__,
			    ws->name);
		lws_dll2_remove(&ws->list);
		lws_dll2_add_tail(&ws->list, &vhd->watcher_services);

	} lws_end_foreach_dll_safe(p, p1);

	lwsac_free(&ac);

	return 0;
}

int
sais_config_watchers(struct vhd *vhd, const char *config_dir)
{
	char path[256];

	lws_snprintf(path, sizeof(path), "%s/conf.d", config_dir);
	lwsl_notice("%s: scanning %s\n", __func__, path);

	return lws_dir(path, vhd, sais_config_watchers_cb);
}
