/*
 * Sai web
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
 * This ws interface is provides the transport for browsers (on path /browse).
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
#include <sys/socket.h>

#include "w-private.h"

const lws_struct_map_t lsm_schema_map_ta[] = {
	LSM_SCHEMA (sai_task_t,	    NULL, lsm_task,    "com-warmcat-sai-ta"),
};



extern const lws_struct_map_t lsm_schema_sq3_map_event[];


typedef enum {
	SHMUT_NONE = -1,
	SHMUT_HOOK,
	SHMUT_BROWSE,
	SHMUT_STATUS,
	SHMUT_ARTIFACTS,
	SHMUT_ARTIFACTS_SAI,
	SHMUT_LOGIN,
	SHMUT_RSS,
	SHMUT_RSS_SAI,
	SHMUT_RSS_JSON,
	SHMUT_RSS_JSON_SAI
} sai_http_murl_t;

static const char * const well_known[] = {
	"/update-hook",
	"/sai/browse",
	"/status",
	"/artifacts/", /* HTTP api for accessing build artifacts */
	"/sai/artifacts/", /* same, via the /sai mount the pages live under */
	"/login",
	"/rss.xml", /* public RSS 2.0 feed of recent events, see w-rss.c */
	"/sai/rss.xml",
	"/rss.json", /* the same feed as JSON */
	"/sai/rss.json"
};

/*
 * Cap on simultaneously-connected browser wss.  Each connected browser can
 * hold a queued tx backlog of up to SAIW_BROWSER_TX_HWM bytes (w-ws-browser.c)
 * while it drains, so the count has to be bounded for worst-case memory to
 * stay bounded too.  Browsers shed at the cap simply reconnect when a slot
 * frees.
 */
#define SAIW_BROWSER_MAX_CONNS 100

/*
 * Cap on a reassembled browser -> sai-web message.  The largest legitimate
 * one is a taskclone: a 4KiB build script JSON-escaped, plus small fields.
 */
#define SAIW_BROWSER_RX_REASM_MAX 32768

int
sai_get_head_status(struct vhd *vhd, const char *projname)
{
	char esc[96], filt[192];
	struct lwsac *ac = NULL;
	lws_dll2_owner_t o;
	sai_event_t *e;
	int state;

	if (!saiw_project_visible(vhd, projname))
		/* as if we never heard of it */
		return -1;

	/*
	 * The newest event of the named project decides it.  Ad-hoc events
	 * are scratch builds seeded by an admin; they don't say anything
	 * about the state of the branch, so skip them, and deleted ones.
	 */
	lws_sql_purify(esc, projname, sizeof(esc));
	lws_snprintf(filt, sizeof(filt), " and repo_name='%s' and state != %d"
		     " and ifnull(adhoc,0)=0", esc, SAIES_DELETED);

	if (lws_struct_sq3_deserialize(vhd->pdb, filt,
				       "created ", lsm_schema_sq3_map_event,
				       &o, &ac, 0, -1))
		return -1;

	if (!o.head)
		return -1;

	e = lws_container_of(o.head, sai_event_t, list);
	state = (int)e->state;

	lwsac_free(&ac);

	return state;
}




enum enum_param_names {
	EPN_LNAME,
	EPN_LPASS,
	EPN_SUCCESS_REDIR,
};

static int
saiw_event_db_close_all_now(struct vhd *vhd)
{
	sais_sqlite_cache_t *sc;

	lws_start_foreach_dll_safe(struct lws_dll2 *, p, p1,
				   vhd->sqlite3_cache.head) {
		sc = lws_container_of(p, sais_sqlite_cache_t, list);

		lws_struct_sq3_close(&sc->pdb);
		lws_dll2_remove(&sc->list);
		free(sc);

	} lws_end_foreach_dll_safe(p, p1);

	return 0;
}

/*
 * Release any artifact-download state on pss.  saiw_get_blob() opened a
 * read-only blob on the event db and took a refcount on the cached db handle;
 * the open blob also pins a read transaction on that db (blocking WAL
 * checkpointing while it exists).  Once the artifact has gone out -- or the
 * client went away mid-stream, or the transaction is being unbound from us on
 * a keepalive connection that is moving on to a fresh transaction with a
 * fresh pss -- the blob and the db refcount must be released here.
 */
static void
saiw_close_artifact(struct pss *pss)
{
	/*
	 * lws hands the close callbacks wsi->user_space, which is NULL if the
	 * connection went away before per-session storage was allocated (eg,
	 * a wsi that never bound to a protocol, closed on error or timeout).
	 * There can be no artifact state without a pss, so nothing to do.
	 */
	if (!pss)
		return;

	if (pss->blob_artifact) {
		sqlite3_blob_close(pss->blob_artifact);
		pss->blob_artifact = NULL;
	}

	if (pss->pdb_artifact) {
		sai_event_db_close(&pss->vhd->sqlite3_cache,
				   &pss->pdb_artifact);
		pss->pdb_artifact = NULL;
	}
}

/*
 * The admin grant comes from the x-lws-login-admin header the lws-login
 * interceptor stamps in the front-end proxy.  Before honouring it, fail
 * closed on the ways that header can be anything but the interceptor's
 * verdict:
 *
 *  - more than one header of that name is ambiguous: the lws accessors
 *    return the first match, and the interceptor's anti-spoof zap only
 *    removes the first client-supplied copy, so a duplicate can survive
 *    to us with the client's value first.  Treat it as a spoof.
 *
 *  - the connection must have reached us on the unix socket the front-end
 *    proxy connects to (the documented deployment); SO_PEERCRED only
 *    succeeds for AF_UNIX peers.  A client that reached a TCP listen
 *    directly could otherwise simply send the header and self-grant.
 *    Where SO_PEERCRED doesn't exist, this check isn't available and we
 *    fall back to the duplicate check alone.
 */
static void
saiw_count_admin_hdr_cb(const char *name, int nlen, void *opaque)
{
	int *count = (int *)opaque;

	if (nlen == 18 && !strncmp(name, "x-lws-login-admin:", 18))
		(*count)++;
}

static int
saiw_admin_header_trusted(struct lws *wsi)
{
	int count = 0;

	if (lws_hdr_custom_name_foreach(wsi, saiw_count_admin_hdr_cb,
					&count) || count > 1) {
		lwsl_wsi_notice(wsi, "%d x-lws-login-admin headers, "
				 "ignoring them", count);

		return 0;
	}

#if defined(SO_PEERCRED)
	{
		/*
		 * We don't need the creds themselves, only whether the
		 * peer is reachable this way: SO_PEERCRED only succeeds
		 * for connected AF_UNIX sockets.  (struct ucred itself is
		 * not portable to every libc's feature macro set.)
		 */
		unsigned char cred[64];
		socklen_t cl = sizeof(cred);

		if (lws_get_socket_fd(wsi) < 0 ||
		    getsockopt(lws_get_socket_fd(wsi), SOL_SOCKET,
			       SO_PEERCRED, cred, &cl)) {
			lwsl_wsi_notice(wsi, "x-lws-login-admin ignored: peer "
					 "is not on the unix socket");

			return 0;
		}
	}
#endif

	return 1;
}

static int
w_callback_ws(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	    void *in, size_t len)
{
	struct vhd *vhd = (struct vhd *)lws_protocol_vh_priv_get(
				lws_get_vhost(wsi), lws_get_protocol(wsi));
	uint8_t buf[LWS_PRE + 8192], *start = &buf[LWS_PRE], *p = start,
		*end = &buf[sizeof(buf) - LWS_PRE - 1];
	struct pss *pss = (struct pss *)user;
	sai_http_murl_t mu = SHMUT_NONE;
	char projname[64];
	int n, resp, r;
	const char *cp;

	(void)end;
	(void)p;

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT:
		vhd = lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
						  lws_get_protocol(wsi),
						  sizeof(struct vhd));
		if (!vhd)
			return -1;

		lwsl_err("web-callback-ws: LWS_CALLBACK_PROTOCOL_INIT\n");
		lws_dll2_owner_clear(&vhd->watcher_services);

		vhd->context = lws_get_context(wsi);
		vhd->vhost = lws_get_vhost(wsi);

		/*
		 * sai-web needs no auth-related pvos: it takes its login state
		 * from the x-lws-login-* headers the lws-login interceptor (in
		 * the front-end lwsws) injects and the proxy forwards.  See
		 * LWS_CALLBACK_ESTABLISHED.
		 */

		if (lws_pvo_get_str(in, "database", &vhd->sqlite3_path_lhs)) {
			lwsl_err("%s: database pvo required\n", __func__);
			return -1;
		}

		/*
		 * Where to find sai-server's control link... the same
		 * "sockpath" as in sai-server's conf.  Without one, fall back
		 * to the legacy abstract-namespace name sai-server also falls
		 * back to.
		 *
		 * The streamtype is nailed_up, so lws_ss_create() connects
		 * immediately: the conf sockpath has to be overlaid on to the
		 * policy endpoint before we get there.
		 */
		if (lws_pvo_get_str(in, "sockpath", &vhd->sockpath)) {
			vhd->sockpath = SAI_WEBSRV_UDS_DEFAULT;
			lwsl_warn("%s: no \"sockpath\" pvo: connecting to"
				  " sai-server's control link on abstract"
				  " socket %s; set \"sockpath\" to the same"
				  " filesystem path in both confs\n",
				  __func__, vhd->sockpath);
		} else {
			char pol[256];

			lws_snprintf(pol, sizeof(pol),
				     "{\"s\":[{\"websrv\":{\"endpoint\":\"+%s\"}}]}",
				     vhd->sockpath);

			if (lws_ss_policy_overlay(vhd->context, pol) < 0) {
				lwsl_err("%s: unable to apply sockpath %s\n",
					 __func__, vhd->sockpath);
				return -1;
			}
		}

		lws_snprintf((char *)buf, sizeof(buf), "%s-events.sqlite3",
				vhd->sqlite3_path_lhs);

		if (lws_struct_sq3_open(vhd->context, (char *)buf, 1, &vhd->pdb)) {
			lwsl_err("%s: Unable to open session db %s: %s\n",
				 __func__, vhd->sqlite3_path_lhs, sqlite3_errmsg(
						 vhd->pdb));

			return -1;
		}

		/* the other daemon has this db open too */
		sqlite3_busy_timeout(vhd->pdb, SAI_SQLITE3_BUSY_TIMEOUT_MS);

		sai_sqlite3_statement(vhd->pdb,
				      "PRAGMA journal_mode=WAL;", "set WAL");

		if (lws_struct_sq3_create_table(vhd->pdb,
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

			sqlite3_exec(vhd->pdb,
				     "ALTER TABLE events ADD COLUMN weburl varchar;",
				     NULL, NULL, &err);
			if (err)
				sqlite3_free(err);

			err = NULL;
			sqlite3_exec(vhd->pdb,
				     "ALTER TABLE events ADD COLUMN adhoc integer;",
				     NULL, NULL, &err);
			if (err)
				sqlite3_free(err);

			err = NULL;
			sqlite3_exec(vhd->pdb,
				     "ALTER TABLE events ADD COLUMN idle integer default 0;",
				     NULL, NULL, &err);
			if (err)
				sqlite3_free(err);
		}

		sai_sqlite3_statement(vhd->pdb, "CREATE UNIQUE INDEX IF NOT EXISTS idx_event_uuid ON events(uuid);", "create event index");

		sai_sqlite3_statement(vhd->pdb,
			"CREATE TABLE IF NOT EXISTS saiweb_state (key TEXT PRIMARY KEY, val INTEGER);",
			"create saiweb_state");

		/*
		 * Which projects this vhost shows, if it doesn't show them
		 * all.  Failing here leaves the vhost without a vhd, which
		 * serves nothing, rather than serving every project.
		 */
		if (saiw_visible_init(vhd, in)) {
			lws_struct_sq3_close(&vhd->pdb);
			return -1;
		}
			
		{
			sqlite3_stmt *stmt;
			if (sqlite3_prepare_v2(vhd->pdb,
				"SELECT val FROM saiweb_state WHERE key='max_power'", -1, &stmt, NULL) == SQLITE_OK) {
				if (sqlite3_step(stmt) == SQLITE_ROW)
					vhd->max_total_power_w = (unsigned int)sqlite3_column_int(stmt, 0);
				sqlite3_finalize(stmt);
			}
		}

		/*
		 * Reach out to the sai-server part over the SS ws websrv link
		 * (nailed_up: this connects, using the sockpath overlaid above)
		 */

		if (lws_ss_create(lws_get_context(wsi), 0, &ssi_saiw_websrv, vhd,
				  &vhd->h_ss_websrv, NULL, NULL)) {
			lwsl_err("%s: failed to create SS for websrv\n",
					__func__);

			return 1;
		}

		/*
		 * The streamtype is nailed_up, so lws_ss_create() above
		 * already tried the connection and owns retrying it via
		 * the ss backoff policy... a synchronous failure there (eg,
		 * sai-server not restarted yet) is normal startup racing.
		 * Don't call lws_ss_client_connect() from init and don't
		 * fail init over the link: returning nonzero would make
		 * lws free the vhd but keep serving this vhost, leaving
		 * browsers on a dead protocol until the next sai-web
		 * restart.
		 */

		return 0;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		/* we may have failed init, and lws freed the vhd */
		if (!vhd)
			goto passthru;
		saiw_event_db_close_all_now(vhd);
		lws_struct_sq3_close(&vhd->pdb);
		saiw_visible_destroy(vhd);
		goto passthru;

	/*
	 * receive http hook notifications
	 */

	case LWS_CALLBACK_HTTP:

		if (!vhd) {
			lwsl_err("%s: NULL vhd\n", __func__);
			return -1;
		}

		resp = HTTP_STATUS_FORBIDDEN;
		pss->vhd = vhd;

		for (n = 0; n < (int)LWS_ARRAY_SIZE(well_known); n++)
			if (!strncmp((const char *)in, well_known[n],
				     strlen(well_known[n]))) {
				mu = n;
				break;
			}

		pss->our_form = 0;

		// lwsl_notice("%s: HTTP: '%s' mu = %d\n", __func__, (const char *)in, n);

		switch (mu) {

		case SHMUT_NONE:
			goto passthru;

		case SHMUT_HOOK:
			pss->our_form = 1;
			lwsl_notice("LWS_CALLBACK_HTTP: sees hook\n");
			return 0;

		case SHMUT_STATUS:
			/*
			 * in is a string like /libwebsockets/status.svg
			 */
			cp = ((const char *)in) + 7;
			while (*cp == '/')
				cp++;
			n = 0;
			while (*cp != '/' && *cp && (size_t)n < sizeof(projname) - 1)
				projname[n++] = *cp++;
			projname[n] = '\0';

			// lwsl_notice("%s: status %s\n", __func__, projname);

			r = sai_get_head_status(vhd, projname);
			if (r < 2)
				r = 2;
			n = lws_snprintf(projname, sizeof(projname),
				     "../decal-%d.svg", r);

			if (lws_http_redirect(wsi, 307,
					      (unsigned char *)projname, n,
					      &p, end) < 0)
				return -1;

			goto passthru;

		case SHMUT_ARTIFACTS:
		case SHMUT_ARTIFACTS_SAI:
			/*
			 * HTTP Bulk GET interface for artifact download
			 *
			 * [/sai]/artifacts/<taskhash>/<down_nonce>/filename
			 */
			lwsl_notice("%s: SHMUT_ARTIFACTS\n", __func__);
			pss->artifact_offset = 0;
			if (saiw_get_blob(vhd,
					  (const char *)in +
					  (mu == SHMUT_ARTIFACTS ? 11 : 15),
					  &pss->pdb_artifact,
					  &pss->blob_artifact,
					  &pss->artifact_length)) {
				lwsl_notice("%s: get_blob failed\n", __func__);
				resp = 404;
				goto http_resp;
			}

			/*
			 * Well, it seems what he wanted exists..
			 */

			if (lws_add_http_header_status(wsi, 200, &p, end))
				goto bail;
			if (lws_add_http_header_content_length(wsi,
					(unsigned long)pss->artifact_length,
					&p, end))
				goto bail;

			if (lws_add_http_header_by_token(wsi,
					WSI_TOKEN_HTTP_CONTENT_TYPE,
					(uint8_t *)"application/octet-stream",
					24, &p, end))
				goto bail;
			if (lws_finalize_write_http_header(wsi, start, &p, end))
				goto bail;

			lwsl_notice("%s: started artifact transaction %d\n", __func__,
					(int)pss->artifact_length);

			lws_callback_on_writable(wsi);
			return 0;

		case SHMUT_RSS:
		case SHMUT_RSS_SAI:
		case SHMUT_RSS_JSON:
		case SHMUT_RSS_JSON_SAI:
			r = saiw_rss_http(vhd, pss, wsi, mu == SHMUT_RSS_JSON ||
							 mu == SHMUT_RSS_JSON_SAI);
			if (r < 0)
				goto bail;
			if (!r)
				return 0;
			if (r == 1)
				goto try_to_reuse;
			resp = r;
			goto http_resp;

		default:
			lwsl_notice("%s: DEFAULT!!!\n", __func__);
			return 0;
		}

http_resp:
		if (lws_add_http_header_status(wsi, (unsigned int)resp, &p, end))
			goto bail;
		if (lws_add_http_header_content_length(wsi, 0, &p, end))
			goto bail;
		if (lws_finalize_write_http_header(wsi, start, &p, end))
			goto bail;
		goto try_to_reuse;


	case LWS_CALLBACK_HTTP_WRITEABLE:

		if (pss && pss->rss_state)
			return saiw_rss_writeable(pss, wsi);

		if (!pss || !pss->blob_artifact)
			break;

		n = lws_ptr_diff(end, start);
		if ((int)(pss->artifact_length - pss->artifact_offset) < n)
			n = (int)(pss->artifact_length - pss->artifact_offset);

		if (sqlite3_blob_read(pss->blob_artifact, start, n,
				      (int)pss->artifact_offset)) {
			lwsl_err("%s: blob read failed\n", __func__);
			return -1;
		}

		pss->artifact_offset = pss->artifact_offset + (unsigned int)n;

		if (lws_write(wsi, start, (unsigned int)n,
				pss->artifact_offset != pss->artifact_length ?
					LWS_WRITE_HTTP : LWS_WRITE_HTTP_FINAL) != n)
			return -1;

		if (pss->artifact_offset != pss->artifact_length)
			lws_callback_on_writable(wsi);
		else
			/* the last part went out, we're done with the blob */
			saiw_close_artifact(pss);

		break;

	case LWS_CALLBACK_CLOSED_HTTP:
		/* the http conn went away, eg, mid-artifact-download */

		saiw_close_artifact(pss);
		saiw_rss_close(pss);
		break;

	case LWS_CALLBACK_HTTP_DROP_PROTOCOL:
		/* the transaction is unbinding from us, drop its tx state */

		saiw_close_artifact(pss);
		saiw_rss_close(pss);
		break;

	/*
	 * Notifcation POSTs
	 */

	case LWS_CALLBACK_HTTP_BODY:

		// lwsl_notice("%s: HTTP_BODY\n", __func__);
		break;

	case LWS_CALLBACK_HTTP_BODY_COMPLETION:
		lwsl_user("%s: LWS_CALLBACK_HTTP_BODY_COMPLETION: %d\n",
			  __func__, (int)len);

		if (!pss->our_form) {
			lwsl_user("%s: no sai form\n", __func__);
			goto passthru;
		}

		/* inform the spa no more payload data coming */
		if (pss->spa)
			lws_spa_finalize(pss->spa);

		if (pss->spa) {
			lws_spa_destroy(pss->spa);
			pss->spa = NULL;
		}

		if (pss->spa_failed)
			lwsl_notice("%s: POST failed\n", __func__);

		if (lws_return_http_status(wsi,
				pss->spa_failed ? HTTP_STATUS_FORBIDDEN :
						  HTTP_STATUS_OK,
				NULL) < 0)
			return -1;
		break;

	/*
	 * ws connections from builders and browsers
	 */
		       case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
	               n = lws_hdr_copy(wsi, (char *)buf, sizeof(buf) - 1,
	                                WSI_TOKEN_GET_URI);

	               /*
	                * This protocol is for browsers on /browse... URLs.
	                * Builders connect on /builder... URLs and should be handled
	                * by sai-server. Explicitly reject them here.
	                *
	                * Returning 0 accepts the connection for this protocol.
	                * Returning non-zero rejects it.
	                */
	               if (n >= 8 && !strncmp((const char *)buf + n - 8,
	                                       "/builder", 8)) {
			       lwsl_wsi_err(wsi, "Terminating unexpected sai-web conn to /builder");
	                       return 1; /* Reject builder connections */
		       }

		       /*
			* Cap concurrent browser connections: the overview is
			* public by design, so anyone can hold wss open, and
			* each holds a bounded tx backlog while draining.  At
			* the cap, shed new connections (they retry).
			*/
		       if (vhd && vhd->browsers.count >= SAIW_BROWSER_MAX_CONNS) {
			       lwsl_wsi_notice(wsi,
				       "Shedding browser conn: at %u conns cap",
				       (unsigned int)vhd->browsers.count);
			       return 1;
		       }

		       /*
			* Security: Cross-Site WebSocket Hijacking (CSWSH).
			*
			* Browser auth here is cookie-based JWT.  A malicious page
			* visited by a logged-in user can attempt `new WebSocket(...)`
			* and the browser will auto-attach the auth cookie, which
			* would let the attacking page drive privileged operations
			* (eventdelete, taskcan, openshell, ...) as the victim.
			*
			* Mitigate by validating the Origin header when present: the
			* Origin's host:port must match the Host header of this
			* request (i.e. the site the browser believes it is talking
			* to).  Non-browser clients (no Origin) are allowed through,
			* matching lws conventions.
			*/
		       {
			       char origin[192], host[160], *ohost;
			       int olen, hlen;

			       /*
				* Only enforce when an Origin header is present
				* (browsers always send it on WS; non-browser
				* clients may omit it).  If it's present we must
				* be able to read it fully -- fail closed on
				* truncation rather than let a suspiciously long
				* Origin through uninspected.
				*/
			       if (lws_hdr_total_length(wsi, WSI_TOKEN_ORIGIN) > 0) {
				       olen = lws_hdr_copy(wsi, origin,
							   sizeof(origin) - 1,
							   WSI_TOKEN_ORIGIN);
				       if (olen <= 0) {
					       lwsl_wsi_notice(wsi,
					       "Rejecting WS: Origin present but unreadable");
					       return 1;
				       }
				       origin[olen] = '\0';
				       /*
					* Origin is scheme://host[:port]; skip to the
					* host part (after "://")
					*/
				       ohost = strstr(origin, "://");
				       ohost = ohost ? ohost + 3 : origin;

				       hlen = lws_hdr_copy(wsi, host,
							   sizeof(host) - 1,
							   WSI_TOKEN_HOST);
				       if (hlen <= 0) {
					       lwsl_wsi_notice(wsi,
					       "Rejecting WS: Origin '%s' but no Host header",
					       origin);
					       return 1;
				       }
				       host[hlen] = '\0';

				       if (strcasecmp(ohost, host)) {
					       lwsl_wsi_notice(wsi,
					       "Rejecting WS: Origin host '%s' != Host '%s'",
					       ohost, host);
					       return 1;
				       }
			       }
		       }


               return 0;
 
	case LWS_CALLBACK_ESTABLISHED:

		if (!vhd) {
			lwsl_err("%s: NULL vhd\n", __func__);
			return -1;
		}

		pss->wsi = wsi;
		pss->vhd = vhd;
		/*
		 * Raise the tx buflist sanity limit well above lws's 2MiB
		 * default: a scoped sidebar overview can carry a large number
		 * of events before the connection drains.  32MiB is plenty for
		 * the biggest event lists while still bounding memory per pss.
		 */
		pss->raw_tx.limit = 32 * 1024 * 1024;
		pss->is_gitohashi = 1;
		{
			int r = 0;
			char tbuf[96];
			while (lws_hdr_copy_fragment(wsi, tbuf, sizeof(tbuf), WSI_TOKEN_HTTP_URI_ARGS, r++) >= 0) {
				if (!strncmp(tbuf, "client=sai", 10)) {
					pss->is_gitohashi = 0;
				}
			}
		}
		pss->alang[0] = '\0';
		lws_hdr_copy(wsi, pss->alang, sizeof(pss->alang),
			     WSI_TOKEN_HTTP_ACCEPT_LANGUAGE);
		buf[0] = '\0';
		lws_hdr_copy(wsi, (char *)buf, sizeof(buf),
			     WSI_TOKEN_X_FORWARDED_FOR);

		lwsl_wsi_info(wsi, "ESTABLISHED: %s %s", (char *)buf, pss->alang);

		if (lws_hdr_total_length(wsi, WSI_TOKEN_GET_URI)) {
			if (lws_hdr_copy(wsi, (char *)start, 64,
					 WSI_TOKEN_GET_URI) < 0) {
				lwsl_wsi_err(wsi, "URI too long");
				return -1;
			}
		}
#if defined(LWS_ROLE_H2)
		else
			if (lws_hdr_copy(wsi, (char *)start, 64,
					 WSI_TOKEN_HTTP_COLON_PATH) < 0) {
				lwsl_wsi_err(wsi, "path too long");

				return -1;
			}
#endif

		/*
		 * sai does no JWT/grant validation of its own.  The lws-login
		 * interceptor (in the front-end lwsws process) authenticated
		 * this WS upgrade and stamped the cooked result as trusted
		 * headers (x-lws-login-admin: 0/1) which the proxy forwarded
		 * to us.  Read the admin flag; everything else (the action gate
		 * at w-ws-browser.c) keys off auth_state.  If the header is
		 * absent (no interceptor configured) we fail closed: not admin,
		 * and if it could be a client-supplied copy rather than the
		 * interceptor's verdict, we ignore it the same way.
		 */
		{
			char admin[8];
			int a = -1;

			pss->auth_state = SAI_AUTH_STATE_LOGGED_IN_NO_GRANT;

			if (saiw_admin_header_trusted(wsi))
				a = lws_hdr_custom_copy(wsi, admin,
							sizeof(admin),
							"x-lws-login-admin:", 18);

			if (a == 1 && admin[0] == '1')
				pss->auth_state =
					SAI_AUTH_STATE_LOGGED_IN_GRANT_ADMIN;

			lwsl_wsi_notice(wsi, "ESTABLISHED WS: x-lws-login-admin=%c (auth_state=%d)",
					a == 1 ? admin[0] : '-', (int)pss->auth_state);
		}

		if (!memcmp((char *)start, "/sai", 4))
			start += 4;

		if (!strncmp((char *)start, "/browse/specific", 16)) {
			const char *spe;

			lwsl_info("%s: ESTABLISHED: browser (specific)\n", __func__);
			pss->wsi = wsi;
			pss->specific_project[0] = '\0';
			spe = (const char *)start + 16;
			while (*spe == '/')
				spe++;
			n = 0;
			while(*spe && *spe != '/' &&
			      (size_t)n < sizeof(pss->specific_project) - 2)
				pss->specific_project[n++] = *spe++;

			pss->specific_project[n] = '\0';

			pss->specific_task[0] = '\0';
			pss->specific_ref[0] = '\0';

			{
				int r = 0;
				char tbuf[96];
				while (1) {
					if (lws_hdr_copy_fragment(wsi, tbuf, sizeof(tbuf), WSI_TOKEN_HTTP_URI_ARGS, r++) <0)
						break;
					lwsl_info("%s:    '%s'\n", __func__, tbuf);
					if (!strncmp(tbuf, "task=", 5)) {
						lws_strncpy(pss->specific_task, tbuf + 5, sizeof(pss->specific_task));
						sai_task_uuid_to_event_uuid(pss->selected_event_uuid, pss->specific_task);
						pss->specificity = SAIM_SPECIFIC_TASK;
						saiw_broadcast_logs_batch(vhd, pss);
					}
					if (!strncmp(tbuf, "h=", 2)) {
						memcpy(pss->specific_ref, "refs/heads/", 11);
						lws_strncpy(pss->specific_ref + 11, tbuf + 2,  sizeof(pss->specific_ref) - 11);
						pss->specificity = SAIM_SPECIFIC_H;
					}
					if (!strncmp(tbuf, "id=", 3)) {
						memcpy(pss->specific_ref, "refs/heads/", 11);
						lws_strncpy(pss->specific_ref + 11, tbuf + 3,  sizeof(pss->specific_ref) - 11);
						pss->specificity = SAIM_SPECIFIC_ID;
					}
				}
			}
			if (pss->specificity == SAIM_SPECIFIC_TASK)
				pss->specific_project[0] = '\0';

			if (!pss->specificity) {
				pss->specificity = SAIM_SPECIFIC_H;
					lws_strncpy(pss->specific_ref,
						"refs/heads/master",
						sizeof(pss->specific_ref));
			}

			saiw_browser_state_changed(pss, 1);

			lwsl_info("%s: spec %d, ref '%s', task '%s' \n", __func__,
					pss->specificity, pss->specific_ref, pss->specific_task);
			break;
		}

		if (!strcmp((char *)start, "/browse")) {
			lwsl_info("%s: ESTABLISHED: browser\n", __func__);
			saiw_browser_state_changed(pss, 1);
			pss->wsi = wsi;

			break;
		}

		lwsl_err("%s: unknown URL '%s'\n", __func__, start);

		return -1;

	case LWS_CALLBACK_CLOSED:

		lwsl_wsi_info(wsi, "CLOSED browse conn");
		if (!pss)
			break;
		lws_buflist2_destroy_all_segments(&pss->raw_tx);
		lws_buflist_destroy_all_segments(&pss->rx_reasm);
		saiw_browser_state_changed(pss, 0);
		lws_dll2_remove(&pss->subs_list);
		lws_sul_cancel(&pss->sul_logcache);
		lws_sul_cancel(&pss->sul_overview);

		for (n = 0; n < 4; n++) {
			if (pss->last_bps[n]) {
				free(pss->last_bps[n]);
				pss->last_bps[n] = NULL;
				pss->last_bps_len[n] = 0;
			}
		}

		lwsac_free(&pss->logs_ac);
		break;

	case LWS_CALLBACK_RECEIVE:

		if (!pss->vhd)
			pss->vhd = vhd;

		// lwsl_user("SWT_BROWSE RX: %d\n", (int)len);
		/*
		 * Browser UI sent us something on websockets.
		 *
		 * saiw_ws_json_rx_browser() parses one-shot and forwards to
		 * sai-server as a unit, so a message that arrives in several
		 * fragments (eg, a taskclone with an edited build script) is
		 * reassembled here first.  The reassembly buffer keeps LWS_PRE
		 * headroom because the forwarding path needs it.
		 */
		if (lws_is_first_fragment(wsi) && lws_is_final_fragment(wsi) &&
		    !pss->rx_reasm) {
			if (saiw_ws_json_rx_browser(vhd, pss, in, len,
						    LWSSS_FLAG_SOM |
						    LWSSS_FLAG_EOM)) {
				lwsl_wsi_err(wsi, "Closing because saiw_ws_json_rx_browser returned it");

				return -1;
			}
			break;
		}

		if (lws_is_first_fragment(wsi))
			/* new message while holding fragments: drop the old */
			lws_buflist_destroy_all_segments(&pss->rx_reasm);

		if (lws_buflist_total_len(&pss->rx_reasm) + len >
		    SAIW_BROWSER_RX_REASM_MAX) {
			lwsl_wsi_notice(wsi, "rx reassembly over size, dropping");
			lws_buflist_destroy_all_segments(&pss->rx_reasm);
			break;
		}

		if (len && lws_buflist_append_segment(&pss->rx_reasm, in,
						      len) < 0) {
			lwsl_wsi_notice(wsi, "rx reassembly oom, dropping");
			lws_buflist_destroy_all_segments(&pss->rx_reasm);
			break;
		}

		if (!lws_is_final_fragment(wsi))
			break;

		{
			size_t rl = lws_buflist_total_len(&pss->rx_reasm);
			uint8_t *reasm = malloc(LWS_PRE + rl);

			if (!reasm) {
				lws_buflist_destroy_all_segments(&pss->rx_reasm);
				break;
			}

			lws_buflist_linear_use(&pss->rx_reasm, reasm + LWS_PRE,
					       rl);
			lws_buflist_destroy_all_segments(&pss->rx_reasm);

			n = saiw_ws_json_rx_browser(vhd, pss, reasm + LWS_PRE,
						    rl, LWSSS_FLAG_SOM |
							LWSSS_FLAG_EOM);
			free(reasm);
			if (n) {
				lwsl_wsi_err(wsi, "Closing because saiw_ws_json_rx_browser returned it");

				return -1;
			}
		}

		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		if (!vhd || !pss->raw_tx.total_len)
			break;

		{
			char som, eom, rb[1200 + LWS_PRE];
			uint8_t *prb = (uint8_t *)rb + LWS_PRE;
			int used, final = 1;
			size_t fsl = lws_buflist2_next_segment_len(&pss->raw_tx, NULL);

			/*
			 * Each segment has a header containing the flags.
			 * We MUST only read it if we are at the start of the segment.
			 * If we are mid-segment, we use the cached flags.
			 */
			if (lws_buflist2_get_frag_start_or_NULL(&pss->raw_tx)) {
				/* This is just a peek to see if we HAVE a segment */
				int *pi = (int *)lws_buflist2_get_frag_start_or_NULL(&pss->raw_tx);
				int flags = *pi;

				/*
				 * fragment_use sets 'som' to true if we are at
				 * the segment start.
				 */
				used = lws_buflist2_fragment_use(&pss->raw_tx, prb, 1200, &som, &eom);
				if (!used)
					return 0;

				if (som)
					pss->segment_flags = flags;
			} else
				return 0;

			if (used < (int)fsl || (pss->segment_flags & LWS_WRITE_NO_FIN))
				final = 0;

			if (lws_write(pss->wsi, prb + ((size_t)som * sizeof(int)),
						(size_t)used  - ((size_t)som * sizeof(int)),
						(lws_ws_sending_multifragment(pss->wsi) ?
								LWS_WRITE_CONTINUATION : LWS_WRITE_TEXT) |
							(!final * LWS_WRITE_NO_FIN)) < 0) {
				lwsl_wsi_err(pss->wsi, "attempt to write %d failed", (int)used - (int)sizeof(int));

				return -1;
			}
		}

		if (pss->raw_tx.total_len)
			lws_callback_on_writable(pss->wsi);
		break;

	default:
passthru:
	//	if (!pss || !vhd)
			break;

	//	return vhd->gsp->callback(wsi, reason, pss->pss_gs, in, len);
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);

bail:
	lwsl_wsi_err(wsi, "Closing on bail");

	return 1;

try_to_reuse:
	if (lws_http_transaction_completed(wsi)) {
		lwsl_wsi_err(wsi, "Closing because transaction_completed said so");

		return -1;
	}

	return 0;
}


const struct lws_protocols protocol_ws = {
	.name = "com-warmcat-sai",
	.callback = w_callback_ws,
	.per_session_data_size = sizeof(struct pss),
	.rx_buffer_size = 0,
};
