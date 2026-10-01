/*
 * Sai server definitions src/server/private.h
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

#include "../common/include/private.h"
#include <sqlite3.h>
#include <sys/stat.h>

#define SAIW_API_VERSION 4

/*
 * How many builder shells one browser connection may have open and so have
 * tracked for ptydata delivery.  Further openshell forwards still work (it
 * is the server that opens the shell), but ptydata for shells past this
 * many is not delivered back to this connection.
 */
#define SAIW_MAX_SHELLS 8

struct sai_plat;

typedef struct sai_platm {
	struct lws_dll2_owner builder_owner;
	struct lws_dll2_owner subs_owner;

	sqlite3 *pdb;
	sqlite3 *pdb_auth;
} sais_t;

typedef struct sai_platform {
	struct lws_dll2		list;

	const char		*name;
	const char		*build;

	uint8_t			nondefault;

	/* build and name over-allocated here */
} sai_platform_t;

typedef struct sai_builder {
	sais_t c;
} saib_t;

struct vhd;

enum {
	SAIM_NOT_SPECIFIC,
	SAIM_SPECIFIC_H,
	SAIM_SPECIFIC_ID,
	SAIM_SPECIFIC_TASK,
};

/* where a feed http transaction is up to, see w-rss.c */
enum {
	SAIW_RSS_IDLE,
	SAIW_RSS_PARKED,	/* held for a long poll, sending keepalives */
	SAIW_RSS_FINISHING,	/* the whole response is in rss_tx */
	SAIW_RSS_FAILED,	/* drop the connection */
};

typedef enum {
	SAI_AUTH_STATE_NOT_LOGGED_IN,
	SAI_AUTH_STATE_LOGGED_IN_NO_GRANT,
	SAI_AUTH_STATE_LOGGED_IN_GRANT_USER,   /* < :2 */
	SAI_AUTH_STATE_LOGGED_IN_GRANT_ADMIN   /* >= :2 */
} sai_auth_state_t;


struct pss {	struct vhd		*vhd;
	struct lws		*wsi;
	uint8_t			is_gitohashi:1;

	struct lws_spa		*spa;
	struct lejp_ctx		ctx;
	/*
	 * Outgoing ws tx backlog for this browser connection.  Uses the
	 * lws_buflist2 API so we can raise the per-owner sanity limit above
	 * the 2MiB lws_buflist default (a scoped sidebar overview can carry
	 * many events' worth of task data).
	 */
	struct lws_buflist2_owner	raw_tx;
	/*
	 * Reassembly of a fragmented browser -> sai-web message (eg, a
	 * taskclone carrying an edited build script), see LWS_CALLBACK_RECEIVE
	 */
	struct lws_buflist		*rx_reasm;
	struct lws_dll2			same; /* owner: vhd.browsers */

	struct lws_dll2		subs_list;

	uint64_t		sub_timestamp;
	/* highest logs.uid shipped to this browser for sub_task_uuid + sub_run */
	uint64_t		sub_uid;
	char			sub_task_uuid[65];
	int			sub_run;
	char			specific_ref[65];
	char			specific_task[65];
	char			specific_project[96];
	char			selected_event_uuid[33];
	/*
	 * One-shot hint set by com.warmcat.sai.eventinfo: when set, the next
	 * saiw_browser_queue_overview() scopes to just this event and emits its
	 * full task list (instead of the summary-only multi-event payload used
	 * for the sidebar list).  Cleared after being consumed.
	 */
	char			event_tasks_uuid[33];

	/*
	 * Runtime project + branch selection coming from the browser's
	 * sidebar (com.warmcat.sai.taskinfo overview request).  Unlike the
	 * specific_* fields above (which are pinned from the connect URL for
	 * the gitohashi /git/<project> mode), these are updated by the browser
	 * at any time and scope the overview / live pushes to its current
	 * selection.
	 */
	char			selected_project[65];
	char			selected_ref[65];

	/*
	 * task_uuids of the builder shells this browser itself opened with
	 * com.warmcat.sai.openshell; shell ptydata from the server is only
	 * queued to connections that own the shell.
	 */
	char			shell_task_uuid[SAIW_MAX_SHELLS][65];
	unsigned int		shell_count;

	sqlite3			*pdb_artifact;
	sqlite3_blob		*blob_artifact;

	/*
	 * Feed (rss.xml / rss.json) http transaction, see w-rss.c: the
	 * rendered response waiting to go out, and for a held long poll
	 * request, its place in vhd->rss_waiters, its keepalive / deadline
	 * timer, and the scope and index it is waiting on
	 */
	struct lws_buflist	*rss_tx;
	lws_dll2_t		rss_list;
	lws_sorted_usec_list_t	sul_rss;
	lws_usec_t		rss_deadline;
	char			rss_project[65];
	char			rss_branch[65];
	char			rss_fetchurl[96];
	char			rss_index[33];
	uint8_t			rss_state; /* SAIW_RSS_* */
	uint8_t			rss_json:1;
	uint8_t			rss_ka:1;

	lws_dll2_owner_t	logs_owner;
	lws_sorted_usec_list_t	sul_logcache;
	lws_sorted_usec_list_t	sul_overview;
	lws_struct_args_t	a;

	union {
		sai_plat_t	*b;
		sai_plat_owner_t *o;
	} u;
	const char		*server_name;

	lws_dll2_owner_t	sched;	/* scheduled messages */

	struct lwsac		*logs_ac;

	int			log_cache_index;
	int			log_cache_size;
	int			specificity;
	int			segment_flags;
	unsigned int		js_api_version;
	unsigned int		overview_offset;

	/* notification hmac information */
	char			notification_sig[128];
	char			alang[128];
	enum lws_genhmac_types	hmac_type;
	char			our_form;

	uint64_t		first_log_timestamp;
	uint64_t		initial_log_timestamp;
	uint64_t		initial_log_uid;
	uint64_t		artifact_offset;
	uint64_t		artifact_length;

	char			*last_bps[4];
	size_t			last_bps_len[4];

	unsigned int		spa_failed:1;
	unsigned int		dry:1;
	unsigned int		frag:1;
	unsigned int		mark_started:1;
	unsigned int		wants_event_updates:1;
	unsigned int		announced:1;
	unsigned int		bulk_binary_data:1;
	unsigned int		toggle_favour_sch:1;
	unsigned int		resolved_task_offset:1;
	unsigned int		tx_shed:1;
	uint8_t			wants_builder_info;
	sai_auth_state_t	auth_state;
};

struct vhd {
	struct lws_context		*context;
	struct lws_vhost		*vhost;

	/* pss lists */
	struct lws_dll2_owner		browsers;

	struct lws_dll2_owner		builders_owner;
	struct lwsac			*builders;

	struct lws_dll2_owner		pcons_owner;
	struct lwsac			*pcons;

	lws_dll2_owner_t		subs_owner;
	sqlite3				*pdb;
	
	lws_dll2_owner_t		watcher_services;
	
	lws_dll2_owner_t		pcon_watts_owner;
	unsigned int			power_history[150];
	int				power_history_count;
	unsigned int			max_total_power_w;

	struct lws_ss_handle		*h_ss_websrv; /* client */

	const char			*sqlite3_path_lhs;
	const char			*sockpath; /* sai-server control link uds */

	lws_dll2_owner_t		sqlite3_cache; /* sais_sqlite_cache_t */
	lws_dll2_owner_t		rss_waiters; /* pss held on long poll */
	lws_dll2_owner_t		tasklog_cache;
};

typedef struct saiw_websrv {
	struct lws_ss_handle	*ss;
	void			*opaque_data;

	lws_struct_args_t	a;
	struct lejp_ctx		ctx;
	struct lws_buflist	*wbltx;

	/*
	 * ptydata rx reassembly (see w-ws-server.c): fragments are buffered
	 * until the message completes, because only the parsed members say
	 * which browser owns the shell, and shell output must not be sent to
	 * anyone else meanwhile.  pty_dropped marks a message whose
	 * reassembly was abandoned (oversize / oom): nothing is forwarded
	 * for it.
	 */
	uint8_t			*pty_accum; /* content at + LWS_PRE */
	size_t			pty_accum_len;
	unsigned int		pty_dropped:1;
} saiw_websrv_t;


extern const struct lws_protocols protocol_ws;
extern const lws_ss_info_t ssi_saiw_websrv;

int
sai_notification_file_upload_cb(void *data, const char *name,
				const char *filename, char *buf, int len,
				enum lws_spa_fileupload_states state);

int
sai_sq3_event_lookup(sqlite3 *pdb, uint64_t start, lws_struct_args_cb cb, void *ca);

int
sai_sql3_get_uint64_cb(void *user, int cols, char **values, char **name);

int
saiw_ws_json_tx_browser(struct vhd *vhd, struct pss *pss, uint8_t *buf, size_t bl);

int
lws_struct_map_set(const lws_struct_map_t *map, char *u);

int
saiw_ws_json_rx_browser(struct vhd *vhd, struct pss *pss,
			     uint8_t *buf, size_t bl, unsigned int ss_flags);

void
sai_task_uuid_to_event_uuid(char *event_uuid33, const char *task_uuid65);

int
sais_ws_json_tx_builder(struct vhd *vhd, struct pss *pss, uint8_t *buf, size_t bl);

int
saiw_subs_request_writeable(struct vhd *vhd, const char *task_uuid);

int
saiw_event_state_change(struct vhd *vhd, const char *event_uuid);

int
saiw_subs_task_state_change(struct vhd *vhd, const char *task_uuid);

void
saiw_central_cb(lws_sorted_usec_list_t *sul);

int
saiw_get_blob(struct vhd *vhd, const char *url, sqlite3 **pdb,
	      sqlite3_blob **blob, uint64_t *length);

int
saiw_browsers_task_state_change(struct vhd *vhd, const char *task_uuid);


void
saiw_ws_broadcast_browsers_REQUIRES_LWS_PRE(struct vhd *vhd, const void *buf, size_t len,
		      enum lws_write_protocol flags);

int
saiw_ws_browser_queue_REQUIRES_LWS_PRE(struct pss *pss, const void *buf,
				       size_t len, enum lws_write_protocol flags);

void
saiw_browser_state_changed(struct pss *pss, int established);

void
saiw_pss_shell_open(struct pss *pss, const char *task_uuid);

void
saiw_pss_shell_close(struct pss *pss, const char *task_uuid);

int
saiw_pss_owns_shell(struct pss *pss, const char *task_uuid);

void
saiw_update_viewer_count(struct vhd *vhd);

int
saiw_broadcast_logs_batch(struct vhd *vhd, struct pss *pss);

int
saiw_browser_queue_overview(struct vhd *vhd, struct pss *pss);

void
saiw_event_summary_string(sqlite3 *pdb_event, const char *event_uuid,
			  char *out, size_t out_len,
			  unsigned int *p_good, unsigned int *p_bad,
			  unsigned int *p_ongoing, unsigned int *p_pending,
			  unsigned int *p_total);

int
saiw_rss_http(struct vhd *vhd, struct pss *pss, struct lws *wsi, int json);

void
saiw_rss_event_change(struct vhd *vhd);

int
saiw_rss_writeable(struct pss *pss, struct lws *wsi);

void
saiw_rss_close(struct pss *pss);

int
saiw_browser_broadcast_queue_builders(struct vhd *vhd, struct pss *pss);
int
saiw_browser_broadcast_queue_pcons(struct vhd *vhd, struct pss *pss);
int
saiw_browser_broadcast_queue_pcon_energy(struct vhd *vhd, struct pss *pss, sai_pcon_energy_report_t *energy);
void
saiw_update_global_power_history(struct vhd *vhd, sai_pcon_energy_report_t *energy);
int
saiw_browser_broadcast_queue_power_history(struct vhd *vhd, struct pss *pss);

extern const lws_struct_map_t lsm_schema_pcon_energy[];

/* w-findings.c, for admins only */

int
saiw_browser_send_findings(struct vhd *vhd, struct pss *pss);

int
saiw_browser_send_finding(struct vhd *vhd, struct pss *pss,
			  const sai_findingset_t *fs);
