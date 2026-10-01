/*
 * Sai server definitions src/server/private.h
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

#include "../common/include/private.h"
#include <sqlite3.h>
#include <sys/stat.h>

#define SAI_EVENTID_LEN 32
#define SAI_TASKID_LEN 64

/*
 * Ad-hoc interactive shell session ids (com.warmcat.sai.openshell et al):
 * the browser mints one when opening the shell and reuses it in ptydata /
 * closeshell; the server mints the same kind when the browser supplied
 * none.  Same shape as an event id: 32 hex chars.
 */
#define SAI_SHELLID_LEN 32

/*
 * The most idle tasks ("lanes") a .sai.json configuration can ask for on each
 * platform
 */
#define SAI_IDLE_LANES_MAX 16

struct sai_plat;

/* lws_wsmsg_ array for different sources */
enum {
	SAI_WEBSRV_PB__PROXIED_FROM_BUILDER,
	SAI_WEBSRV_PB__PROXIED_FROM_BUILDER_LR,
	SAI_WEBSRV_PB__LOGS,
	SAI_WEBSRV_PB__GENERATED,
	SAI_WEBSRV_PB__ACTIVITY,

	SAI_WEBSRV_PB__COUNT
};



typedef enum {
	SAI_DB_RESULT_OK,
	SAI_DB_RESULT_BUSY,
	SAI_DB_RESULT_ERROR,
} sai_db_result_t;

typedef struct sai_platm {
	lws_dll2_owner_t builder_owner;
	lws_dll2_owner_t subs_owner;
	lws_dll2_owner_t power_state_owner; /* sai_power_state_t */

	/* the list of well-known, configured resources */
	lws_dll2_owner_t resource_wellknown_owner; /* sai_resource_wellknown_t */

	/* Live PCON topology from sai-power */
	lws_dll2_owner_t power_controllers; /* sai_power_controller_t */

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

typedef struct websrvss_srv {
	struct lws_ss_handle 		*ss;
	struct vhd			*vhd;

	struct lejp_ctx			ctx;
	struct lws_buflist		*bl_srv_to_web;
	/*
	 * Reassembly of fragmented web -> server messages (eg, a taskclone
	 * carrying an edited build script), see websrvss_ws_rx()
	 */
	struct lws_buflist		*rx_reasm;
	unsigned int			viewers;

	struct lws_buflist		*private_heads[SAI_WEBSRV_PB__COUNT];
} websrvss_srv_t;

typedef struct sai_powering_up_plat {
	lws_dll2_t list;
	char name[256];
} sai_powering_up_plat_t;

typedef enum {
	SAIN_ACTION_INVALID,
	SAIN_ACTION_REPO_UPDATED
} sai_notification_action_t;

typedef struct {

	sai_event_t			e;
	sai_task_t			t;

	char				platbuild[4096];
	char				platname[96];
	char				explicit_platforms[2048];

	int				event_task_index;
	int				idle_lanes; /* per platform, this config */

	struct lws_b64state		b64;
	char				*saifile;
	uint64_t			when;
	size_t				saifile_in_len;
	size_t				saifile_out_len;
	size_t				saifile_out_pos;
	size_t				saifile_in_seen;
	sai_notification_action_t	action;

	uint8_t				nondefault;
} sai_notification_t;


typedef struct sai_builder {
	sais_t c;
} saib_t;

struct vhd;

/* a pool sync connection's state, see s-pool.c */
typedef struct sais_pool_session sais_pool_session_t;

/* an open pool db, shared by everything using it, see s-pool.c */
typedef struct sais_pool_db {
	lws_dll2_t		list;		/* vhd->pool_dbs */
	sqlite3			*pdb;
	int			refcount;
	unsigned int		live;		/* live entries */
	char			key[128];	/* "<repo>/<pool>" */
	char			repo[65];
	char			pool[33];
} sais_pool_db_t;

struct pss {
	struct vhd		*vhd;
	struct lws		*wsi;

	struct lws_spa		*spa;
	struct lejp_ctx		ctx;
	sai_notification_t	sn;
	struct lws_dll2		same; /* owner: vhd.builders */

	struct lws_buflist	*onward_reassembly;
	struct lws_buflist	*power_rx_cache;

	sqlite3			*pdb_artifact;
	sqlite3_blob		*blob_artifact;

	sais_pool_session_t	*pool; /* it's a pool sync connection */

	lws_dll2_owner_t	platform_owner; /* sai_platform_t builder offers */
	lws_dll2_owner_t	task_cancel_owner; /* sai_platform_t builder offers */
	lws_dll2_owner_t	rebuild_owner;
	lws_dll2_owner_t	stay_owner;
	lws_dll2_owner_t	pcon_control_owner;
	lws_dll2_owner_t	openshell_owner;
	lws_dll2_owner_t	ptydata_owner;
	lws_dll2_owner_t	aft_owner; /* for statefully spooling artifact info */
	lws_dll2_owner_t	res_owner; /* sai_resource_requisition_t
					    * owner of resource objects related
					    * to this pss */
	lws_dll2_owner_t	res_pending_reply_owner; /* sai_resource_msg_t
							  * resource JSON return
							  * messages to builder */
	lws_dll2_owner_t	viewer_state_owner;
	lws_struct_args_t	a;
	struct lejp_ctx		ctx_power;

	/* link auth state: parse of the first ws message from the peer */
	struct lejp_ctx		auth_ctx;

	const char		*server_name;

	struct lwsac		*query_ac;
	struct lwsac		*logs_ac;
	lws_dll2_owner_t	issue_task_owner; /* list of sai_task_t */
	const sai_task_t	*one_task; /* only for browser */
	const sai_event_t	*one_event;
	lws_dll2_owner_t	query_owner;
	lws_dll2_t		*walk;

	sai_task_t		alloc_task;
	struct lwsac		*ac_alloc_task;

	char			peer_ip[48];
	char			last_power_report[8192];

	int			task_index;
	int			log_cache_index;
	int			log_cache_size;
	int			authorized;
	int			specificity;
	unsigned long		expiry_unix_time;

	/* notification hmac information */
	char			notification_sig[128];
	struct lws_genhmac_ctx	hmac;
	enum lws_genhmac_types	hmac_type;
	char			our_form;

	uint64_t		first_log_timestamp;
	uint64_t		artifact_offset;
	uint64_t		artifact_length;

	unsigned int		spa_failed:1;
	unsigned int		subsequent:1; /* for individual JSON */
	unsigned int		dry:1;
	unsigned int		frag:1;
	unsigned int		mark_started:1;
	unsigned int		wants_event_updates:1;
	unsigned int		announced:1;
	unsigned int		bulk_binary_data:1;
	unsigned int		is_power:1;
	unsigned int		link_authed:1;
	unsigned int		auth_secret_ok:1;

	uint8_t			ovstate; /* SOS_ substate when doing overview */
};

typedef struct sais_plat {
	lws_dll2_t	list;
	const char	*plat;
	char		busy;
	int		pending_count;
	int		unmet_count;
} sais_plat_t;

/*
 * Server's record of a builder platform's idle task budget, see s-idle.c.  It's
 * kept by name, since it has to outlive the builder being disconnected.
 */
typedef struct sais_idle_budget {
	lws_dll2_t	list;		/* vhd->idle_budgets */
	lws_usec_t	debt_us;	/* rest owed before the next slice */
	lws_usec_t	last_tick;
	lws_usec_t	period_start;	/* 0, or when its slices began */
	unsigned int	share;		/* % of idle time for idle tasks */
	unsigned int	instances;	/* concurrent idle tasks */
	unsigned int	slice_secs;
	char		name[96];	/* builder.platform, as sai_plat_t .name */
	char		platform[96];
} sais_idle_budget_t;

/* a platform on an event whose lanes are the ones to run for its ref */
typedef struct sais_idle_host {
	lws_dll2_t	list;		/* vhd->idle_hosts */
	char		event_uuid[33];
	char		platform[96];
	int		free_lanes;	/* lanes not running a slice */
} sais_idle_host_t;

typedef struct sai_shell_session {
	lws_dll2_t	list;
	char		task_uuid[65];
	char		builder_name[96];
	lws_dll2_owner_t ptydata_owner;
} sai_shell_session_t;

struct vhd {
	struct lws_context	*context;
	struct lws_vhost	*vhost;

	sais_t			server;

	struct lws_ss_handle	*h_ss_websrv; /* server */

	/* pss lists */
	struct lws_dll2_owner	builders;
	struct lws_dll2_owner	sai_powers;
	struct lws_dll2_owner	pending_plats;
	lws_dll2_owner_t	powering_up_list; /* sai_powering_up_plat_t */
	lws_dll2_owner_t	shell_sessions; /* sai_shell_session_t */

	struct lwsac		*ac_plats;

	const char		*sqlite3_path_lhs;
	sqlite3			*pdb_metrics;

	lws_dll2_owner_t	sqlite3_cache; /* sais_sqlite_cache_t */
	lws_dll2_owner_t	tasklog_cache;
	lws_sorted_usec_list_t	sul_logcache;
	lws_sorted_usec_list_t	sul_central; /* background task allocation sul */
	lws_sorted_usec_list_t	sul_activity; /* activity broadcast sul */
	lws_sorted_usec_list_t	sul_gc_events; /* incremental GC of deleted events */
	lws_sorted_usec_list_t	sul_watcher; /* generic async service watcher sul */
 
	lws_dll2_owner_t	watcher_services; /* sai_watcher_service_t from config */

	/* findings, see s-findings.c */
	const char		*findings_notify; /* mail new findings to */
	const char		*findings_from;
	const char		*findings_url; /* sai-web, for links in mail */
	lws_usec_t		findings_last_retry;
	char			findings_reset_done;

	/* pools, see s-pool.c */
	lws_dll2_owner_t	pool_dbs; /* sais_pool_db_t, open pool dbs */
	lws_dll2_owner_t	pool_conns; /* pss of pool sync connections */

	/* idle tasks, see s-idle.c */
	lws_dll2_owner_t	idle_budgets; /* sais_idle_budget_t */
	lws_dll2_owner_t	idle_hosts; /* sais_idle_host_t in ac_idle_hosts */
	struct lwsac		*ac_idle_hosts;
	lws_usec_t		idle_hosts_refreshed;
	char			idle_hosts_stale;

	lws_usec_t		last_check_abandoned_tasks;

	const char		*notification_key;
	const char		*link_key; /* fleet secret builders / sai-power auth with */
	const char		*websrv_sockpath; /* control link uds we serve */
	unsigned int		task_abandoned_timeout_mins;

	/*
	 * Only honor the X-Forwarded-For header for source_ip attribution when
	 * the operator explicitly set "trust-x-forwarded-for" in the vhost pvo
	 * (i.e. sai-server is behind a trusted reverse proxy).  Default off:
	 * use the real peer address, since XFF is trivially spoofable otherwise.
	 */
	unsigned int		trust_xff:1;

	unsigned int		browser_viewer_count;
	unsigned int		viewers_are_present:1;
};

extern const struct lws_protocols protocol_ws, protocol_ws_power;

int
sai_notification_file_upload_cb(void *data, const char *name,
				const char *filename, char *buf, int len,
				enum lws_spa_fileupload_states state);

int
sai_sq3_event_lookup(sqlite3 *pdb, uint64_t start, lws_struct_args_cb cb, void *ca);

int
sai_sql3_get_uint64_cb(void *user, int cols, char **values, char **name);

/*
 * Say something in a task's own log, as the server.  Used where we decide a
 * task's fate and the builder either cannot say why or is already gone.
 */
int
sais_task_logf(struct vhd *vhd, const char *task_uuid, const char *fmt, ...)
	LWS_FORMAT(3);

int
sais_validate_id(const char *id, int reqlen);

int
sais_buflist_append_bounded(struct lws_buflist **head, const uint8_t *buf,
			    size_t len, size_t cap);

int
sais_watcher_url_matches(const sai_watcher_service_t *s, const char *url);

int
saiw_ws_json_tx_browser(struct vhd *vhd, struct pss *pss, uint8_t *buf, size_t bl);

int
sais_ws_json_rx_builder(struct vhd *vhd, struct pss *pss, uint8_t *buf, size_t bl, unsigned int ss_flags);

int
sais_list_builders(struct vhd *vhd);

void
sais_eventchange(struct lws_ss_handle *h, const char *event_uuid, int state);

void
sais_taskchange(struct lws_ss_handle *h, const char *task_uuid, int state);

int
lws_struct_map_set(const lws_struct_map_t *map, char *u);

void
sai_task_uuid_to_event_uuid(char *event_uuid33, const char *task_uuid65);

int
sais_ws_json_tx_builder(struct vhd *vhd, struct pss *pss, uint8_t *buf, size_t bl);

int
sais_subs_request_writeable(struct vhd *vhd, const char *task_uuid);

void
sais_central_cb(lws_sorted_usec_list_t *sul);

void
sais_activity_cb(lws_sorted_usec_list_t *sul);

void
sais_central_gc_deleted_events_cb(lws_sorted_usec_list_t *sul);

sai_db_result_t
sais_task_clear_build_and_logs(struct vhd *vhd, const char *task_uuid, int from_rejection);
sai_db_result_t
sais_task_rebuild_last_step(struct vhd *vhd, const char *task_uuid);
 
void
sais_watcher_cb(lws_sorted_usec_list_t *sul);
 
int
sais_config_watchers(struct vhd *vhd, const char *config_dir);

int
sais_task_cancel(struct vhd *vhd, const char *task_uuid, int erase, int killed);

int
sais_allocate_task(struct vhd *vhd, struct pss *pss, sai_plat_t *cb,
		   const char *cns_name);

int
sais_create_and_offer_task_step(struct vhd *vhd, const char *task_uuid);

int
sais_set_task_state(struct vhd *vhd, const char *task_uuid, sai_event_state_t state,
		    uint64_t started, uint64_t duration);

int
sais_task_pause(struct vhd *vhd, const char *task_uuid);

int
sais_bind_task_to_builder(struct vhd *vhd, const char *builder_name,
			  const char *builder_uuid, const char *task_uuid);

int
sais_websrv_broadcast_REQUIRES_LWS_PRE(struct lws_ss_handle *hsrv,
				       lws_wsmsg_info_t *info);

int
sql3_get_integer_cb(void *user, int cols, char **values, char **name);

sai_resource_wellknown_t *
sais_resource_wellknown_by_name(sais_t *sais, const char *name);

void
sais_resource_wellknown_remove_pss(sais_t *sais, struct pss *pss);

void
sais_resource_check_if_can_accept_queued(sai_resource_wellknown_t *wk);

sai_resource_requisition_t *
sais_resource_lookup_lease_by_cookie(sais_t *sais, const char *cookie);

void
sais_resource_destroy_queued_by_cookie(sais_t *sais, const char *cookie);

void
sais_resource_rr_destroy(sai_resource_requisition_t *rr);

int
sais_platforms_with_tasks_pending(struct vhd *vhd);

void
sais_add_pending_plat(struct vhd *vhd, const char *name, int count, int unmet);

void
sais_idle_plat_update(struct vhd *vhd, const sai_plat_t *build);

void
sais_idle_destroy(struct vhd *vhd);

void
sais_idle_add_pending_plats(struct vhd *vhd);

int
sais_idle_allocate(struct vhd *vhd, struct pss *pss, sai_plat_t *sp);

void
sais_idle_slice_ended(struct vhd *vhd, sqlite3 *pdb, const char *task_uuid);

void
sais_idle_declined(struct vhd *vhd, sai_plat_t *sp, const char *task_uuid);

void
sais_idle_builder_gone(struct vhd *vhd, sai_plat_t *sp);

int
sais_pool_hello(struct vhd *vhd, struct pss *pss, const sai_pool_hello_t *hello);

int
sais_pool_rx(struct vhd *vhd, struct pss *pss, const uint8_t *buf, size_t len);

int
sais_pool_tx(struct vhd *vhd, struct pss *pss);

void
sais_pool_session_destroy(struct pss *pss);

void
sais_findings_received(struct vhd *vhd, sais_pool_db_t *db, const char *sub,
		       size_t sub_len, const char *name, size_t name_len,
		       const uint8_t *data, size_t len, const char *hash,
		       const char *platform);

void
sais_findings_set(struct vhd *vhd, const char *repo, const char *pool,
		  const char *group, const char *op);

void
sais_findings_notify_retry(struct vhd *vhd);

sais_pool_db_t *
sais_pool_db_get(struct vhd *vhd, const char *repo, const char *pool);

void
sais_pool_db_put(sais_pool_db_t *db);

int
sais_pool_log_entry(sais_pool_db_t *db, int ns, const char *sub,
		    size_t sub_len, const char *name, size_t name_len,
		    const uint8_t *blob, size_t len);

sai_plat_t *
sais_builder_from_uuid(struct vhd *vhd, const char *hostname);
sai_plat_t *
sais_builder_from_host(struct vhd *vhd, const char *host);

void
sais_builder_disconnected(struct vhd *vhd, struct lws *wsi);

void
sais_set_builder_power_state(struct vhd *vhd, const char *name, int up, int down);

int
sql3_get_string_cb(void *user, int cols, char **values, char **name);

int
sais_is_task_inflight(struct vhd *vhd, sai_plat_t *build, const char *uuid,
		      sai_uuid_list_t **hit);

int
sais_add_to_inflight_list_if_absent(struct vhd *vhd, sai_plat_t *sp,
				    const char *uuid, int idle);

void
sais_inflight_entry_destroy(sai_uuid_list_t *ul);
void
sais_prune_inflight_list(struct vhd *vhd);

sai_db_result_t
sais_plat_reset(struct vhd *vhd, const char *event_uuid, const char *platform);

sai_db_result_t
sais_event_delete(struct vhd *vhd, const char *event_uuid);

sai_db_result_t
sais_event_reset(struct vhd *vhd, const char *event_uuid);

sai_db_result_t
sais_event_clone_task(struct vhd *vhd, const sai_browse_rx_taskclone_t *tc);

int
sais_push_record(struct vhd *vhd, const char *repo_name, const char *ref,
		 const char *hash);

int
sais_push_lookup(struct vhd *vhd, const char *repo_name, const char *ref,
		 char *hash, size_t hash_len);

int
sais_task_build_step_count(const char *build);

int
sais_task_insert(struct lws_context *cx, sqlite3 *pdb, sai_event_t *e,
		 sai_task_t *t, int uid);

int
sai_detach_builder(struct lws_dll2 *d, void *user);

int
sai_detach_resource(struct lws_dll2 *d, void *user);

int
sai_destroy_resource_wellknown(struct lws_dll2 *d, void *user);

int
sai_pcon_destroy_cb(struct lws_dll2 *d, void *user);

void
sais_server_destroy(struct vhd *vhd, sais_t *server);

void
sais_get_task_metrics_estimates(struct vhd *vhd, sai_task_t *task);

int
sais_task_cancel(struct vhd *vhd, const char *task_uuid, int erase, int killed);

int
sais_task_stop_on_builders(struct vhd *vhd, const char *task_uuid, int killed);

sai_db_result_t
sais_task_clear_build_and_logs(struct vhd *vhd, const char *task_uuid, int from_rejection);

sai_db_result_t
sais_task_remove_all_tries(struct vhd *vhd, const char *task_uuid);

sai_db_result_t
sais_task_rebuild_last_step(struct vhd *vhd, const char *task_uuid);

int
sais_power_rx(struct vhd *vhd, struct pss *pss, uint8_t *buf,
	      size_t bl, unsigned int ss_flags);

void
sais_plat_find_jobs_cb(lws_sorted_usec_list_t *sul);

void
sais_plat_busy(sai_plat_t *sp, char set);

void
sais_websrv_broadcast_buflist(struct lws_ss_handle *hsrv, struct lws_buflist **bl);

int
sais_metrics_db_init(struct vhd *vhd);

int
sais_metrics_db_prune(struct vhd *vhd, const char *key);

int
sais_power_tx(struct vhd *vhd, struct pss *pss, uint8_t *buf, size_t bl);
