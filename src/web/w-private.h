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

#define SAIW_API_VERSION 3

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

struct pss {
	struct vhd		*vhd;
	struct lws		*wsi;

	struct lws_spa		*spa;
	struct lejp_ctx		ctx;
	struct lws_buflist	*raw_tx;
	struct lws_dll2		same; /* owner: vhd.browsers */

	struct lws_dll2		subs_list;

	uint64_t		sub_timestamp;
	char			sub_task_uuid[65];
	char			specific_ref[65];
	char			specific_task[65];
	char			specific_project[96];
	char			auth_user[33];

	sqlite3			*pdb_artifact;
	sqlite3_blob		*blob_artifact;

	lws_dll2_owner_t	logs_owner;
	lws_sorted_usec_list_t	sul_logcache;
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
	int			authorized;
	int			specificity;
	int			segment_flags;
	unsigned int		js_api_version;
	unsigned long		expiry_unix_time;

	/* notification hmac information */
	char			notification_sig[128];
	char			alang[128];
	struct lws_genhmac_ctx	hmac;
	enum lws_genhmac_types	hmac_type;
	char			our_form;
	char			login_form;

	uint64_t		first_log_timestamp;
	uint64_t		initial_log_timestamp;
	uint64_t		artifact_offset;
	uint64_t		artifact_length;

	unsigned int		spa_failed:1;
	unsigned int		dry:1;
	unsigned int		frag:1;
	unsigned int		mark_started:1;
	unsigned int		wants_event_updates:1;
	unsigned int		announced:1;
	unsigned int		bulk_binary_data:1;
	unsigned int		toggle_favour_sch:1;
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

	/* our keys */
	struct lws_jwk			jwt_jwk_auth;
	char				jwt_auth_alg[16];
	const char			*jwt_issuer;
	const char			*jwt_audience;

	lws_dll2_owner_t		web_to_srv_owner;
	lws_dll2_owner_t		subs_owner;
	sqlite3				*pdb;
	sqlite3				*pdb_auth;

	struct lws_ss_handle		*h_ss_websrv; /* client */

	const char			*sqlite3_path_lhs;

	lws_dll2_owner_t		sqlite3_cache; /* sais_sqlite_cache_t */
	lws_dll2_owner_t		tasklog_cache;
};

typedef struct saiw_websrv {
	struct lws_ss_handle		*ss;
	void				*opaque_data;

	lws_struct_args_t		a;
	struct lejp_ctx			ctx;
	struct lws_buflist		*wbltx;
} saiw_websrv_t;


extern struct lws_context *
sai_lws_context_from_json(const char *config_dir,
			  struct lws_context_creation_info *info,
			  const struct lws_protocols **pprotocols,
			  const char *pol);
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
saiw_task_cancel(struct vhd *vhd, const char *task_uuid);

int
saiw_get_blob(struct vhd *vhd, const char *url, sqlite3 **pdb,
	      sqlite3_blob **blob, uint64_t *length);

int
saiw_browsers_task_state_change(struct vhd *vhd, const char *task_uuid);


void
saiw_ws_broadcast_browsers_REQUIRES_LWS_PRE(struct vhd *vhd, const void *buf, size_t len,
		      enum lws_write_protocol flags);

void
saiw_browser_state_changed(struct pss *pss, int established);

void
saiw_update_viewer_count(struct vhd *vhd);

int
saiw_broadcast_logs_batch(struct vhd *vhd, struct pss *pss);

int
saiw_browser_queue_overview(struct vhd *vhd, struct pss *pss);

int
saiw_browser_broadcast_queue_builders(struct vhd *vhd, struct pss *pss);
int
saiw_browser_broadcast_queue_pcons(struct vhd *vhd, struct pss *pss);


