/*
 * Sai power definitions src/power/b-private.h
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

#ifndef SAI_POWER_P_PRIVATE_H
#define SAI_POWER_P_PRIVATE_H

#include "../common/include/private.h"

#include <sys/stat.h>
#if defined(WIN32)
#include <direct.h>
#define read _read
#define open _open
#define close _close
#define write _write
#define mkdir(x,y) _mkdir(x)
#define rmdir _rmdir
#define unlink _unlink
#define HAVE_STRUCT_TIMESPEC
#if defined(pid_t)
#undef pid_t
#endif
#endif
#include <pthread.h>

#define SAI_POWERDOWN_HOLDOFF_US	(50 * LWS_US_PER_SEC)

typedef struct tasmota_parse {
	tasmota_data_t		td;
	struct lws_tokenize	ts;
	uint16_t		match;
	uint8_t			s;
} tasmota_parse_t;

struct saip_pcon;

typedef struct saip_pcon {
	struct lws_dll2		list; /* sai_power.sai_pcon_owner */

	/* List of builders registered to this PCON (dynamic) */
	lws_dll2_owner_t	registered_builders_owner; /* saip_builder_t */

	lws_sorted_usec_list_t	sul_delay_off;

	struct saip_pcon	*parent; /* if we depend on another pcon */
	const char		*depends_on; /* name from config */

	const char		*name;
	const char		*type;
	const char		*url;
	const char		*mac; /* For WOL */

	char			url_on[128];
	char			url_off[128];
	char			url_monitor[128];

	struct lws_ss_handle	*ss_tasmota_on;
	struct lws_ss_handle	*ss_tasmota_off;
	struct lws_ss_handle	*ss_tasmota_monitor;

	tasmota_data_t		latest_data;
	lws_usec_t		last_monitor_time;

	/* For RX accumulation */
	char			monitor_rx_buf[4096];
	size_t			monitor_rx_pos;

	char			on;
	char			user_keep_on; /* user asked to keep this PCON on via UI */
	char			server_requested_on; /* server requested stay for jobs */
	char			needed; /* transiently set by deps analysis */
} saip_pcon_t;

/* Represents a builder connected to us */
typedef struct saip_builder {
	struct lws_dll2		list; /* in saip_pcon.registered_builders_owner */
	lws_dll2_owner_t	platforms_owner; /* saip_builder_platform_t */

	char			name[64];

	/* The websocket wsi for this builder connection (if connected) */
	struct lws		*wsi;
} saip_builder_t;

typedef struct saip_builder_platform {
	lws_dll2_t		list;
	char			name[64];
} saip_builder_platform_t;


struct saip_ws_pss;

typedef struct saip_server {
	lws_dll2_t		list;

	/* Removed sai_plat_owner as sai-power no longer manages platforms directly */
	/* lws_dll2_owner_t	sai_plat_owner; */

	struct lws_ss_handle	*ss;

	const char		*url;
	const char		*name;
} saip_server_t;

/*
 * This represents this power process as a whole
 */

struct sai_power {
	lws_dll2_owner_t	sai_server_owner; /* servers we connect to */

	lws_dll2_owner_t	sai_pcon_owner; /* saip_pcon_t */

	struct lwsac		*ac_conf_head;
	struct lws_context	*context;
	struct lws_vhost	*vhost;

	lws_sorted_usec_list_t	sul_idle;
	lws_sorted_usec_list_t	sul_pcon_check; /* periodic check for cold start */
	lws_sorted_usec_list_t	sul_monitor; /* periodic energy monitoring */

	const char		*power_off;

	const char		*wol_if;

	const char		*bind;		/* listen socket binding */
	const char		*perms;		/* user:group */

	const char		*port;		/* port we listen on */
};


struct jpargs {
	struct sai_power	*power;

	saip_server_t		*sai_server;
	saip_pcon_t		*sai_pcon;

	sai_plat_server_ref_t	*mref;

	int			next_server_index;
	int			next_plat_index;
};

LWS_SS_USER_TYPEDEF
        char                    payload[200];
        size_t                  size;
        size_t                  pos;

	struct lws_buflist	*bl_pwr_to_srv;
} saip_server_link_t;


extern struct sai_power power;
extern const lws_ss_info_t ssi_saip_server_link_t, ssi_saip_smartplug_t;
extern const struct lws_protocols protocol_com_warmcat_sai;
extern struct lws_spawn_piped *lsp_wol;
int
saip_config_global(struct sai_power *power, const char *d);
extern int saip_config(struct sai_power *power, const char *d);
extern void saip_config_destroy(struct sai_power *power);
extern void
saip_notify_server_power_state(const char *pcon_name, int up, int down);

void
saip_set_stay(const char *pcon_name, int stay_on);
int
saip_queue_stay_info(saip_server_t *sps);

int
saip_queue_energy_report(saip_server_t *sps);

saip_pcon_t *
saip_pcon_by_name(struct sai_power *power, const char *name);

saip_pcon_t *
saip_pcon_create(struct sai_power *power, const char *name);

int
saip_parse_tasmota_status(tasmota_parse_t *tp);

void
saip_ss_create_tasmota(void);

void
saip_pcon_start_check(void);

void
saip_switch(saip_pcon_t *pc, int on);

/* Handler for builder WS connections */
int
callback_builder(struct lws *wsi, enum lws_callback_reasons reason,
                 void *user, void *in, size_t len);

#endif

saip_pcon_t *
find_pcon_by_builder_name(struct sai_power *pwr, const char *builder_name);

void
saip_builder_bringup(saip_server_t *sps, saip_pcon_t *pc);
