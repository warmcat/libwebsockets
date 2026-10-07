/*
 * Sai - ./src/common/include/private.h
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
 * structs common across the various different sai daemons and tools
 */

#include <libwebsockets.h>

/*
 * lws made lejp '#' to-end-of-line comments opt-in (LEJP_FLAG_FEAT_COMMENTS);
 * .sai.json and the /etc/sai conf files document comment support, so opt
 * their parsers in.  Older lws accepted comments unconditionally.
 */
#if defined(LEJP_FLAG_FEAT_COMMENTS)
#define sai_lejp_enable_comments(_ctx) ((_ctx)->flags |= LEJP_FLAG_FEAT_COMMENTS)
#else
#define sai_lejp_enable_comments(_ctx) do { (void)(_ctx); } while (0)
#endif

#if defined(WIN32)
#define HAVE_STRUCT_TIMESPEC
#endif

//#include <sai_config_private.h>

#if defined(__linux__)
#define UDS_PATHNAME_LOGPROXY "@com.warmcat.com.saib.logproxy"
#define UDS_PATHNAME_RESPROXY "@com.warmcat.com.saib.resproxy"
#else
#define UDS_PATHNAME_LOGPROXY "/var/run/com.warmcat.com.saib.logproxy"
#define UDS_PATHNAME_RESPROXY "/var/run/com.warmcat.com.saib.resproxy"
#endif

/*
 * The sai-web <-> sai-server ss control link ("websrv").  The link is
 * admin-equivalent (eventdelete, taskreset, taskclone...), so it should be
 * served on a path-based unix socket that filesystem permissions gate: both
 * daemons take the path from the "sockpath" pvo in their lejp conf, which is
 * the single source of truth for it.
 *
 * Without a conf sockpath, both sides fall back to this abstract-namespace
 * name, which older confs relied on.  Any local uid can connect to an
 * abstract socket (F-015), so both daemons warn when they end up here.
 */
#define SAI_WEBSRV_UDS_DEFAULT "@com.warmcat.sai-websrv"

/*
 * Builders and sai-power daemons prove the fleet-wide link secret (conf
 * "link-key" on all three daemons) in the first ws message on their
 * connection to sai-server, before sai-server processes anything else from
 * them.  This is the schema name of that message.
 */
#define SAI_LINKAUTH_SCHEMA "com.warmcat.sai.linkauth"

#define SAI_BUILDER_INSTANCE_LIMIT 256

/*
 * sai-server and sai-web each hold their own connections to the same sqlite3
 * files (the events db and the per-event dbs).  Without a busy timeout, a
 * write that meets the other process's write lock fails at once with "database
 * is locked" and the data (eg, task log lines) is lost.  Wait this long for
 * the lock instead: writes are small, so contention is brief.
 */
#define SAI_SQLITE3_BUSY_TIMEOUT_MS 500

struct sai_plat;
struct sai_builder;
struct saib_opaque_spawn;

typedef enum {
	SAIES_WAITING				= 0,
	SAIES_PASSED_TO_BUILDER			= 1,
	SAIES_BEING_BUILT			= 2,
	SAIES_SUCCESS				= 3,
	SAIES_FAIL				= 4,
	SAIES_CANCELLED				= 5,
	SAIES_BEING_BUILT_HAS_FAILURES		= 6,
	SAIES_DELETED				= 7,

	SAIES_NOT_READY_FOR_BUILD		= 8,
	SAIES_STEP_SUCCESS			= 9,
	SAIES_PAUSED				= 10,
	/*
	 * An idle task's slice that was stopped by the builder, either to make
	 * way for real work or because the slice ran its length.  It's not a
	 * failure, the lane just rests until the next slice.
	 */
	SAIES_YIELDED				= 11,
} sai_event_state_t;

enum {
	SAISPRF_TIMEDOUT		= 0x1000,
	SAISPRF_TERMINATED		= 0x2000,
	SAISPRF_EXIT			= 0x8000,
	SAISPRF_SIGNALLED		= 0x4000,
	/* with SAISPRF_TERMINATED: the builder stopped an idle task's slice */
	SAISPRF_YIELDED			= 0x10000,
	/* with SAISPRF_YIELDED: ... because it ran past the end of the slice */
	SAISPRF_OVERRAN			= 0x20000,
};

typedef enum {
	SAIWS_QUEUED,
	SAIWS_ONGOING,
	SAIWS_FINISHED,
	SAIWS_FAILED
} sai_watcher_state_t;

typedef struct sai_watcher_rule {
	lws_dll2_t			list;
	const char			*label;
	const char			*prefix;
	const char			*suffix;
	const char			*anchor;
	const char			*json_path; /* optional lejp path for json payloads */
	
	uint8_t				final;
} sai_watcher_rule_t;

typedef struct sai_watcher_ui_rule {
	lws_dll2_t			list;
	const char			*label;
	const char			*key;
	int				warn_if_gt;
	int				fail_if_gt;
} sai_watcher_ui_rule_t;

typedef struct sai_watcher_service {
	lws_dll2_t			list;
	const char			*name;
	const char			*match;
	const char			*icon;
	const char			*auth_token_file; /* optional file with secret token */
	uint8_t				allow_private; /* accept private/loopback hosts */

	lws_dll2_owner_t		rules_owner; /* sai_watcher_rule_t */
	lws_dll2_owner_t		ui_owner;    /* sai_watcher_ui_rule_t */
} sai_watcher_service_t;

typedef struct sai_watcher {
	lws_dll2_t			list;
	char				service_name[32];
	char				event_hash[65];
	char				task_hash[65];
	char				url[256];
	char				metrics_json[2048]; /* scraped data */
	uint64_t			created;
	uint64_t			last_polled;
	int				state; /* sai_watcher_state_t */

	/* server side only: transient ptr to service def if available */
	const sai_watcher_service_t	*service;
	void				*vhd;
} sai_watcher_t;

typedef struct sais_sqlite_cache {
	lws_dll2_t			list;
	char				uuid[65];
	struct sqlite3			*pdb;
	lws_usec_t			idle_since;
	int				refcount;
} sais_sqlite_cache_t;

/* The top-level load report message from a builder */
typedef struct sai_active_task_info {
	lws_dll2_t			list;
	char				task_uuid[65];
	char				task_name[96];
	int				build_step;
	int				total_steps;
	unsigned int			est_peak_mem_kib;
	unsigned int			est_disk_kib;
	uint64_t			started;
	char				repo_name[64];
	char				git_hash[65];
} sai_active_task_info_t;

typedef struct sai_active_shell {
	lws_dll2_t			list;
	char				task_uuid[65];
} sai_active_shell_t;

typedef struct sai_active_shells {
	lws_dll2_owner_t		shells;
} sai_active_shells_t;

typedef struct sai_load_report {
	lws_dll2_t			list; /* For queuing on sai_plat_server */
	char				builder_name[64];
	int				core_count;
	unsigned int			initial_free_ram_kib;
	unsigned int			reserved_ram_kib;
	unsigned int			initial_free_disk_kib;
	unsigned int			reserved_disk_kib;
	unsigned int			active_steps;
	unsigned int			cpu_percent;
	lws_dll2_owner_t		active_tasks;
} sai_load_report_t;

/*
 * viewer state.
 * Sent from server -> builder.
 */
typedef struct sai_viewer_state {
	lws_dll2_t			list;        /* Not used, for schema mapping */
	unsigned int			viewers;
} sai_viewer_state_t;

typedef struct {
	lws_dll2_owner_t		watchers;
} sai_watcher_conf_t;

typedef struct sai_platform_load {
       lws_dll2_t			list;        /* Not used, for schema mapping */
       char				platform_name[128];
       lws_dll2_owner_t			loads;
} sai_platform_load_t;


struct sai_nspawn;

typedef struct sai_plat sai_plat_t;

typedef struct {
	lws_dll2_t			list; /* managed by an owner via LSM_SCHEMA_DLL2 / lsm_task */
	lws_dll2_t			pending_assign_list;

	const struct sai_event		*one_event; /* event we are associated with */

	char				platform[96];
	char				build[4096]; /* strsubst and serialized */
	char				taskname[96];
	char				packages[2048];
	char				artifacts[256];
	char				prep[4096];  /* only build is serialized */
	char				cmake[4096];  /* only build is serialized */
	char				builder[65 + 5];
	char				event_uuid[65];
	char				art_up_nonce[33];
	char				art_down_nonce[33];
	char				uuid[65];
	char				builder_name[96];
	char				cpack[512];
	char				script[4096];
	char				branches[256];

	struct lwsac			*ac_task_container;

	const char			*server_name;		/* used in offer */
	const char			*repo_name;		/* used in offer */
	const char			*git_ref;		/* used in offer */
	const char			*git_hash;		/* used in offer */
	const char			*git_repo_url;		/* used in offer */
	uint64_t			last_updated;
	uint64_t			started;
	uint64_t			duration;
	int				state;
	int				uid;
	int				build_step;
	int				build_step_count;

	/* estimations for builder resource consumption */
	unsigned int			est_peak_mem_kib;
	unsigned int			est_disk_kib;
	unsigned int			est_wallclock_ms;
	unsigned int			est_compute_ms;
	unsigned int			task_log_limit;

	int				parallel;
	char				told_ongoing;

	char				rebuildable;
	int				run;
	/*
	 * Nonzero for an idle task: a "lane" that only runs in time builders
	 * would otherwise spend idle, one slice (run) at a time, and that
	 * does not count towards its event's state.  See README-idle.md.
	 */
	int				idle;
	/*
	 * Optional name of the repo's shared pool the task works with, eg,
	 * "fuzz" for fuzzing corpora.  The builder keeps it synced with the
	 * server while the task runs.  See READMEs/README-pool.md.
	 */
	char				pool[33];
	/*
	 * Nonzero for an idle task's run that the builder had to stop
	 * because it ran past the end of its slice, so admins can see the
	 * lane needs looking at.  Like a failed run, it's kept for longer.
	 */
	int				overran;
} sai_task_t;

struct saib_logproxy {
	char				sockpath[128];
	struct sai_nspawn		*ns;
	int				log_channel_idx;
};

struct saib_resproxy {
	char				sockpath[128];
	struct sai_nspawn		*ns;
};

struct saib_pool;

struct sai_nspawn {
	char				inp[512];
	char				inp_vn[16];
	char				path[384];
	char				script_path[290];

	struct saib_logproxy		slp_control;
	struct saib_logproxy		slp[2];
	struct lws_vhost		*vhosts[3];

	lws_dll2_t			list;		/* sai_plat owner lists sai_nspawns */
	struct sai_builder		*builder;
	struct lws_fsmount		fsm;
	struct saib_opaque_spawn	*op;
	sai_task_t			*task;

	unsigned int			log_count;
	unsigned int			killed_for_spew:1;

	struct lws			*stdwsi[3];
	uint8_t				stdwsi_paused[3];

#if defined(LWS_WITH_SPAWN)
	lws_spawn_resource_us_t		res;
#endif

	lws_sorted_usec_list_t		sul_cleaner;
	lws_sorted_usec_list_t		sul_mirror;
	lws_sorted_usec_list_t		sul_task_cancel;

	/* builder: sai_artifact_t of uploads still in flight for this ns */
	lws_dll2_owner_t		artifact_owner;

	/* builder: the task's pool, if any, and waiting for it to sync */
	struct saib_pool		*pool;
	lws_dll2_t			pool_wait_list;

	sai_plat_t			*sp; /* the sai_plat */
	struct sai_plat_server		*spm; /* the sai plat / server with the ss / wsi */

	uint64_t			last_cpu_usec;
	lws_usec_t			last_cpu_usec_time;

	uint64_t			us_wallclock;
	uint64_t			us_cpu_user;
	uint64_t			us_cpu_sys;
	uint64_t			worst_mem;
	uint64_t			worst_stg;

	const char			*server_name;	/* sai-server name who triggered this, eg, 'warmcat' */
	const char			*project_name;	/* name of the git project, eg, 'libwebsockets' */
	const char			*ref;		/* remote refname, eg 'server' */
	const char			*hash;		/* remote hash */
	const char			*git_repo_url;

	int				retcode;
	int				instance_ordinal;
	int				count_artifacts;

	/*
	 * What we actually added to builder.ram_reserved_kib /
	 * disk_reserved_kib for this nspawn, so the destroy can give back
	 * exactly that and no more.  The task's estimates are not usable for
	 * that: an nspawn that failed before the reservation was made never
	 * added anything, and giving back its estimate anyway underflows the
	 * builder-wide counters (which then reject every subsequent task and
	 * make the deletion path purge job dirs).
	 */
	unsigned int			res_ram_kib;
	unsigned int			res_disk_kib;

	uint8_t				spins;
	uint8_t				state;		/* NSSTATE_ */
	uint8_t				stdcount;
	uint8_t				term_budget;

	uint8_t				retcode_set:1;
	uint8_t				idle_yield:1; /* we stopped this idle slice */
	uint8_t				idle_overran:1; /* ...it ran past its end */
	uint8_t				state_changed:1;
	uint8_t				user_cancel:1;
	uint8_t				user_killed:1;
	uint8_t				reap_cb_called:1;
	uint8_t				destroying:1;
};

/*
 * Builder is indicating he can't take the task and server should free it up
 * and try another builder.
 *
 */

enum {
	SAI_TASK_REASON_ACCEPTED  = 0,
 	SAI_TASK_REASON_DUPE	  = 1,
	SAI_TASK_REASON_BUSY	  = 2,
	SAI_TASK_REASON_DESTROYED = 3,
	/*
	 * Builder won't take the offered idle task right now, eg, because it
	 * has real work, or recently had.  Unlike BUSY, this says nothing
	 * about whether it can take real tasks.
	 */
	SAI_TASK_REASON_IDLE_DECLINED = 4,
};

typedef struct sai_rejection {
	struct lws_dll2 list;

	char				host_platform[65];
	char				task_uuid[65];
	unsigned int			avail_mem_kib;
	unsigned int			avail_sto_kib;
	unsigned int			ecode;
	unsigned int			step; /* 1-based; 0 = not given */
	unsigned char			reason;
} sai_rejection_t;

/*
 * Master is broadcasting that builders should stop work on the given task,
 * because, eg, the task was reset
 */

typedef struct sai_cancel {
	struct lws_dll2			list;
	char				task_uuid[65];
	unsigned int			erase;
	unsigned int			killed;
} sai_cancel_t;

/*
 * Browser -> sai-web -> sai-server
 *
 * Open an ad-hoc shell on a builder
 */

typedef struct sai_openshell {
	lws_dll2_t			list;
	char				builder_name[96];
	char				task_uuid[65];
} sai_openshell_t;

typedef struct sai_closeshell {
	lws_dll2_t			list;
	char				task_uuid[65];
} sai_closeshell_t;

typedef struct sai_ptydata {
	lws_dll2_t			list;
	char				builder_name[96];
	char				task_uuid[65];
	int				channel;
	char				*data;
	size_t				len;
	unsigned int			cols;
	unsigned int			rows;
} sai_ptydata_t;

/*
 * Browser is asking a builder to rebuild
 */

typedef struct sai_rebuild {
	lws_dll2_t			list;
	char				builder_name[96];
} sai_rebuild_t;

typedef struct sai_platreset {
	lws_dll2_t			list;
	char				event_uuid[65];
	char				platform[65];
} sai_browse_rx_platreset_t;

typedef struct sai_builderdelete {
	lws_dll2_t			list;
	char				builder_name[96];
} sai_browse_rx_builderdelete_t;

struct sai_event;

typedef struct sai_event {
	struct lws_dll2			list;
	char				repo_name[65];
	char				repo_fetchurl[96];
	/* optional http(s) url for browsing the repo in a web ui */
	char				repo_weburl[128];
	char				ref[65];
	char				hash[65];
	char				uuid[65];
	char				source_ip[32];
	void				*pdb; /* server only, sqlite3 */
	uint64_t			created;
	uint64_t			last_updated;
	sai_event_state_t		state;
	int				uid;
	int				sec;
	/*
	 * Nonzero for an ad-hoc event: a single-task event seeded from an
	 * existing task by an admin in the web UI, rather than created by
	 * a hook notification.  Ad-hoc events are excluded from the
	 * notification dedupe on hash, from the project head status badge and
	 * from anything else that treats "newest event" as "state of the
	 * branch".
	 */
	int				adhoc;
	/* how many idle tasks ("lanes") the event has, see sai_task_t .idle */
	int				idle;

	lws_dll2_owner_t		watcher_owner; /* sai_watcher_t */
} sai_event_t;

/*
 * One event as sai-web's public feed of recent events reports it, and the
 * feed itself, so the JSON form of the feed (rss.json) is written by sai-web
 * and read by sai-push with the same lws_struct map
 */

typedef struct sai_feed_item {
	struct lws_dll2			list;
	char				uuid[65];
	char				project[65];
	/* the ref less any refs/heads/ */
	char				branch[65];
	char				ref[65];
	char				hash[65];
	char				fetchurl[96];
	char				weburl[128];
	/* eg, "building", "succeeded", see w-rss.c */
	char				state_name[16];
	char				summary[96];
	/* unix time the notification creating the event arrived */
	uint64_t			received;
	int				state;
	int				adhoc;
	unsigned int			tasks_total;
	unsigned int			tasks_ok;
	unsigned int			tasks_bad;
	unsigned int			tasks_building;
	unsigned int			tasks_wait;
} sai_feed_item_t;

typedef struct sai_feed {
	/*
	 * Changes whenever an event joins or leaves the feed, or an event's
	 * state_name changes (but not when only task counts change)
	 */
	char				index[33];
	lws_dll2_owner_t		items; /* sai_feed_item_t */
} sai_feed_t;

typedef struct {
	struct lws_dll2			list;
	char				task_uuid[65];
	char				*log;
	uint64_t			timestamp;
	size_t				len;
	int				finished;
	int				channel;
	int				uid;

	/* builder can report this along with step completion */
	unsigned int			avail_mem_kib;
	unsigned int			avail_sto_kib;
	int				run;
	/*
	 * Nonzero if the builder said which run the log is for.  Logs from
	 * builders that don't say, and the server's own, are for the task's
	 * latest run at the time they arrive.
	 */
	unsigned int			run_given;
} sai_log_t;

typedef struct {
	struct lws_dll2			list;

	struct lws_ss_handle 		*ss;
	void				*opaque_data;

	struct sai_nspawn		*ns;
	char				task_uuid[65];
	char				artifact_up_nonce[33];
	char				artifact_down_nonce[33];
	char				blob_filename[65];
	char				path[256]; /* for unlink on completion */
	void				*blob;
	uint64_t			ofs;
	uint64_t			timestamp;
	size_t				len;
	int				uid;
	int				fd;
	char				sent_auth;
	char				sent_json;
	int				run;
} sai_artifact_t;

/* communication part of resource allocation requests */

typedef struct {
	const char			*resname;
	const char			*cookie;
	unsigned int			amount;
	unsigned int			lease;
} sai_resource_t;

typedef struct {
	lws_dll2_t			list_resource_wellknown;
	lws_dll2_t			list_resource_queued_leased;
	lws_dll2_t			list_pss;

	lws_sorted_usec_list_t		sul_expiry;

	const char			*cookie;

	time_t				requested_since_time;
	time_t				allocated_since_time;
	unsigned int			amount;
	unsigned int			lease_secs;

	/* cookie is overallocated */
} sai_resource_requisition_t;

typedef struct {
	lws_dll2_t			list;

	struct lws_context		*cx;

	/* any related resources listed here so we can get this object */
	lws_dll2_owner_t		owner; /* sai_resource_requisition_t */
	/* queue for pending requests on this resource */
	lws_dll2_owner_t		owner_queued; /* sai_resource_requisition_t */
	/* list of allocated leases */
	lws_dll2_owner_t		owner_leased; /* sai_resource_requisition_t */

	const char			*name;
	long				budget;
	long				allocated;

	/* name is overallocated */
} sai_resource_wellknown_t;

typedef struct {
	lws_dll2_t			list;
	const char			*msg;
	size_t				len;
	/* msg is overallocated */
} sai_resource_msg_t;

struct sai_plat;

/*
 * One SS per unique server the builder connects to; one of these as the SS
 * userdata object
 *
 * May be in use by multiple plats offered by same builder to same server
 */

typedef struct sai_plat_server {
	lws_dll2_t			list;

	lws_dll2_owner_t		resource_pss_list; /* so we can find the cookie */

	struct lws_buflist2_owner	bl_to_srv;

	char				resproxy_path[128];

	/* for load reporting */
	lws_sorted_usec_list_t		sul_load_report;
	unsigned int			viewer_count;

	const char			*url;
	const char			*name;

	struct lws_ss_handle 		*ss;
	void				*opaque_data;

	lws_dll2_t			*last_logging_nspawn;
	struct sai_plat			*last_logging_platform;

	int				refcount;

	int				index;  /* used to create unique build dir path */

	uint16_t			retries;
	unsigned int			tx_flags;

	char				last_msg_start[128];
	uint8_t				inside_msg;
	uint8_t				tx_corrupted;

	struct lejp_ctx			ctx;
	lws_struct_args_t		a;
} sai_plat_server_t;

struct sai_env {
	lws_dll2_t			list;

	const char			*name;
	const char			*value;
};

typedef struct sai_plat_server_ref {
	lws_dll2_t			list;
	sai_plat_server_t		*spm;
	char				was_active;
} sai_plat_server_ref_t;

/* common struct for lists of task uuids on a builder */
typedef struct sai_uuid_list {
	lws_dll2_t			list;
	lws_usec_t			us_time_listed;
	char				uuid[65];
	char				started;
	char				idle; /* server: it's an idle task */
} sai_uuid_list_t;

/*
 * One of these instantiated per platform instance
 *
 * It lists a sai_plat_server per server / ss that can use the platform
 *
 * It contains an nspawn for each platform builder instance
 *
 * It's also used as the object on server side that represents a builder /
 * platform instance and status.
 *
 *
 * Caution: about the naming, there are `builder platform triplets`, which bind
 * to the .sai.json description of the type of builder needed for particular
 * tasks.  These look like, eg:
 *
 * rocky9/x86_64-amd/gcc
 * coverity/x86_64/gcc
 *
 * and then there are `builder device names` which represent individual physical
 * builder devices which can be powered up and down.  These look like, eg
 *
 * l2
 * ubuntu_rpi4
 *
 * One builder can offer multiple different platform triplets.  In the examples
 * above, the builder l2 offers both rocky9/x86_64-amd/gcc and
 * coverity/x86_64/gcc on the same box.
 *
 * When sai-server looks for a matching builder platform triplet needed by a
 * task, it's not bothered which device it binds the job to, if more than one
 * offer the platform.  So you can have multiple builder devices offering
 * popular platforms and jobs should be shared between them.  At other times
 * sai has to disambiguate the device + platform triplet, in these cases it
 * looks like:
 *
 * l2.rocky9/x86_64-amd/gcc
 * l2.coverity/x86_64/gcc
 *
 * For power purposes, only the builder device name is considered, since we can
 * only turn the whole device on or off.  If any platform offered by the builder
 * is in use, the builder device is kept on.
 */

typedef struct sai_plat {
	lws_dll2_t			sai_plat_list;

	lws_dll2_owner_t		servers; /* list of sai_plat_server_ref_t */

	lws_sorted_usec_list_t		sul_find_jobs; /* server */

	char				peer_ip[48];

	const char			*name;
	const char			*platform;
	const char			*pcon; /* PCON name */

	struct lejp_ctx			ctx;
	lws_dll2_owner_t		nspawn_owner;
	struct lwsac			*deserialization_ac;

	struct lws_context		*cx;
	struct lws			*wsi; /* server side only */
	void				*vhd;

	lws_dll2_owner_t		env_head;
	char				sai_hash[41];
	char				lws_hash[41];
	uint64_t			uid;
	lws_dll2_owner_t		loads;
	int				online; /* 1 = connected, 0 = offline */
	uint64_t			last_seen; /* unix time */
	int				powering_up; /* 1 = sai-power is booting it */
	int				powering_down;
	unsigned int			job_limit;

	/*
	 * Idle tasks: from the builder conf "idle" object on the platform,
	 * and told to the server with the platform.  A zero share means the
	 * platform takes no idle tasks.
	 */
	unsigned int			idle_share; /* % of idle time to fill */
	unsigned int			idle_instances; /* concurrent idle tasks */
	unsigned int			idle_slice_secs; /* length of one slice */
	unsigned int			idle_settle_secs; /* builder only */

	/* server side only: builder resource tracking */
	lws_dll2_owner_t		inflight_owner; /* sai_uuid_list_t */
	int				avail_slots;
	unsigned int			avail_mem_kib;
	unsigned int			avail_sto_kib;
	/* server: don't offer idle tasks before this, after a decline */
	lws_usec_t			idle_backoff_until;

	unsigned int			windows;
	unsigned int			power_managed;
	unsigned int			stay_on;
	char				busy;

	int				index; /* used to create unique build dir path */
} sai_plat_t;

typedef struct sai_plat_owner {
	lws_dll2_owner_t		plat_owner;

} sai_plat_owner_t;

typedef struct sai_repo {
	char				*name;
	char				*fetch_url;
	char				*notification_key;
} sai_repo_t;

typedef enum {
	SAILOGA_STARTED,
} sai_log_action_t;

typedef struct sai_browse_rx_evinfo {
	char				event_hash[65];
	int				state;
} sai_browse_rx_evinfo_t;

typedef struct sai_browse_rx_taskinfo {
	char				task_hash[65];
	uint64_t			last_log_ts;
	/*
	 * The highest logs.uid the browser already has for this task + run, so
	 * a reconnecting or refreshing browser resumes where it left off.
	 *
	 * This used to be done with last_log_ts, but the log timestamps come
	 * from the builder's lws_now_usecs(), ie, its CLOCK_MONOTONIC, which is
	 * relative to that machine's boot: a builder VM that reboots (or any
	 * other builder taking over) issues timestamps below the cursor and
	 * every row after that is silently never delivered.  uid is the logs
	 * table's autoincrement primary key, so it only ever increases.
	 */
	uint64_t			last_log_uid;
	unsigned int			log_start;
	unsigned int			js_api_version;
	unsigned int			offset;
	uint8_t				logs;
	int				run;
	/*
	 * When sent with an empty task_hash (overview request), the browser
	 * also passes the project + ref it currently has selected, so the
	 * server can return the overview scoped to that project + branch.
	 */
	char				project[65];
	char				ref[65];
} sai_browse_rx_taskinfo_t;

/*
 * Browser -> sai-web requests for the unique project list and the unique
 * branch list for a given project.  Both are read-only and need no auth.
 */
typedef struct sai_browse_rx_branchlist {
	char				project[65];
} sai_browse_rx_branchlist_t;

/*
 * Browser -> sai-web -> sai-server: admin asks for a new ad-hoc event with a
 * single task, seeded from an existing task (build dimension, platform, repo
 * and so on are inherited from the seed), but building the head of "ref" as
 * last pushed to the server, and with a possibly-edited build script.
 *
 * The browser never supplies the repo or its fetch url; those are taken from
 * the seed task's event on the server side.  The ref is resolved to a hash on
 * the server from the pushes table, so the browser cannot name an arbitrary
 * hash either.
 */
typedef struct sai_browse_rx_taskclone {
	char				seed_uuid[65];
	char				ref[65];
	char				build[4096];
} sai_browse_rx_taskclone_t;

/* sai-power -> sai-server, tells it that a platform is being powered up */
typedef struct sai_power_state {
	lws_dll2_t			list; /* for parser */
	char				host[256];
	int				powering_up;
	int				powering_down;
} sai_power_state_t;

typedef struct sai_build_metric {
	lws_dll2_t			list;
	char				key[65];
	char				task_uuid[65];
	char				builder_name[96];
	char				project_name[96];
	char				ref[96];
	uint64_t			unixtime;/* actually autoincrement index in sql3 */
	uint64_t			unix_time;
	uint64_t			us_cpu_user;
	uint64_t			us_cpu_sys;
	uint64_t			wallclock_us;
	uint64_t			peak_mem_rss;
	uint64_t			stg_bytes;
	int				parallel;
	int				step;
} sai_build_metric_t;

/*
 * Browser -> sai-web -> sai-server -> sai-power
 *
 * A browser user wants to set or release a "stay" on a builder, so it won't
 * power down automatically when idle.
 */
typedef struct sai_stay {
	lws_dll2_t			list;
	char				builder_name[64];
	char				pcon_name[64];
	unsigned int			stay_on; /* 0 = release, 1 = set */
} sai_stay_t;

typedef struct sai_controlled_builder {
	lws_dll2_t			list;
	char				name[64];
} sai_controlled_builder_t;

/* sai-power -> sai-server, tells it about power controllers */
typedef struct sai_power_controller {
	lws_dll2_t			list;
	lws_dll2_owner_t 		controlled_builders_owner;
	char				name[64];
	char				type[32];
	char				depends_on[64];
	char				power_on_type[16];
	char				power_on_url[128];
	char				power_on_mac[24];
	char				power_off_type[16];
	char				power_off_url[128];
	char				power_monitor_url[128];
	unsigned int			on;
	unsigned int			manual_on;
} sai_power_controller_t;

/* sai-power -> sai-server, tells it the builders it can manage */
typedef struct sai_power_managed_builder {
	lws_dll2_t			list;
	char				name[64];
	unsigned int			stay_on;
} sai_power_managed_builder_t;

typedef struct sai_power_managed_builders {
	lws_dll2_t			list;
	lws_dll2_owner_t 		builders; /* sai_power_managed_builder_t */
	lws_dll2_owner_t 		power_controllers; /* sai_power_controller_t */
} sai_power_managed_builders_t;


typedef struct sai_stay_state_update {
	lws_dll2_t			list;
	char				builder_name[64];
	unsigned int			stay_on;
} sai_stay_state_update_t;

/* Builder -> sai-power registration */

typedef struct sai_builder_platform {
	lws_dll2_t			list;
	char				name[64];
} sai_builder_platform_t;

typedef struct sai_builder_registration {
	lws_dll2_t			list;
	lws_dll2_owner_t		platforms_owner; /* sai_builder_platform_t */
	char				builder_name[64];
	char				power_controller_name[64];
	char				power_on_type[16];
	char				power_on_url[128];
	char				power_on_mac[24];
	char				power_off_type[16];
	char				power_off_url[128];
	char				power_monitor_url[128];
	char				secret[129]; /* fleet link-key (wire only) */
} sai_builder_registration_t;

typedef struct tasmota_data {
	unsigned int		voltage_v;
	unsigned int		current_ma;
	unsigned int		active_power_w;
	unsigned int		apparent_power_va;
	unsigned int		reactive_power_var;
	unsigned int		power_factor_scaled_1000;
	unsigned int		energy_today_wh;
	unsigned int		energy_yesterday_wh;
	unsigned int		energy_total_wh;
} tasmota_data_t;

typedef struct sai_pcon_energy_report_item {
	lws_dll2_t		list;
	tasmota_data_t		data;
	char			name[64];
} sai_pcon_energy_report_item_t;

typedef struct sai_pcon_energy_report {
	lws_dll2_owner_t	items;
} sai_pcon_energy_report_t;

typedef struct sai_pcon_control {
	lws_dll2_t		list;
	char			pcon_name[64];
	char			on;
} sai_pcon_control_t;

typedef struct sai_platform_pending_task {
	lws_dll2_t		list;
	char			plat[64];
	unsigned int		pending;
	unsigned int		unmet;
} sai_platform_pending_task_t;

typedef struct sai_platform_pending_tasks {
	lws_dll2_t		list;
	char			pcons[1024];
	lws_dll2_owner_t	tasks; /* sai_platform_pending_task_t */
} sai_platform_pending_tasks_t;

/*
 * Because the definitions of these arrays of map structs are mostly in
 * common/struct-metadata.c, we are forced to repeat the length of the struct
 * so we can know the length at the usage.
 *
 * We must take care to also maintain these lengths when the struct definitions
 * change length.
 */

extern const lws_struct_map_t
	lsm_stay[3],
	lsm_schema_stay[1],
	lsm_power_managed_builder[2],
	lsm_power_managed_builders_list[2],
	lsm_schema_power_managed_builders[1],
	lsm_power_controller[12],
	lsm_schema_json_map_task[],
	lsm_schema_sq3_map_task[],
	lsm_schema_sq3_map_event[],
	lsm_schema_json_map_log[],
	lsm_schema_sq3_map_log[],
	lsm_schema_sq3_map_plat[1],
	lsm_schema_json_map_artifact[1],
	lsm_schema_sq3_map_artifact[1],
	lsm_schema_map_ta[1],
	lsm_schema_map_plat_simple[1],
	lsm_event[15],
	lsm_task[35],
	lsm_log[9],
	lsm_artifact[9],
	lsm_plat_list[1],
	lsm_schema_map_plat[1],
	lsm_task_rej[5],
	lsm_task_cancel[3],
	lsm_schema_json_map_can[1],
	lsm_schema_json_map_task[1],
	lsm_schema_json_map_event[1],
	lsm_feed_item[17],
	lsm_feed[2],
	lsm_schema_json_map_feed[1],
	lsm_resource[4],
	lsm_power_state[3],
	lsm_openshell[2],
	lsm_schema_openshell[1],
	lsm_closeshell[1],
	lsm_schema_map_active_shells[1],
	lsm_schema_active_shells[1],
	lsm_schema_closeshell[1],
	lsm_ptydata[7],
	lsm_schema_ptydata[1],
	lsm_rebuild[1],
	lsm_schema_rebuild[1],
	lsm_schema_map_build_metric[1],
	lsm_schema_sq3_map_build_metric[1],
	lsm_load_report_members[9],
	lsm_schema_json_task_rej[1],
	lsm_stay_state_update[2],
	lsm_schema_stay_state_update[1],
	lsm_build_metric[14],
	lsm_plat[17], /* +1 for pcon */
	lsm_builder_platform[1],
	lsm_builder_registration[10],
	lsm_schema_sq3_map_power_controller[1],
	lsm_schema_sq3_map_controlled_builder[1],
	lsm_schema_builder_registration[1],
	lsm_schema_sq3_map_builder_registration[1],
	lsm_pcon_energy_report[1],
	lsm_schema_pcon_energy[1],
	lsm_pcon_control[2],
	lsm_schema_pcon_control[1],
	lsm_taskclone[3],
	lsm_schema_taskclone[1],
	lsm_watcher_rule[6],
	lsm_watcher_ui_rule[4],
	lsm_watcher_service[7],
	lsm_watcher[8],
	lsm_schema_sq3_map_watcher[1],
	lsm_schema_json_map_watcher[1],
	lsm_watcher_conf[1],
	lsm_pending_task[3],
	lsm_pending_tasks[2],
	lsm_schema_pending_tasks[1];

extern const lws_ss_info_t ssi_said_logproxy;
extern struct lws_ss_handle *ssh[3];

typedef void (*saicom_drain_cb)(void *opaque);

int
saicom_lp_add(struct lws_ss_handle *h, const char *buf, size_t len);

struct lws_ss_handle *
saicom_lp_ss_from_env(struct lws_context *context, const char *env_name);

int
saicom_lp_callback_on_drain(saicom_drain_cb cb, void *opaque);

int
sai_uuid16_create(struct lws_context *context, char *dest33);

const char *
sai_task_describe(sai_task_t *task, char *buf, size_t len);

int
sai_metrics_hash(uint8_t *key, size_t key_len, const char *sp_name,
		 const char *spawn, const char *project_name,
		 const char *ref);

const char *
sai_get_ref(const char *fullref);

/*
 * Input validation helpers for attacker-influenced strings that arrive via
 * signed git-hook notifications and are later interpolated into shell scripts
 * and filesystem paths on the builder.  See src/common/c-utils.c.
 */
int
sai_str_has_shell_metachars(const char *s);

int
sai_is_git_hash(const char *s);

int
sai_is_safe_ref(const char *s);

/*
 * The .sai.json "artifacts" field is repo-controlled and reaches the
 * builder as a comma-separated list of globs, possibly with a path part
 * before the first '*', eg "build/ *.rpm,*.tar.gz".  The builder scans
 * them under the per-instance build dir and renames what it matches into
 * its uploads dir, so a pattern whose path part climbs out of the
 * instance dir (a ".." component, an absolute pattern, or a windows
 * drive / UNC shape) turns repo content into host-file exfiltration and
 * destructive moves.  These return 1 when safe to scan, else 0.
 */
int
sai_artifacts_pattern_safe(const char *pat);

int
sai_artifacts_list_safe(const char *list);

void
sai_dump_stderr(const uint8_t *buf, size_t w);

int
sai_ss_queue_frag_on_buflist_REQUIRES_LWS_PRE(struct lws_ss_handle *h,
					      struct lws_buflist **buflist,
					      void *buf, size_t len,
					      unsigned int ss_flags);

int
sai_ss_serialize_queue_helper(struct lws_ss_handle *h,
			      struct lws_buflist **buflist,
			      const lws_struct_map_t *map,
			      size_t map_len, void *root);

lws_ss_state_return_t
sai_ss_tx_from_buflist_helper(struct lws_ss_handle *ss, struct lws_buflist **buflist,
			      uint8_t *buf, size_t *len, int *flags);

int
sai_event_db_ensure_open(struct lws_context *cx, lws_dll2_owner_t *sqlite3_cache,
			 const char *sqlite3_path_lhs, const char *event_uuid,
			  char create_if_needed, struct sqlite3 **ppdb);
void
sai_event_db_close(lws_dll2_owner_t *sqlite3_cache, struct sqlite3 **ppdb);

int
sai_event_db_close_all_now(lws_dll2_owner_t *sqlite3_cache);

int
sai_event_db_delete_database(const char *sqlite3_path_lhs, const char *event_uuid);

int
sai_sqlite3_statement(struct sqlite3 *pdb, const char *cmd, const char *desc);

/* not everyone including us includes sqlite3.h */
struct sqlite3_stmt;

int
sai_sqlite3_step_done(struct sqlite3 *pdb, struct sqlite3_stmt *sm,
		      const char *desc);

/*
 * Pools: a repo's named sets of files that the builders running its tasks keep
 * synced through sai-server, eg, fuzzing corpora.  See READMEs/README-pool.md.
 *
 * A builder opens a connection to sai-server's /builder endpoint for each
 * sync, proves the link key as usual, then sends a JSON "hello" naming the
 * task it syncs for, with the task's artifact upload nonce, which decides the
 * repo and pool.  After that, both ways, it's a stream of binary records:
 *
 *   u8 type, u8 ns, u16 name length, u32 data length (big endian),
 *   the name, then the data
 *
 * Names are "<sub>/<name>", eg, "corpus-h2/<sha1>", except as noted.
 */

#define SAI_POOL_SCHEMA		"com.warmcat.sai.pool"
#define SAI_POOL_REC_HDR_LEN	8
#define SAI_POOL_REC_NAME_MAX	128
/* the most one corpus or known entry may be */
#define SAI_POOL_ENTRY_MAX	(1024u * 1024u)
/* the most one finding may be */
#define SAI_POOL_FINDING_MAX	(8u * 1024u * 1024u)
/*
 * The most an OFFER (and so the WANT answering it) may list, the sender splits
 * longer lists over several; and the most a REPLACE's list of names to keep,
 * which can't be split, may be
 */
#define SAI_POOL_OFFER_MAX	(512u * 1024u)
#define SAI_POOL_LIST_MAX	(8u * 1024u * 1024u)

enum {
	/*
	 * Both ways, and the entries are content addressed: the name is the
	 * lowercase hex sha1 of the content
	 */
	SAI_POOL_NS_CORPUS,
	/* server -> builder only, content addressed, eg, known reproducers */
	SAI_POOL_NS_KNOWN,
	/* builder -> server only, any safe name, eg, fuzzer findings */
	SAI_POOL_NS_FINDINGS,

	SAI_POOL_NS_COUNT
};

enum {
	/* builder -> server */

	SAI_POOL_REC_PULL	= 1,	/* data: u64 BE cursor we have up to */
	SAI_POOL_REC_OFFER,		/* data: '\n'-separated names we have */
	SAI_POOL_REC_PUT,		/* name, data: the content */
	SAI_POOL_REC_REPLACE,		/* name: sub only, data: u64 BE base
					 * cursor then '\n'-separated names in
					 * sub to keep, see README-pool.md */

	/* server -> builder */

	SAI_POOL_REC_ENTRY	= 0x81,	/* name, data: the content */
	SAI_POOL_REC_DEAD,		/* name: the entry was removed */
	SAI_POOL_REC_PULL_END,		/* data: u64 BE cursor now */
	SAI_POOL_REC_WANT,		/* data: '\n'-separated offered names
					 * the server doesn't have */
	SAI_POOL_REC_ACK,		/* name: of the PUT, or sub of the
					 * REPLACE, that was stored */
};

/*
 * Browser -> sai-web -> sai-server: an admin changes a findings group, see
 * s-findings.c.  op is "ack", "fixed", "wontfix" or "reopen".
 */
typedef struct sai_findingset {
	lws_dll2_t			list;
	char				repo[65];
	char				pool[33];
	char				group[17];
	char				op[16];
} sai_findingset_t;

typedef struct sai_pool_hello {
	char				task_uuid[65];
	char				nonce[33];
} sai_pool_hello_t;

typedef struct sai_pool_rec_hdr {
	uint32_t			len;
	uint16_t			name_len;
	uint8_t				type;
	uint8_t				ns;
} sai_pool_rec_hdr_t;

extern const lws_struct_map_t lsm_pool_hello[2], lsm_schema_pool_hello[1],
				lsm_findingset[4];

/* src/common/c-pool.c */

int
sai_pool_name_ok(const char *name);

int
sai_pool_sub_ok(const char *sub, size_t len);

int
sai_pool_entry_name_ok(int ns, const char *name, size_t len);

int
sai_pool_content_matches(const uint8_t *data, size_t len, const char *sha1hex);

void
sai_pool_rec_hdr_write(uint8_t *p, int type, int ns, size_t name_len,
		       size_t len);

void
sai_pool_rec_hdr_read(const uint8_t *p, sai_pool_rec_hdr_t *h);

size_t
sai_pool_rec_max(int ns, int type);

void
sai_pool_db_path(char *buf, size_t len, const char *lhs, const char *repo,
		 const char *pool);

void
sai_pool_u64_write(uint8_t *p, uint64_t v);

uint64_t
sai_pool_u64_read(const uint8_t *p);

/*
 * c-conf.c: create the context and vhosts from an lwsws-style config dir.
 * info must be zeroed and passed through lws_cmdline_option_handle_builtin()
 * by the caller first.
 */
struct lws_context *
sai_lws_context_from_json(const char *config_dir,
			  struct lws_context_creation_info *info,
			  const struct lws_protocols **pprotocols,
			  const char *jpol);
