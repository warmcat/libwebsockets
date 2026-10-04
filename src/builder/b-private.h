/*
 * Sai builder definitions src/builder/b-private.h
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

#if !defined(WIN32)
#include <pwd.h>
#include <grp.h>
#endif

#if defined(__linux__) || defined(__APPLE__)
#include <unistd.h>
#endif

#if defined(__APPLE__)
#include <sys/stat.h>	/* for mkdir() */
#include <sys/wait.h>
#endif

#if defined(WIN32)
#include <initguid.h>
#include <KnownFolders.h>
#include <Shlobj.h>
#include <processthreadsapi.h>
#include <handleapi.h>


#if !defined(PATH_MAX)
#define PATH_MAX MAX_PATH
#endif
#endif

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
#if defined(pid_t)
#undef pid_t
#endif
#endif
#include <pthread.h>

extern char suspender_exists;

struct lws_spawn_piped;
struct lws_stub_manager;

/*
 * One "env" item from a platform in the builder conf, in the conf lwsac and
 * listed on the sai_plat .env_head, in conf order
 */

typedef struct saib_env {
	lws_dll2_t		list;
	const char		*name;
	const char		*value; /* NULL = the builder's own value */
} saib_env_t;

struct saib_opaque_spawn {
	struct sai_nspawn	*ns;
	struct lws_spawn_piped	*lsp;
	char			*spawn;
	lws_usec_t		start_time;
};

#define SAI_LOAD_REPORT_US			(1 * LWS_US_PER_SEC)
#define SAI_IDLE_GRACE_US			(builder.one_shot_active ? (10 * LWS_US_PER_SEC) : \
						 builder.event_affinity_active ? (15 * LWS_US_PER_SEC) : \
						 (30 * LWS_US_PER_SEC))
/* let the powering_down plats reach the servers before we act */
#define SAI_POWER_NOTIFY_FLUSH_US		(2 * LWS_US_PER_SEC)
/* suspend byte written: if we are still awake after this, it failed */
#define SAI_POWER_SUSPEND_DEADLINE_US		(15 * LWS_US_PER_SEC)
/* how long to wait for sai-power to ACK / NAK an auto-power-off */
#define SAI_POWER_OFF_REPLY_US			(10 * LWS_US_PER_SEC)
/* sai-power ACKed and we asked for shutdown: sai-power's own holdoff is 50s */
#define SAI_POWER_OFF_DEADLINE_US		(90 * LWS_US_PER_SEC)
/* after a failed power action, before we consider going idle again */
#define SAI_POWER_RETRY_HOLDOFF_US		(5 * 60 * LWS_US_PER_SEC)
#define SAI_STAY_POLL_US			(20 * LWS_US_PER_SEC)
#define SAI_CLEANUP_JOBS_INTERVAL_US		(60ULL * 60ULL * LWS_US_PER_SEC)
#define SAI_CLEANUP_JOB_DIR_MIN_AGE_SECS	(24ull * 3600u)
/*
 * The disk-pressure path may delete job dirs of any age, so it needs its own
 * floor: a dir this young is either in use or between the steps of a task we
 * are still building, and deleting it breaks that build.
 */
#define SAI_FREEKIB_JOB_DIR_MIN_AGE_SECS	(30u * 60u)
/*
 * How long a job dir hold survives without being renewed.  A task whose steps
 * are still coming renews its hold at every step, so this only has to outlast
 * the gap between one step finishing and the next being offered (plus however
 * long the server takes to get around to us).  It is the backstop that stops a
 * task that died on the server side pinning its job dir forever.
 */
#define SAI_JOBDIR_HOLD_MAX_SECS		(2u * 3600u)
/*
 * How far the wall clock and the monotonic clock may disagree about how much
 * time has passed before we call it a step rather than drift.  ntp slews both,
 * so in normal running they track each other within a second.
 */
#define SAI_CLOCK_STEP_TOLERANCE_SECS		60
/*
 * After the wall clock has been stepped, every mtime written before the step is
 * wrong by the size of the step, and there is no way to tell one from a
 * genuinely old file.  So stop making age-based decisions for this long (of
 * monotonic time) afterwards.  Deleting old job dirs is only housekeeping; it
 * can always wait for the next pass.
 */
#define SAI_CLOCK_STEP_SETTLE_SECS		(60 * 60)
/*
 * A wall clock reading before this is not a clock that has been set yet, it is
 * a VM that has just booted.  It only has to be later than any default date a
 * builder might come up with and earlier than now, so it never needs moving;
 * a clock that is wrong but still after it is caught by the step detection
 * above instead.  (2025-01-01 UTC)
 */
#define SAI_CLOCK_PLAUSIBLE_AFTER		1735689600ull
/*
 * How long to wait for the clock to be set before starting work anyway.  A
 * builder that never appears is worse than one with a wrong clock, and the step
 * detection above stops a late correction eating the job dirs regardless.
 */
#define SAI_CLOCK_WAIT_MAX_SECS			(5 * 60)


/*
 * Idle tasks, when the platform's conf "idle" object doesn't say: how long one
 * slice of an idle task runs for, and how long after the last real work we
 * wait before we count as idle again (tasks tend to arrive in bursts, and the
 * server offers a task's steps one at a time with gaps between)
 */
#define SAIB_IDLE_DEF_SLICE_SECS		(15 * 60)
#define SAIB_IDLE_DEF_SETTLE_SECS		120
/* how much longer than its slice an idle task step may run before we stop it */
#define SAIB_IDLE_SLICE_GRACE_SECS		120

struct saib_ws_pss;

enum nsstate {
	NSSTATE_INIT,
	NSSTATE_MOUNTING,
	NSSTATE_EXECUTING_STEPS,
	NSSTATE_DONE,
	NSSTATE_UPLOADING_ARTIFACTS,
	NSSTATE_FAILED,
};

/*
 * Auto power management, see saib_power_event() in b-power.c
 */

enum saib_power_state {
	SAIB_PWR_ACTIVE,	/* tasks, shells or stay: nothing pending */
	SAIB_PWR_IDLE,		/* nothing running, idle grace timer running */
	SAIB_PWR_HOLDOFF,	/* a power action failed, waiting before retry */
	SAIB_PWR_SUSPEND_WAIT,	/* servers told we're going, flushing before suspend */
	SAIB_PWR_SUSPENDING,	/* suspend requested, waiting for it to happen */
	SAIB_PWR_OFF_REQ,	/* asked sai-power to power us off, awaiting reply */
	SAIB_PWR_OFF_WAIT,	/* sai-power agreed, shutdown requested, waiting */
};

enum saib_power_event {
	SAIB_PWR_EV_BUSY,	/* a task or shell started, or stay asserted */
	SAIB_PWR_EV_IDLE,	/* nothing running and no stay */
	SAIB_PWR_EV_TIMER,	/* the current state's deadline expired */
	SAIB_PWR_EV_POWER_ACK,	/* sai-power scheduled our power-off */
	SAIB_PWR_EV_POWER_NAK,	/* sai-power declined or is unreachable */
};

/*
 * This represents this builder process as a whole
 */

struct sai_shell {
	struct lws_dll2		list;
	char			task_uuid[33];
	struct sai_plat_server	*spm;
	struct lws_spawn_piped	*lsp;
	struct lws		*stdwsi[3];
	char			stdwsi_paused[3];
	int			user_cancel;
};

struct sai_builder {
	lws_dll2_owner_t	sai_plat_owner; /* list of platforms we offer */
	lws_dll2_owner_t	sai_plat_server_owner; /* servers we connect to */
	lws_dll2_owner_t	devices_owner; /* sai_serial_t */
	lws_dll2_owner_t	lsp_owner; /* list of lws_spawn_piped */
	lws_dll2_owner_t	jobdir_hold_owner; /* saib_jobdir_hold_t */
	lws_dll2_owner_t	shell_owner; /* list of sai_shell */
	lws_dll2_owner_t	pool_owner; /* saib_pool_t, see b-pool.c */

	struct lws_ss_handle	*ss_stay;
	struct lws_ss_handle	*ss_power_off;


	struct sai_nspawn	suspend_nspawn;

	struct lwsac		*conf_head;
	struct lws_context	*context;
	struct lws_vhost	*vhost;

	lws_sorted_usec_list_t	sul_power; /* current power state's deadline */
	lws_sorted_usec_list_t	sul_stay;
	lws_sorted_usec_list_t	sul_cleanup_jobs;
	lws_sorted_usec_list_t	sul_clock_wait;
	lws_sorted_usec_list_t	sul_deletion_respawn;

#if defined(__APPLE__)
	lws_sorted_usec_list_t	sul_release_wakelock;
	pid_t			wakelock_pid;
#endif

	const char		*metrics_uri;
	const char		*metrics_path;
	const char		*metrics_secret;

	/* fleet secret shared with sai-server ("link-key" in conf) */
	const char		*link_key;

	const char		*url_sai_power;
	const char		*power_controller_name;

	const char		*power_off_type;
	const char		*power_off_url;
	const char		*power_on_type;
	const char		*power_on_url;
	const char		*power_on_mac;
	const char		*power_monitor_url;

	const char		*home;		/* home dir, usually /sai/home */
	const char		*perms;		/* user:group */

	const char		*host;		/* prepended before hostname */
	const char		*rebuild_script_user;
	const char		*rebuild_script_root;

	char			path[256];
	char			path_power_off[256];

#if defined(__linux__) || defined(__APPLE__)
	/* For system-wide load calculation */
	uint64_t		last_sys_total;
	uint64_t		last_sys_idle;
#elif defined(WIN32)
	ULARGE_INTEGER		last_sys_total;
	ULARGE_INTEGER		last_sys_idle;
	ULARGE_INTEGER		last_sys_kernel;
	ULARGE_INTEGER		last_sys_user;
#endif
	char			stay;

	enum saib_power_state	power_state;
	time_t			power_action_time; /* wall clock at last command */
	lws_usec_t		power_action_us; /* monotonic at last command */
	int			power_fail_count;
	char			power_unavailable_logged;

	char			event_affinity[65];
	char			event_affinity_active;
	char			one_shot_task_uuid[65];
	char			one_shot_active;

	/* resource management */

	uint64_t		ram_limit_kib;
	uint64_t		ram_reserved_kib;
	uint64_t		disk_total_kib;
	uint64_t		disk_reserved_kib;

	/*
	 * Wall clock vs monotonic clock baseline, for noticing that something
	 * (ntp, usually, on a VM that booted with a nonsense date) has stepped
	 * the wall clock under us.  Job dir ages are wall clock minus file
	 * mtime, so a step makes every existing job dir look as old as the step
	 * was big, and the deletion paths take dirs that are still in use.
	 */
	uint64_t		wall_at_base;		/* lws_now_secs() */
	lws_usec_t		mono_at_base;
	lws_usec_t		mono_last_clock_step;	/* 0: none seen */

	/*
	 * Strictly-increasing log chunk timestamp latch.  It is builder-wide
	 * and not per-nspawn: a task's steps are each a separate nspawn, and
	 * the browser pages a task's logs with a strictly-greater-than
	 * timestamp cursor, so a later step issuing a timestamp a previous
	 * step already used means those rows are never delivered.
	 */
	lws_usec_t		last_log_us;

	/*
	 * When we were last offered, or last finished, a step of a real task
	 * (not an idle one), for the idle task settle time
	 */
	lws_usec_t		last_real_us;

	uint16_t		wrap14;
	unsigned int		build_timeout_secs;

#if !defined(WIN32)
	int			pipe_suspender_wr;
#else
	void			*pipe_suspender_wr;
#endif
	struct lws_stub_manager	*mgr_deletion;
};

struct jpargs {
	struct sai_builder	*builder;

	struct sai_nspawn	*nspawn;
	struct sai_plat		*sai_plat;

	struct sai_platform	*pl;

	sai_plat_server_ref_t	*mref;

	int			next_server_index;
	int			next_plat_index;
};

struct ws_capture_chunk {
	struct lws_dll2 list;

	lws_usec_t	us;	/* builder time that we saw this */
	size_t		len;
	uint8_t		stdfd;	/* 1 = stdout, 2 = stderr */

	/* len bytes of data is overallocated after this */
};


extern struct sai_builder builder;
extern const lws_ss_info_t ssi_sai_builder, ssi_sai_mirror, ssi_sai_artifact,
			   ssi_sai_pool;
extern const struct lws_protocols protocol_com_warmcat_sai;
int
saib_config_global(struct sai_builder *builder, const char *d);
extern int saib_config(struct sai_builder *builder, const char *d);
extern void saib_config_destroy(struct sai_builder *builder);

int
saib_overlay_mount(struct sai_builder *b, struct sai_nspawn *ns);

int
saib_overlay_unmount(struct sai_nspawn *ns);

int
saib_spawn_script(struct sai_nspawn *ns);

int
saib_prepare_mount(struct sai_builder *b, struct sai_nspawn *ns);

int
saib_ws_json_rx_builder(struct sai_plat_server *spm, const void *in, size_t len);

int
saib_generate(struct sai_plat *sp, char *buf, int len);

enum lws_threadpool_task_return
saib_mirror_task(void *user, enum lws_threadpool_task_status s);

int
saib_set_ns_state(struct sai_nspawn *ns, int state);

void
saib_task_destroy(struct sai_nspawn *ns);

void
saib_task_grace(struct sai_nspawn *ns);

int
saib_log_chunk_create(struct sai_nspawn *ns, void *buf, size_t len, int channel);

int
rm_rf_cb(const char *dirpath, void *user, struct lws_dir_entry *lde);

extern const struct lws_protocols protocol_logproxy, protocol_resproxy;

void *
saib_thread_suspend(void *d);


int
saib_create_resproxy_listen_uds(struct lws_context *context,
				struct sai_plat_server *spm);

int
saib_handle_resource_result(struct sai_plat_server *spm, const char *in, size_t len);

void
saib_sul_load_report_cb(struct lws_sorted_usec_list *sul);

int
saib_get_cgroup_cpu(struct sai_nspawn *ns);

int
saib_get_system_cpu(struct sai_builder *b);

int saib_get_cpu_count(void);

unsigned int
saib_get_free_ram_kib(void);

unsigned int
saib_get_total_ram_kib(void);

unsigned int
saib_get_free_disk_kib(const char *path);

unsigned int
saib_get_total_disk_kib(const char *path);

int
saib_create_listen_uds(struct lws_context *context, struct saib_logproxy *lp, struct lws_vhost **);

int
saib_srv_queue_tx(struct lws_ss_handle *h, void *buf, size_t len, unsigned int ss_flags);

/*
 * Queue a log chunk for a task that has no nspawn (yet, or ever): the task-
 * acceptance path needs to be able to explain a refusal or a failed setup in
 * the task's own log, since that is the only log that survives the builder's
 * VM going away.
 */
int
saib_log_chunk_create_uuid(struct sai_plat_server *spm, const char *task_uuid,
			   const void *buf, size_t len, int channel);

/*
 * Report a builder-side decision about a task into the task's own log (and our
 * local log).  \p ns may be NULL, in which case \p spm and \p task_uuid say
 * where it goes.
 */
int
saib_task_logf(struct sai_plat_server *spm, struct sai_nspawn *ns,
	       const char *task_uuid, const char *fmt, ...)
	LWS_FORMAT(4);

int
saib_srv_queue_json_fragments_helper(struct lws_ss_handle *h,
				     const lws_struct_map_t *map,
                                     size_t map_entries, void *object);

int
saib_queue_task_status_update(sai_plat_t *sp, struct sai_plat_server *spm,
			      const sai_task_t *task, unsigned int ecode,
			      unsigned int reason);

int
saib_consider_allocating_task(struct sai_plat_server *spm, lws_struct_args_t *a,
			      const uint8_t *in, size_t len, int flags);

void
saib_sul_task_cancel(struct lws_sorted_usec_list *sul);

/* b-pool.c */

int
saib_pool_attach(struct sai_nspawn *ns);

int
saib_pool_defer_spawn(struct sai_nspawn *ns);

int
saib_pool_waiter_abort(struct sai_nspawn *ns);

void
saib_pool_detach(struct sai_nspawn *ns);

void
saib_pool_env(struct sai_nspawn *ns, char *buf, size_t len);

int
saib_pool_busy(void);

int
saib_env_add(sai_plat_t *sp, struct lwsac **ac, const char *name,
	     size_t nlen, const char *value);

const char **
saib_env_build(const sai_plat_t *sp, struct lwsac **ac);

void
saib_pool_destroy_all(void);

int
saib_suspender_get_pipe(void);

extern int
saib_suspender_fork(const char *path);
extern int
sai_deletion_worker(const char *home_dir);
extern int
saib_suspender_start(void);
extern int
saib_power_init(void);
extern int
saib_deletion_init(const char *argv0);
int
saib_deletion_request(const char *job);
extern void
suspender_destroy(void);
int
saib_deletion_free_kib(unsigned int needed_kib, const char *protect_vn);

/*
 * A task's build steps are each their own nspawn, so between steps there is no
 * live nspawn pointing at the job dir and nothing else stops the deletion paths
 * removing it.  A hold on the job dir's 8-char "vn" name covers that gap.
 */

typedef struct saib_jobdir_hold {
	lws_dll2_t		list;
	char			vn[16];
	uint64_t		renewed;	/* lws_now_secs() */
} saib_jobdir_hold_t;

void
saib_jobdir_hold(const char *vn);
void
saib_jobdir_release(const char *vn);
int
saib_jobdir_is_held(const char *vn);
void
saib_jobdir_holds_destroy(void);

/*
 * The job dir name for a task: the first 4 and last 4 chars of its uuid.  Both
 * the acceptance path (which must protect the dir before the nspawn exists)
 * and the nspawn setup derive it, so it lives in one place.
 */
void
saib_task_jobdir_vn(char *dest, size_t dest_len, const char *task_uuid);

/*
 * Wall clock step detection.  saib_clock_baseline() records where the two
 * clocks started out; saib_clock_ages_trustworthy() reports whether file ages
 * computed from the wall clock can be believed right now, and notices (and
 * reports) a step as a side effect of being asked.
 */
void
saib_clock_baseline(void);
int
saib_clock_ages_trustworthy(void);
int
saib_reassess_idle_situation(void);
void
saib_power_event(enum saib_power_event ev);
void
saib_power_shutdown(void);

extern int interrupted;

int
saib_app_run(int argc, const char **argv);

void
saib_app_stop(void);

#if defined(__APPLE__)
int
saib_need_wakelock(void);

void
sul_release_wakelock_cb(lws_sorted_usec_list_t *sul);

void
saib_wakelock(void);
#endif

