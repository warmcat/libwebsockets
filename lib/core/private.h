/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2019 Andy Green <andy@warmcat.com>
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

#include "lws_config.h"
#include "lws_config_private.h"

#if defined(LWS_WITH_CGI) && defined(LWS_HAVE_VFORK) && \
    !defined(NO_GNU_SOURCE_THIS_TIME)
 #define  _GNU_SOURCE
#endif

/*
#if !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200112L
#endif
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <limits.h>
#include <stdarg.h>

#ifdef LWS_HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#include <assert.h>

#ifdef LWS_HAVE_SYS_TYPES_H
 #include <sys/types.h>
#endif
#if defined(LWS_HAVE_SYS_STAT_H) && !defined(LWS_PLAT_OPTEE)
 #include <sys/stat.h>
#endif

#if LWS_MAX_SMP > 1
 #include <pthread.h>
#endif

#ifndef LWS_DEF_HEADER_LEN
#define LWS_DEF_HEADER_LEN 4096
#endif
#ifndef LWS_DEF_HEADER_POOL
#define LWS_DEF_HEADER_POOL 4
#endif
#ifndef LWS_MAX_PROTOCOLS
#define LWS_MAX_PROTOCOLS 5
#endif
#ifndef LWS_MAX_EXTENSIONS_ACTIVE
#define LWS_MAX_EXTENSIONS_ACTIVE 1
#endif
#ifndef LWS_MAX_EXT_OFFERS
#define LWS_MAX_EXT_OFFERS 8
#endif
#ifndef SPEC_LATEST_SUPPORTED
#define SPEC_LATEST_SUPPORTED 13
#endif
#ifndef AWAITING_TIMEOUT
#define AWAITING_TIMEOUT 20
#endif
#ifndef CIPHERS_LIST_STRING
#define CIPHERS_LIST_STRING "DEFAULT"
#endif
#ifndef LWS_SOMAXCONN
#define LWS_SOMAXCONN SOMAXCONN
#endif

#define MAX_WEBSOCKET_04_KEY_LEN 128

#ifndef SYSTEM_RANDOM_FILEPATH
#define SYSTEM_RANDOM_FILEPATH "/dev/urandom"
#endif

#define LWS_H2_RX_SCRATCH_SIZE 512

#define lws_socket_is_valid(x) (x != LWS_SOCK_INVALID)

#ifndef LWS_HAVE_STRERROR
 #define strerror(x) ""
#endif


 /*
  *
  *  ------ private platform defines ------
  *
  */

#if defined(LWS_WITH_ESP32)
 #include "plat/esp32/private.h"
#else
 #if defined(WIN32) || defined(_WIN32)
  #include "plat/windows/private.h"
 #else
  #if defined(LWS_PLAT_OPTEE)
   #include "plat/optee/private.h"
  #else
   #include "plat/unix/private.h"
  #endif
 #endif
#endif

 /*
  *
  *  ------ public api ------
  *
  */

#include "libwebsockets.h"

#include "tls/private.h"

#if defined(WIN32) || defined(_WIN32)
	 // Visual studio older than 2015 and WIN_CE has only _stricmp
	#if (defined(_MSC_VER) && _MSC_VER < 1900) || defined(_WIN32_WCE)
	#define strcasecmp _stricmp
	#define strncasecmp _strnicmp
	#elif !defined(__MINGW32__)
	#define strcasecmp stricmp
	#define strncasecmp strnicmp
	#endif
	#define getdtablesize() 30000
#endif

#ifndef LWS_ARRAY_SIZE
#define LWS_ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
#endif

#ifdef __cplusplus
extern "C" {
#endif



#if defined(__clang__)
#define lws_memory_barrier() __sync_synchronize()
#elif defined(__GNUC__)
#define lws_memory_barrier() __sync_synchronize()
#else
#define lws_memory_barrier()
#endif


struct lws_ring {
	void *buf;
	void (*destroy_element)(void *element);
	uint32_t buflen;
	uint32_t element_len;
	uint32_t head;
	uint32_t oldest_tail;
};

struct lws_protocols;
struct lws;

#if defined(LWS_WITH_NETWORK)
#include "event-libs/private.h"


struct lws_io_watcher {
#ifdef LWS_WITH_LIBEV
	struct lws_io_watcher_libev ev;
#endif
#ifdef LWS_WITH_LIBUV
	struct lws_io_watcher_libuv uv;
#endif
#ifdef LWS_WITH_LIBEVENT
	struct lws_io_watcher_libevent event;
#endif
	struct lws_context *context;

	uint8_t actual_events;
};

struct lws_signal_watcher {
#ifdef LWS_WITH_LIBEV
	struct lws_signal_watcher_libev ev;
#endif
#ifdef LWS_WITH_LIBUV
	struct lws_signal_watcher_libuv uv;
#endif
#ifdef LWS_WITH_LIBEVENT
	struct lws_signal_watcher_libevent event;
#endif
	struct lws_context *context;
};

struct lws_foreign_thread_pollfd {
	struct lws_foreign_thread_pollfd *next;
	int fd_index;
	int _and;
	int _or;
};
#endif

#if LWS_MAX_SMP > 1

struct lws_mutex_refcount {
	pthread_mutex_t lock;
	pthread_t lock_owner;
	const char *last_lock_reason;
	char lock_depth;
	char metadata;
};

void
lws_mutex_refcount_init(struct lws_mutex_refcount *mr);

void
lws_mutex_refcount_destroy(struct lws_mutex_refcount *mr);

void
lws_mutex_refcount_lock(struct lws_mutex_refcount *mr, const char *reason);

void
lws_mutex_refcount_unlock(struct lws_mutex_refcount *mr);
#endif

#if defined(LWS_WITH_NETWORK)
#include "core-net/private.h"
#endif

struct lws_deferred_free
{
	struct lws_deferred_free *next;
	time_t deadline;
	void *payload;
};

/*
 * the rest is managed per-context, that includes
 *
 *  - processwide single fd -> wsi lookup
 *  - contextwide headers pool
 */

struct lws_context {
	time_t last_ws_ping_pong_check_s;
	lws_usec_t time_up; /* monotonic */
	const struct lws_plat_file_ops *fops;
	struct lws_plat_file_ops fops_platform;
	struct lws_context **pcontext_finalize;

	const struct lws_tls_ops *tls_ops;

	const char *username, *groupname;

#if defined(LWS_WITH_HTTP2)
	struct http2_settings set;
#endif
#if defined(LWS_WITH_ZIP_FOPS)
	struct lws_plat_file_ops fops_zip;
#endif
#if defined(LWS_WITH_NETWORK)
	struct lws_context_per_thread pt[LWS_MAX_SMP];
	struct lws_conn_stats conn_stats;
	struct lws_vhost *vhost_list;
	struct lws_vhost *no_listener_vhost_list;
	struct lws_vhost *vhost_pending_destruction_list;
	struct lws_plugin *plugin_list;
#ifdef _WIN32
/* different implementation between unix and windows */
	struct lws_fd_hashtable fd_hashtable[FD_HASHTABLE_MODULUS];
#else
	struct lws **lws_lookup;

#endif
#endif
#if LWS_MAX_SMP > 1
	struct lws_mutex_refcount mr;
#endif

#if defined(LWS_AMAZON_RTOS)
	mbedtls_entropy_context mec;
	mbedtls_ctr_drbg_context mcdc;
#endif

	struct lws_deferred_free *deferred_free_list;

#if defined(LWS_WITH_THREADPOOL)
	struct lws_threadpool *tp_list_head;
#endif

#if defined(LWS_WITH_PEER_LIMITS)
	struct lws_peer **pl_hash_table;
	struct lws_peer *peer_wait_list;
	time_t next_cull;
#endif

	void *external_baggage_free_on_destroy;
	const struct lws_token_limits *token_limits;
	void *user_space;
	const struct lws_protocol_vhost_options *reject_service_keywords;
	lws_reload_func deprecation_cb;
	void (*eventlib_signal_cb)(void *event_lib_handle, int signum);

#if defined(LWS_HAVE_SYS_CAPABILITY_H) && defined(LWS_HAVE_LIBCAP)
	cap_value_t caps[4];
	char count_caps;
#endif

#if defined(LWS_WITH_NETWORK)
#if defined(LWS_WITH_LIBEV)
	struct lws_context_eventlibs_libev ev;
#endif
#if defined(LWS_WITH_LIBUV)
	struct lws_context_eventlibs_libuv uv;
#endif
#if defined(LWS_WITH_LIBEVENT)
	struct lws_context_eventlibs_libevent event;
#endif
	struct lws_event_loop_ops *event_loop_ops;
#endif

#if defined(LWS_WITH_TLS) && defined(LWS_WITH_NETWORK)
	struct lws_context_tls tls;
#endif

	char canonical_hostname[128];
	const char *server_string;

#ifdef LWS_LATENCY
	unsigned long worst_latency;
	char worst_latency_info[256];
#endif

#if defined(LWS_WITH_ESP32)
	unsigned long time_last_state_dump;
	uint32_t last_free_heap;
#endif

	int max_fds;
	int count_event_loop_static_asset_handles;
#if !defined(LWS_NO_DAEMONIZE)
	pid_t started_with_parent;
#endif
	int uid, gid;

	int fd_random;

	int count_wsi_allocated;
	int count_cgi_spawned;
	unsigned int options;
	unsigned int fd_limit_per_thread;
	unsigned int timeout_secs;
	unsigned int pt_serv_buf_size;
	int max_http_header_data;
	int max_http_header_pool;
	int simultaneous_ssl_restriction;
	int simultaneous_ssl;
#if defined(LWS_WITH_PEER_LIMITS)
	uint32_t pl_hash_elements;	/* protected by context->lock */
	uint32_t count_peers;		/* protected by context->lock */
	unsigned short ip_limit_ah;
	unsigned short ip_limit_wsi;
#endif
	unsigned int deprecated:1;
	unsigned int being_destroyed:1;
	unsigned int being_destroyed1:1;
	unsigned int being_destroyed2:1;
	unsigned int requested_kill:1;
	unsigned int protocol_init_done:1;
	unsigned int doing_protocol_init:1;
	unsigned int done_protocol_destroy_cb:1;
	unsigned int finalize_destroy_after_internal_loops_stopped:1;
	unsigned int max_fds_unrelated_to_ulimit:1;

	short count_threads;
	short plugin_protocol_count;
	short plugin_extension_count;
	short server_string_len;
	unsigned short ws_ping_pong_interval;
	unsigned short deprecation_pending_listen_close_count;

	uint8_t max_fi;

#if defined(LWS_WITH_STATS)
	uint8_t updated;
#endif
};

int
lws_check_deferred_free(struct lws_context *context, int tsi, int force);

#define lws_get_context_protocol(ctx, x) ctx->vhost_list->protocols[x]
#define lws_get_vh_protocol(vh, x) vh->protocols[x]

int
lws_jws_base64_enc(const char *in, size_t in_len, char *out, size_t out_max);

void
lws_vhost_destroy1(struct lws_vhost *vh);


#if defined(LWS_WITH_ESP32)
LWS_EXTERN int
lws_find_string_in_file(const char *filename, const char *str, int stringlen);
#endif


signed char char_to_hex(const char c);


struct lws_buflist {
	struct lws_buflist *next;

	size_t len;
	size_t pos;

	uint8_t buf[1]; /* true length of this is set by the oversize malloc */
};


LWS_EXTERN char *
lws_strdup(const char *s);

LWS_EXTERN int log_level;



#ifndef LWS_LATENCY
static LWS_INLINE void
lws_latency(struct lws_context *context, struct lws *wsi, const char *action,
	    int ret, int completion) {
	do {
		(void)context; (void)wsi; (void)action; (void)ret;
		(void)completion;
	} while (0);
}
static LWS_INLINE void
lws_latency_pre(struct lws_context *context, struct lws *wsi) {
	do { (void)context; (void)wsi; } while (0);
}
#else
#define lws_latency_pre(_context, _wsi) lws_latency(_context, _wsi, NULL, 0, 0)
extern void
lws_latency(struct lws_context *context, struct lws *wsi, const char *action,
	    int ret, int completion);
#endif


LWS_EXTERN int
lws_b64_selftest(void);





#ifndef LWS_NO_DAEMONIZE
 LWS_EXTERN int get_daemonize_pid();
#else
 #define get_daemonize_pid() (0)
#endif

LWS_EXTERN void lwsl_emit_stderr(int level, const char *line);

#if !defined(LWS_WITH_TLS)
 #define LWS_SSL_ENABLED(context) (0)
 #define lws_context_init_server_ssl(_a, _b) (0)
 #define lws_ssl_destroy(_a)
 #define lws_context_init_alpn(_a)
 #define lws_ssl_capable_read lws_ssl_capable_read_no_ssl
 #define lws_ssl_capable_write lws_ssl_capable_write_no_ssl
 #define lws_ssl_pending lws_ssl_pending_no_ssl
 #define lws_server_socket_service_ssl(_b, _c) (0)
 #define lws_ssl_close(_a) (0)
 #define lws_ssl_context_destroy(_a)
 #define lws_ssl_SSL_CTX_destroy(_a)
 #define lws_ssl_remove_wsi_from_buffered_list(_a)
 #define __lws_ssl_remove_wsi_from_buffered_list(_a)
 #define lws_context_init_ssl_library(_a)
 #define lws_context_deinit_ssl_library(_a)
 #define lws_tls_check_all_cert_lifetimes(_a)
 #define lws_tls_acme_sni_cert_destroy(_a)
#endif



#if LWS_MAX_SMP > 1
#define lws_context_lock(c, reason) lws_mutex_refcount_lock(&c->mr, reason)
#define lws_context_unlock(c) lws_mutex_refcount_unlock(&c->mr)

static LWS_INLINE void
lws_vhost_lock(struct lws_vhost *vhost)
{
	pthread_mutex_lock(&vhost->lock);
}

static LWS_INLINE void
lws_vhost_unlock(struct lws_vhost *vhost)
{
	pthread_mutex_unlock(&vhost->lock);
}


#else
#define lws_pt_mutex_init(_a) (void)(_a)
#define lws_pt_mutex_destroy(_a) (void)(_a)
#define lws_pt_lock(_a, b) (void)(_a)
#define lws_pt_unlock(_a) (void)(_a)
#define lws_context_lock(_a, _b) (void)(_a)
#define lws_context_unlock(_a) (void)(_a)
#define lws_vhost_lock(_a) (void)(_a)
#define lws_vhost_unlock(_a) (void)(_a)
#define lws_pt_stats_lock(_a) (void)(_a)
#define lws_pt_stats_unlock(_a) (void)(_a)
#endif

LWS_EXTERN int LWS_WARN_UNUSED_RESULT
lws_ssl_capable_read_no_ssl(struct lws *wsi, unsigned char *buf, int len);

LWS_EXTERN int LWS_WARN_UNUSED_RESULT
lws_ssl_capable_write_no_ssl(struct lws *wsi, unsigned char *buf, int len);

LWS_EXTERN int LWS_WARN_UNUSED_RESULT
lws_ssl_pending_no_ssl(struct lws *wsi);

int
lws_tls_check_cert_lifetime(struct lws_vhost *vhost);

int lws_jws_selftest(void);
int lws_jwe_selftest(void);

int
lws_protocol_init(struct lws_context *context);

int
lws_bind_protocol(struct lws *wsi, const struct lws_protocols *p,
		  const char *reason);

const struct lws_protocol_vhost_options *
lws_vhost_protocol_options(struct lws_vhost *vh, const char *name);

const struct lws_http_mount *
lws_find_mount(struct lws *wsi, const char *uri_ptr, int uri_len);

/*
 * custom allocator
 */
LWS_EXTERN void *
lws_realloc(void *ptr, size_t size, const char *reason);

LWS_EXTERN void * LWS_WARN_UNUSED_RESULT
lws_zalloc(size_t size, const char *reason);

#ifdef LWS_PLAT_OPTEE
void *lws_malloc(size_t size, const char *reason);
void lws_free(void *p);
#define lws_free_set_NULL(P)    do { lws_free(P); (P) = NULL; } while(0)
#else
#define lws_malloc(S, R)	lws_realloc(NULL, S, R)
#define lws_free(P)	lws_realloc(P, 0, "lws_free")
#define lws_free_set_NULL(P)	do { lws_realloc(P, 0, "free"); (P) = NULL; } while(0)
#endif

int
lws_create_event_pipes(struct lws_context *context);

int
lws_plat_apply_FD_CLOEXEC(int n);

const struct lws_plat_file_ops *
lws_vfs_select_fops(const struct lws_plat_file_ops *fops, const char *vfs_path,
		    const char **vpath);

/* lws_plat_ */

LWS_EXTERN int
lws_plat_context_early_init(void);
LWS_EXTERN void
lws_plat_context_early_destroy(struct lws_context *context);
LWS_EXTERN void
lws_plat_context_late_destroy(struct lws_context *context);

LWS_EXTERN int
lws_plat_init(struct lws_context *context,
	      const struct lws_context_creation_info *info);
LWS_EXTERN int
lws_plat_drop_app_privileges(struct lws_context *context, int actually_drop);

#if defined(LWS_WITH_UNIX_SOCK)
int
lws_plat_user_colon_group_to_ids(const char *u_colon_g, uid_t *puid, gid_t *pgid);
#endif

LWS_EXTERN int
lws_check_byte_utf8(unsigned char state, unsigned char c);
LWS_EXTERN int LWS_WARN_UNUSED_RESULT
lws_check_utf8(unsigned char *state, unsigned char *buf, size_t len);
LWS_EXTERN int alloc_file(struct lws_context *context, const char *filename,
			  uint8_t **buf, lws_filepos_t *amount);

void
lws_context_destroy2(struct lws_context *context);


#ifdef __cplusplus
};
#endif
