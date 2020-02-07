/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2019 Andy Green <andy@warmcat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#if !defined(__LWS_CORE_NET_PRIVATE_H__)
#define __LWS_CORE_NET_PRIVATE_H__

#if !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200112L
#endif

/*
 * Generic pieces needed to manage muxable stream protocols like h2
 */

struct lws_muxable {
	struct lws	*parent_wsi;
	struct lws	*child_list;
	struct lws	*sibling_list;

	unsigned int	my_sid;
	unsigned int	child_count;

	uint8_t		requested_POLLOUT;
};

#include "private-lib-roles.h"

#ifdef LWS_WITH_IPV6
#if defined(WIN32) || defined(_WIN32)
#include <iphlpapi.h>
#else
#include <net/if.h>
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * All lws_tls...() functions must return this type, converting the
 * native backend result and doing the extra work to determine which one
 * as needed.
 *
 * Native TLS backend return codes are NOT ALLOWED outside the backend.
 *
 * Non-SSL mode also uses these types.
 */
enum lws_ssl_capable_status {
	LWS_SSL_CAPABLE_ERROR			= -1, /* it failed */
	LWS_SSL_CAPABLE_DONE			= 0,  /* it succeeded */
	LWS_SSL_CAPABLE_MORE_SERVICE_READ	= -2, /* retry WANT_READ */
	LWS_SSL_CAPABLE_MORE_SERVICE_WRITE	= -3, /* retry WANT_WRITE */
	LWS_SSL_CAPABLE_MORE_SERVICE		= -4, /* general retry */
};


/*
 *
 *  ------ roles ------
 *
 */

/* null-terminated array of pointers to roles lws built with */
extern const struct lws_role_ops *available_roles[];

#define LWS_FOR_EVERY_AVAILABLE_ROLE_START(xx) { \
		const struct lws_role_ops **ppxx = available_roles; \
		while (*ppxx) { \
			const struct lws_role_ops *xx = *ppxx++;

#define LWS_FOR_EVERY_AVAILABLE_ROLE_END }}

/*
 *
 *  ------ event_loop ops ------
 *
 */

/* enums of socks version */
enum socks_version {
	SOCKS_VERSION_4 = 4,
	SOCKS_VERSION_5 = 5
};

/* enums of subnegotiation version */
enum socks_subnegotiation_version {
	SOCKS_SUBNEGOTIATION_VERSION_1 = 1,
};

/* enums of socks commands */
enum socks_command {
	SOCKS_COMMAND_CONNECT = 1,
	SOCKS_COMMAND_BIND = 2,
	SOCKS_COMMAND_UDP_ASSOCIATE = 3
};

/* enums of socks address type */
enum socks_atyp {
	SOCKS_ATYP_IPV4 = 1,
	SOCKS_ATYP_DOMAINNAME = 3,
	SOCKS_ATYP_IPV6 = 4
};

/* enums of socks authentication methods */
enum socks_auth_method {
	SOCKS_AUTH_NO_AUTH = 0,
	SOCKS_AUTH_GSSAPI = 1,
	SOCKS_AUTH_USERNAME_PASSWORD = 2
};

/* enums of subnegotiation status */
enum socks_subnegotiation_status {
	SOCKS_SUBNEGOTIATION_STATUS_SUCCESS = 0,
};

/* enums of socks request reply */
enum socks_request_reply {
	SOCKS_REQUEST_REPLY_SUCCESS = 0,
	SOCKS_REQUEST_REPLY_FAILURE_GENERAL = 1,
	SOCKS_REQUEST_REPLY_CONNECTION_NOT_ALLOWED = 2,
	SOCKS_REQUEST_REPLY_NETWORK_UNREACHABLE = 3,
	SOCKS_REQUEST_REPLY_HOST_UNREACHABLE = 4,
	SOCKS_REQUEST_REPLY_CONNECTION_REFUSED = 5,
	SOCKS_REQUEST_REPLY_TTL_EXPIRED = 6,
	SOCKS_REQUEST_REPLY_COMMAND_NOT_SUPPORTED = 7,
	SOCKS_REQUEST_REPLY_ATYP_NOT_SUPPORTED = 8
};

/* enums used to generate socks messages */
enum socks_msg_type {
	/* greeting */
	SOCKS_MSG_GREETING,
	/* credential, user name and password */
	SOCKS_MSG_USERNAME_PASSWORD,
	/* connect command */
	SOCKS_MSG_CONNECT
};

enum {
	LWS_RXFLOW_ALLOW = (1 << 0),
	LWS_RXFLOW_PENDING_CHANGE = (1 << 1),
};

typedef enum lws_parser_return {
	LPR_FORBIDDEN	= -2,
	LPR_FAIL	= -1,
	LPR_OK		= 0,
	LPR_DO_FALLBACK = 2,
} lws_parser_return_t;

enum pmd_return {
	PMDR_UNKNOWN,
	PMDR_DID_NOTHING,
	PMDR_HAS_PENDING,
	PMDR_EMPTY_NONFINAL,
	PMDR_EMPTY_FINAL,

	PMDR_FAILED = -1
};

#if defined(LWS_WITH_PEER_LIMITS)
struct lws_peer {
	struct lws_peer *next;
	struct lws_peer *peer_wait_list;

	time_t time_created;
	time_t time_closed_all;

	uint8_t addr[32];
	uint32_t hash;
	uint32_t count_wsi;
	uint32_t total_wsi;

#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
	struct lws_peer_role_http http;
#endif

	uint8_t af;
};
#endif

enum {
	LWS_EV_READ = (1 << 0),
	LWS_EV_WRITE = (1 << 1),
	LWS_EV_START = (1 << 2),
	LWS_EV_STOP = (1 << 3),

	LWS_EV_PREPARE_DELETION = (1u << 31),
};

#ifdef LWS_WITH_IPV6
#define LWS_IPV6_ENABLED(vh) \
	(!lws_check_opt(vh->context->options, LWS_SERVER_OPTION_DISABLE_IPV6) && \
	 !lws_check_opt(vh->options, LWS_SERVER_OPTION_DISABLE_IPV6))
#else
#define LWS_IPV6_ENABLED(context) (0)
#endif

#ifdef LWS_WITH_UNIX_SOCK
#define LWS_UNIX_SOCK_ENABLED(vhost) \
	(vhost->options & LWS_SERVER_OPTION_UNIX_SOCK)
#else
#define LWS_UNIX_SOCK_ENABLED(vhost) (0)
#endif

enum uri_path_states {
	URIPS_IDLE,
	URIPS_SEEN_SLASH,
	URIPS_SEEN_SLASH_DOT,
	URIPS_SEEN_SLASH_DOT_DOT,
};

enum uri_esc_states {
	URIES_IDLE,
	URIES_SEEN_PERCENT,
	URIES_SEEN_PERCENT_H1,
};

#if defined(LWS_WITH_CLIENT)

enum {
	CIS_ADDRESS,
	CIS_PATH,
	CIS_HOST,
	CIS_ORIGIN,
	CIS_PROTOCOL,
	CIS_METHOD,
	CIS_IFACE,
	CIS_ALPN,


	CIS_COUNT
};

struct client_info_stash {
	char *cis[CIS_COUNT];
	void *opaque_user_data; /* not allocated or freed by lws */
};
#endif

#if defined(LWS_WITH_UDP)
#define lws_wsi_is_udp(___wsi) (!!___wsi->udp)
#endif

#define LWS_H2_FRAME_HEADER_LENGTH 9

int
__lws_sul_insert(lws_dll2_owner_t *own, lws_sorted_usec_list_t *sul,
		 lws_usec_t us);

lws_usec_t
__lws_sul_service_ripe(lws_dll2_owner_t *own, lws_usec_t usnow);

struct lws_timed_vh_protocol {
	struct lws_timed_vh_protocol	*next;
	lws_sorted_usec_list_t		sul;
	const struct lws_protocols	*protocol;
	struct lws_vhost *vhost; /* only used for pending processing */
	int				reason;
	int				tsi_req;
};

/*
 * lws_dsh
*/

typedef struct lws_dsh_obj_head {
	lws_dll2_owner_t		owner;
	int				kind;
} lws_dsh_obj_head_t;

typedef struct lws_dsh_obj {
	lws_dll2_t			list;	/* must be first */
	struct lws_dsh	  		*dsh;	/* invalid when on free list */
	size_t				size;	/* invalid when on free list */
	size_t				asize;
} lws_dsh_obj_t;

typedef struct lws_dsh {
	lws_dll2_t			list;
	uint8_t				*buf;
	lws_dsh_obj_head_t		*oha;	/* array of object heads/kind */
	size_t				buffer_size;
	size_t				locally_in_use;
	size_t				locally_free;
	int				count_kinds;
	uint8_t				being_destroyed;
	/*
	 * Overallocations at create:
	 *
	 *  - the buffer itself
	 *  - the object heads array
	 */
} lws_dsh_t;

/*
 * lws_async_dns
 */

typedef struct lws_async_dns {
	lws_sockaddr46 		sa46; /* nameserver */
	lws_dll2_owner_t	waiting;
	lws_dll2_owner_t	cached;
	struct lws		*wsi;
	time_t			time_set_server;
	char			dns_server_set;
} lws_async_dns_t;

typedef enum {
	LADNS_CONF_SERVER_UNKNOWN				= -1,
	LADNS_CONF_SERVER_SAME,
	LADNS_CONF_SERVER_CHANGED
} lws_async_dns_server_check_t;

#if defined(LWS_WITH_SYS_ASYNC_DNS)
void
lws_aysnc_dns_completed(struct lws *wsi, void *sa, size_t salen,
			lws_async_dns_retcode_t ret);
#endif
void
lws_async_dns_cancel(struct lws *wsi);

/*
 * so we can have n connections being serviced simultaneously,
 * these things need to be isolated per-thread.
 */

struct lws_context_per_thread {
#if LWS_MAX_SMP > 1
	pthread_mutex_t lock_stats;
	struct lws_mutex_refcount mr;
	pthread_t self;
#endif
	struct lws_dll2_owner dll_buflist_owner;  /* guys with pending rxflow */
	struct lws_dll2_owner seq_owner;	   /* list of lws_sequencer-s */
	lws_dll2_owner_t      attach_owner;	/* pending lws_attach */

	struct lws_dll2_owner pt_sul_owner;

#if defined (LWS_WITH_SEQUENCER)
	lws_sorted_usec_list_t sul_seq_heartbeat;
#endif
#if (defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)) && defined(LWS_WITH_SERVER)
	lws_sorted_usec_list_t sul_ah_lifecheck;
#endif
#if defined(LWS_WITH_TLS) && defined(LWS_WITH_SERVER)
	lws_sorted_usec_list_t sul_tls;
#endif
#if defined(LWS_PLAT_UNIX)
	lws_sorted_usec_list_t sul_plat;
#endif
#if defined(LWS_ROLE_CGI)
	lws_sorted_usec_list_t sul_cgi;
#endif
#if defined(LWS_WITH_STATS)
	uint64_t lws_stats[LWSSTATS_SIZE];
	int updated;
	lws_sorted_usec_list_t sul_stats;
#endif
#if defined(LWS_WITH_PEER_LIMITS)
	lws_sorted_usec_list_t sul_peer_limits;
#endif

#if defined(LWS_WITH_TLS)
	struct lws_pt_tls tls;
#endif
	struct lws *fake_wsi;	/* used for callbacks where there's no wsi */

	struct lws_context *context;

	/*
	 * usable by anything in the service code, but only if the scope
	 * does not last longer than the service action (since next service
	 * of any socket can likewise use it and overwrite)
	 */
	unsigned char *serv_buf;

	struct lws_pollfd *fds;
	volatile struct lws_foreign_thread_pollfd * volatile foreign_pfd_list;
#ifdef _WIN32
	WSAEVENT events;
	CRITICAL_SECTION interrupt_lock;
#endif
	lws_sockfd_type dummy_pipe_fds[2];
	struct lws *pipe_wsi;

	/* --- role based members --- */

#if defined(LWS_ROLE_WS) && !defined(LWS_WITHOUT_EXTENSIONS)
	struct lws_pt_role_ws ws;
#endif
#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
	struct lws_pt_role_http http;
#endif
#if defined(LWS_ROLE_DBUS)
	struct lws_pt_role_dbus dbus;
#endif

	/* --- event library based members --- */

#if defined(LWS_WITH_LIBEV)
	struct lws_pt_eventlibs_libev ev;
#endif
#if defined(LWS_WITH_LIBUV)
	struct lws_pt_eventlibs_libuv uv;
#endif
#if defined(LWS_WITH_LIBEVENT)
	struct lws_pt_eventlibs_libevent event;
#endif
#if defined(LWS_WITH_GLIB)
	struct lws_pt_eventlibs_glib glib;
#endif

#if defined(LWS_WITH_LIBEV) || defined(LWS_WITH_LIBUV) || \
    defined(LWS_WITH_LIBEVENT)
	struct lws_signal_watcher w_sigint;
#endif

#if defined(LWS_WITH_DETAILED_LATENCY)
	lws_usec_t	ust_left_poll;
#endif

	/* --- */

	unsigned long count_conns;
	unsigned int fds_count;

	/*
	 * set to the Thread ID that's doing the service loop just before entry
	 * to poll indicates service thread likely idling in poll()
	 * volatile because other threads may check it as part of processing
	 * for pollfd event change.
	 */
	volatile int service_tid;
	int service_tid_detected;

	volatile unsigned char inside_poll;
	volatile unsigned char foreign_spinlock;

	unsigned char tid;

	unsigned char inside_service:1;
	unsigned char inside_lws_service:1;
	unsigned char event_loop_foreign:1;
	unsigned char event_loop_destroy_processing_done:1;
	unsigned char destroy_self:1;
	unsigned char is_destroyed:1;
#ifdef _WIN32
	unsigned char interrupt_requested:1;
#endif
};

#if defined(LWS_WITH_SERVER_STATUS)
struct lws_conn_stats {
	unsigned long long rx, tx;
	unsigned long h1_conn, h1_trans, h2_trans, ws_upg, h2_alpn, h2_subs,
		      h2_upg, rejected;
};
#endif

/*
 * virtual host -related context information
 *   vhostwide SSL context
 *   vhostwide proxy
 *
 * hierarchy:
 *
 * context -> vhost -> wsi
 *
 * incoming connection non-SSL vhost binding:
 *
 *    listen socket -> wsi -> select vhost after first headers
 *
 * incoming connection SSL vhost binding:
 *
 *    SSL SNI -> wsi -> bind after SSL negotiation
 */

struct lws_vhost {
#if defined(LWS_WITH_CLIENT) && defined(LWS_CLIENT_HTTP_PROXYING)
	char proxy_basic_auth_token[128];
#endif
#if LWS_MAX_SMP > 1
	pthread_mutex_t lock;
	char close_flow_vs_tsi[LWS_MAX_SMP];
#endif

#if defined(LWS_ROLE_H2)
	struct lws_vhost_role_h2 h2;
#endif
#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
	struct lws_vhost_role_http http;
#endif
#if defined(LWS_ROLE_WS) && !defined(LWS_WITHOUT_EXTENSIONS)
	struct lws_vhost_role_ws ws;
#endif

#if defined(LWS_WITH_SOCKS5)
	char socks_proxy_address[128];
	char socks_user[96];
	char socks_password[96];
#endif
#if defined(LWS_WITH_LIBEV)
	struct lws_io_watcher w_accept;
#endif
#if defined(LWS_WITH_SERVER_STATUS)
	struct lws_conn_stats conn_stats;
#endif

	uint64_t options;

	struct lws_context *context;
	struct lws_vhost *vhost_next;

	const lws_retry_bo_t *retry_policy;

	struct lws *lserv_wsi;
	const char *name;
	const char *iface;
	const char *listen_accept_role;
	const char *listen_accept_protocol;
	const char *unix_socket_perms;

	void (*finalize)(struct lws_vhost *vh, void *arg);
	void *finalize_arg;

	const struct lws_protocols *protocols;
	void **protocol_vh_privs;
	const struct lws_protocol_vhost_options *pvo;
	const struct lws_protocol_vhost_options *headers;
	struct lws_dll2_owner *same_vh_protocol_owner;
	struct lws_vhost *no_listener_vhost_list;
	struct lws_dll2_owner abstract_instances_owner;		/* vh lock */

#if defined(LWS_WITH_CLIENT)
	struct lws_dll2_owner dll_cli_active_conns_owner;
#endif
	struct lws_dll2_owner vh_awaiting_socket_owner;

#if defined(LWS_WITH_TLS)
	struct lws_vhost_tls tls;
#endif

	struct lws_timed_vh_protocol *timed_vh_protocol_list;
	void *user;

	int listen_port;
#if !defined(LWS_PLAT_FREERTOS) && !defined(OPTEE_TA) && !defined(WIN32)
	int bind_iface;
#endif

#if defined(LWS_WITH_SOCKS5)
	unsigned int socks_proxy_port;
#endif
	int count_protocols;
	int ka_time;
	int ka_probes;
	int ka_interval;
	int keepalive_timeout;
	int timeout_secs_ah_idle;

	int count_bound_wsi;

#ifdef LWS_WITH_ACCESS_LOG
	int log_fd;
#endif

	unsigned int allocated_vhost_protocols:1;
	unsigned int created_vhost_protocols:1;
	unsigned int being_destroyed:1;

	unsigned char default_protocol_index;
	unsigned char raw_protocol_index;
};

void
__lws_vhost_destroy2(struct lws_vhost *vh);

#define mux_to_wsi(_m) lws_container_of(_m, struct lws, mux)

void
lws_wsi_mux_insert(struct lws *wsi, struct lws *parent_wsi, int sid);
int
lws_wsi_mux_mark_parents_needing_writeable(struct lws *wsi);
struct lws *
lws_wsi_mux_move_child_to_tail(struct lws **wsi2);
int
lws_wsi_mux_action_pending_writeable_reqs(struct lws *wsi);

void
lws_wsi_mux_dump_children(struct lws *wsi);

void
lws_wsi_mux_close_children(struct lws *wsi, int reason);

void
lws_wsi_mux_sibling_disconnect(struct lws *wsi);

void
lws_wsi_mux_dump_waiting_children(struct lws *wsi);

int
lws_wsi_mux_apply_queue(struct lws *wsi);

/*
 * struct lws
 */

struct lws {
	/* structs */

#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
	struct _lws_http_mode_related	http;
#endif
#if defined(LWS_ROLE_H2)
	struct _lws_h2_related		h2;
#endif
#if defined(LWS_ROLE_WS)
	struct _lws_websocket_related	*ws; /* allocated if we upgrade to ws */
#endif
#if defined(LWS_ROLE_DBUS)
	struct _lws_dbus_mode_related	dbus;
#endif

#if defined(LWS_ROLE_H2)
	struct lws_muxable		mux;
	struct lws_tx_credit		txc;
#endif

	/* lifetime members */

#if defined(LWS_WITH_LIBEV) || defined(LWS_WITH_LIBUV) || \
    defined(LWS_WITH_LIBEVENT) || defined(LWS_WITH_GLIB)
	struct lws_io_watcher		w_read;
#endif
#if defined(LWS_WITH_LIBEV) || defined(LWS_WITH_LIBEVENT)
	struct lws_io_watcher		w_write;
#endif

#if defined(LWS_WITH_DETAILED_LATENCY)
	lws_detlat_t	detlat;
#endif

	lws_sorted_usec_list_t		sul_timeout;
	lws_sorted_usec_list_t		sul_hrtimer;
	lws_sorted_usec_list_t		sul_validity;

	struct lws_dll2			dll_buflist; /* guys with pending rxflow */
	struct lws_dll2			same_vh_protocol;
	struct lws_dll2			vh_awaiting_socket;
#if defined(LWS_WITH_SYS_ASYNC_DNS)
	struct lws_dll2			adns; /* on adns list of guys to tell result */
	lws_async_dns_cb_t		adns_cb; /* callback with result */
#endif
#if defined(LWS_WITH_CLIENT)
	struct lws_dll2			dll_cli_active_conns;
	struct lws_dll2			dll2_cli_txn_queue;
	struct lws_dll2_owner		dll2_cli_txn_queue_owner;
#endif

#if defined(LWS_WITH_ACCESS_LOG)
	char simple_ip[(8 * 5)];
#endif
	/* pointers */

	struct lws_context		*context;
	struct lws_vhost		*vhost;
	struct lws			*parent; /* points to parent, if any */
	struct lws			*child_list; /* points to first child */
	struct lws			*sibling_list; /* subsequent children at same level */
	const struct lws_role_ops	*role_ops;
	const struct lws_protocols	*protocol;
	struct lws_sequencer		*seq;	/* associated sequencer if any */
	const lws_retry_bo_t		*retry_policy;

#if defined(LWS_WITH_THREADPOOL)
	struct lws_threadpool_task	*tp_task;
#endif

#if defined(LWS_WITH_PEER_LIMITS)
	struct lws_peer			*peer;
#endif

#if defined(LWS_WITH_UDP)
	struct lws_udp			*udp;
#endif
#if defined(LWS_WITH_CLIENT)
	struct client_info_stash	*stash;
	char				*cli_hostname_copy;
	const struct addrinfo		*dns_results;
	const struct addrinfo		*dns_results_next;
#endif
	void				*user_space;
	void				*opaque_parent_data;
	void				*opaque_user_data;

	struct lws_buflist		*buflist; /* input-side buflist */
	struct lws_buflist		*buflist_out; /* output-side buflist */

#if defined(LWS_WITH_TLS)
	struct lws_lws_tls		tls;
#endif

	lws_sock_file_fd_type		desc; /* .filefd / .sockfd */
#if defined(LWS_WITH_STATS)
	uint64_t active_writable_req_us;
#if defined(LWS_WITH_TLS)
	uint64_t accept_start_us;
#endif
#endif
	lws_wsi_state_t			wsistate;
	lws_wsi_state_t			wsistate_pre_close;

	/* ints */
#define LWS_NO_FDS_POS (-1)
	int				position_in_fds_table;

#if defined(LWS_WITH_CLIENT)
	int				chunk_remaining;
	int				flags;
#endif
	unsigned int			cache_secs;

	unsigned int			hdr_parsing_completed:1;
	unsigned int			mux_substream:1;
	unsigned int			upgraded_to_http2:1;
	unsigned int			mux_stream_immortal:1;
	unsigned int			h2_stream_carries_ws:1; /* immortal set as well */
	unsigned int			h2_stream_carries_sse:1; /* immortal set as well */
	unsigned int			h2_acked_settings:1;
	unsigned int			seen_nonpseudoheader:1;
	unsigned int			listener:1;
	unsigned int			pf_packet:1;
	unsigned int			do_broadcast:1;
	unsigned int			user_space_externally_allocated:1;
	unsigned int			socket_is_permanently_unusable:1;
	unsigned int			rxflow_change_to:2;
	unsigned int			conn_stat_done:1;
	unsigned int			cache_reuse:1;
	unsigned int			cache_revalidate:1;
	unsigned int			cache_intermediaries:1;
	unsigned int			favoured_pollin:1;
	unsigned int			sending_chunked:1;
	unsigned int			interpreting:1;
	unsigned int			already_did_cce:1;
	unsigned int			told_user_closed:1;
	unsigned int			told_event_loop_closed:1;
	unsigned int			waiting_to_send_close_frame:1;
	unsigned int			close_needs_ack:1;
	unsigned int			ipv6:1;
	unsigned int			parent_pending_cb_on_writable:1;
	unsigned int			cgi_stdout_zero_length:1;
	unsigned int			seen_zero_length_recv:1;
	unsigned int			rxflow_will_be_applied:1;
	unsigned int			event_pipe:1;
	unsigned int			handling_404:1;
	unsigned int			protocol_bind_balance:1;
	unsigned int			unix_skt:1;
	unsigned int			close_when_buffered_out_drained:1;
	unsigned int			h1_ws_proxied:1;
	unsigned int			proxied_ws_parent:1;
	unsigned int			do_bind:1;
	unsigned int			oom4:1;
	unsigned int			validity_hup:1;

	unsigned int			could_have_pending:1; /* detect back-to-back writes */
	unsigned int			outer_will_close:1;
	unsigned int			shadow:1; /* we do not control fd lifecycle at all */

#ifdef LWS_WITH_ACCESS_LOG
	unsigned int			access_log_pending:1;
#endif
#if defined(LWS_WITH_CLIENT)
	unsigned int			do_ws:1; /* whether we are doing http or ws flow */
	unsigned int			chunked:1; /* if the clientside connection is chunked */
	unsigned int			client_rx_avail:1;
	unsigned int			client_http_body_pending:1;
	unsigned int			transaction_from_pipeline_queue:1;
	unsigned int			keepalive_active:1;
	unsigned int			keepalive_rejected:1;
	unsigned int			redirected_to_get:1;
	unsigned int			client_pipeline:1;
	unsigned int			client_h2_alpn:1;
	unsigned int			client_mux_substream:1;
	unsigned int			client_mux_migrated:1;
	unsigned int			client_subsequent_mime_part:1;
	unsigned int                    client_no_follow_redirect:1;
#endif

#ifdef _WIN32
	unsigned int sock_send_blocking:1;
#endif

	uint16_t			ocport, c_port;
	uint16_t			retry;

	/* chars */

	char lws_rx_parse_state; /* enum lws_rx_parse_state */
	char rx_frame_type; /* enum lws_write_protocol */
	char pending_timeout; /* enum pending_timeout */
	char tsi; /* thread service index we belong to */
	char protocol_interpret_idx;
	char redirects;
	uint8_t rxflow_bitmap;
	uint8_t bound_vhost_index;
#ifdef LWS_WITH_CGI
	char cgi_channel; /* which of stdin/out/err */
	char hdr_state;
#endif
#if defined(LWS_WITH_CLIENT)
	char chunk_parser; /* enum lws_chunk_parser */
	uint8_t addrinfo_idx;
	uint8_t sys_tls_client_cert;
#endif
#if defined(LWS_WITH_CGI) || defined(LWS_WITH_CLIENT)
	char reason_bf; /* internal writeable callback reason bitfield */
#endif
#if defined(LWS_WITH_STATS) && defined(LWS_WITH_TLS)
	char seen_rx;
#endif
	uint8_t immortal_substream_count;
	/* volatile to make sure code is aware other thread can change */
	volatile char handling_pollout;
	volatile char leave_pollout_active;
#if LWS_MAX_SMP > 1
	volatile char undergoing_init_from_other_pt;
#endif

};

#define lws_is_flowcontrolled(w) (!!(wsi->rxflow_bitmap))

void
lws_service_do_ripe_rxflow(struct lws_context_per_thread *pt);

const struct lws_role_ops *
lws_role_by_name(const char *name);

int
lws_socket_bind(struct lws_vhost *vhost, lws_sockfd_type sockfd, int port,
		const char *iface, int ipv6_allowed);

#if defined(LWS_WITH_IPV6)
unsigned long
lws_get_addr_scope(const char *ipaddr);
#endif

void
lws_close_free_wsi(struct lws *wsi, enum lws_close_status, const char *caller);
void
__lws_close_free_wsi(struct lws *wsi, enum lws_close_status, const char *caller);

void
__lws_free_wsi(struct lws *wsi);

#if LWS_MAX_SMP > 1

static LWS_INLINE void
lws_pt_mutex_init(struct lws_context_per_thread *pt)
{
	lws_mutex_refcount_init(&pt->mr);
	pthread_mutex_init(&pt->lock_stats, NULL);
}

static LWS_INLINE void
lws_pt_mutex_destroy(struct lws_context_per_thread *pt)
{
	pthread_mutex_destroy(&pt->lock_stats);
	lws_mutex_refcount_destroy(&pt->mr);
}

#define lws_pt_lock(pt, reason) lws_mutex_refcount_lock(&pt->mr, reason)
#define lws_pt_unlock(pt) lws_mutex_refcount_unlock(&pt->mr)

static LWS_INLINE void
lws_pt_stats_lock(struct lws_context_per_thread *pt)
{
	pthread_mutex_lock(&pt->lock_stats);
}

static LWS_INLINE void
lws_pt_stats_unlock(struct lws_context_per_thread *pt)
{
	pthread_mutex_unlock(&pt->lock_stats);
}
#endif

/*
 * EXTENSIONS
 */

#if defined(LWS_WITHOUT_EXTENSIONS)
#define lws_any_extension_handled(_a, _b, _c, _d) (0)
#define lws_ext_cb_active(_a, _b, _c, _d) (0)
#define lws_ext_cb_all_exts(_a, _b, _c, _d, _e) (0)
#define lws_issue_raw_ext_access lws_issue_raw
#define lws_context_init_extensions(_a, _b)
#endif

int LWS_WARN_UNUSED_RESULT
lws_client_interpret_server_handshake(struct lws *wsi);

int LWS_WARN_UNUSED_RESULT
lws_ws_rx_sm(struct lws *wsi, char already_processed, unsigned char c);

int LWS_WARN_UNUSED_RESULT
lws_issue_raw_ext_access(struct lws *wsi, unsigned char *buf, size_t len);

void
lws_role_transition(struct lws *wsi, enum lwsi_role role, enum lwsi_state state,
		    const struct lws_role_ops *ops);

int
lws_http_to_fallback(struct lws *wsi, unsigned char *buf, size_t len);

int LWS_WARN_UNUSED_RESULT
user_callback_handle_rxflow(lws_callback_function, struct lws *wsi,
			    enum lws_callback_reasons reason, void *user,
			    void *in, size_t len);

int
lws_plat_set_nonblocking(lws_sockfd_type fd);

int
lws_plat_set_socket_options(struct lws_vhost *vhost, lws_sockfd_type fd,
			    int unix_skt);

int
lws_plat_check_connection_error(struct lws *wsi);

int LWS_WARN_UNUSED_RESULT
lws_header_table_attach(struct lws *wsi, int autoservice);

int
lws_header_table_detach(struct lws *wsi, int autoservice);
int
__lws_header_table_detach(struct lws *wsi, int autoservice);

void
lws_header_table_reset(struct lws *wsi, int autoservice);

void
__lws_header_table_reset(struct lws *wsi, int autoservice);

char * LWS_WARN_UNUSED_RESULT
lws_hdr_simple_ptr(struct lws *wsi, enum lws_token_indexes h);

int LWS_WARN_UNUSED_RESULT
lws_hdr_simple_create(struct lws *wsi, enum lws_token_indexes h, const char *s);

int LWS_WARN_UNUSED_RESULT
lws_ensure_user_space(struct lws *wsi);

int LWS_WARN_UNUSED_RESULT
lws_change_pollfd(struct lws *wsi, int _and, int _or);

#if defined(LWS_WITH_SERVER)
 int _lws_vhost_init_server(const struct lws_context_creation_info *info,
			      struct lws_vhost *vhost);
 LWS_EXTERN struct lws_vhost *
 lws_select_vhost(struct lws_context *context, int port, const char *servername);
 LWS_EXTERN int LWS_WARN_UNUSED_RESULT
 lws_parse_ws(struct lws *wsi, unsigned char **buf, size_t len);
 LWS_EXTERN void
 lws_server_get_canonical_hostname(struct lws_context *context,
				   const struct lws_context_creation_info *info);
#else
 #define _lws_vhost_init_server(_a, _b) (0)
 #define lws_parse_ws(_a, _b, _c) (0)
 #define lws_server_get_canonical_hostname(_a, _b)
#endif

int
__remove_wsi_socket_from_fds(struct lws *wsi);

enum {
	LWSRXFC_ERROR = -1,
	LWSRXFC_CACHED = 0,
	LWSRXFC_ADDITIONAL = 1,
	LWSRXFC_TRIMMED = 2,
};


int
_lws_plat_service_forced_tsi(struct lws_context *context, int tsi);

int
lws_rxflow_cache(struct lws *wsi, unsigned char *buf, int n, int len);

int
lws_service_flag_pending(struct lws_context *context, int tsi);

static LWS_INLINE int
lws_has_buffered_out(struct lws *wsi) { return !!wsi->buflist_out; }

int LWS_WARN_UNUSED_RESULT
lws_ws_client_rx_sm(struct lws *wsi, unsigned char c);

lws_parser_return_t LWS_WARN_UNUSED_RESULT
lws_parse(struct lws *wsi, unsigned char *buf, int *len);

int LWS_WARN_UNUSED_RESULT
lws_parse_urldecode(struct lws *wsi, uint8_t *_c);

int LWS_WARN_UNUSED_RESULT
lws_http_action(struct lws *wsi);

void
__lws_close_free_wsi_final(struct lws *wsi);
void
lws_libuv_closehandle(struct lws *wsi);
int
lws_libuv_check_watcher_active(struct lws *wsi);

LWS_VISIBLE LWS_EXTERN int
lws_plat_plugins_init(struct lws_context * context, const char * const *d);

LWS_VISIBLE LWS_EXTERN int
lws_plat_plugins_destroy(struct lws_context * context);

struct lws *
lws_adopt_socket_vhost(struct lws_vhost *vh, lws_sockfd_type accept_fd);

void
lws_vhost_bind_wsi(struct lws_vhost *vh, struct lws *wsi);
void
lws_vhost_unbind_wsi(struct lws *wsi);

void
__lws_set_timeout(struct lws *wsi, enum pending_timeout reason, int secs);
int
__lws_change_pollfd(struct lws *wsi, int _and, int _or);


int
lws_callback_as_writeable(struct lws *wsi);

int
lws_role_call_client_bind(struct lws *wsi,
			  const struct lws_client_connect_info *i);
void
lws_remove_child_from_any_parent(struct lws *wsi);

char *
lws_generate_client_ws_handshake(struct lws *wsi, char *p, const char *conn1);
int
lws_client_ws_upgrade(struct lws *wsi, const char **cce);
int
lws_create_client_ws_object(const struct lws_client_connect_info *i,
			    struct lws *wsi);
int
lws_alpn_comma_to_openssl(const char *comma, uint8_t *os, int len);
int
lws_role_call_alpn_negotiated(struct lws *wsi, const char *alpn);
int
lws_tls_server_conn_alpn(struct lws *wsi);

int
lws_ws_client_rx_sm_block(struct lws *wsi, unsigned char **buf, size_t len);
void
lws_destroy_event_pipe(struct lws *wsi);

/* socks */
int
socks_generate_msg(struct lws *wsi, enum socks_msg_type type, ssize_t *msg_len);

#if defined(LWS_WITH_SERVER_STATUS)
void
lws_sum_stats(const struct lws_context *ctx, struct lws_conn_stats *cs);
#endif

int
__lws_timed_callback_remove(struct lws_vhost *vh, struct lws_timed_vh_protocol *p);

int LWS_WARN_UNUSED_RESULT
__insert_wsi_socket_into_fds(struct lws_context *context, struct lws *wsi);

int LWS_WARN_UNUSED_RESULT
lws_issue_raw(struct lws *wsi, unsigned char *buf, size_t len);

lws_usec_t
__lws_seq_timeout_check(struct lws_context_per_thread *pt, lws_usec_t usnow);

struct lws * LWS_WARN_UNUSED_RESULT
lws_client_connect_2_dnsreq(struct lws *wsi);

LWS_VISIBLE struct lws * LWS_WARN_UNUSED_RESULT
lws_client_reset(struct lws **wsi, int ssl, const char *address, int port,
		 const char *path, const char *host, char weak);

struct lws * LWS_WARN_UNUSED_RESULT
lws_create_new_server_wsi(struct lws_vhost *vhost, int fixed_tsi);

char * LWS_WARN_UNUSED_RESULT
lws_generate_client_handshake(struct lws *wsi, char *pkt);

int
lws_handle_POLLOUT_event(struct lws *wsi, struct lws_pollfd *pollfd);

struct lws *
lws_http_client_connect_via_info2(struct lws *wsi);


#if defined(LWS_WITH_CLIENT)
int
lws_client_socket_service(struct lws *wsi, struct lws_pollfd *pollfd);

int LWS_WARN_UNUSED_RESULT
lws_http_transaction_completed_client(struct lws *wsi);
#if !defined(LWS_WITH_TLS)
	#define lws_context_init_client_ssl(_a, _b) (0)
#endif
void
lws_decode_ssl_error(void);
#else
#define lws_context_init_client_ssl(_a, _b) (0)
#endif

int
__lws_rx_flow_control(struct lws *wsi);

int
_lws_change_pollfd(struct lws *wsi, int _and, int _or, struct lws_pollargs *pa);

#if defined(LWS_WITH_SERVER)
int
lws_handshake_server(struct lws *wsi, unsigned char **buf, size_t len);
#else
#define lws_server_socket_service(_b, _c) (0)
#define lws_handshake_server(_a, _b, _c) (0)
#endif

#ifdef LWS_WITH_ACCESS_LOG
int
lws_access_log(struct lws *wsi);
void
lws_prepare_access_log_info(struct lws *wsi, char *uri_ptr, int len, int meth);
#else
#define lws_access_log(_a)
#endif

#if defined(_DEBUG)
void
lws_wsi_txc_describe(struct lws_tx_credit *txc, const char *at, uint32_t sid);
#else
#define lws_wsi_txc_describe(x, y, z) { (void)x; }
#endif

int
lws_wsi_txc_check_skint(struct lws_tx_credit *txc, int32_t tx_cr);

int
lws_wsi_txc_report_manual_txcr_in(struct lws *wsi, int32_t bump);

void
lws_mux_mark_immortal(struct lws *wsi);
void
lws_http_close_immortal(struct lws *wsi);

int
lws_cgi_kill_terminated(struct lws_context_per_thread *pt);

void
lws_cgi_remove_and_kill(struct lws *wsi);

void
lws_plat_delete_socket_from_fds(struct lws_context *context,
				struct lws *wsi, int m);
void
lws_plat_insert_socket_into_fds(struct lws_context *context,
				struct lws *wsi);

int
lws_plat_change_pollfd(struct lws_context *context, struct lws *wsi,
		       struct lws_pollfd *pfd);


int
lws_plat_pipe_create(struct lws *wsi);
int
lws_plat_pipe_signal(struct lws *wsi);
void
lws_plat_pipe_close(struct lws *wsi);

void
lws_addrinfo_clean(struct lws *wsi);

void
lws_add_wsi_to_draining_ext_list(struct lws *wsi);
void
lws_remove_wsi_from_draining_ext_list(struct lws *wsi);
int
lws_poll_listen_fd(struct lws_pollfd *fd);
int
lws_plat_service(struct lws_context *context, int timeout_ms);
LWS_VISIBLE int
_lws_plat_service_tsi(struct lws_context *context, int timeout_ms, int tsi);

int
lws_pthread_self_to_tsi(struct lws_context *context);
const char * LWS_WARN_UNUSED_RESULT
lws_plat_inet_ntop(int af, const void *src, char *dst, int cnt);
int LWS_WARN_UNUSED_RESULT
lws_plat_inet_pton(int af, const char *src, void *dst);

void
lws_same_vh_protocol_remove(struct lws *wsi);
void
__lws_same_vh_protocol_remove(struct lws *wsi);
void
lws_same_vh_protocol_insert(struct lws *wsi, int n);

void
lws_seq_destroy_all_on_pt(struct lws_context_per_thread *pt);

int
lws_broadcast(struct lws_context_per_thread *pt, int reason, void *in, size_t len);

#if defined(LWS_WITH_STATS)
 void
 lws_stats_bump(struct lws_context_per_thread *pt, int i, uint64_t bump);
 void
 lws_stats_max(struct lws_context_per_thread *pt, int index, uint64_t val);
#else
 static LWS_INLINE uint64_t lws_stats_bump(
		struct lws_context_per_thread *pt, int index, uint64_t bump) {
	(void)pt; (void)index; (void)bump; return 0; }
 static LWS_INLINE uint64_t lws_stats_max(
		struct lws_context_per_thread *pt, int index, uint64_t val) {
	(void)pt; (void)index; (void)val; return 0; }
#endif



#if defined(LWS_WITH_PEER_LIMITS)
void
lws_peer_track_wsi_close(struct lws_context *context, struct lws_peer *peer);
int
lws_peer_confirm_ah_attach_ok(struct lws_context *context,
			      struct lws_peer *peer);
void
lws_peer_track_ah_detach(struct lws_context *context, struct lws_peer *peer);
void
lws_peer_cull_peer_wait_list(struct lws_context *context);
struct lws_peer *
lws_get_or_create_peer(struct lws_vhost *vhost, lws_sockfd_type sockfd);
void
lws_peer_add_wsi(struct lws_context *context, struct lws_peer *peer,
		 struct lws *wsi);
void
lws_peer_dump_from_wsi(struct lws *wsi);
#endif

#ifdef LWS_WITH_HUBBUB
hubbub_error
html_parser_cb(const hubbub_token *token, void *pw);
#endif

int
lws_threadpool_tsi_context(struct lws_context *context, int tsi);

void
__lws_wsi_remove_from_sul(struct lws *wsi);

void
lws_validity_confirmed(struct lws *wsi);
void
_lws_validity_confirmed_role(struct lws *wsi);

int
lws_seq_pt_init(struct lws_context_per_thread *pt);

int
lws_buflist_aware_read(struct lws_context_per_thread *pt, struct lws *wsi,
		       struct lws_tokens *ebuf, char fr, const char *hint);
int
lws_buflist_aware_finished_consuming(struct lws *wsi, struct lws_tokens *ebuf,
				     int used, int buffered, const char *hint);

extern const struct lws_protocols protocol_abs_client_raw_skt,
				  protocol_abs_client_unit_test;

void
__lws_reset_wsi(struct lws *wsi);

void
lws_inform_client_conn_fail(struct lws *wsi, void *arg, size_t len);

#if defined(LWS_WITH_SYS_ASYNC_DNS)
lws_async_dns_server_check_t
lws_plat_asyncdns_init(struct lws_context *context, lws_sockaddr46 *sa);
int
lws_async_dns_init(struct lws_context *context);
void
lws_async_dns_deinit(lws_async_dns_t *dns);
#endif

int
lws_protocol_init_vhost(struct lws_vhost *vh, int *any);
int
_lws_generic_transaction_completed_active_conn(struct lws **wsi);

#define ACTIVE_CONNS_SOLO 0
#define ACTIVE_CONNS_MUXED 1
#define ACTIVE_CONNS_QUEUED 2

int
lws_vhost_active_conns(struct lws *wsi, struct lws **nwsi, const char *adsin);

const char *
lws_wsi_client_stash_item(struct lws *wsi, int stash_idx, int hdr_idx);

int
lws_plat_BINDTODEVICE(lws_sockfd_type fd, const char *ifname);

#ifdef __cplusplus
};
#endif

#endif
