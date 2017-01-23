/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2016 Andy Green <andy@warmcat.com>
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


#if defined(LWS_WITH_CGI) && defined(LWS_HAVE_VFORK)
#define  _GNU_SOURCE
#endif

#ifdef LWS_HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <limits.h>
#include <stdarg.h>
#if defined(LWS_WITH_ESP8266)
#include <user_interface.h>
#define assert(n)

/* rom-provided stdc functions for free, ensure use these instead of libc ones */

int ets_vsprintf(char *str, const char *format, va_list argptr);
int ets_vsnprintf(char *buffer, size_t sizeOfBuffer,  const char *format, va_list argptr);
int ets_snprintf(char *str, size_t size, const char *format, ...);
int ets_sprintf(char *str, const char *format, ...);
int os_printf_plus(const char *format, ...);
#undef malloc
#undef realloc
#undef free
void *pvPortMalloc(size_t s, const char *f, int line);
#define malloc(s) pvPortMalloc(s, "", 0)
void *pvPortRealloc(void *p, size_t s, const char *f, int line);
#define realloc(p, s) pvPortRealloc(p, s, "", 0)
void vPortFree(void *p, const char *f, int line);
#define free(p) vPortFree(p, "", 0)
#undef memcpy
void *ets_memcpy(void *dest, const void *src, size_t n);
#define memcpy ets_memcpy
void *ets_memset(void *dest, int v, size_t n);
#define memset ets_memset
char *ets_strcpy(char *dest, const char *src);
#define strcpy ets_strcpy
char *ets_strncpy(char *dest, const char *src, size_t n);
#define strncpy ets_strncpy
char *ets_strstr(const char *haystack, const char *needle);
#define strstr ets_strstr
int ets_strcmp(const char *s1, const char *s2);
int ets_strncmp(const char *s1, const char *s2, size_t n);
#define strcmp ets_strcmp
#define strncmp ets_strncmp
size_t ets_strlen(const char *s);
#define strlen ets_strlen
void *ets_memmove(void *dest, const void *src, size_t n);
#define memmove ets_memmove
char *ets_strchr(const char *s, int c);
#define strchr_ets_strchr
#undef _DEBUG
#include <osapi.h>

#else
#define STORE_IN_ROM
#include <assert.h>
#endif
#if LWS_MAX_SMP > 1
#include <pthread.h>
#endif

#ifdef LWS_HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#if defined(WIN32) || defined(_WIN32)
#if (WINVER < 0x0501)
#undef WINVER
#undef _WIN32_WINNT
#define WINVER 0x0501
#define _WIN32_WINNT WINVER
#endif
#define LWS_NO_DAEMONIZE
#define LWS_ERRNO WSAGetLastError()
#define LWS_EAGAIN WSAEWOULDBLOCK
#define LWS_EALREADY WSAEALREADY
#define LWS_EINPROGRESS WSAEINPROGRESS
#define LWS_EINTR WSAEINTR
#define LWS_EISCONN WSAEISCONN
#define LWS_EWOULDBLOCK WSAEWOULDBLOCK
#define MSG_NOSIGNAL 0
#define SHUT_RDWR SD_BOTH
#define SOL_TCP IPPROTO_TCP
#define SHUT_WR SD_SEND

#define compatible_close(fd) closesocket(fd)
#define lws_set_blocking_send(wsi) wsi->sock_send_blocking = 1
#define lws_socket_is_valid(x) (!!x)
#define LWS_SOCK_INVALID 0
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <tchar.h>
#ifdef LWS_HAVE_IN6ADDR_H
#include <in6addr.h>
#endif
#include <mstcpip.h>
#include <io.h>

#ifndef __func__
#define __func__ __FUNCTION__
#endif

#ifdef LWS_HAVE__VSNPRINTF
#define vsnprintf _vsnprintf
#endif

/* we don't have an implementation for this on windows... */
int kill(int pid, int sig);
int fork(void);
#ifndef SIGINT
#define SIGINT 2
#endif

#else /* not windows --> */

#include <fcntl.h>
#include <strings.h>
#include <unistd.h>
#include <sys/types.h>
#ifndef MBED_OPERATORS
#ifndef __cplusplus
#include <errno.h>
#endif
#include <netdb.h>
#include <signal.h>
#ifdef LWS_WITH_ESP8266
#include <sockets.h>
#define vsnprintf ets_vsnprintf
#define snprintf ets_snprintf
#define sprintf ets_sprintf

int kill(int pid, int sig);

#else
#include <sys/socket.h>
#endif
#ifdef LWS_WITH_HTTP_PROXY
#include <hubbub/hubbub.h>
#include <hubbub/parser.h>
#endif
#if defined(LWS_BUILTIN_GETIFADDRS)
 #include <getifaddrs.h>
#else
 #if !defined(LWS_WITH_ESP8266)
 #include <ifaddrs.h>
 #endif
#endif
#if defined (__ANDROID__)
#include <syslog.h>
#include <sys/resource.h>
#elif defined (__sun)
#include <syslog.h>
#else
#if !defined(LWS_WITH_ESP8266)
#include <sys/syslog.h>
#endif
#endif
#include <netdb.h>
#if !defined(LWS_WITH_ESP8266)
#include <sys/mman.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <poll.h>
#endif
#ifdef LWS_USE_LIBEV
#include <ev.h>
#endif
#ifdef LWS_USE_LIBUV
#include <uv.h>
#endif

#endif /* MBED */

#ifndef LWS_NO_FORK
#ifdef LWS_HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif
#endif

#include <sys/time.h>

#define LWS_ERRNO errno
#define LWS_EAGAIN EAGAIN
#define LWS_EALREADY EALREADY
#define LWS_EINPROGRESS EINPROGRESS
#define LWS_EINTR EINTR
#define LWS_EISCONN EISCONN
#define LWS_EWOULDBLOCK EWOULDBLOCK

#define lws_set_blocking_send(wsi)

#if defined(MBED_OPERATORS) || defined(LWS_WITH_ESP8266)
#define lws_socket_is_valid(x) ((x) != NULL)
#define LWS_SOCK_INVALID (NULL)
struct lws;
const char *
lws_plat_get_peer_simple(struct lws *wsi, char *name, int namelen);
#else
#define lws_socket_is_valid(x) (x >= 0)
#define LWS_SOCK_INVALID (-1)
#endif
#endif

#ifndef LWS_HAVE_BZERO
#ifndef bzero
#define bzero(b, len) (memset((b), '\0', (len)), (void) 0)
#endif
#endif

#ifndef LWS_HAVE_STRERROR
#define strerror(x) ""
#endif

#ifdef LWS_OPENSSL_SUPPORT

#ifdef USE_WOLFSSL
#ifdef USE_OLD_CYASSL
#include <cyassl/openssl/ssl.h>
#include <cyassl/error-ssl.h>
#else
#include <wolfssl/openssl/ssl.h>
#include <wolfssl/error-ssl.h>
#define OPENSSL_NO_TLSEXT
#endif /* not USE_OLD_CYASSL */
#else
#if defined(LWS_USE_POLARSSL)
#include <polarssl/ssl.h>
#include <polarssl/error.h>
#include <polarssl/md5.h>
#include <polarssl/sha1.h>
#include <polarssl/ecdh.h>
#define SSL_ERROR_WANT_READ POLARSSL_ERR_NET_WANT_READ
#define SSL_ERROR_WANT_WRITE POLARSSL_ERR_NET_WANT_WRITE
#define OPENSSL_VERSION_NUMBER  0x10002000L
#else
#if defined(LWS_USE_MBEDTLS)
#include <mbedtls/ssl.h>
#include <mbedtls/error.h>
#include <mbedtls/md5.h>
#include <mbedtls/sha1.h>
#include <mbedtls/ecdh.h>
#else
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#ifdef LWS_HAVE_OPENSSL_ECDH_H
#include <openssl/ecdh.h>
#endif
#include <openssl/x509v3.h>

#if (OPENSSL_VERSION_NUMBER < 0x0009080afL)
/* later openssl defines this to negate the presence of tlsext... but it was only
 * introduced at 0.9.8j.  Earlier versions don't know it exists so don't
 * define it... making it look like the feature exists...
 */
#define OPENSSL_NO_TLSEXT
#endif

#endif /* not USE_MBEDTLS */
#endif /* not USE_POLARSSL */
#endif /* not USE_WOLFSSL */
#endif

#include "libwebsockets.h"
#if defined(WIN32) || defined(_WIN32)
#else
static inline int compatible_close(int fd) { return close(fd); }
#endif

#if defined(WIN32) || defined(_WIN32)
#include <gettimeofday.h>
#endif

#if defined(MBED_OPERATORS)
#undef compatible_close
#define compatible_close(fd) mbed3_delete_tcp_stream_socket(fd)
#ifndef BIG_ENDIAN
#define BIG_ENDIAN    4321  /* to show byte order (taken from gcc) */
#endif
#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN 1234
#endif
#ifndef BYTE_ORDER
#define BYTE_ORDER LITTLE_ENDIAN
#endif
#endif

#if defined(LWS_WITH_ESP8266)
#undef compatible_close
#define compatible_close(fd) { fd->state=ESPCONN_CLOSE; espconn_delete(fd); }
lws_sockfd_type
esp8266_create_tcp_stream_socket(void);
void
esp8266_tcp_stream_bind(lws_sockfd_type fd, int port, struct lws *wsi);
#ifndef BIG_ENDIAN
#define BIG_ENDIAN    4321  /* to show byte order (taken from gcc) */
#endif
#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN 1234
#endif
#ifndef BYTE_ORDER
#define BYTE_ORDER LITTLE_ENDIAN
#endif
#endif


#if defined(WIN32) || defined(_WIN32)

#ifndef BIG_ENDIAN
#define BIG_ENDIAN    4321  /* to show byte order (taken from gcc) */
#endif
#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN 1234
#endif
#ifndef BYTE_ORDER
#define BYTE_ORDER LITTLE_ENDIAN
#endif
#ifndef u_int64_t
typedef unsigned __int64 u_int64_t;
#endif

#undef __P
#ifndef __P
#if __STDC__
#define __P(protos) protos
#else
#define __P(protos) ()
#endif
#endif

#else

#include <sys/stat.h>
#include <sys/time.h>

#if defined(__APPLE__)
#include <machine/endian.h>
#elif defined(__FreeBSD__)
#include <sys/endian.h>
#elif defined(__linux__)
#include <endian.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__QNX__)
	#include <gulliver.h>
	#if defined(__LITTLEENDIAN__)
		#define BYTE_ORDER __LITTLEENDIAN__
		#define LITTLE_ENDIAN __LITTLEENDIAN__
		#define BIG_ENDIAN 4321  /* to show byte order (taken from gcc); for suppres warning that BIG_ENDIAN is not defined. */
	#endif
	#if defined(__BIGENDIAN__)
		#define BYTE_ORDER __BIGENDIAN__
		#define LITTLE_ENDIAN 1234  /* to show byte order (taken from gcc); for suppres warning that LITTLE_ENDIAN is not defined. */
		#define BIG_ENDIAN __BIGENDIAN__
	#endif
#endif

#if defined(__sun) && defined(__GNUC__)
# define BYTE_ORDER __BYTE_ORDER__
# define LITTLE_ENDIAN __ORDER_LITTLE_ENDIAN__
# define BIG_ENDIAN __ORDER_BIG_ENDIAN__
#endif

#if !defined(BYTE_ORDER)
# define BYTE_ORDER __BYTE_ORDER
#endif
#if !defined(LITTLE_ENDIAN)
# define LITTLE_ENDIAN __LITTLE_ENDIAN
#endif
#if !defined(BIG_ENDIAN)
# define BIG_ENDIAN __BIG_ENDIAN
#endif

#endif

/*
 * Mac OSX as well as iOS do not define the MSG_NOSIGNAL flag,
 * but happily have something equivalent in the SO_NOSIGPIPE flag.
 */
#ifdef __APPLE__
#define MSG_NOSIGNAL SO_NOSIGPIPE
#endif

/*
 * Solaris 11.X only supports POSIX 2001, MSG_NOSIGNAL appears in
 * POSIX 2008.
 */
#ifdef __sun
#define MSG_NOSIGNAL 0
#endif

#ifdef _WIN32
#ifndef FD_HASHTABLE_MODULUS
#define FD_HASHTABLE_MODULUS 32
#endif
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
#define LWS_MAX_EXTENSIONS_ACTIVE 2
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

enum lws_websocket_opcodes_07 {
	LWSWSOPC_CONTINUATION = 0,
	LWSWSOPC_TEXT_FRAME = 1,
	LWSWSOPC_BINARY_FRAME = 2,

	LWSWSOPC_NOSPEC__MUX = 7,

	/* control extensions 8+ */

	LWSWSOPC_CLOSE = 8,
	LWSWSOPC_PING = 9,
	LWSWSOPC_PONG = 0xa,
};


enum lws_connection_states {
	LWSS_HTTP,
	LWSS_HTTP_ISSUING_FILE,
	LWSS_HTTP_HEADERS,
	LWSS_HTTP_BODY,
	LWSS_DEAD_SOCKET,
	LWSS_ESTABLISHED,
	LWSS_CLIENT_HTTP_ESTABLISHED,
	LWSS_CLIENT_UNCONNECTED,
	LWSS_RETURNED_CLOSE_ALREADY,
	LWSS_AWAITING_CLOSE_ACK,
	LWSS_FLUSHING_STORED_SEND_BEFORE_CLOSE,
	LWSS_SHUTDOWN,

	LWSS_HTTP2_AWAIT_CLIENT_PREFACE,
	LWSS_HTTP2_ESTABLISHED_PRE_SETTINGS,
	LWSS_HTTP2_ESTABLISHED,

	LWSS_CGI,
};

enum http_version {
	HTTP_VERSION_1_0,
	HTTP_VERSION_1_1,
	HTTP_VERSION_2
};

enum http_connection_type {
	HTTP_CONNECTION_CLOSE,
	HTTP_CONNECTION_KEEP_ALIVE
};

enum lws_pending_protocol_send {
	LWS_PPS_NONE,
	LWS_PPS_HTTP2_MY_SETTINGS,
	LWS_PPS_HTTP2_ACK_SETTINGS,
	LWS_PPS_HTTP2_PONG,
};

enum lws_rx_parse_state {
	LWS_RXPS_NEW,

	LWS_RXPS_04_mask_1,
	LWS_RXPS_04_mask_2,
	LWS_RXPS_04_mask_3,

	LWS_RXPS_04_FRAME_HDR_1,
	LWS_RXPS_04_FRAME_HDR_LEN,
	LWS_RXPS_04_FRAME_HDR_LEN16_2,
	LWS_RXPS_04_FRAME_HDR_LEN16_1,
	LWS_RXPS_04_FRAME_HDR_LEN64_8,
	LWS_RXPS_04_FRAME_HDR_LEN64_7,
	LWS_RXPS_04_FRAME_HDR_LEN64_6,
	LWS_RXPS_04_FRAME_HDR_LEN64_5,
	LWS_RXPS_04_FRAME_HDR_LEN64_4,
	LWS_RXPS_04_FRAME_HDR_LEN64_3,
	LWS_RXPS_04_FRAME_HDR_LEN64_2,
	LWS_RXPS_04_FRAME_HDR_LEN64_1,

	LWS_RXPS_07_COLLECT_FRAME_KEY_1,
	LWS_RXPS_07_COLLECT_FRAME_KEY_2,
	LWS_RXPS_07_COLLECT_FRAME_KEY_3,
	LWS_RXPS_07_COLLECT_FRAME_KEY_4,

	LWS_RXPS_PAYLOAD_UNTIL_LENGTH_EXHAUSTED
};

#define LWSCM_FLAG_IMPLIES_CALLBACK_CLOSED_CLIENT_HTTP 32

enum connection_mode {
	LWSCM_HTTP_SERVING,
	LWSCM_HTTP_SERVING_ACCEPTED, /* actual HTTP service going on */
	LWSCM_PRE_WS_SERVING_ACCEPT,

	LWSCM_WS_SERVING,
	LWSCM_WS_CLIENT,

	LWSCM_HTTP2_SERVING,

	/* transient, ssl delay hiding */
	LWSCM_SSL_ACK_PENDING,
	LWSCM_SSL_INIT,

	/* special internal types */
	LWSCM_SERVER_LISTENER,
	LWSCM_CGI, /* stdin, stdout, stderr for another cgi master wsi */

	/* HTTP Client related */
	LWSCM_HTTP_CLIENT = LWSCM_FLAG_IMPLIES_CALLBACK_CLOSED_CLIENT_HTTP,
	LWSCM_HTTP_CLIENT_ACCEPTED, /* actual HTTP service going on */
	LWSCM_WSCL_WAITING_CONNECT,
	LWSCM_WSCL_WAITING_PROXY_REPLY,
	LWSCM_WSCL_ISSUE_HANDSHAKE,
	LWSCM_WSCL_ISSUE_HANDSHAKE2,
	LWSCM_WSCL_ISSUE_HTTP_BODY,
	LWSCM_WSCL_WAITING_SSL,
	LWSCM_WSCL_WAITING_SERVER_REPLY,
	LWSCM_WSCL_WAITING_EXTENSION_CONNECT,
	LWSCM_WSCL_PENDING_CANDIDATE_CHILD,

	/****** add new things just above ---^ ******/


};

enum {
	LWS_RXFLOW_ALLOW = (1 << 0),
	LWS_RXFLOW_PENDING_CHANGE = (1 << 1),
};

/* this is not usable directly by user code any more, lws_close_reason() */
#define LWS_WRITE_CLOSE 4

struct lws_protocols;
struct lws;

#if defined(LWS_USE_LIBEV) || defined(LWS_USE_LIBUV)

struct lws_io_watcher {
#ifdef LWS_USE_LIBEV
	ev_io ev_watcher;
#endif
#ifdef LWS_USE_LIBUV
	uv_poll_t uv_watcher;
#endif
	struct lws_context *context;
};

struct lws_signal_watcher {
#ifdef LWS_USE_LIBEV
	ev_signal ev_watcher;
#endif
#ifdef LWS_USE_LIBUV
	uv_signal_t uv_watcher;
#endif
	struct lws_context *context;
};
#endif

#ifdef _WIN32
#define LWS_FD_HASH(fd) ((fd ^ (fd >> 8) ^ (fd >> 16)) % FD_HASHTABLE_MODULUS)
struct lws_fd_hashtable {
	struct lws **wsi;
	int length;
};
#endif

/*
 * This is totally opaque to code using the library.  It's exported as a
 * forward-reference pointer-only declaration; the user can use the pointer with
 * other APIs to get information out of it.
 */

struct lws_fragments {
	unsigned int offset;
	unsigned short len;
	unsigned char nfrag; /* which ah->frag[] continues this content, or 0 */
};

/*
 * these are assigned from a pool held in the context.
 * Both client and server mode uses them for http header analysis
 */

struct allocated_headers {
	struct lws *wsi; /* owner */
	char *data; /* prepared by context init to point to dedicated storage */
	/*
	 * the randomly ordered fragments, indexed by frag_index and
	 * lws_fragments->nfrag for continuation.
	 */
	struct lws_fragments frags[WSI_TOKEN_COUNT * 2];
	time_t assigned;
	/*
	 * for each recognized token, frag_index says which frag[] his data
	 * starts in (0 means the token did not appear)
	 * the actual header data gets dumped as it comes in, into data[]
	 */
	unsigned char frag_index[WSI_TOKEN_COUNT];
	unsigned char rx[2048];

	unsigned int rxpos;
	unsigned int rxlen;
	unsigned int pos;

	unsigned int http_response;

#ifndef LWS_NO_CLIENT
	char initial_handshake_hash_base64[30];
#endif

	unsigned char in_use;
	unsigned char nfrag;
};

/*
 * so we can have n connections being serviced simultaneously,
 * these things need to be isolated per-thread.
 */

struct lws_context_per_thread {
#if LWS_MAX_SMP > 1
	pthread_mutex_t lock;
#endif
	struct lws_pollfd *fds;
#if defined(LWS_WITH_ESP8266)
	struct lws **lws_vs_fds_index;
#endif
	struct lws *rx_draining_ext_list;
	struct lws *tx_draining_ext_list;
	struct lws *timeout_list;
#ifdef LWS_USE_LIBUV
	struct lws_context *context;
#endif
#ifdef LWS_WITH_CGI
	struct lws_cgi *cgi_list;
#endif
	void *http_header_data;
	struct allocated_headers *ah_pool;
	struct lws *ah_wait_list;
	int ah_wait_list_length;
#ifdef LWS_OPENSSL_SUPPORT
	struct lws *pending_read_list; /* linked list */
#endif
#if defined(LWS_USE_LIBEV)
	struct ev_loop *io_loop_ev;
#endif
#if defined(LWS_USE_LIBUV)
	uv_loop_t *io_loop_uv;
	uv_signal_t signals[8];
	uv_timer_t uv_timeout_watcher;
	uv_idle_t uv_idle;
#endif
#if defined(LWS_USE_LIBEV)
	struct lws_io_watcher w_accept;
#endif
#if defined(LWS_USE_LIBEV) || defined(LWS_USE_LIBUV)
	struct lws_signal_watcher w_sigint;
	unsigned char ev_loop_foreign:1;
#endif

	unsigned long count_conns;
	/*
	 * usable by anything in the service code, but only if the scope
	 * does not last longer than the service action (since next service
	 * of any socket can likewise use it and overwrite)
	 */
	unsigned char *serv_buf;
#ifdef _WIN32
	WSAEVENT *events;
#else
	lws_sockfd_type dummy_pipe_fds[2];
#endif
	unsigned int fds_count;

	short ah_count_in_use;
	unsigned char tid;
	unsigned char lock_depth;
};

struct lws_conn_stats {
	unsigned long long rx, tx;
	unsigned long conn, trans, ws_upg, http2_upg, rejected;
};

void
lws_sum_stats(const struct lws_context *ctx, struct lws_conn_stats *cs);

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
#if !defined(LWS_WITH_ESP8266)
	char http_proxy_address[128];
	char proxy_basic_auth_token[128];
#endif
#if defined(LWS_WITH_ESP8266)
	/* listen sockets need a place to hang their hat */
	esp_tcp tcp;
#endif
	struct lws_conn_stats conn_stats;
	struct lws_context *context;
	struct lws_vhost *vhost_next;
	const struct lws_http_mount *mount_list;
	struct lws *lserv_wsi;
	const char *name;
	const char *iface;
	const struct lws_protocols *protocols;
	void **protocol_vh_privs;
	const struct lws_protocol_vhost_options *pvo;
	const struct lws_protocol_vhost_options *headers;
	struct lws **same_vh_protocol_list;
#ifdef LWS_OPENSSL_SUPPORT
	SSL_CTX *ssl_ctx;
	SSL_CTX *ssl_client_ctx;
#endif
#ifndef LWS_NO_EXTENSIONS
	const struct lws_extension *extensions;
#endif

	int listen_port;
	unsigned int http_proxy_port;
	unsigned int options;
	int count_protocols;
	int ka_time;
	int ka_probes;
	int ka_interval;
	int keepalive_timeout;
#ifdef LWS_WITH_ACCESS_LOG
	int log_fd;
#endif

#ifdef LWS_OPENSSL_SUPPORT
	int use_ssl;
	int allow_non_ssl_on_ssl_port;
	unsigned int user_supplied_ssl_ctx:1;
#endif

	unsigned int created_vhost_protocols:1;

	unsigned char default_protocol_index;
};

/*
 * the rest is managed per-context, that includes
 *
 *  - processwide single fd -> wsi lookup
 *  - contextwide headers pool
 */

struct lws_context {
	time_t last_timeout_check_s;
	time_t last_ws_ping_pong_check_s;
	time_t time_up;
	struct lws_plat_file_ops fops;
	struct lws_context_per_thread pt[LWS_MAX_SMP];
	struct lws_conn_stats conn_stats;
#ifdef _WIN32
/* different implementation between unix and windows */
	struct lws_fd_hashtable fd_hashtable[FD_HASHTABLE_MODULUS];
#else
#if defined(LWS_WITH_ESP8266)
	struct espconn **connpool; /* .reverse points to the wsi */
	void *rxd;
	int rxd_len;
	os_timer_t to_timer;
#else
	struct lws **lws_lookup;  /* fd to wsi */
#endif
#endif
	struct lws_vhost *vhost_list;
	struct lws_plugin *plugin_list;

	void *external_baggage_free_on_destroy;
	const struct lws_token_limits *token_limits;
	void *user_space;
	const char *server_string;
	const struct lws_protocol_vhost_options *reject_service_keywords;
	lws_reload_func deprecation_cb;

#if defined(LWS_USE_LIBEV)
	lws_ev_signal_cb_t * lws_ev_sigint_cb;
#endif
#if defined(LWS_USE_LIBUV)
	uv_signal_cb lws_uv_sigint_cb;
#endif
	char canonical_hostname[128];
#ifdef LWS_LATENCY
	unsigned long worst_latency;
	char worst_latency_info[256];
#endif

	int max_fds;
#if defined(LWS_USE_LIBEV) || defined(LWS_USE_LIBUV)
	int use_ev_sigint;
#endif
	int started_with_parent;
	int uid, gid;

	int fd_random;
#ifdef LWS_OPENSSL_SUPPORT
#define lws_ssl_anybody_has_buffered_read(w) \
		(w->vhost->use_ssl && \
		 w->context->pt[(int)w->tsi].pending_read_list)
#define lws_ssl_anybody_has_buffered_read_tsi(c, t) \
		(/*c->use_ssl && */ \
		 c->pt[(int)t].pending_read_list)
#else
#define lws_ssl_anybody_has_buffered_read(ctx) (0)
#define lws_ssl_anybody_has_buffered_read_tsi(ctx, t) (0)
#endif
	int count_wsi_allocated;
	int count_cgi_spawned;
	unsigned int options;
	unsigned int fd_limit_per_thread;
	unsigned int timeout_secs;
	unsigned int pt_serv_buf_size;
	int max_http_header_data;

	unsigned int deprecated:1;
	unsigned int being_destroyed:1;
	unsigned int being_destroyed1:1;
	unsigned int requested_kill:1;
	unsigned int protocol_init_done:1;

	/*
	 * set to the Thread ID that's doing the service loop just before entry
	 * to poll indicates service thread likely idling in poll()
	 * volatile because other threads may check it as part of processing
	 * for pollfd event change.
	 */
	volatile int service_tid;
	int service_tid_detected;

	short max_http_header_pool;
	short count_threads;
	short plugin_protocol_count;
	short plugin_extension_count;
	short server_string_len;
	unsigned short ws_ping_pong_interval;
	unsigned short deprecation_pending_listen_close_count;
};

#define lws_get_context_protocol(ctx, x) ctx->vhost_list->protocols[x]
#define lws_get_vh_protocol(vh, x) vh->protocols[x]

LWS_EXTERN void
lws_close_free_wsi_final(struct lws *wsi);
LWS_EXTERN void
lws_libuv_closehandle(struct lws *wsi);

LWS_VISIBLE LWS_EXTERN int
lws_plat_plugins_init(struct lws_context * context, const char * const *d);

LWS_VISIBLE LWS_EXTERN int
lws_plat_plugins_destroy(struct lws_context * context);

LWS_EXTERN void
lws_restart_ws_ping_pong_timer(struct lws *wsi);

struct lws *
lws_adopt_socket_vhost(struct lws_vhost *vh, lws_sockfd_type accept_fd);


enum {
	LWS_EV_READ = (1 << 0),
	LWS_EV_WRITE = (1 << 1),
	LWS_EV_START = (1 << 2),
	LWS_EV_STOP = (1 << 3),

	LWS_EV_PREPARE_DELETION = (1 << 31),
};

#if defined(LWS_USE_LIBEV)
LWS_EXTERN void
lws_libev_accept(struct lws *new_wsi, lws_sockfd_type accept_fd);
LWS_EXTERN void
lws_libev_io(struct lws *wsi, int flags);
LWS_EXTERN int
lws_libev_init_fd_table(struct lws_context *context);
LWS_EXTERN void
lws_libev_destroyloop(struct lws_context *context, int tsi);
LWS_EXTERN void
lws_libev_run(const struct lws_context *context, int tsi);
#define LWS_LIBEV_ENABLED(context) lws_check_opt(context->options, LWS_SERVER_OPTION_LIBEV)
LWS_EXTERN void lws_feature_status_libev(struct lws_context_creation_info *info);
#else
#define lws_libev_accept(_a, _b) ((void) 0)
#define lws_libev_io(_a, _b) ((void) 0)
#define lws_libev_init_fd_table(_a) (0)
#define lws_libev_run(_a, _b) ((void) 0)
#define lws_libev_destroyloop(_a, _b) ((void) 0)
#define LWS_LIBEV_ENABLED(context) (0)
#if LWS_POSIX
#define lws_feature_status_libev(_a) \
			lwsl_notice("libev support not compiled in\n")
#else
#define lws_feature_status_libev(_a)
#endif
#endif

#if defined(LWS_USE_LIBUV)
LWS_EXTERN void
lws_libuv_accept(struct lws *new_wsi, lws_sockfd_type accept_fd);
LWS_EXTERN void
lws_libuv_io(struct lws *wsi, int flags);
LWS_EXTERN int
lws_libuv_init_fd_table(struct lws_context *context);
LWS_EXTERN void
lws_libuv_run(const struct lws_context *context, int tsi);
LWS_EXTERN void
lws_libuv_destroyloop(struct lws_context *context, int tsi);
LWS_EXTERN int
lws_uv_initvhost(struct lws_vhost* vh, struct lws*);
#define LWS_LIBUV_ENABLED(context) lws_check_opt(context->options, LWS_SERVER_OPTION_LIBUV)
LWS_EXTERN void lws_feature_status_libuv(struct lws_context_creation_info *info);
#else
#define lws_libuv_accept(_a, _b) ((void) 0)
#define lws_libuv_io(_a, _b) ((void) 0)
#define lws_libuv_init_fd_table(_a) (0)
#define lws_libuv_run(_a, _b) ((void) 0)
#define lws_libuv_destroyloop(_a, _b) ((void) 0)
#define LWS_LIBUV_ENABLED(context) (0)
#if LWS_POSIX
#define lws_feature_status_libuv(_a) \
			lwsl_notice("libuv support not compiled in\n")
#else
#define lws_feature_status_libuv(_a)
#endif
#endif


#ifdef LWS_USE_IPV6
#define LWS_IPV6_ENABLED(vh) \
	(!lws_check_opt(vh->context->options, LWS_SERVER_OPTION_DISABLE_IPV6) && \
	 !lws_check_opt(vh->options, LWS_SERVER_OPTION_DISABLE_IPV6))
#else
#define LWS_IPV6_ENABLED(context) (0)
#endif

#ifdef LWS_USE_UNIX_SOCK
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

/* notice that these union members:
 *
 *  hdr
 *  http
 *  http2
 *
 * all have a pointer to allocated_headers struct as their first member.
 *
 * It means for allocated_headers access, the three union paths can all be
 * used interchangeably to access the same data
 */


#ifndef LWS_NO_CLIENT
struct client_info_stash {
	char address[256];
	char path[4096];
	char host[256];
	char origin[256];
	char protocol[256];
	char method[16];
};
#endif

struct _lws_header_related {
	/* MUST be first in struct */
	struct allocated_headers *ah;
	struct lws *ah_wait_list;
	unsigned char *preamble_rx;
#ifndef LWS_NO_CLIENT
	struct client_info_stash *stash;
#endif
	unsigned int preamble_rx_len;
	enum uri_path_states ups;
	enum uri_esc_states ues;
	short lextable_pos;
	unsigned int current_token_limit;
#ifndef LWS_NO_CLIENT
	unsigned short c_port;
#endif
	char esc_stash;
	char post_literal_equal;
	unsigned char parser_state; /* enum lws_token_indexes */
	char redirects;
};

#if defined(LWS_WITH_RANGES)
enum range_states {
	LWSRS_NO_ACTIVE_RANGE,
	LWSRS_BYTES_EQ,
	LWSRS_FIRST,
	LWSRS_STARTING,
	LWSRS_ENDING,
	LWSRS_COMPLETED,
	LWSRS_SYNTAX,
};

struct lws_range_parsing {
	unsigned long long start, end, extent, agg, budget;
	const char buf[128];
	int pos;
	enum range_states state;
	char start_valid, end_valid, ctr, count_ranges, did_try, inside, send_ctr;
};

int
lws_ranges_init(struct lws *wsi, struct lws_range_parsing *rp, unsigned long long extent);
int
lws_ranges_next(struct lws_range_parsing *rp);
void
lws_ranges_reset(struct lws_range_parsing *rp);
#endif

struct _lws_http_mode_related {
	/* MUST be first in struct */
	struct allocated_headers *ah; /* mirroring  _lws_header_related */
	struct lws *ah_wait_list;
	unsigned char *preamble_rx;
#ifndef LWS_NO_CLIENT
	struct client_info_stash *stash;
#endif
	unsigned int preamble_rx_len;
	struct lws *new_wsi_list;
	unsigned long filepos;
	unsigned long filelen;
	lws_filefd_type fd;

#if defined(LWS_WITH_RANGES)
	struct lws_range_parsing range;
	char multipart_content_type[64];
#endif

	enum http_version request_version;
	enum http_connection_type connection_type;
	unsigned int content_length;
	unsigned int content_remain;
};

#ifdef LWS_USE_HTTP2

enum lws_http2_settings {
	LWS_HTTP2_SETTINGS__HEADER_TABLE_SIZE = 1,
	LWS_HTTP2_SETTINGS__ENABLE_PUSH,
	LWS_HTTP2_SETTINGS__MAX_CONCURRENT_STREAMS,
	LWS_HTTP2_SETTINGS__INITIAL_WINDOW_SIZE,
	LWS_HTTP2_SETTINGS__MAX_FRAME_SIZE,
	LWS_HTTP2_SETTINGS__MAX_HEADER_LIST_SIZE,

	LWS_HTTP2_SETTINGS__COUNT /* always last */
};

enum lws_http2_wellknown_frame_types {
	LWS_HTTP2_FRAME_TYPE_DATA,
	LWS_HTTP2_FRAME_TYPE_HEADERS,
	LWS_HTTP2_FRAME_TYPE_PRIORITY,
	LWS_HTTP2_FRAME_TYPE_RST_STREAM,
	LWS_HTTP2_FRAME_TYPE_SETTINGS,
	LWS_HTTP2_FRAME_TYPE_PUSH_PROMISE,
	LWS_HTTP2_FRAME_TYPE_PING,
	LWS_HTTP2_FRAME_TYPE_GOAWAY,
	LWS_HTTP2_FRAME_TYPE_WINDOW_UPDATE,
	LWS_HTTP2_FRAME_TYPE_CONTINUATION,

	LWS_HTTP2_FRAME_TYPE_COUNT /* always last */
};

enum lws_http2_flags {
	LWS_HTTP2_FLAG_END_STREAM = 1,
	LWS_HTTP2_FLAG_END_HEADERS = 4,
	LWS_HTTP2_FLAG_PADDED = 8,
	LWS_HTTP2_FLAG_PRIORITY = 0x20,

	LWS_HTTP2_FLAG_SETTINGS_ACK = 1,
};

#define LWS_HTTP2_STREAM_ID_MASTER 0
#define LWS_HTTP2_FRAME_HEADER_LENGTH 9
#define LWS_HTTP2_SETTINGS_LENGTH 6

struct http2_settings {
	unsigned int setting[LWS_HTTP2_SETTINGS__COUNT];
};

enum http2_hpack_state {

	/* optional before first header block */
	HPKS_OPT_PADDING,
	HKPS_OPT_E_DEPENDENCY,
	HKPS_OPT_WEIGHT,

	/* header block */
	HPKS_TYPE,

	HPKS_IDX_EXT,

	HPKS_HLEN,
	HPKS_HLEN_EXT,

	HPKS_DATA,

	/* optional after last header block */
	HKPS_OPT_DISCARD_PADDING,
};

enum http2_hpack_type {
	HPKT_INDEXED_HDR_7,
	HPKT_INDEXED_HDR_6_VALUE_INCR,
	HPKT_LITERAL_HDR_VALUE_INCR,
	HPKT_INDEXED_HDR_4_VALUE,
	HPKT_LITERAL_HDR_VALUE,
	HPKT_SIZE_5
};

struct hpack_dt_entry {
	int token; /* additions that don't map to a token are ignored */
	int arg_offset;
	int arg_len;
};

struct hpack_dynamic_table {
	struct hpack_dt_entry *entries;
	char *args;
	int pos;
	int next;
	int num_entries;
	int args_length;
};

struct _lws_http2_related {
	/*
	 * having this first lets us also re-use all HTTP union code
	 * and in turn, http_mode_related has allocated headers in right
	 * place so we can use the header apis on the wsi directly still
	 */
	struct _lws_http_mode_related http; /* MUST BE FIRST IN STRUCT */

	struct http2_settings my_settings;
	struct http2_settings peer_settings;

	struct lws *parent_wsi;
	struct lws *next_child_wsi;

	struct hpack_dynamic_table *hpack_dyn_table;
	struct lws *stream_wsi;
	unsigned char ping_payload[8];
	unsigned char one_setting[LWS_HTTP2_SETTINGS_LENGTH];

	unsigned int count;
	unsigned int length;
	unsigned int stream_id;
	enum http2_hpack_state hpack;
	enum http2_hpack_type hpack_type;
	unsigned int header_index;
	unsigned int hpack_len;
	unsigned int hpack_e_dep;
	int tx_credit;
	unsigned int my_stream_id;
	unsigned int child_count;
	int my_priority;

	unsigned int END_STREAM:1;
	unsigned int END_HEADERS:1;
	unsigned int send_END_STREAM:1;
	unsigned int GOING_AWAY;
	unsigned int requested_POLLOUT:1;
	unsigned int waiting_tx_credit:1;
	unsigned int huff:1;
	unsigned int value:1;

	unsigned short round_robin_POLLOUT;
	unsigned short count_POLLOUT_children;
	unsigned short hpack_pos;

	unsigned char type;
	unsigned char flags;
	unsigned char frame_state;
	unsigned char padding;
	unsigned char hpack_m;
	unsigned char initialized;
};

#define HTTP2_IS_TOPLEVEL_WSI(wsi) (!wsi->u.http2.parent_wsi)

#endif

struct _lws_websocket_related {
	/* cheapest way to deal with ah overlap with ws union transition */
	struct _lws_header_related hdr;
	char *rx_ubuf;
	unsigned int rx_ubuf_alloc;
	struct lws *rx_draining_ext_list;
	struct lws *tx_draining_ext_list;
	time_t time_next_ping_check;
	size_t rx_packet_length;
	unsigned int rx_ubuf_head;
	unsigned char mask[4];
	/* Also used for close content... control opcode == < 128 */
	unsigned char ping_payload_buf[128 - 3 + LWS_PRE];

	unsigned char ping_payload_len;
	unsigned char mask_idx;
	unsigned char opcode;
	unsigned char rsv;
	unsigned char rsv_first_msg;
	/* zero if no info, or length including 2-byte close code */
	unsigned char close_in_ping_buffer_len;
	unsigned char utf8;
	unsigned char stashed_write_type;
	unsigned char tx_draining_stashed_wp;

	unsigned int final:1;
	unsigned int frame_is_binary:1;
	unsigned int all_zero_nonce:1;
	unsigned int this_frame_masked:1;
	unsigned int inside_frame:1; /* next write will be more of frame */
	unsigned int clean_buffer:1; /* buffer not rewritten by extension */
	unsigned int payload_is_close:1; /* process as PONG, but it is close */
	unsigned int ping_pending_flag:1;
	unsigned int continuation_possible:1;
	unsigned int owed_a_fin:1;
	unsigned int check_utf8:1;
	unsigned int defeat_check_utf8:1;
	unsigned int pmce_compressed_message:1;
	unsigned int stashed_write_pending:1;
	unsigned int rx_draining_ext:1;
	unsigned int tx_draining_ext:1;
	unsigned int send_check_ping:1;
};

#ifdef LWS_WITH_CGI

/* wsi who is master of the cgi points to an lws_cgi */

struct lws_cgi {
	struct lws_cgi *cgi_list;
	struct lws *stdwsi[3]; /* points to the associated stdin/out/err wsis */
	struct lws *wsi; /* owner */
	unsigned long content_length;
	unsigned long content_length_seen;
	int pipe_fds[3][2];
	int pid;

	unsigned int being_closed:1;

	unsigned char chunked_grace;
};
#endif

signed char char_to_hex(const char c);

#ifndef LWS_NO_CLIENT
enum lws_chunk_parser {
	ELCP_HEX,
	ELCP_CR,
	ELCP_CONTENT,
	ELCP_POST_CR,
	ELCP_POST_LF,
};
#endif

struct lws_rewrite;

#ifdef LWS_WITH_ACCESS_LOG
struct lws_access_log {
	char *header_log;
	char *user_agent;
	unsigned long sent;
	int response;
};
#endif

struct lws {

	/* structs */
	/* members with mutually exclusive lifetimes are unionized */

	union u {
		struct _lws_http_mode_related http;
#ifdef LWS_USE_HTTP2
		struct _lws_http2_related http2;
#endif
		struct _lws_header_related hdr;
		struct _lws_websocket_related ws;
	} u;

	/* lifetime members */

#if defined(LWS_USE_LIBEV) || defined(LWS_USE_LIBUV)
	struct lws_io_watcher w_read;
#endif
#if defined(LWS_USE_LIBEV)
	struct lws_io_watcher w_write;
#endif
	time_t pending_timeout_limit;

	/* pointers */

	struct lws_context *context;
	struct lws_vhost *vhost;
	struct lws *parent; /* points to parent, if any */
	struct lws *child_list; /* points to first child */
	struct lws *sibling_list; /* subsequent children at same level */
#ifdef LWS_WITH_CGI
	struct lws_cgi *cgi; /* wsi being cgi master have one of these */
#endif
	const struct lws_protocols *protocol;
	struct lws **same_vh_protocol_prev, *same_vh_protocol_next;
	struct lws *timeout_list;
	struct lws **timeout_list_prev;
#ifdef LWS_WITH_ACCESS_LOG
	struct lws_access_log access_log;
#endif
	void *user_space;
	/* rxflow handling */
	unsigned char *rxflow_buffer;
	/* truncated send handling */
	unsigned char *trunc_alloc; /* non-NULL means buffering in progress */

#if defined (LWS_WITH_ESP8266)
	void *premature_rx;
	unsigned short prem_rx_size, prem_rx_pos;
#endif

#ifndef LWS_NO_EXTENSIONS
	const struct lws_extension *active_extensions[LWS_MAX_EXTENSIONS_ACTIVE];
	void *act_ext_user[LWS_MAX_EXTENSIONS_ACTIVE];
#endif
#ifdef LWS_OPENSSL_SUPPORT
	SSL *ssl;
#if !defined(LWS_USE_POLARSSL) && !defined(LWS_USE_MBEDTLS)
	BIO *client_bio;
#endif
	struct lws *pending_read_list_prev, *pending_read_list_next;
#endif
#ifdef LWS_WITH_HTTP_PROXY
	struct lws_rewrite *rw;
#endif
#ifdef LWS_LATENCY
	unsigned long action_start;
	unsigned long latency_start;
#endif
	/* pointer / int */
	lws_sockfd_type sock;

	/* ints */
	int position_in_fds_table;
	int rxflow_len;
	int rxflow_pos;
	unsigned int trunc_alloc_len; /* size of malloc */
	unsigned int trunc_offset; /* where we are in terms of spilling */
	unsigned int trunc_len; /* how much is buffered */
#ifndef LWS_NO_CLIENT
	int chunk_remaining;
#endif
	unsigned int cache_secs;

	unsigned int hdr_parsing_completed:1;
	unsigned int http2_substream:1;
	unsigned int listener:1;
	unsigned int user_space_externally_allocated:1;
	unsigned int socket_is_permanently_unusable:1;
	unsigned int rxflow_change_to:2;
	unsigned int more_rx_waiting:1; /* has to live here since ah may stick to end */
	unsigned int conn_stat_done:1;
	unsigned int cache_reuse:1;
	unsigned int cache_revalidate:1;
	unsigned int cache_intermediaries:1;
	unsigned int favoured_pollin:1;
	unsigned int sending_chunked:1;
	unsigned int already_did_cce:1;
	unsigned int told_user_closed:1;
	unsigned int :1;
#if defined(LWS_WITH_ESP8266)
	unsigned int pending_send_completion:3;
	unsigned int close_is_pending_send_completion:1;
#endif
#ifdef LWS_WITH_ACCESS_LOG
	unsigned int access_log_pending:1;
#endif
#ifndef LWS_NO_CLIENT
	unsigned int do_ws:1; /* whether we are doing http or ws flow */
	unsigned int chunked:1; /* if the clientside connection is chunked */
	unsigned int client_rx_avail:1;
	unsigned int client_http_body_pending:1;
#endif
#ifdef LWS_WITH_HTTP_PROXY
	unsigned int perform_rewrite:1;
#endif
#ifndef LWS_NO_EXTENSIONS
	unsigned int extension_data_pending:1;
#endif
#ifdef LWS_OPENSSL_SUPPORT
	unsigned int use_ssl:3;
#endif
#ifdef _WIN32
	unsigned int sock_send_blocking:1;
#endif
#ifdef LWS_OPENSSL_SUPPORT
	unsigned int redirect_to_https:1;
#endif

	/* chars */
#ifndef LWS_NO_EXTENSIONS
	unsigned char count_act_ext;
#endif
	unsigned char ietf_spec_revision;
	char mode; /* enum connection_mode */
	char state; /* enum lws_connection_states */
	char state_pre_close;
	char lws_rx_parse_state; /* enum lws_rx_parse_state */
	char rx_frame_type; /* enum lws_write_protocol */
	char pending_timeout; /* enum pending_timeout */
	char pps; /* enum lws_pending_protocol_send */
	char tsi; /* thread service index we belong to */
	char protocol_interpret_idx;
#ifdef LWS_WITH_CGI
	char cgi_channel; /* which of stdin/out/err */
	char hdr_state;
#endif
#ifndef LWS_NO_CLIENT
	char chunk_parser; /* enum lws_chunk_parser */
#endif
#if defined(LWS_WITH_CGI) || !defined(LWS_NO_CLIENT)
	char reason_bf; /* internal writeable callback reason bitfield */
#endif
};

LWS_EXTERN int log_level;

LWS_EXTERN int
lws_socket_bind(struct lws_vhost *vhost, lws_sockfd_type sockfd, int port,
		const char *iface);

LWS_EXTERN void
lws_close_free_wsi(struct lws *wsi, enum lws_close_status);

LWS_EXTERN int
remove_wsi_socket_from_fds(struct lws *wsi);
LWS_EXTERN int
lws_rxflow_cache(struct lws *wsi, unsigned char *buf, int n, int len);

#ifndef LWS_LATENCY
static inline void
lws_latency(struct lws_context *context, struct lws *wsi, const char *action,
	    int ret, int completion) {
	do {
		(void)context; (void)wsi; (void)action; (void)ret;
		(void)completion;
	} while (0);
}
static inline void
lws_latency_pre(struct lws_context *context, struct lws *wsi) {
	do { (void)context; (void)wsi; } while (0);
}
#else
#define lws_latency_pre(_context, _wsi) lws_latency(_context, _wsi, NULL, 0, 0)
extern void
lws_latency(struct lws_context *context, struct lws *wsi, const char *action,
	    int ret, int completion);
#endif

LWS_EXTERN void
lws_set_protocol_write_pending(struct lws *wsi,
			       enum lws_pending_protocol_send pend);
LWS_EXTERN int LWS_WARN_UNUSED_RESULT
lws_client_rx_sm(struct lws *wsi, unsigned char c);

LWS_EXTERN int LWS_WARN_UNUSED_RESULT
lws_parse(struct lws *wsi, unsigned char c);

LWS_EXTERN int LWS_WARN_UNUSED_RESULT
lws_http_action(struct lws *wsi);

LWS_EXTERN int
lws_b64_selftest(void);

LWS_EXTERN int
lws_service_flag_pending(struct lws_context *context, int tsi);

#if defined(_WIN32) || defined(MBED_OPERATORS) || defined(LWS_WITH_ESP8266)
LWS_EXTERN struct lws *
wsi_from_fd(const struct lws_context *context, lws_sockfd_type fd);

LWS_EXTERN int
insert_wsi(struct lws_context *context, struct lws *wsi);

LWS_EXTERN int
delete_from_fd(struct lws_context *context, lws_sockfd_type fd);
#else
#define wsi_from_fd(A,B)  A->lws_lookup[B]
#define insert_wsi(A,B)   assert(A->lws_lookup[B->sock] == 0); A->lws_lookup[B->sock]=B
#define delete_from_fd(A,B) A->lws_lookup[B]=0
#endif

LWS_EXTERN int LWS_WARN_UNUSED_RESULT
insert_wsi_socket_into_fds(struct lws_context *context, struct lws *wsi);

LWS_EXTERN int LWS_WARN_UNUSED_RESULT
lws_issue_raw(struct lws *wsi, unsigned char *buf, size_t len);


LWS_EXTERN int LWS_WARN_UNUSED_RESULT
lws_service_timeout_check(struct lws *wsi, unsigned int sec);

LWS_EXTERN struct lws * LWS_WARN_UNUSED_RESULT
lws_client_connect_2(struct lws *wsi);

LWS_VISIBLE struct lws * LWS_WARN_UNUSED_RESULT
lws_client_reset(struct lws *wsi, int ssl, const char *address, int port,
		 const char *path, const char *host);

LWS_EXTERN struct lws * LWS_WARN_UNUSED_RESULT
lws_create_new_server_wsi(struct lws_vhost *vhost);

LWS_EXTERN char * LWS_WARN_UNUSED_RESULT
lws_generate_client_handshake(struct lws *wsi, char *pkt);

LWS_EXTERN int
lws_handle_POLLOUT_event(struct lws *wsi, struct lws_pollfd *pollfd);

LWS_EXTERN struct lws *
lws_client_connect_via_info2(struct lws *wsi);

/*
 * EXTENSIONS
 */

#ifndef LWS_NO_EXTENSIONS
LWS_VISIBLE void
lws_context_init_extensions(struct lws_context_creation_info *info,
			    struct lws_context *context);
LWS_EXTERN int
lws_any_extension_handled(struct lws *wsi, enum lws_extension_callback_reasons r,
			  void *v, size_t len);

LWS_EXTERN int
lws_ext_cb_active(struct lws *wsi, int reason, void *buf, int len);
LWS_EXTERN int
lws_ext_cb_all_exts(struct lws_context *context, struct lws *wsi, int reason,
		    void *arg, int len);

#else
#define lws_any_extension_handled(_a, _b, _c, _d) (0)
#define lws_ext_cb_active(_a, _b, _c, _d) (0)
#define lws_ext_cb_all_exts(_a, _b, _c, _d, _e) (0)
#define lws_issue_raw_ext_access lws_issue_raw
#define lws_context_init_extensions(_a, _b)
#endif

LWS_EXTERN int LWS_WARN_UNUSED_RESULT
lws_client_interpret_server_handshake(struct lws *wsi);

LWS_EXTERN int LWS_WARN_UNUSED_RESULT
lws_rx_sm(struct lws *wsi, unsigned char c);

LWS_EXTERN int
lws_payload_until_length_exhausted(struct lws *wsi, unsigned char **buf, size_t *len);

LWS_EXTERN int LWS_WARN_UNUSED_RESULT
lws_issue_raw_ext_access(struct lws *wsi, unsigned char *buf, size_t len);

LWS_EXTERN void
lws_union_transition(struct lws *wsi, enum connection_mode mode);

LWS_EXTERN int LWS_WARN_UNUSED_RESULT
user_callback_handle_rxflow(lws_callback_function, struct lws *wsi,
			    enum lws_callback_reasons reason, void *user,
			    void *in, size_t len);
#ifdef LWS_USE_HTTP2
LWS_EXTERN struct lws *lws_http2_get_network_wsi(struct lws *wsi);
struct lws * lws_http2_get_nth_child(struct lws *wsi, int n);
LWS_EXTERN int
lws_http2_interpret_settings_payload(struct http2_settings *settings,
				     unsigned char *buf, int len);
LWS_EXTERN void lws_http2_init(struct http2_settings *settings);
LWS_EXTERN int
lws_http2_parser(struct lws *wsi, unsigned char c);
LWS_EXTERN int lws_http2_do_pps_send(struct lws_context *context,
				     struct lws *wsi);
LWS_EXTERN int lws_http2_frame_write(struct lws *wsi, int type, int flags,
				     unsigned int sid, unsigned int len,
				     unsigned char *buf);
LWS_EXTERN struct lws *
lws_http2_wsi_from_id(struct lws *wsi, unsigned int sid);
LWS_EXTERN int lws_hpack_interpret(struct lws *wsi,
				   unsigned char c);
LWS_EXTERN int
lws_add_http2_header_by_name(struct lws *wsi,
			     const unsigned char *name,
			     const unsigned char *value, int length,
			     unsigned char **p, unsigned char *end);
LWS_EXTERN int
lws_add_http2_header_by_token(struct lws *wsi,
			    enum lws_token_indexes token,
			    const unsigned char *value, int length,
			    unsigned char **p, unsigned char *end);
LWS_EXTERN int
lws_add_http2_header_status(struct lws *wsi,
			    unsigned int code, unsigned char **p,
			    unsigned char *end);
LWS_EXTERN
void lws_http2_configure_if_upgraded(struct lws *wsi);
#else
#define lws_http2_configure_if_upgraded(x)
#endif

LWS_EXTERN int
lws_plat_set_socket_options(struct lws_vhost *vhost, lws_sockfd_type fd);

LWS_EXTERN int
lws_plat_check_connection_error(struct lws *wsi);

LWS_EXTERN int LWS_WARN_UNUSED_RESULT
lws_header_table_attach(struct lws *wsi, int autoservice);

LWS_EXTERN int
lws_header_table_detach(struct lws *wsi, int autoservice);

LWS_EXTERN void
lws_header_table_reset(struct lws *wsi, int autoservice);

LWS_EXTERN char * LWS_WARN_UNUSED_RESULT
lws_hdr_simple_ptr(struct lws *wsi, enum lws_token_indexes h);

LWS_EXTERN int LWS_WARN_UNUSED_RESULT
lws_hdr_simple_create(struct lws *wsi, enum lws_token_indexes h, const char *s);

LWS_EXTERN int LWS_WARN_UNUSED_RESULT
lws_ensure_user_space(struct lws *wsi);

LWS_EXTERN int
lws_change_pollfd(struct lws *wsi, int _and, int _or);

#ifndef LWS_NO_SERVER
int lws_context_init_server(struct lws_context_creation_info *info,
			    struct lws_vhost *vhost);
LWS_EXTERN struct lws_vhost *
lws_select_vhost(struct lws_context *context, int port, const char *servername);
LWS_EXTERN int
handshake_0405(struct lws_context *context, struct lws *wsi);
LWS_EXTERN int LWS_WARN_UNUSED_RESULT
lws_interpret_incoming_packet(struct lws *wsi, unsigned char **buf, size_t len);
LWS_EXTERN void
lws_server_get_canonical_hostname(struct lws_context *context,
				  struct lws_context_creation_info *info);
#else
#define lws_context_init_server(_a, _b) (0)
#define lws_interpret_incoming_packet(_a, _b, _c) (0)
#define lws_server_get_canonical_hostname(_a, _b)
#endif

#ifndef LWS_NO_DAEMONIZE
LWS_EXTERN int get_daemonize_pid();
#else
#define get_daemonize_pid() (0)
#endif

#if !defined(MBED_OPERATORS) && !defined(LWS_WITH_ESP8266)
LWS_EXTERN int LWS_WARN_UNUSED_RESULT
interface_to_sa(struct lws_vhost *vh, const char *ifname,
		struct sockaddr_in *addr, size_t addrlen);
#endif
LWS_EXTERN void lwsl_emit_stderr(int level, const char *line);

enum lws_ssl_capable_status {
	LWS_SSL_CAPABLE_ERROR = -1,
	LWS_SSL_CAPABLE_MORE_SERVICE = -2,
};

#ifndef LWS_OPENSSL_SUPPORT
#define LWS_SSL_ENABLED(context) (0)
#define lws_context_init_server_ssl(_a, _b) (0)
#define lws_ssl_destroy(_a)
#define lws_context_init_http2_ssl(_a)
#define lws_ssl_capable_read lws_ssl_capable_read_no_ssl
#define lws_ssl_capable_write lws_ssl_capable_write_no_ssl
#define lws_ssl_pending lws_ssl_pending_no_ssl
#define lws_server_socket_service_ssl(_b, _c) (0)
#define lws_ssl_close(_a) (0)
#define lws_ssl_context_destroy(_a)
#define lws_ssl_SSL_CTX_destroy(_a)
#define lws_ssl_remove_wsi_from_buffered_list(_a)
#define lws_context_init_ssl_library(_a)
#else
#define LWS_SSL_ENABLED(context) (context->use_ssl)
LWS_EXTERN int openssl_websocket_private_data_index;
LWS_EXTERN int LWS_WARN_UNUSED_RESULT
lws_ssl_capable_read(struct lws *wsi, unsigned char *buf, int len);
LWS_EXTERN int LWS_WARN_UNUSED_RESULT
lws_ssl_capable_write(struct lws *wsi, unsigned char *buf, int len);
LWS_EXTERN int LWS_WARN_UNUSED_RESULT
lws_ssl_pending(struct lws *wsi);
LWS_EXTERN int
lws_context_init_ssl_library(struct lws_context_creation_info *info);
LWS_EXTERN int LWS_WARN_UNUSED_RESULT
lws_server_socket_service_ssl(struct lws *new_wsi, lws_sockfd_type accept_fd);
LWS_EXTERN int
lws_ssl_close(struct lws *wsi);
LWS_EXTERN void
lws_ssl_SSL_CTX_destroy(struct lws_vhost *vhost);
LWS_EXTERN void
lws_ssl_context_destroy(struct lws_context *context);
LWS_VISIBLE void
lws_ssl_remove_wsi_from_buffered_list(struct lws *wsi);
LWS_EXTERN int
lws_ssl_client_bio_create(struct lws *wsi);
LWS_EXTERN int
lws_ssl_client_connect1(struct lws *wsi);
LWS_EXTERN int
lws_ssl_client_connect2(struct lws *wsi);
LWS_EXTERN void
lws_ssl_elaborate_error(void);
#ifndef LWS_NO_SERVER
LWS_EXTERN int
lws_context_init_server_ssl(struct lws_context_creation_info *info,
			    struct lws_vhost *vhost);
#else
#define lws_context_init_server_ssl(_a, _b) (0)
#endif
LWS_EXTERN void
lws_ssl_destroy(struct lws_vhost *vhost);

/* HTTP2-related */

#ifdef LWS_USE_HTTP2
LWS_EXTERN void
lws_context_init_http2_ssl(struct lws_vhost *vhost);
#else
#define lws_context_init_http2_ssl(_a)
#endif
#endif

#if LWS_MAX_SMP > 1
static LWS_INLINE void
lws_pt_mutex_init(struct lws_context_per_thread *pt)
{
	pthread_mutex_init(&pt->lock, NULL);
}

static LWS_INLINE void
lws_pt_mutex_destroy(struct lws_context_per_thread *pt)
{
	pthread_mutex_destroy(&pt->lock);
}

static LWS_INLINE void
lws_pt_lock(struct lws_context_per_thread *pt)
{
	if (!pt->lock_depth++)
		pthread_mutex_lock(&pt->lock);
}

static LWS_INLINE void
lws_pt_unlock(struct lws_context_per_thread *pt)
{
	if (!(--pt->lock_depth))
		pthread_mutex_unlock(&pt->lock);
}
#else
#define lws_pt_mutex_init(_a) (void)(_a)
#define lws_pt_mutex_destroy(_a) (void)(_a)
#define lws_pt_lock(_a) (void)(_a)
#define lws_pt_unlock(_a) (void)(_a)
#endif

LWS_EXTERN int LWS_WARN_UNUSED_RESULT
lws_ssl_capable_read_no_ssl(struct lws *wsi, unsigned char *buf, int len);

LWS_EXTERN int LWS_WARN_UNUSED_RESULT
lws_ssl_capable_write_no_ssl(struct lws *wsi, unsigned char *buf, int len);

LWS_EXTERN int LWS_WARN_UNUSED_RESULT
lws_ssl_pending_no_ssl(struct lws *wsi);

#ifdef LWS_WITH_HTTP_PROXY
struct lws_rewrite {
	hubbub_parser *parser;
	hubbub_parser_optparams params;
	const char *from, *to;
	int from_len, to_len;
	unsigned char *p, *end;
	struct lws *wsi;
};
static LWS_INLINE int hstrcmp(hubbub_string *s, const char *p, int len)
{
	if (s->len != len)
		return 1;

	return strncmp((const char *)s->ptr, p, len);
}
typedef hubbub_error (*hubbub_callback_t)(const hubbub_token *token, void *pw);
LWS_EXTERN struct lws_rewrite *
lws_rewrite_create(struct lws *wsi, hubbub_callback_t cb, const char *from, const char *to);
LWS_EXTERN void
lws_rewrite_destroy(struct lws_rewrite *r);
LWS_EXTERN int
lws_rewrite_parse(struct lws_rewrite *r, const unsigned char *in, int in_len);
#endif

#ifndef LWS_NO_CLIENT
LWS_EXTERN int lws_client_socket_service(struct lws_context *context,
					 struct lws *wsi,
					 struct lws_pollfd *pollfd);
LWS_EXTERN int LWS_WARN_UNUSED_RESULT
lws_http_transaction_completed_client(struct lws *wsi);
#ifdef LWS_OPENSSL_SUPPORT
LWS_EXTERN int
lws_context_init_client_ssl(struct lws_context_creation_info *info,
			    struct lws_vhost *vhost);
#else
	#define lws_context_init_client_ssl(_a, _b) (0)
#endif
LWS_EXTERN int LWS_WARN_UNUSED_RESULT
lws_handshake_client(struct lws *wsi, unsigned char **buf, size_t len);
LWS_EXTERN void
lws_decode_ssl_error(void);
#else
#define lws_context_init_client_ssl(_a, _b) (0)
#define lws_handshake_client(_a, _b, _c) (0)
#endif

LWS_EXTERN int
_lws_rx_flow_control(struct lws *wsi);

LWS_EXTERN int
_lws_change_pollfd(struct lws *wsi, int _and, int _or, struct lws_pollargs *pa);

#ifndef LWS_NO_SERVER
LWS_EXTERN int
lws_server_socket_service(struct lws_context *context, struct lws *wsi,
			  struct lws_pollfd *pollfd);
LWS_EXTERN int
lws_handshake_server(struct lws *wsi, unsigned char **buf, size_t len);
#else
#define lws_server_socket_service(_a, _b, _c) (0)
#define lws_handshake_server(_a, _b, _c) (0)
#endif

#ifdef LWS_WITH_ACCESS_LOG
LWS_EXTERN int
lws_access_log(struct lws *wsi);
#else
#define lws_access_log(_a)
#endif

LWS_EXTERN int
lws_cgi_kill_terminated(struct lws_context_per_thread *pt);

int
lws_protocol_init(struct lws_context *context);

int
lws_bind_protocol(struct lws *wsi, const struct lws_protocols *p);

const struct lws_http_mount *
lws_find_mount(struct lws *wsi, const char *uri_ptr, int uri_len);

/*
 * custom allocator
 */
LWS_EXTERN void *
lws_realloc(void *ptr, size_t size);

LWS_EXTERN void * LWS_WARN_UNUSED_RESULT
lws_zalloc(size_t size);

#define lws_malloc(S)	lws_realloc(NULL, S)
#define lws_free(P)	lws_realloc(P, 0)
#define lws_free_set_NULL(P)	do { lws_realloc(P, 0); (P) = NULL; } while(0)

/* lws_plat_ */
LWS_EXTERN void
lws_plat_delete_socket_from_fds(struct lws_context *context,
				struct lws *wsi, int m);
LWS_EXTERN void
lws_plat_insert_socket_into_fds(struct lws_context *context,
				struct lws *wsi);
LWS_EXTERN void
lws_plat_service_periodic(struct lws_context *context);

LWS_EXTERN int
lws_plat_change_pollfd(struct lws_context *context, struct lws *wsi,
		       struct lws_pollfd *pfd);
LWS_EXTERN int
lws_plat_context_early_init(void);
LWS_EXTERN void
lws_plat_context_early_destroy(struct lws_context *context);
LWS_EXTERN void
lws_plat_context_late_destroy(struct lws_context *context);
LWS_EXTERN int
lws_poll_listen_fd(struct lws_pollfd *fd);
LWS_EXTERN int
lws_plat_service(struct lws_context *context, int timeout_ms);
LWS_EXTERN LWS_VISIBLE int
_lws_plat_service_tsi(struct lws_context *context, int timeout_ms, int tsi);
LWS_EXTERN int
lws_plat_init(struct lws_context *context,
	      struct lws_context_creation_info *info);
LWS_EXTERN void
lws_plat_drop_app_privileges(struct lws_context_creation_info *info);
LWS_EXTERN unsigned long long
time_in_microseconds(void);
LWS_EXTERN const char * LWS_WARN_UNUSED_RESULT
lws_plat_inet_ntop(int af, const void *src, char *dst, int cnt);

LWS_EXTERN int LWS_WARN_UNUSED_RESULT
lws_check_utf8(unsigned char *state, unsigned char *buf, size_t len);

#ifdef __cplusplus
};
#endif
