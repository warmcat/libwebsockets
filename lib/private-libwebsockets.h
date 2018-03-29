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

#if defined(__COVERITY__)
typedef struct { long double x, y; } _Float128;
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
#include <inttypes.h>

#if defined(LWS_WITH_ESP32)
#define MSG_NOSIGNAL 0
#define SOMAXCONN 3
#endif

#define STORE_IN_ROM
#include <assert.h>
#if LWS_MAX_SMP > 1
#include <pthread.h>
#endif

#ifdef LWS_HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#if defined(WIN32) || defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

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

#if !defined(LWS_HAVE_ATOLL)
#if defined(LWS_HAVE__ATOI64)
#define atoll _atoi64
#else
#warning No atoll or _atoi64 available, using atoi
#define atoll atoi
#endif
#endif

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

#ifndef __cplusplus
#include <errno.h>
#endif
#include <netdb.h>
#include <signal.h>
#include <sys/socket.h>
#ifdef LWS_WITH_HTTP_PROXY
#include <hubbub/hubbub.h>
#include <hubbub/parser.h>
#endif
#if defined(LWS_BUILTIN_GETIFADDRS)
 #include "./misc/getifaddrs.h"
#else
 #if !defined(LWS_WITH_ESP32)
 #if defined(__HAIKU__)
   #define _BSD_SOURCE
 #endif
 #include <ifaddrs.h>
 #endif
#endif
#if defined (__ANDROID__)
#include <syslog.h>
#include <sys/resource.h>
#elif defined (__sun) || defined(__HAIKU__) || defined(__QNX__)
#include <syslog.h>
#else
#if !defined(LWS_WITH_ESP32)
#include <sys/syslog.h>
#endif
#endif
#include <netdb.h>
#if !defined(LWS_WITH_ESP32)
#include <sys/mman.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <poll.h>
#endif
#if defined(LWS_WITH_LIBEV)
#include <ev.h>
#endif
#ifdef LWS_WITH_LIBUV
#include <uv.h>
#endif
#if defined(LWS_WITH_LIBEVENT) && !defined(LWS_HIDE_LIBEVENT)
#include <event2/event.h>
#endif

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

#define lws_socket_is_valid(x) (x >= 0)
#define LWS_SOCK_INVALID (-1)
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
#if defined(LWS_WITH_ESP32)
#define OPENSSL_NO_TLSEXT
#undef MBEDTLS_CONFIG_FILE
#define MBEDTLS_CONFIG_FILE <mbedtls/esp_config.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include "tls/mbedtls/wrapper/include/openssl/ssl.h" /* wrapper !!!! */
#else
#if defined(LWS_WITH_MBEDTLS)
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_csr.h>
#include "tls/mbedtls/wrapper/include/openssl/ssl.h" /* wrapper !!!! */
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
#endif
#if defined(OPENSSL_VERSION_NUMBER)
#if (OPENSSL_VERSION_NUMBER < 0x0009080afL)
/* later openssl defines this to negate the presence of tlsext... but it was only
 * introduced at 0.9.8j.  Earlier versions don't know it exists so don't
 * define it... making it look like the feature exists...
 */
#define OPENSSL_NO_TLSEXT
#endif
#endif
#endif /* not ESP32 */
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

#include <arpa/nameser_compat.h>

#if !defined (BYTE_ORDER)
# define BYTE_ORDER __BYTE_ORDER__
#endif

#if !defined(LITTLE_ENDIAN)
# define LITTLE_ENDIAN __ORDER_LITTLE_ENDIAN__
#endif

#if !defined(BIG_ENDIAN)
# define BIG_ENDIAN __ORDER_BIG_ENDIAN__
#endif

#endif /* sun + GNUC */

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

/*
 * Choose the SSL backend
 */

#if defined(LWS_OPENSSL_SUPPORT)
#if defined(LWS_WITH_MBEDTLS________)
struct lws_tls_mbed_ctx {

};
struct lws_tls_mbed_conn {

};
struct lws_tls_mbed_bio {

};
struct lws_tls_mbed_x509 {

};
typedef struct lws_tls_mbed_conn lws_tls_conn;
typedef struct lws_tls_mbed_ctx lws_tls_ctx;
typedef struct lws_tls_mbed_bio lws_tls_bio;
typedef struct lws_tls_mbed_x509 lws_tls_x509;
#else
typedef SSL lws_tls_conn;
typedef SSL_CTX lws_tls_ctx;
typedef BIO lws_tls_bio;
typedef X509 lws_tls_x509;
#endif
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
	LWS_SSL_CAPABLE_ERROR = -1,		 /* it failed */
	LWS_SSL_CAPABLE_DONE = 0,		 /* it succeeded */
	LWS_SSL_CAPABLE_MORE_SERVICE_READ = -2,	 /* retry WANT_READ */
	LWS_SSL_CAPABLE_MORE_SERVICE_WRITE = -3,  /* retry WANT_WRITE */
	LWS_SSL_CAPABLE_MORE_SERVICE = -4,	 /* general retry */
};

#if defined(__clang__)
#define lws_memory_barrier() __sync_synchronize()
#elif defined(__GNUC__)
#define lws_memory_barrier() __sync_synchronize()
#else
#define lws_memory_barrier()
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
	/* FLAG: one or another kind of ws link */
	_LSF_WEBSOCKET					= (1 << 5),
	/* FLAG: close callback */
	_LSF_CCB					= (1 << 6),
	/* FLAG: pollout capable */
	_LSF_POLLOUT					= (1 << 7),

	LWSS_HTTP					= _LSF_CCB | 0,
	LWSS_HTTP_ISSUING_FILE				=  1,
	LWSS_HTTP_HEADERS				=  2,
	LWSS_HTTP_BODY					= _LSF_CCB | 3,
	LWSS_DEAD_SOCKET				=  4,
	LWSS_ESTABLISHED				= _LSF_CCB | 5 |
							  _LSF_WEBSOCKET |
							  _LSF_POLLOUT,
	LWSS_CLIENT_HTTP_ESTABLISHED			=  6,
	LWSS_CLIENT_UNCONNECTED				=  7,
	LWSS_WAITING_TO_SEND_CLOSE_NOTIFICATION		= _LSF_CCB |  8 |
							  _LSF_POLLOUT,
	LWSS_RETURNED_CLOSE_ALREADY			= _LSF_CCB |  9 |
							  _LSF_POLLOUT,
	LWSS_AWAITING_CLOSE_ACK				= _LSF_CCB | 10,
	LWSS_FLUSHING_SEND_BEFORE_CLOSE			= _LSF_CCB | 11 |
							  _LSF_POLLOUT,
	LWSS_SHUTDOWN					= 12,

	LWSS_HTTP2_AWAIT_CLIENT_PREFACE			= 13,
	LWSS_HTTP2_ESTABLISHED_PRE_SETTINGS		= 14 | _LSF_POLLOUT,
	LWSS_HTTP2_ESTABLISHED				= _LSF_CCB | 15 |
							  _LSF_POLLOUT,
	LWSS_HTTP2_ESTABLISHED_WS			= _LSF_CCB | 16 |
							  _LSF_WEBSOCKET |
							  _LSF_POLLOUT,

	LWSS_CGI					= 17,

	LWSS_HTTP2_DEFERRING_ACTION			= _LSF_CCB | 18 |
							  _LSF_POLLOUT,

	LWSS_HTTP_DEFERRING_ACTION			= _LSF_CCB | 19 |
							  _LSF_POLLOUT,
};

#define lws_state_is_ws(s) (!!((s) & _LSF_WEBSOCKET))

enum http_version {
	HTTP_VERSION_1_0,
	HTTP_VERSION_1_1,
	HTTP_VERSION_2
};

enum http_connection_type {
	HTTP_CONNECTION_CLOSE,
	HTTP_CONNECTION_KEEP_ALIVE
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
	/* actual HTTP service going on */
	LWSCM_HTTP_SERVING_ACCEPTED,
	LWSCM_PRE_WS_SERVING_ACCEPT,

	LWSCM_WS_SERVING,
	LWSCM_WS_CLIENT,

	LWSCM_HTTP2_SERVING,
	LWSCM_HTTP2_WS_SERVING,

	/* transient, ssl delay hiding */
	LWSCM_SSL_ACK_PENDING,
	LWSCM_SSL_INIT,
	/* as above, but complete into LWSCM_RAW */
	LWSCM_SSL_ACK_PENDING_RAW,
	LWSCM_SSL_INIT_RAW,

	/* special internal types */
	LWSCM_SERVER_LISTENER,
	LWSCM_CGI, /* stdin, stdout, stderr for another cgi master wsi */
	LWSCM_RAW, /* raw with bulk handling */
	LWSCM_RAW_FILEDESC, /* raw without bulk handling */
	LWSCM_EVENT_PIPE, /* event pipe with no vhost or protocol binding */

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
	LWSCM_WSCL_WAITING_SOCKS_GREETING_REPLY,
	LWSCM_WSCL_WAITING_SOCKS_CONNECT_REPLY,
	LWSCM_WSCL_WAITING_SOCKS_AUTH_REPLY,

	/****** add new things just above ---^ ******/
};

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

struct lws_ring {
	void *buf;
	void (*destroy_element)(void *element);
	uint32_t buflen;
	uint32_t element_len;
	uint32_t head;
	uint32_t oldest_tail;
};

/* this is not usable directly by user code any more, lws_close_reason() */
#define LWS_WRITE_CLOSE 4

struct lws_protocols;
struct lws;

#if defined(LWS_WITH_LIBEV) || defined(LWS_WITH_LIBUV) || defined(LWS_WITH_LIBEVENT)

struct lws_io_watcher {
#ifdef LWS_WITH_LIBEV
	ev_io ev_watcher;
#endif
#ifdef LWS_WITH_LIBUV
	uv_poll_t uv_watcher;
#endif
#ifdef LWS_WITH_LIBEVENT
	struct event *event_watcher;
#endif
	struct lws_context *context;

	uint8_t actual_events;
};

struct lws_signal_watcher {
#ifdef LWS_WITH_LIBEV
	ev_signal ev_watcher;
#endif
#ifdef LWS_WITH_LIBUV
	uv_signal_t uv_watcher;
#endif
#ifdef LWS_WITH_LIBEVENT
	struct event *event_watcher;
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

struct lws_foreign_thread_pollfd {
	struct lws_foreign_thread_pollfd *next;
	int fd_index;
	int _and;
	int _or;
};

/*
 * This is totally opaque to code using the library.  It's exported as a
 * forward-reference pointer-only declaration; the user can use the pointer with
 * other APIs to get information out of it.
 */

#if defined(LWS_WITH_ESP32)
typedef uint16_t ah_data_idx_t;
#else
typedef uint32_t ah_data_idx_t;
#endif

struct lws_fragments {
	ah_data_idx_t	offset;
	uint16_t	len;
	uint8_t		nfrag; /* which ah->frag[] continues this content, or 0 */
	uint8_t		flags; /* only http2 cares */
};

/*
 * these are assigned from a pool held in the context.
 * Both client and server mode uses them for http header analysis
 */

struct allocated_headers {
	struct allocated_headers *next; /* linked list */
	struct lws *wsi; /* owner */
	char *data; /* prepared by context init to point to dedicated storage */
	ah_data_idx_t data_length;
	/*
	 * the randomly ordered fragments, indexed by frag_index and
	 * lws_fragments->nfrag for continuation.
	 */
	struct lws_fragments frags[WSI_TOKEN_COUNT];
	time_t assigned;
	/*
	 * for each recognized token, frag_index says which frag[] his data
	 * starts in (0 means the token did not appear)
	 * the actual header data gets dumped as it comes in, into data[]
	 */
	uint8_t frag_index[WSI_TOKEN_COUNT];
#if defined(LWS_WITH_ESP32)
	uint8_t rx[256];
#else
	uint8_t rx[2048];
#endif
#ifndef LWS_NO_CLIENT
	char initial_handshake_hash_base64[30];
#endif

	uint32_t pos;
	uint32_t http_response;
	uint32_t current_token_limit;
	int hdr_token_idx;

	int16_t rxpos;
	int16_t rxlen;
	int16_t lextable_pos;

	uint8_t in_use;
	uint8_t nfrag;
	char /*enum uri_path_states */ ups;
	char /*enum uri_esc_states */ ues;

	char esc_stash;
	char post_literal_equal;
	uint8_t /* enum lws_token_indexes */ parser_state;
};

#define LWS_HRTIMER_NOWAIT (0x7fffffffffffffffll)

/*
 * so we can have n connections being serviced simultaneously,
 * these things need to be isolated per-thread.
 */

struct lws_context_per_thread {
#if LWS_MAX_SMP > 1
	pthread_mutex_t lock;
	pthread_mutex_t lock_stats;
#endif
	struct lws_pollfd *fds;
	volatile struct lws_foreign_thread_pollfd * volatile foreign_pfd_list;
	struct lws *rx_draining_ext_list;
	struct lws *tx_draining_ext_list;
	struct lws_dll_lws dll_head_timeout;
	struct lws_dll_lws dll_head_hrtimer;
#if defined(LWS_WITH_LIBUV) || defined(LWS_WITH_LIBEVENT)
	struct lws_context *context;
#endif
#ifdef LWS_WITH_CGI
	struct lws_cgi *cgi_list;
#endif
	void *http_header_data;
	struct allocated_headers *ah_list;
	struct lws *ah_wait_list;
#if defined(LWS_HAVE_PTHREAD_H)
	const char *last_lock_reason;
#endif
	int ah_wait_list_length;
#ifdef LWS_OPENSSL_SUPPORT
	struct lws *pending_read_list; /* linked list */
#endif
#if defined(LWS_WITH_LIBEV)
	struct ev_loop *io_loop_ev;
#endif
#if defined(LWS_WITH_LIBUV)
	uv_loop_t *io_loop_uv;
	uv_signal_t signals[8];
	uv_timer_t uv_timeout_watcher;
	uv_timer_t uv_hrtimer;
	uv_idle_t uv_idle;
#endif
#if defined(LWS_WITH_LIBEVENT)
	struct event_base *io_loop_event_base;
#endif
#if defined(LWS_WITH_LIBEV) || defined(LWS_WITH_LIBUV) || defined(LWS_WITH_LIBEVENT)
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
#endif
	lws_sockfd_type dummy_pipe_fds[2];
	struct lws *pipe_wsi;

	volatile unsigned char inside_poll;
	volatile unsigned char foreign_spinlock;

	unsigned int fds_count;
	uint32_t ah_pool_length;

	short ah_count_in_use;
	unsigned char tid;
	unsigned char lock_depth;
#if LWS_MAX_SMP > 1
	pthread_t lock_owner;
#endif
};

struct lws_conn_stats {
	unsigned long long rx, tx;
	unsigned long h1_conn, h1_trans, h2_trans, ws_upg, h2_alpn, h2_subs,
		      h2_upg, rejected;
};

void
lws_sum_stats(const struct lws_context *ctx, struct lws_conn_stats *cs);


enum lws_h2_settings {
	H2SET_HEADER_TABLE_SIZE = 1,
	H2SET_ENABLE_PUSH,
	H2SET_MAX_CONCURRENT_STREAMS,
	H2SET_INITIAL_WINDOW_SIZE,
	H2SET_MAX_FRAME_SIZE,
	H2SET_MAX_HEADER_LIST_SIZE,
	H2SET_RESERVED7,
	H2SET_ENABLE_CONNECT_PROTOCOL, /* defined in mcmanus-httpbis-h2-ws-02 */

	H2SET_COUNT /* always last */
};

struct http2_settings {
	uint32_t s[H2SET_COUNT];
};

struct lws_timed_vh_protocol {
	struct lws_timed_vh_protocol *next;
	const struct lws_protocols *protocol;
	time_t time;
	int reason;
};

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

struct lws_tls_ss_pieces;

struct lws_vhost {
	char http_proxy_address[128];
	char proxy_basic_auth_token[128];
#if LWS_MAX_SMP > 1
	pthread_mutex_t lock;
#endif
#if defined(LWS_WITH_HTTP2)
	struct http2_settings set;
#endif
#if defined(LWS_WITH_SOCKS5)
	char socks_proxy_address[128];
	char socks_user[96];
	char socks_password[96];
#endif
#if defined(LWS_WITH_LIBEV)
	struct lws_io_watcher w_accept;
#endif
	struct lws_conn_stats conn_stats;
	struct lws_context *context;
	struct lws_vhost *vhost_next;
	const struct lws_http_mount *mount_list;
	struct lws *lserv_wsi;
	const char *name;
	const char *iface;
	char *alloc_cert_path;
	char *key_path;
#if !defined(LWS_WITH_ESP32) && !defined(OPTEE_TA) && !defined(WIN32)
	int bind_iface;
#endif
	const struct lws_protocols *protocols;
	void **protocol_vh_privs;
	const struct lws_protocol_vhost_options *pvo;
	const struct lws_protocol_vhost_options *headers;
	struct lws **same_vh_protocol_list;
	struct lws_vhost *no_listener_vhost_list;
#if !defined(LWS_NO_CLIENT)
	struct lws_dll_lws dll_active_client_conns;
#endif
	const char *error_document_404;
#ifdef LWS_OPENSSL_SUPPORT
	lws_tls_ctx *ssl_ctx;
	lws_tls_ctx *ssl_client_ctx;
	struct lws_tls_ss_pieces *ss; /* for acme tls certs */
	char ecdh_curve[16];
#endif
#if defined(LWS_WITH_MBEDTLS)
	lws_tls_x509 *x509_client_CA;
#endif
#if !defined(LWS_WITHOUT_EXTENSIONS)
	const struct lws_extension *extensions;
#endif
	struct lws_timed_vh_protocol *timed_vh_protocol_list;
	void *user;

	int listen_port;
	unsigned int http_proxy_port;
#if defined(LWS_WITH_SOCKS5)
	unsigned int socks_proxy_port;
#endif
	unsigned int options;
	int count_protocols;
	int ka_time;
	int ka_probes;
	int ka_interval;
	int keepalive_timeout;
	int timeout_secs_ah_idle;
	int ssl_info_event_mask;
#ifdef LWS_WITH_ACCESS_LOG
	int log_fd;
#endif

#ifdef LWS_OPENSSL_SUPPORT
	int use_ssl;
	int allow_non_ssl_on_ssl_port;
	unsigned int user_supplied_ssl_ctx:1;
#endif

	unsigned int created_vhost_protocols:1;
	unsigned int being_destroyed:1;
	unsigned int skipped_certs:1;
	unsigned int acme_challenge:1;

	unsigned char default_protocol_index;
	unsigned char raw_protocol_index;
};

struct lws_deferred_free
{
	struct lws_deferred_free *next;
	time_t deadline;
	void *payload;
};

typedef union {
#ifdef LWS_WITH_IPV6
	struct sockaddr_in6 sa6;
#endif
	struct sockaddr_in sa4;
} sockaddr46;


#if defined(LWS_WITH_PEER_LIMITS)
struct lws_peer {
	struct lws_peer *next;
	struct lws_peer *peer_wait_list;

	time_t time_created;
	time_t time_closed_all;

	uint8_t addr[32];
	uint32_t hash;
	uint32_t count_wsi;
	uint32_t count_ah;

	uint32_t total_wsi;
	uint32_t total_ah;

	uint8_t af;
};
#endif

/*
 * the rest is managed per-context, that includes
 *
 *  - processwide single fd -> wsi lookup
 *  - contextwide headers pool
 */

struct lws_context {
	time_t last_timeout_check_s;
	time_t last_ws_ping_pong_check_s;
	time_t last_cert_check_s;
	time_t time_up;
	time_t time_discontiguity;
	time_t time_fixup;
	const struct lws_plat_file_ops *fops;
	struct lws_plat_file_ops fops_platform;
#if defined(LWS_WITH_HTTP2)
	struct http2_settings set;
#endif
#if defined(LWS_WITH_ZIP_FOPS)
	struct lws_plat_file_ops fops_zip;
#endif
	struct lws_context_per_thread pt[LWS_MAX_SMP];
	struct lws_conn_stats conn_stats;
#if LWS_MAX_SMP > 1
	pthread_mutex_t lock;
	int lock_depth;
#endif
#ifdef _WIN32
/* different implementation between unix and windows */
	struct lws_fd_hashtable fd_hashtable[FD_HASHTABLE_MODULUS];
#else
	struct lws **lws_lookup;  /* fd to wsi */
#endif
	struct lws_vhost *vhost_list;
	struct lws_vhost *no_listener_vhost_list;
	struct lws_vhost *vhost_pending_destruction_list;
	struct lws_plugin *plugin_list;
	struct lws_deferred_free *deferred_free_list;
#if defined(LWS_WITH_PEER_LIMITS)
	struct lws_peer **pl_hash_table;
	struct lws_peer *peer_wait_list;
	time_t next_cull;
#endif

	void *external_baggage_free_on_destroy;
	const struct lws_token_limits *token_limits;
	void *user_space;
	const char *server_string;
	const struct lws_protocol_vhost_options *reject_service_keywords;
	lws_reload_func deprecation_cb;

#if defined(LWS_HAVE_SYS_CAPABILITY_H) && defined(LWS_HAVE_LIBCAP)
	cap_value_t caps[4];
	char count_caps;
#endif

#if defined(LWS_WITH_LIBEV)
	lws_ev_signal_cb_t * lws_ev_sigint_cb;
#endif
#if defined(LWS_WITH_LIBUV)
	uv_signal_cb lws_uv_sigint_cb;
	uv_loop_t pu_loop;
#endif
#if defined(LWS_WITH_LIBEVENT)
#if defined(LWS_HIDE_LIBEVENT)
	void * lws_event_sigint_cb;
#else
	lws_event_signal_cb_t * lws_event_sigint_cb;
#endif
#endif
	char canonical_hostname[128];
#ifdef LWS_LATENCY
	unsigned long worst_latency;
	char worst_latency_info[256];
#endif

#if defined(LWS_WITH_STATS)
	uint64_t lws_stats[LWSSTATS_SIZE];
	uint64_t last_dump;
	int updated;
#endif
#if defined(LWS_WITH_ESP32)
	unsigned long time_last_state_dump;
	uint32_t last_free_heap;
#endif

	int max_fds;
#if defined(LWS_WITH_LIBEV) || defined(LWS_WITH_LIBUV) || defined(LWS_WITH_LIBEVENT)
	int use_ev_sigint;
#endif
	int started_with_parent;
	int uid, gid;

	int fd_random;

	int count_wsi_allocated;
	int count_cgi_spawned;
	unsigned int options;
	unsigned int fd_limit_per_thread;
	unsigned int timeout_secs;
	unsigned int pt_serv_buf_size;
	int max_http_header_data;
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
	unsigned int requested_kill:1;
	unsigned int protocol_init_done:1;
	unsigned int ssl_gate_accepts:1;
	unsigned int doing_protocol_init;
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

	uint8_t max_fi;
};

int
lws_check_deferred_free(struct lws_context *context, int force);

#define lws_get_context_protocol(ctx, x) ctx->vhost_list->protocols[x]
#define lws_get_vh_protocol(vh, x) vh->protocols[x]

LWS_EXTERN void
__lws_close_free_wsi_final(struct lws *wsi);
LWS_EXTERN void
lws_libuv_closehandle(struct lws *wsi);
LWS_EXTERN void
lws_libuv_closehandle_manually(struct lws *wsi);
LWS_EXTERN int
lws_libuv_check_watcher_active(struct lws *wsi);

LWS_VISIBLE LWS_EXTERN int
lws_plat_plugins_init(struct lws_context * context, const char * const *d);

LWS_VISIBLE LWS_EXTERN int
lws_plat_plugins_destroy(struct lws_context * context);

LWS_EXTERN void
lws_restart_ws_ping_pong_timer(struct lws *wsi);

struct lws *
lws_adopt_socket_vhost(struct lws_vhost *vh, lws_sockfd_type accept_fd);

int
lws_jws_base64_enc(const char *in, size_t in_len, char *out, size_t out_max);


enum {
	LWS_EV_READ = (1 << 0),
	LWS_EV_WRITE = (1 << 1),
	LWS_EV_START = (1 << 2),
	LWS_EV_STOP = (1 << 3),

	LWS_EV_PREPARE_DELETION = (1 << 31),
};

#if defined(LWS_WITH_LIBEV)
LWS_EXTERN void
lws_libev_accept(struct lws *new_wsi, lws_sock_file_fd_type desc);
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
#if LWS_POSIX && !defined(LWS_WITH_ESP32)
#define lws_feature_status_libev(_a) \
			lwsl_info("libev support not compiled in\n")
#else
#define lws_feature_status_libev(_a)
#endif
#endif

#if defined(LWS_WITH_LIBUV)
LWS_EXTERN void
lws_libuv_accept(struct lws *new_wsi, lws_sock_file_fd_type desc);
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
#if LWS_POSIX && !defined(LWS_WITH_ESP32)
#define lws_feature_status_libuv(_a) \
			lwsl_info("libuv support not compiled in\n")
#else
#define lws_feature_status_libuv(_a)
#endif
#endif

#if defined(LWS_WITH_LIBEVENT)
LWS_EXTERN void
lws_libevent_accept(struct lws *new_wsi, lws_sock_file_fd_type desc);
LWS_VISIBLE void
lws_libevent_destroy(struct lws *wsi);
LWS_EXTERN void
lws_libevent_io(struct lws *wsi, int flags);
LWS_EXTERN int
lws_libevent_init_fd_table(struct lws_context *context);
LWS_EXTERN void
lws_libevent_destroyloop(struct lws_context *context, int tsi);
LWS_EXTERN void
lws_libevent_run(const struct lws_context *context, int tsi);
#define LWS_LIBEVENT_ENABLED(context) lws_check_opt(context->options, LWS_SERVER_OPTION_LIBEVENT)
LWS_EXTERN void lws_feature_status_libevent(struct lws_context_creation_info *info);
#else
#define lws_libevent_accept(_a, _b) ((void) 0)
#define lws_libevent_destroy(_a) ((void) 0)
#define lws_libevent_io(_a, _b) ((void) 0)
#define lws_libevent_init_fd_table(_a) (0)
#define lws_libevent_run(_a, _b) ((void) 0)
#define lws_libevent_destroyloop(_a, _b) ((void) 0)
#define LWS_LIBEVENT_ENABLED(context) (0)
#if LWS_POSIX && !defined(LWS_WITH_ESP32)
#define lws_feature_status_libevent(_a) \
			lwsl_info("libevent support not compiled in\n")
#else
#define lws_feature_status_libevent(_a)
#endif
#endif


#if defined(LWS_WITH_ESP32)
LWS_EXTERN int
lws_find_string_in_file(const char *filename, const char *string, int stringlen);
#endif

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


#ifndef LWS_NO_CLIENT
struct client_info_stash {
	char *address;
	char *path;
	char *host;
	char *origin;
	char *protocol;
	char *method;
	char *iface;
};
#endif

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
	struct lws *new_wsi_list;
	lws_filepos_t filepos;
	lws_filepos_t filelen;
	lws_fop_fd_t fop_fd;

#if defined(LWS_WITH_RANGES)
	struct lws_range_parsing range;
	char multipart_content_type[64];
#endif

	enum http_version request_version;
	enum http_connection_type connection_type;
	lws_filepos_t tx_content_length;
	lws_filepos_t tx_content_remain;
	lws_filepos_t rx_content_length;
	lws_filepos_t rx_content_remain;
};

#define LWS_H2_FRAME_HEADER_LENGTH 9

#ifdef LWS_WITH_HTTP2

enum lws_h2_wellknown_frame_types {
	LWS_H2_FRAME_TYPE_DATA,
	LWS_H2_FRAME_TYPE_HEADERS,
	LWS_H2_FRAME_TYPE_PRIORITY,
	LWS_H2_FRAME_TYPE_RST_STREAM,
	LWS_H2_FRAME_TYPE_SETTINGS,
	LWS_H2_FRAME_TYPE_PUSH_PROMISE,
	LWS_H2_FRAME_TYPE_PING,
	LWS_H2_FRAME_TYPE_GOAWAY,
	LWS_H2_FRAME_TYPE_WINDOW_UPDATE,
	LWS_H2_FRAME_TYPE_CONTINUATION,

	LWS_H2_FRAME_TYPE_COUNT /* always last */
};

enum lws_h2_flags {
	LWS_H2_FLAG_END_STREAM = 1,
	LWS_H2_FLAG_END_HEADERS = 4,
	LWS_H2_FLAG_PADDED = 8,
	LWS_H2_FLAG_PRIORITY = 0x20,

	LWS_H2_FLAG_SETTINGS_ACK = 1,
};

enum lws_h2_errors {
	H2_ERR_NO_ERROR,		   /* Graceful shutdown */
	H2_ERR_PROTOCOL_ERROR,	   /* Protocol error detected */
	H2_ERR_INTERNAL_ERROR,	   /* Implementation fault */
	H2_ERR_FLOW_CONTROL_ERROR,  /* Flow-control limits exceeded */
	H2_ERR_SETTINGS_TIMEOUT,	   /* Settings not acknowledged */
	H2_ERR_STREAM_CLOSED,	   /* Frame received for closed stream */
	H2_ERR_FRAME_SIZE_ERROR,	   /* Frame size incorrect */
	H2_ERR_REFUSED_STREAM,	   /* Stream not processed */
	H2_ERR_CANCEL,		   /* Stream cancelled */
	H2_ERR_COMPRESSION_ERROR,   /* Compression state not updated */
	H2_ERR_CONNECT_ERROR,	   /* TCP connection error for CONNECT method */
	H2_ERR_ENHANCE_YOUR_CALM,   /* Processing capacity exceeded */
	H2_ERR_INADEQUATE_SECURITY, /* Negotiated TLS parameters not acceptable */
	H2_ERR_HTTP_1_1_REQUIRED,   /* Use HTTP/1.1 for the request */
};

enum lws_h2_states {
	LWS_H2_STATE_IDLE,
	/*
	 * Send PUSH_PROMISE    -> LWS_H2_STATE_RESERVED_LOCAL
	 * Recv PUSH_PROMISE    -> LWS_H2_STATE_RESERVED_REMOTE
	 * Send HEADERS         -> LWS_H2_STATE_OPEN
	 * Recv HEADERS         -> LWS_H2_STATE_OPEN
	 *
	 *  - Only PUSH_PROMISE + HEADERS valid to send
	 *  - Only HEADERS or PRIORITY valid to receive
	 */
	LWS_H2_STATE_RESERVED_LOCAL,
	/*
	 * Send RST_STREAM      -> LWS_H2_STATE_CLOSED
	 * Recv RST_STREAM      -> LWS_H2_STATE_CLOSED
	 * Send HEADERS         -> LWS_H2_STATE_HALF_CLOSED_REMOTE
	 *
	 * - Only HEADERS, RST_STREAM, or PRIORITY valid to send
	 * - Only RST_STREAM, PRIORITY, or WINDOW_UPDATE valid to receive
	 */
	LWS_H2_STATE_RESERVED_REMOTE,
	/*
	 * Send RST_STREAM      -> LWS_H2_STATE_CLOSED
	 * Recv RST_STREAM      -> LWS_H2_STATE_CLOSED
	 * Recv HEADERS         -> LWS_H2_STATE_HALF_CLOSED_LOCAL
	 *
	 *  - Only RST_STREAM, WINDOW_UPDATE, or PRIORITY valid to send
	 *  - Only HEADERS, RST_STREAM, or PRIORITY valid to receive
	 */
	LWS_H2_STATE_OPEN,
	/*
	 * Send RST_STREAM      -> LWS_H2_STATE_CLOSED
	 * Recv RST_STREAM      -> LWS_H2_STATE_CLOSED
	 * Send END_STREAM flag -> LWS_H2_STATE_HALF_CLOSED_LOCAL
	 * Recv END_STREAM flag -> LWS_H2_STATE_HALF_CLOSED_REMOTE
	 */
	LWS_H2_STATE_HALF_CLOSED_REMOTE,
	/*
	 * Send RST_STREAM      -> LWS_H2_STATE_CLOSED
	 * Recv RST_STREAM      -> LWS_H2_STATE_CLOSED
	 * Send END_STREAM flag -> LWS_H2_STATE_CLOSED
	 *
	 *  - Any frame valid to send
	 *  - Only WINDOW_UPDATE, PRIORITY, or RST_STREAM valid to receive
	 */
	LWS_H2_STATE_HALF_CLOSED_LOCAL,
	/*
	 * Send RST_STREAM      -> LWS_H2_STATE_CLOSED
	 * Recv RST_STREAM      -> LWS_H2_STATE_CLOSED
	 * Recv END_STREAM flag -> LWS_H2_STATE_CLOSED
	 *
	 *  - Only WINDOW_UPDATE, PRIORITY, and RST_STREAM valid to send
	 *  - Any frame valid to receive
	 */
	LWS_H2_STATE_CLOSED,
	/*
	 *  - Only PRIORITY, WINDOW_UPDATE (IGNORE) and RST_STREAM (IGNORE)
	 *     may be received
	 *
	 *  - Only PRIORITY valid to send
	 */
};

#define LWS_H2_STREAM_ID_MASTER 0
#define LWS_H2_SETTINGS_LEN 6

enum http2_hpack_state {
	HPKS_TYPE,

	HPKS_IDX_EXT,

	HPKS_HLEN,
	HPKS_HLEN_EXT,

	HPKS_DATA,
};

/*
 * lws general parsimonious header strategy is only store values from known
 * headers, and refer to them by index.
 *
 * That means if we can't map the peer header name to one that lws knows, we
 * will drop the content but track the indexing with associated_lws_hdr_idx =
 * LWS_HPACK_IGNORE_ENTRY.
 */

enum http2_hpack_type {
	HPKT_INDEXED_HDR_7,		/* 1xxxxxxx: just "header field" */
	HPKT_INDEXED_HDR_6_VALUE_INCR,  /* 01xxxxxx: NEW indexed hdr with value */
	HPKT_LITERAL_HDR_VALUE_INCR,	/* 01000000: NEW literal hdr with value */
	HPKT_INDEXED_HDR_4_VALUE,	/* 0000xxxx: indexed hdr with value */
	HPKT_INDEXED_HDR_4_VALUE_NEVER,	/* 0001xxxx: indexed hdr with value NEVER NEW */
	HPKT_LITERAL_HDR_VALUE,		/* 00000000: literal hdr with value */
	HPKT_LITERAL_HDR_VALUE_NEVER,	/* 00010000: literal hdr with value NEVER NEW */
	HPKT_SIZE_5
};

#define LWS_HPACK_IGNORE_ENTRY 0xffff


struct hpack_dt_entry {
	char *value; /* malloc'd */
	uint16_t value_len;
	uint16_t hdr_len; /* virtual, for accounting */
	uint16_t lws_hdr_idx; /* LWS_HPACK_IGNORE_ENTRY = IGNORE */
};

struct hpack_dynamic_table {
	struct hpack_dt_entry *entries; /* malloc'd */
	uint32_t virtual_payload_usage;
	uint32_t virtual_payload_max;
	uint16_t pos;
	uint16_t used_entries;
	uint16_t num_entries;
};

enum lws_h2_protocol_send_type {
	LWS_PPS_NONE,
	LWS_H2_PPS_MY_SETTINGS,
	LWS_H2_PPS_ACK_SETTINGS,
	LWS_H2_PPS_PONG,
	LWS_H2_PPS_GOAWAY,
	LWS_H2_PPS_RST_STREAM,
	LWS_H2_PPS_UPDATE_WINDOW,
};

struct lws_h2_protocol_send {
	struct lws_h2_protocol_send *next; /* linked list */
	enum lws_h2_protocol_send_type type;

	union uu {
		struct {
			char		str[32];
			uint32_t	highest_sid;
			uint32_t	err;
		} ga;
		struct {
			uint32_t	sid;
			uint32_t	err;
		} rs;
		struct {
			uint8_t		ping_payload[8];
		} ping;
		struct {
			uint32_t	sid;
			uint32_t	credit;
		} update_window;
	} u;
};

struct lws_h2_ghost_sid {
	struct lws_h2_ghost_sid *next;
	uint32_t sid;
};

#define LWS_H2_RX_SCRATCH_SIZE 512

/*
 * http/2 connection info that is only used by the root connection that has
 * the network connection.
 *
 * h2 tends to spawn many child connections from one network connection, so
 * it's necessary to make members only needed by the network connection
 * distinct and only malloc'd on network connections.
 *
 * There's only one HPACK parser per network connection.
 *
 * But there is an ah per logical child connection... the network connection
 * fills it but it belongs to the logical child.
 */
struct lws_h2_netconn {
	struct http2_settings set;
	struct hpack_dynamic_table hpack_dyn_table;
	uint8_t	ping_payload[8];
	uint8_t one_setting[LWS_H2_SETTINGS_LEN];
	char goaway_str[32]; /* for rx */
	struct lws *swsi;
	struct lws_h2_protocol_send *pps; /* linked list */
	char *rx_scratch;

	enum http2_hpack_state hpack;
	enum http2_hpack_type hpack_type;

	unsigned int huff:1;
	unsigned int value:1;
	unsigned int unknown_header:1;
	unsigned int cont_exp:1;
	unsigned int cont_exp_headers:1;
	unsigned int we_told_goaway:1;
	unsigned int pad_length:1;
	unsigned int collected_priority:1;
	unsigned int is_first_header_char:1;
	unsigned int zero_huff_padding:1;
	unsigned int last_action_dyntable_resize:1;

	uint32_t hdr_idx;
	uint32_t hpack_len;
	uint32_t hpack_e_dep;
	uint32_t count;
	uint32_t preamble;
	uint32_t length;
	uint32_t sid;
	uint32_t inside;
	uint32_t highest_sid;
	uint32_t highest_sid_opened;
	uint32_t cont_exp_sid;
	uint32_t dep;
	uint32_t goaway_last_sid;
	uint32_t goaway_err;
	uint32_t hpack_hdr_len;

	uint32_t rx_scratch_pos;
	uint32_t rx_scratch_len;

	uint16_t hpack_pos;

	uint8_t frame_state;
	uint8_t type;
	uint8_t flags;
	uint8_t padding;
	uint8_t weight_temp;
	uint8_t huff_pad;
	char first_hdr_char;
	uint8_t hpack_m;
	uint8_t ext_count;
};

struct _lws_h2_related {

	struct lws_h2_netconn *h2n; /* malloc'd for root net conn */
	struct lws *parent_wsi;
	struct lws *child_list;
	struct lws *sibling_list;

	char *pending_status_body;

	int tx_cr;
	int peer_tx_cr_est;
	unsigned int my_sid;
	unsigned int child_count;
	int my_priority;
	uint32_t dependent_on;

	unsigned int END_STREAM:1;
	unsigned int END_HEADERS:1;
	unsigned int send_END_STREAM:1;
	unsigned int GOING_AWAY;
	unsigned int requested_POLLOUT:1;
	unsigned int skint:1;

	uint16_t round_robin_POLLOUT;
	uint16_t count_POLLOUT_children;

	uint8_t h2_state; /* the RFC7540 state of the connection */
	uint8_t weight;
	uint8_t initialized;
};

#define HTTP2_IS_TOPLEVEL_WSI(wsi) (!wsi->h2.parent_wsi)

#endif

struct _lws_websocket_related {
	char *rx_ubuf;
	struct lws *rx_draining_ext_list;
	struct lws *tx_draining_ext_list;
	/* Also used for close content... control opcode == < 128 */
	uint8_t ping_payload_buf[128 - 3 + LWS_PRE];
	uint8_t mask[4];

	time_t time_next_ping_check;
	size_t rx_packet_length;
	uint32_t rx_ubuf_head;
	uint32_t rx_ubuf_alloc;

	uint8_t ping_payload_len;
	uint8_t mask_idx;
	uint8_t opcode;
	uint8_t rsv;
	uint8_t rsv_first_msg;
	/* zero if no info, or length including 2-byte close code */
	uint8_t close_in_ping_buffer_len;
	uint8_t utf8;
	uint8_t stashed_write_type;
	uint8_t tx_draining_stashed_wp;
	uint8_t ietf_spec_revision;

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
	unsigned int first_fragment:1;
};

#ifdef LWS_WITH_CGI

#define LWS_HTTP_CHUNK_HDR_SIZE 16

enum {
	SIGNIFICANT_HDR_CONTENT_LENGTH,
	SIGNIFICANT_HDR_LOCATION,
	SIGNIFICANT_HDR_STATUS,
	SIGNIFICANT_HDR_TRANSFER_ENCODING,

	SIGNIFICANT_HDR_COUNT
};

/* wsi who is master of the cgi points to an lws_cgi */

struct lws_cgi {
	struct lws_cgi *cgi_list;
	struct lws *stdwsi[3]; /* points to the associated stdin/out/err wsis */
	struct lws *wsi; /* owner */
	unsigned char *headers_buf;
	unsigned char *headers_start;
	unsigned char *headers_pos;
	unsigned char *headers_dumped;
	unsigned char *headers_end;

	char summary[128];

	lws_filepos_t content_length;
	lws_filepos_t content_length_seen;

	int pipe_fds[3][2];
	int match[SIGNIFICANT_HDR_COUNT];
	char l[12];
	int pid;
	int response_code;
	int lp;

	unsigned char being_closed:1;
	unsigned char explicitly_chunked:1;

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

enum lws_parse_urldecode_results {
	LPUR_CONTINUE,
	LPUR_SWALLOW,
	LPUR_FORBID,
	LPUR_EXCESSIVE,
};

struct lws_rewrite;

#ifdef LWS_WITH_ACCESS_LOG
struct lws_access_log {
	char *header_log;
	char *user_agent;
	char *referrer;
	unsigned long sent;
	int response;
};
#endif

#define lws_wsi_is_udp(___wsi) (!!___wsi->udp)

struct lws {
	/* structs */

	struct _lws_http_mode_related http;
#ifdef LWS_WITH_HTTP2
	struct _lws_h2_related h2;
#endif

	/* lifetime members */

#if defined(LWS_WITH_LIBEV) || defined(LWS_WITH_LIBUV) || defined(LWS_WITH_LIBEVENT)
	struct lws_io_watcher w_read;
#endif
#if defined(LWS_WITH_LIBEV) || defined(LWS_WITH_LIBEVENT)
	struct lws_io_watcher w_write;
#endif
#ifdef LWS_WITH_ACCESS_LOG
	struct lws_access_log access_log;
#endif

	/* pointers */

	struct lws_context *context;
	struct lws_vhost *vhost;
	struct lws *parent; /* points to parent, if any */
	struct lws *child_list; /* points to first child */
	struct lws *sibling_list; /* subsequent children at same level */
	struct _lws_websocket_related *ws; /* allocated if we upgrade to ws */
#ifdef LWS_WITH_CGI
	struct lws_cgi *cgi; /* wsi being cgi master have one of these */
#endif
	const struct lws_protocols *protocol;
	struct lws **same_vh_protocol_prev, *same_vh_protocol_next;

	struct lws_dll_lws dll_timeout;
	struct lws_dll_lws dll_hrtimer;
#if defined(LWS_WITH_PEER_LIMITS)
	struct lws_peer *peer;
#endif
	struct allocated_headers *ah;
	struct lws *ah_wait_list;
	struct lws_udp *udp;
	unsigned char *preamble_rx;
#ifndef LWS_NO_CLIENT
	struct client_info_stash *stash;
	struct lws_dll_lws dll_active_client_conns;
	struct lws_dll_lws dll_client_transaction_queue_head;
	struct lws_dll_lws dll_client_transaction_queue;
#endif
	void *user_space;
	void *opaque_parent_data;
	/* rxflow handling */
	unsigned char *rxflow_buffer;
	/* truncated send handling */
	unsigned char *trunc_alloc; /* non-NULL means buffering in progress */

#if !defined(LWS_WITHOUT_EXTENSIONS)
	const struct lws_extension *active_extensions[LWS_MAX_EXTENSIONS_ACTIVE];
	void *act_ext_user[LWS_MAX_EXTENSIONS_ACTIVE];
#endif
#ifdef LWS_OPENSSL_SUPPORT
	lws_tls_conn *ssl;
	lws_tls_bio *client_bio;
	struct lws *pending_read_list_prev, *pending_read_list_next;
#endif
#ifdef LWS_WITH_HTTP_PROXY
	struct lws_rewrite *rw;
#endif
#ifdef LWS_LATENCY
	unsigned long action_start;
	unsigned long latency_start;
#endif
	lws_sock_file_fd_type desc; /* .filefd / .sockfd */
#if defined(LWS_WITH_STATS)
	uint64_t active_writable_req_us;
#if defined(LWS_OPENSSL_SUPPORT)
	uint64_t accept_start_us;
#endif
#endif
	lws_usec_t pending_timer;

	time_t pending_timeout_set;

	/* ints */
	int position_in_fds_table;
	uint32_t rxflow_len;
	uint32_t rxflow_pos;
	uint32_t preamble_rx_len;
	unsigned int trunc_alloc_len; /* size of malloc */
	unsigned int trunc_offset; /* where we are in terms of spilling */
	unsigned int trunc_len; /* how much is buffered */
#ifndef LWS_NO_CLIENT
	int chunk_remaining;
#endif
	unsigned int cache_secs;

	unsigned int hdr_parsing_completed:1;
	unsigned int http2_substream:1;
	unsigned int upgraded_to_http2:1;
	unsigned int h2_stream_carries_ws:1;
	unsigned int seen_nonpseudoheader:1;
	unsigned int listener:1;
	unsigned int user_space_externally_allocated:1;
	unsigned int socket_is_permanently_unusable:1;
	unsigned int rxflow_change_to:2;
	unsigned int conn_stat_done:1;
	unsigned int cache_reuse:1;
	unsigned int cache_revalidate:1;
	unsigned int cache_intermediaries:1;
	unsigned int favoured_pollin:1;
	unsigned int sending_chunked:1;
	unsigned int interpreting:1;
	unsigned int already_did_cce:1;
	unsigned int told_user_closed:1;
	unsigned int waiting_to_send_close_frame:1;
	unsigned int ipv6:1;
	unsigned int parent_carries_io:1;
	unsigned int parent_pending_cb_on_writable:1;
	unsigned int cgi_stdout_zero_length:1;
	unsigned int seen_zero_length_recv:1;
	unsigned int rxflow_will_be_applied:1;
	unsigned int event_pipe:1;
	unsigned int on_same_vh_list:1;
	unsigned int handling_404:1;

	unsigned int could_have_pending:1; /* detect back-to-back writes */
	unsigned int outer_will_close:1;

#ifdef LWS_WITH_ACCESS_LOG
	unsigned int access_log_pending:1;
#endif
#ifndef LWS_NO_CLIENT
	unsigned int do_ws:1; /* whether we are doing http or ws flow */
	unsigned int chunked:1; /* if the clientside connection is chunked */
	unsigned int client_rx_avail:1;
	unsigned int client_http_body_pending:1;
	unsigned int transaction_from_pipeline_queue:1;
	unsigned int keepalive_active:1;
	unsigned int keepalive_rejected:1;
	unsigned int client_pipeline:1;
#endif
#ifdef LWS_WITH_HTTP_PROXY
	unsigned int perform_rewrite:1;
#endif
#if !defined(LWS_WITHOUT_EXTENSIONS)
	unsigned int extension_data_pending:1;
#endif
#ifdef LWS_OPENSSL_SUPPORT
	unsigned int use_ssl:4;
#endif
#ifdef _WIN32
	unsigned int sock_send_blocking:1;
#endif
#ifdef LWS_OPENSSL_SUPPORT
	unsigned int redirect_to_https:1;
#endif

#ifndef LWS_NO_CLIENT
	unsigned short c_port;
#endif
	unsigned short pending_timeout_limit;

	uint8_t state; /* enum lws_connection_states */
	uint8_t mode; /* enum connection_mode */

	/* chars */
#if !defined(LWS_WITHOUT_EXTENSIONS)
	uint8_t count_act_ext;
#endif
	uint8_t state_pre_close;
	char lws_rx_parse_state; /* enum lws_rx_parse_state */
	char rx_frame_type; /* enum lws_write_protocol */
	char pending_timeout; /* enum pending_timeout */
	char tsi; /* thread service index we belong to */
	char protocol_interpret_idx;
	char redirects;
	uint8_t rxflow_bitmap;
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
#if defined(LWS_WITH_STATS) && defined(LWS_OPENSSL_SUPPORT)
	char seen_rx;
#endif
	uint8_t ws_over_h2_count;
	/* volatile to make sure code is aware other thread can change */
	volatile char handling_pollout;
	volatile char leave_pollout_active;
};

#define lws_is_flowcontrolled(w) (!!(wsi->rxflow_bitmap))

LWS_EXTERN int log_level;

LWS_EXTERN int
lws_socket_bind(struct lws_vhost *vhost, lws_sockfd_type sockfd, int port,
		const char *iface);

#if defined(LWS_WITH_IPV6)
LWS_EXTERN unsigned long
lws_get_addr_scope(const char *ipaddr);
#endif

LWS_EXTERN void
lws_close_free_wsi(struct lws *wsi, enum lws_close_status, const char *caller);
LWS_EXTERN void
__lws_close_free_wsi(struct lws *wsi, enum lws_close_status, const char *caller);

LWS_EXTERN void
__lws_free_wsi(struct lws *wsi);

LWS_EXTERN int
__remove_wsi_socket_from_fds(struct lws *wsi);
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

LWS_EXTERN int LWS_WARN_UNUSED_RESULT
lws_client_rx_sm(struct lws *wsi, unsigned char c);

LWS_EXTERN int LWS_WARN_UNUSED_RESULT
lws_parse(struct lws *wsi, unsigned char *buf, int *len);

LWS_EXTERN int LWS_WARN_UNUSED_RESULT
lws_parse_urldecode(struct lws *wsi, uint8_t *_c);

LWS_EXTERN int LWS_WARN_UNUSED_RESULT
lws_http_action(struct lws *wsi);

LWS_EXTERN int
lws_b64_selftest(void);

LWS_EXTERN int
lws_service_flag_pending(struct lws_context *context, int tsi);

LWS_EXTERN int
lws_timed_callback_remove(struct lws_vhost *vh, struct lws_timed_vh_protocol *p);

#if defined(_WIN32)
LWS_EXTERN struct lws *
wsi_from_fd(const struct lws_context *context, lws_sockfd_type fd);

LWS_EXTERN int
insert_wsi(struct lws_context *context, struct lws *wsi);

LWS_EXTERN int
delete_from_fd(struct lws_context *context, lws_sockfd_type fd);
#else
#define wsi_from_fd(A,B)  A->lws_lookup[B - lws_plat_socket_offset()]
#define insert_wsi(A,B)   assert(A->lws_lookup[B->desc.sockfd - lws_plat_socket_offset()] == 0); A->lws_lookup[B->desc.sockfd - lws_plat_socket_offset()]=B
#define delete_from_fd(A,B) A->lws_lookup[B - lws_plat_socket_offset()]=0
#endif

LWS_EXTERN int LWS_WARN_UNUSED_RESULT
__insert_wsi_socket_into_fds(struct lws_context *context, struct lws *wsi);

LWS_EXTERN int LWS_WARN_UNUSED_RESULT
lws_issue_raw(struct lws *wsi, unsigned char *buf, size_t len);

LWS_EXTERN void
lws_remove_from_timeout_list(struct lws *wsi);

LWS_EXTERN struct lws * LWS_WARN_UNUSED_RESULT
lws_client_connect_2(struct lws *wsi);

LWS_VISIBLE struct lws * LWS_WARN_UNUSED_RESULT
lws_client_reset(struct lws **wsi, int ssl, const char *address, int port,
		 const char *path, const char *host);

LWS_EXTERN struct lws * LWS_WARN_UNUSED_RESULT
lws_create_new_server_wsi(struct lws_vhost *vhost);

LWS_EXTERN char * LWS_WARN_UNUSED_RESULT
lws_generate_client_handshake(struct lws *wsi, char *pkt);

LWS_EXTERN int
lws_handle_POLLOUT_event(struct lws *wsi, struct lws_pollfd *pollfd);

LWS_EXTERN struct lws *
lws_client_connect_via_info2(struct lws *wsi);

LWS_EXTERN int
_lws_destroy_ah(struct lws_context_per_thread *pt, struct allocated_headers *ah);

LWS_EXTERN void
lws_client_stash_destroy(struct lws *wsi);

/*
 * EXTENSIONS
 */

#if !defined(LWS_WITHOUT_EXTENSIONS)
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
#ifdef LWS_WITH_HTTP2
int
lws_h2_rst_stream(struct lws *wsi, uint32_t err, const char *reason);
struct lws * lws_h2_get_nth_child(struct lws *wsi, int n);
LWS_EXTERN void lws_h2_init(struct lws *wsi);
LWS_EXTERN int
lws_h2_settings(struct lws *nwsi, struct http2_settings *settings,
				     unsigned char *buf, int len);
LWS_EXTERN int
lws_h2_parser(struct lws *wsi, unsigned char *in, lws_filepos_t inlen,
	      lws_filepos_t *inused);
LWS_EXTERN int lws_h2_do_pps_send(struct lws *wsi);
LWS_EXTERN int lws_h2_frame_write(struct lws *wsi, int type, int flags,
				     unsigned int sid, unsigned int len,
				     unsigned char *buf);
LWS_EXTERN struct lws *
lws_h2_wsi_from_id(struct lws *wsi, unsigned int sid);
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
LWS_EXTERN int
lws_h2_configure_if_upgraded(struct lws *wsi);
LWS_EXTERN void
lws_hpack_destroy_dynamic_header(struct lws *wsi);
LWS_EXTERN int
lws_hpack_dynamic_size(struct lws *wsi, int size);
LWS_EXTERN int
lws_h2_goaway(struct lws *wsi, uint32_t err, const char *reason);
LWS_EXTERN int
lws_h2_tx_cr_get(struct lws *wsi);
LWS_EXTERN void
lws_h2_tx_cr_consume(struct lws *wsi, int consumed);
LWS_EXTERN int
lws_hdr_extant(struct lws *wsi, enum lws_token_indexes h);
LWS_EXTERN void
lws_pps_schedule(struct lws *wsi, struct lws_h2_protocol_send *pss);

LWS_EXTERN const struct http2_settings lws_h2_defaults;
LWS_EXTERN int
lws_h2_ws_handshake(struct lws *wsi);
#else
#define lws_h2_configure_if_upgraded(x)
#endif

LWS_EXTERN int
lws_plat_socket_offset(void);

LWS_EXTERN int
lws_plat_set_socket_options(struct lws_vhost *vhost, lws_sockfd_type fd);

LWS_EXTERN int
lws_plat_check_connection_error(struct lws *wsi);

LWS_EXTERN int LWS_WARN_UNUSED_RESULT
lws_header_table_attach(struct lws *wsi, int autoservice);

LWS_EXTERN int
lws_header_table_detach(struct lws *wsi, int autoservice);
LWS_EXTERN int
__lws_header_table_detach(struct lws *wsi, int autoservice);

LWS_EXTERN void
lws_header_table_reset(struct lws *wsi, int autoservice);
void
_lws_header_table_reset(struct allocated_headers *ah);
void
__lws_header_table_reset(struct lws *wsi, int autoservice);

void
lws_header_table_force_to_detachable_state(struct lws *wsi);
int
lws_header_table_is_in_detachable_state(struct lws *wsi);

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

LWS_EXTERN int LWS_WARN_UNUSED_RESULT
interface_to_sa(struct lws_vhost *vh, const char *ifname,
		struct sockaddr_in *addr, size_t addrlen);
LWS_EXTERN void lwsl_emit_stderr(int level, const char *line);

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
#define __lws_ssl_remove_wsi_from_buffered_list(_a)
#define lws_context_init_ssl_library(_a)
#define lws_ssl_anybody_has_buffered_read_tsi(_a, _b) (0)
#define lws_tls_check_all_cert_lifetimes(_a)
#define lws_tls_acme_sni_cert_destroy(_a)
#else
#define LWS_SSL_ENABLED(context) (context->use_ssl)

enum lws_tls_extant {
	LWS_TLS_EXTANT_NO,
	LWS_TLS_EXTANT_YES,
	LWS_TLS_EXTANT_ALTERNATIVE
};
LWS_EXTERN enum lws_tls_extant
lws_tls_use_any_upgrade_check_extant(const char *name);
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
void
__lws_ssl_remove_wsi_from_buffered_list(struct lws *wsi);
LWS_VISIBLE void
lws_ssl_remove_wsi_from_buffered_list(struct lws *wsi);
LWS_EXTERN int
lws_ssl_client_bio_create(struct lws *wsi);
LWS_EXTERN int
lws_ssl_client_connect1(struct lws *wsi);
LWS_EXTERN int
lws_ssl_client_connect2(struct lws *wsi, char *errbuf, int len);
LWS_EXTERN void
lws_ssl_elaborate_error(void);
LWS_EXTERN int
lws_ssl_anybody_has_buffered_read_tsi(struct lws_context *context, int tsi);
LWS_EXTERN int
lws_gate_accepts(struct lws_context *context, int on);
LWS_EXTERN void
lws_ssl_bind_passphrase(lws_tls_ctx *ssl_ctx, struct lws_context_creation_info *info);
LWS_EXTERN void
lws_ssl_info_callback(const lws_tls_conn *ssl, int where, int ret);
LWS_EXTERN int
lws_tls_openssl_cert_info(X509 *x509, enum lws_tls_cert_info type,
			  union lws_tls_cert_info_results *buf, size_t len);
LWS_EXTERN int
lws_tls_check_all_cert_lifetimes(struct lws_context *context);
LWS_EXTERN int
lws_tls_server_certs_load(struct lws_vhost *vhost, struct lws *wsi,
			  const char *cert, const char *private_key,
			  const char *mem_cert, size_t len_mem_cert,
			  const char *mem_privkey, size_t mem_privkey_len);
LWS_EXTERN enum lws_tls_extant
lws_tls_generic_cert_checks(struct lws_vhost *vhost, const char *cert,
			    const char *private_key);
LWS_EXTERN int
lws_tls_alloc_pem_to_der_file(struct lws_context *context, const char *filename,
			const char *inbuf, lws_filepos_t inlen,
		      uint8_t **buf, lws_filepos_t *amount);
#ifndef LWS_NO_SERVER
LWS_EXTERN int
lws_context_init_server_ssl(struct lws_context_creation_info *info,
			    struct lws_vhost *vhost);
void
lws_tls_acme_sni_cert_destroy(struct lws_vhost *vhost);
#else
#define lws_context_init_server_ssl(_a, _b) (0)
#define lws_tls_acme_sni_cert_destroy(_a)
#endif
LWS_EXTERN void
lws_ssl_destroy(struct lws_vhost *vhost);
LWS_EXTERN char *
lws_ssl_get_error_string(int status, int ret, char *buf, size_t len);

/*
 * lws_tls_ abstract backend implementations
 */

LWS_EXTERN int
lws_tls_server_client_cert_verify_config(struct lws_vhost *vh);
LWS_EXTERN int
lws_tls_server_vhost_backend_init(struct lws_context_creation_info *info,
				  struct lws_vhost *vhost, struct lws *wsi);
LWS_EXTERN int
lws_tls_server_new_nonblocking(struct lws *wsi, lws_sockfd_type accept_fd);

LWS_EXTERN enum lws_ssl_capable_status
lws_tls_server_accept(struct lws *wsi);

LWS_EXTERN enum lws_ssl_capable_status
lws_tls_server_abort_connection(struct lws *wsi);

LWS_EXTERN enum lws_ssl_capable_status
__lws_tls_shutdown(struct lws *wsi);

LWS_EXTERN enum lws_ssl_capable_status
lws_tls_client_connect(struct lws *wsi);
LWS_EXTERN int
lws_tls_client_confirm_peer_cert(struct lws *wsi, char *ebuf, int ebuf_len);
LWS_EXTERN int
lws_tls_client_create_vhost_context(struct lws_vhost *vh,
				    struct lws_context_creation_info *info,
				    const char *cipher_list,
				    const char *ca_filepath,
				    const char *cert_filepath,
				    const char *private_key_filepath);

LWS_EXTERN lws_tls_ctx *
lws_tls_ctx_from_wsi(struct lws *wsi);
LWS_EXTERN int
lws_ssl_get_error(struct lws *wsi, int n);

/* HTTP2-related */

#ifdef LWS_WITH_HTTP2
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
	pthread_mutex_init(&pt->lock_stats, NULL);
}

static LWS_INLINE void
lws_pt_mutex_destroy(struct lws_context_per_thread *pt)
{
	pthread_mutex_destroy(&pt->lock_stats);
	pthread_mutex_destroy(&pt->lock);
}

static LWS_INLINE void
lws_pt_lock(struct lws_context_per_thread *pt, const char *reason)
{
	if (pt->lock_owner == pthread_self()) {
		pt->lock_depth++;
		return;
	}
	pthread_mutex_lock(&pt->lock);
	pt->last_lock_reason = reason;
	pt->lock_owner = pthread_self();
	//lwsl_notice("tid %d: lock %s\n", pt->tid, reason);
}

static LWS_INLINE void
lws_pt_unlock(struct lws_context_per_thread *pt)
{
	if (pt->lock_depth) {
		pt->lock_depth--;
		return;
	}
	pt->last_lock_reason ="free";
	pt->lock_owner = 0;
	//lwsl_notice("tid %d: unlock %s\n", pt->tid, pt->last_lock_reason);
	pthread_mutex_unlock(&pt->lock);
}

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

static LWS_INLINE void
lws_context_lock(struct lws_context *context)
{
	pthread_mutex_lock(&context->lock);
}

static LWS_INLINE void
lws_context_unlock(struct lws_context *context)
{
	pthread_mutex_unlock(&context->lock);
}

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
#define lws_context_lock(_a) (void)(_a)
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
	if ((int)s->len != len)
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
LWS_EXTERN int lws_client_socket_service(struct lws *wsi,
					 struct lws_pollfd *pollfd,
					 struct lws *wsi_conn);
LWS_EXTERN struct lws *
lws_client_wsi_effective(struct lws *wsi);
LWS_EXTERN int LWS_WARN_UNUSED_RESULT
lws_http_transaction_completed_client(struct lws *wsi);
#ifdef LWS_OPENSSL_SUPPORT
LWS_EXTERN int
lws_context_init_client_ssl(struct lws_context_creation_info *info,
			    struct lws_vhost *vhost);

LWS_EXTERN void
lws_ssl_info_callback(const lws_tls_conn *ssl, int where, int ret);

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
__lws_rx_flow_control(struct lws *wsi);

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
LWS_EXTERN void
lws_prepare_access_log_info(struct lws *wsi, char *uri_ptr, int meth);
#else
#define lws_access_log(_a)
#endif

LWS_EXTERN int
lws_cgi_kill_terminated(struct lws_context_per_thread *pt);

LWS_EXTERN void
lws_cgi_remove_and_kill(struct lws *wsi);

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
lws_plat_pipe_create(struct lws *wsi);
int
lws_plat_pipe_signal(struct lws *wsi);
void
lws_plat_pipe_close(struct lws *wsi);
int
lws_create_event_pipes(struct lws_context *context);

const struct lws_plat_file_ops *
lws_vfs_select_fops(const struct lws_plat_file_ops *fops, const char *vfs_path,
		    const char **vpath);

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
LWS_EXTERN void
lws_add_wsi_to_draining_ext_list(struct lws *wsi);
LWS_EXTERN void
lws_remove_wsi_from_draining_ext_list(struct lws *wsi);
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
lws_plat_inet_pton(int af, const char *src, void *dst);

LWS_EXTERN int LWS_WARN_UNUSED_RESULT
lws_check_utf8(unsigned char *state, unsigned char *buf, size_t len);
LWS_EXTERN int alloc_file(struct lws_context *context, const char *filename, uint8_t **buf,
		                lws_filepos_t *amount);


LWS_EXTERN void
lws_same_vh_protocol_remove(struct lws *wsi);
LWS_EXTERN void
lws_same_vh_protocol_insert(struct lws *wsi, int n);

LWS_EXTERN int
lws_broadcast(struct lws_context *context, int reason, void *in, size_t len);

#if defined(LWS_WITH_STATS)
void
lws_stats_atomic_bump(struct lws_context * context,
		struct lws_context_per_thread *pt, int index, uint64_t bump);
void
lws_stats_atomic_max(struct lws_context * context,
		struct lws_context_per_thread *pt, int index, uint64_t val);
#else
static inline uint64_t lws_stats_atomic_bump(struct lws_context * context,
		struct lws_context_per_thread *pt, int index, uint64_t bump) {
	(void)context; (void)pt; (void)index; (void)bump; return 0; }
static inline uint64_t lws_stats_atomic_max(struct lws_context * context,
		struct lws_context_per_thread *pt, int index, uint64_t val) {
	(void)context; (void)pt; (void)index; (void)val; return 0; }
#endif

/* socks */
void socks_generate_msg(struct lws *wsi, enum socks_msg_type type,
			ssize_t *msg_len);

#if defined(LWS_WITH_PEER_LIMITS)
void
lws_peer_track_wsi_close(struct lws_context *context, struct lws_peer *peer);
int
lws_peer_confirm_ah_attach_ok(struct lws_context *context, struct lws_peer *peer);
void
lws_peer_track_ah_detach(struct lws_context *context, struct lws_peer *peer);
void
lws_peer_cull_peer_wait_list(struct lws_context *context);
struct lws_peer *
lws_get_or_create_peer(struct lws_vhost *vhost, lws_sockfd_type sockfd);
void
lws_peer_add_wsi(struct lws_context *context, struct lws_peer *peer,
		 struct lws *wsi);
#endif


void
__lws_remove_from_timeout_list(struct lws *wsi);

lws_usec_t
__lws_hrtimer_service(struct lws_context_per_thread *pt);

void
__lws_set_timeout(struct lws *wsi, enum pending_timeout reason, int secs);
int
__lws_change_pollfd(struct lws *wsi, int _and, int _or);

#ifdef __cplusplus
};
#endif
