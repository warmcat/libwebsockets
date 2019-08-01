/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2018 Andy Green <andy@warmcat.com>
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

/** @file */

#ifndef LIBWEBSOCKET_H_3060898B846849FF9F88F5DB59B5950C
#define LIBWEBSOCKET_H_3060898B846849FF9F88F5DB59B5950C

#ifdef __cplusplus
#include <cstddef>
#include <cstdarg>

extern "C" {
#else
#include <stdarg.h>
#endif

#include <string.h>
#include <stdlib.h>

#include "lws_config.h"

/*
 * CARE: everything using cmake defines needs to be below here
 */

#if defined(LWS_HAS_INTPTR_T)
#include <stdint.h>
#define lws_intptr_t intptr_t
#else
typedef unsigned long long lws_intptr_t;
#endif

#if defined(WIN32) || defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stddef.h>
#include <basetsd.h>
#include <io.h>
#ifndef _WIN32_WCE
#include <fcntl.h>
#else
#define _O_RDONLY	0x0000
#define O_RDONLY	_O_RDONLY
#endif

#define LWS_INLINE __inline
#define LWS_VISIBLE
#define LWS_WARN_UNUSED_RESULT
#define LWS_WARN_DEPRECATED
#define LWS_FORMAT(string_index)

#if !defined(LWS_EXTERN)
#ifdef LWS_DLL
#ifdef LWS_INTERNAL
#define LWS_EXTERN extern __declspec(dllexport)
#else
#define LWS_EXTERN extern __declspec(dllimport)
#endif
#else
#define LWS_EXTERN
#endif
#endif

#define LWS_INVALID_FILE INVALID_HANDLE_VALUE
#define LWS_SOCK_INVALID (INVALID_SOCKET)
#define LWS_O_RDONLY _O_RDONLY
#define LWS_O_WRONLY _O_WRONLY
#define LWS_O_CREAT _O_CREAT
#define LWS_O_TRUNC _O_TRUNC

#ifndef __func__
#define __func__ __FUNCTION__
#endif

#else /* NOT WIN32 */
#include <unistd.h>
#if defined(LWS_HAVE_SYS_CAPABILITY_H) && defined(LWS_HAVE_LIBCAP)
#include <sys/capability.h>
#endif

#if defined(__NetBSD__) || defined(__FreeBSD__) || defined(__QNX__) || defined(__OpenBSD__)
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#define LWS_INLINE inline
#define LWS_O_RDONLY O_RDONLY
#define LWS_O_WRONLY O_WRONLY
#define LWS_O_CREAT O_CREAT
#define LWS_O_TRUNC O_TRUNC

#if !defined(LWS_PLAT_OPTEE) && !defined(OPTEE_TA) && !defined(LWS_WITH_ESP32)
#include <poll.h>
#include <netdb.h>
#define LWS_INVALID_FILE -1
#define LWS_SOCK_INVALID (-1)
#else
#define getdtablesize() (30)
#if defined(LWS_WITH_ESP32)
#define LWS_INVALID_FILE NULL
#define LWS_SOCK_INVALID (-1)
#else
#define LWS_INVALID_FILE NULL
#define LWS_SOCK_INVALID (-1)
#endif
#endif

#if defined(__GNUC__)

/* warn_unused_result attribute only supported by GCC 3.4 or later */
#if __GNUC__ >= 4 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 4)
#define LWS_WARN_UNUSED_RESULT __attribute__((warn_unused_result))
#else
#define LWS_WARN_UNUSED_RESULT
#endif

#define LWS_VISIBLE __attribute__((visibility("default")))
#define LWS_WARN_DEPRECATED __attribute__ ((deprecated))
#define LWS_FORMAT(string_index) __attribute__ ((format(printf, string_index, string_index+1)))
#else
#define LWS_VISIBLE
#define LWS_WARN_UNUSED_RESULT
#define LWS_WARN_DEPRECATED
#define LWS_FORMAT(string_index)
#endif

#if defined(__ANDROID__)
#include <netinet/in.h>
#include <unistd.h>
#endif

#endif

#if defined(LWS_WITH_LIBEV)
#include <ev.h>
#endif /* LWS_WITH_LIBEV */
#ifdef LWS_WITH_LIBUV
#include <uv.h>
#ifdef LWS_HAVE_UV_VERSION_H
#include <uv-version.h>
#endif
#ifdef LWS_HAVE_NEW_UV_VERSION_H
#include <uv/version.h>
#endif
#endif /* LWS_WITH_LIBUV */
#if defined(LWS_WITH_LIBEVENT)
#include <event2/event.h>
#endif /* LWS_WITH_LIBEVENT */

#ifndef LWS_EXTERN
#define LWS_EXTERN extern
#endif

#ifdef _WIN32
#define random rand
#else
#if !defined(LWS_PLAT_OPTEE)
#include <sys/time.h>
#include <unistd.h>
#endif
#endif

#if defined(LWS_WITH_TLS)

#ifdef USE_WOLFSSL
#ifdef USE_OLD_CYASSL
#ifdef _WIN32
/*
 * Include user-controlled settings for windows from
 * <wolfssl-root>/IDE/WIN/user_settings.h
 */
#include <IDE/WIN/user_settings.h>
#include <cyassl/ctaocrypt/settings.h>
#else
#include <cyassl/options.h>
#endif
#include <cyassl/openssl/ssl.h>
#include <cyassl/error-ssl.h>

#else
#ifdef _WIN32
/*
 * Include user-controlled settings for windows from
 * <wolfssl-root>/IDE/WIN/user_settings.h
 */
#include <IDE/WIN/user_settings.h>
#include <wolfssl/wolfcrypt/settings.h>
#else
#include <wolfssl/options.h>
#endif
#include <wolfssl/openssl/ssl.h>
#include <wolfssl/error-ssl.h>
#endif /* not USE_OLD_CYASSL */
#else
#if defined(LWS_WITH_MBEDTLS)
#if defined(LWS_WITH_ESP32)
/* this filepath is passed to us but without quotes or <> */
#if !defined(LWS_AMAZON_RTOS)
/* AMAZON RTOS has its own setting via MTK_MBEDTLS_CONFIG_FILE */
#undef MBEDTLS_CONFIG_FILE
#define MBEDTLS_CONFIG_FILE <mbedtls/esp_config.h>
#endif
#endif
#include <mbedtls/ssl.h>
#else
#include <openssl/ssl.h>
#if !defined(LWS_WITH_MBEDTLS)
#include <openssl/err.h>
#endif
#endif
#endif /* not USE_WOLFSSL */
#endif

/*
 * Helpers for pthread mutex in user code... if lws is built for
 * multiple service threads, these resolve to pthread mutex
 * operations.  In the case LWS_MAX_SMP is 1 (the default), they
 * are all NOPs and no pthread type or api is referenced.
 */

#if LWS_MAX_SMP > 1

#include <pthread.h>

#define lws_pthread_mutex(name) pthread_mutex_t name;

static LWS_INLINE void
lws_pthread_mutex_init(pthread_mutex_t *lock)
{
	pthread_mutex_init(lock, NULL);
}

static LWS_INLINE void
lws_pthread_mutex_destroy(pthread_mutex_t *lock)
{
	pthread_mutex_destroy(lock);
}

static LWS_INLINE void
lws_pthread_mutex_lock(pthread_mutex_t *lock)
{
	pthread_mutex_lock(lock);
}

static LWS_INLINE void
lws_pthread_mutex_unlock(pthread_mutex_t *lock)
{
	pthread_mutex_unlock(lock);
}

#else
#define lws_pthread_mutex(name)
#define lws_pthread_mutex_init(_a)
#define lws_pthread_mutex_destroy(_a)
#define lws_pthread_mutex_lock(_a)
#define lws_pthread_mutex_unlock(_a)
#endif


#define CONTEXT_PORT_NO_LISTEN -1
#define CONTEXT_PORT_NO_LISTEN_SERVER -2

#include <libwebsockets/lws-logs.h>


#include <stddef.h>

#ifndef lws_container_of
#define lws_container_of(P,T,M)	((T *)((char *)(P) - offsetof(T, M)))
#endif

struct lws;

/* api change list for user code to test against */

#define LWS_FEATURE_SERVE_HTTP_FILE_HAS_OTHER_HEADERS_ARG

/* the struct lws_protocols has the id field present */
#define LWS_FEATURE_PROTOCOLS_HAS_ID_FIELD

/* you can call lws_get_peer_write_allowance */
#define LWS_FEATURE_PROTOCOLS_HAS_PEER_WRITE_ALLOWANCE

/* extra parameter introduced in 917f43ab821 */
#define LWS_FEATURE_SERVE_HTTP_FILE_HAS_OTHER_HEADERS_LEN

/* File operations stuff exists */
#define LWS_FEATURE_FOPS


#if defined(_WIN32)
#if !defined(LWS_WIN32_HANDLE_TYPES)
typedef SOCKET lws_sockfd_type;
typedef HANDLE lws_filefd_type;
#endif

struct lws_pollfd {
	lws_sockfd_type fd; /**< file descriptor */
	SHORT events; /**< which events to respond to */
	SHORT revents; /**< which events happened */
};
#define LWS_POLLHUP (FD_CLOSE)
#define LWS_POLLIN (FD_READ | FD_ACCEPT)
#define LWS_POLLOUT (FD_WRITE)
#else


#if defined(LWS_WITH_ESP32)
#include <libwebsockets/lws-esp32.h>
#else
typedef int lws_sockfd_type;
typedef int lws_filefd_type;
#endif

#if defined(LWS_PLAT_OPTEE)
#include <time.h>
struct timeval {
	time_t         	tv_sec;
	unsigned int    tv_usec;
};
#if defined(LWS_WITH_NETWORK)
// #include <poll.h>
#define lws_pollfd pollfd

struct timezone;

int gettimeofday(struct timeval *tv, struct timezone *tz);

    /* Internet address. */
    struct in_addr {
        uint32_t       s_addr;     /* address in network byte order */
    };

typedef unsigned short sa_family_t;
typedef unsigned short in_port_t;
typedef uint32_t socklen_t;

#include <libwebsockets/lws-optee.h>

#if !defined(TEE_SE_READER_NAME_MAX)
           struct addrinfo {
               int              ai_flags;
               int              ai_family;
               int              ai_socktype;
               int              ai_protocol;
               socklen_t        ai_addrlen;
               struct sockaddr *ai_addr;
               char            *ai_canonname;
               struct addrinfo *ai_next;
           };
#endif

ssize_t recv(int sockfd, void *buf, size_t len, int flags);
ssize_t send(int sockfd, const void *buf, size_t len, int flags);
ssize_t read(int fd, void *buf, size_t count);
int getsockopt(int sockfd, int level, int optname,
                      void *optval, socklen_t *optlen);
       int setsockopt(int sockfd, int level, int optname,
                      const void *optval, socklen_t optlen);
int connect(int sockfd, const struct sockaddr *addr,
                   socklen_t addrlen);

extern int errno;

uint16_t ntohs(uint16_t netshort);
uint16_t htons(uint16_t hostshort);

int bind(int sockfd, const struct sockaddr *addr,
                socklen_t addrlen);


#define  MSG_NOSIGNAL 0x4000
#define	EAGAIN		11
#define EINTR		4
#define EWOULDBLOCK	EAGAIN
#define	EADDRINUSE	98	
#define INADDR_ANY	0
#define AF_INET		2
#define SHUT_WR 1
#define AF_UNSPEC	0
#define PF_UNSPEC	0
#define SOCK_STREAM	1
#define SOCK_DGRAM	2
# define AI_PASSIVE	0x0001
#define IPPROTO_UDP	17
#define SOL_SOCKET	1
#define SO_SNDBUF	7
#define	EISCONN		106	
#define	EALREADY	114
#define	EINPROGRESS	115
int shutdown(int sockfd, int how);
int close(int fd);
int atoi(const char *nptr);
long long atoll(const char *nptr);

int socket(int domain, int type, int protocol);
       int getaddrinfo(const char *node, const char *service,
                       const struct addrinfo *hints,
                       struct addrinfo **res);

       void freeaddrinfo(struct addrinfo *res);

#if !defined(TEE_SE_READER_NAME_MAX)
struct lws_pollfd
{
        int fd;                     /* File descriptor to poll.  */
        short int events;           /* Types of events poller cares about.  */
        short int revents;          /* Types of events that actually occurred.  */
};
#endif

int poll(struct pollfd *fds, int nfds, int timeout);

#define LWS_POLLHUP (0x18)
#define LWS_POLLIN (1)
#define LWS_POLLOUT (4)
#else
struct lws_pollfd;
struct sockaddr_in;
#endif
#else
#define lws_pollfd pollfd
#define LWS_POLLHUP (POLLHUP | POLLERR)
#define LWS_POLLIN (POLLIN)
#define LWS_POLLOUT (POLLOUT)
#endif
#endif


#if (defined(WIN32) || defined(_WIN32)) && !defined(__MINGW32__)
/* ... */
#define ssize_t SSIZE_T
#endif

#if defined(WIN32) && defined(LWS_HAVE__STAT32I64)
#include <sys/types.h>
#include <sys/stat.h>
#endif

#if defined(LWS_HAVE_STDINT_H)
#include <stdint.h>
#else
#if defined(WIN32) || defined(_WIN32)
/* !!! >:-[  */
typedef __int64 int64_t;
typedef unsigned __int64 uint64_t;
typedef __int32 int32_t;
typedef unsigned __int32 uint32_t;
typedef __int16 int16_t;
typedef unsigned __int16 uint16_t;
typedef unsigned __int8 uint8_t;
#else
typedef unsigned int uint32_t;
typedef unsigned short uint16_t;
typedef unsigned char uint8_t;
#endif
#endif

typedef int64_t lws_usec_t;
typedef unsigned long long lws_filepos_t;
typedef long long lws_fileofs_t;
typedef uint32_t lws_fop_flags_t;

#define lws_concat_temp(_t, _l) (_t + sizeof(_t) - _l)
#define lws_concat_used(_t, _l) (sizeof(_t) - _l)

/** struct lws_pollargs - argument structure for all external poll related calls
 * passed in via 'in' */
struct lws_pollargs {
	lws_sockfd_type fd;	/**< applicable socket descriptor */
	int events;		/**< the new event mask */
	int prev_events;	/**< the previous event mask */
};

struct lws_extension; /* needed even with ws exts disabled for create context */
struct lws_token_limits;
struct lws_context;
struct lws_tokens;
struct lws_vhost;
struct lws;

#include <libwebsockets/lws-ws-close.h>
#include <libwebsockets/lws-callbacks.h>
#include <libwebsockets/lws-ws-state.h>
#include <libwebsockets/lws-ws-ext.h>
#include <libwebsockets/lws-protocols-plugins.h>
#include <libwebsockets/lws-plugin-generic-sessions.h>
#include <libwebsockets/lws-context-vhost.h>
#include <libwebsockets/lws-client.h>
#include <libwebsockets/lws-http.h>
#include <libwebsockets/lws-spa.h>
#include <libwebsockets/lws-purify.h>
#include <libwebsockets/lws-timeout-timer.h>
#include <libwebsockets/lws-service.h>
#include <libwebsockets/lws-write.h>
#include <libwebsockets/lws-writeable.h>
#include <libwebsockets/lws-adopt.h>
#include <libwebsockets/lws-network-helper.h>
#include <libwebsockets/lws-misc.h>
#include <libwebsockets/lws-ring.h>
#include <libwebsockets/lws-sha1-base64.h>
#include <libwebsockets/lws-x509.h>
#include <libwebsockets/lws-cgi.h>
#include <libwebsockets/lws-vfs.h>
#include <libwebsockets/lws-lejp.h>
#include <libwebsockets/lws-stats.h>
#include <libwebsockets/lws-struct.h>
#include <libwebsockets/lws-threadpool.h>
#include <libwebsockets/lws-tokenize.h>
#include <libwebsockets/lws-lwsac.h>
#include <libwebsockets/lws-fts.h>
#include <libwebsockets/lws-diskcache.h>
#include <libwebsockets/lws-sequencer.h>

#include <libwebsockets/abstract/abstract.h>

#include <libwebsockets/lws-test-sequencer.h>

#if defined(LWS_WITH_TLS)

#if defined(LWS_WITH_MBEDTLS)
#include <mbedtls/md5.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#endif

#include <libwebsockets/lws-gencrypto.h>
#include <libwebsockets/lws-genhash.h>
#include <libwebsockets/lws-genrsa.h>
#include <libwebsockets/lws-genaes.h>
#include <libwebsockets/lws-genec.h>

#include <libwebsockets/lws-jwk.h>
#include <libwebsockets/lws-jose.h>
#include <libwebsockets/lws-jws.h>
#include <libwebsockets/lws-jwe.h>

#endif

#ifdef __cplusplus
}
#endif

#endif
