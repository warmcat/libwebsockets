/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2018 Andy Green <andy@warmcat.com>
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
 *  Included from lib/core/private.h if LWS_WITH_ESP32
 */

#define MSG_NOSIGNAL 0
#define SOMAXCONN 3

#if defined(LWS_AMAZON_RTOS)
 int
 open(const char *path, int oflag, ...);
#else
 #include <fcntl.h>
#endif

 #include <strings.h>
 #include <unistd.h>
 #include <sys/stat.h>
 #include <sys/types.h>
 #include <sys/time.h>
 #include <netdb.h>

 #ifndef __cplusplus
  #include <errno.h>
 #endif
 #include <netdb.h>
 #include <signal.h>
#if defined(LWS_AMAZON_RTOS)
const char *
gai_strerror(int);
#else
 #include <sys/socket.h>
#endif

#if defined(LWS_AMAZON_RTOS)
 #include "FreeRTOS.h"
 #include "timers.h"
 #include <esp_attr.h>
#else
 #include "freertos/timers.h"
 #include <esp_attr.h>
 #include <esp_system.h>
 #include <esp_task_wdt.h>
#endif

#include "lwip/apps/sntp.h"

#include <lwip/sockets.h>

 #if defined(LWS_BUILTIN_GETIFADDRS)
  #include "./misc/getifaddrs.h"
 #endif

 #define LWS_ERRNO errno
 #define LWS_EAGAIN EAGAIN
 #define LWS_EALREADY EALREADY
 #define LWS_EINPROGRESS EINPROGRESS
 #define LWS_EINTR EINTR
 #define LWS_EISCONN EISCONN
 #define LWS_ENOTCONN ENOTCONN
 #define LWS_EWOULDBLOCK EWOULDBLOCK
 #define LWS_EADDRINUSE EADDRINUSE

 #define lws_set_blocking_send(wsi)

 #ifndef LWS_NO_FORK
  #ifdef LWS_HAVE_SYS_PRCTL_H
   #include <sys/prctl.h>
  #endif
 #endif

#define compatible_close(x) close(x)
#define lws_plat_socket_offset() LWIP_SOCKET_OFFSET
#define wsi_from_fd(A,B)  A->lws_lookup[B - lws_plat_socket_offset()]

struct lws_context;
struct lws;

int
insert_wsi(const struct lws_context *context, struct lws *wsi);

#define delete_from_fd(A,B) A->lws_lookup[B - lws_plat_socket_offset()] = 0

