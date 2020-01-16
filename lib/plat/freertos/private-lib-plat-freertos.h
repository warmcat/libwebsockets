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
 *
 * Included from lib/private-lib-core.h if LWS_PLAT_FREERTOS
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
#if defined(LWS_WITH_SYS_ASYNC_DNS)
 #include "FreeRTOS_IP.h"
#endif
 #include "timers.h"
 #include <esp_attr.h>
#else
 #include "freertos/timers.h"
 #include <esp_attr.h>
 #include <esp_system.h>
 #include <esp_task_wdt.h>
#endif

#if defined(LWS_WITH_ESP32)
#include "lwip/apps/sntp.h"
#endif

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

