#if defined(_WIN32) && defined(EXTERNAL_POLL)
#define WINVER 0x0600
#define _WIN32_WINNT 0x0600
#define poll(fdArray, fds, timeout)  WSAPoll((LPWSAPOLLFD)(fdArray), (ULONG)(fds), (INT)(timeout))
#endif

#include "lws_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <signal.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#ifndef _WIN32
#include <dirent.h>
#endif

#include "../lib/libwebsockets.h"
#include "lejp.h"

#ifdef _WIN32
#include <io.h>
#include "gettimeofday.h"
#else
#include <syslog.h>
#include <sys/time.h>
#include <unistd.h>
#endif

extern void test_server_lock(int care);
extern void test_server_unlock(int care);

#ifndef __func__
#define __func__ __FUNCTION__
#endif

struct per_session_data__http {
	lws_filefd_type fd;
#ifdef LWS_WITH_CGI
	struct lws_cgi_args args;
#endif
#if defined(LWS_WITH_CGI) || !defined(LWS_NO_CLIENT)
	int reason_bf;
#endif
	char post_string[256];
	unsigned int client_finished:1;
};

extern int
lwsws_get_config_globals(struct lws_context_creation_info *info, const char *d,
		char **config_strings, int *len);

extern int
lwsws_get_config_vhosts(struct lws_context *context,
			struct lws_context_creation_info *info, const char *d,
			char **config_strings, int *len);

extern int
callback_http(struct lws *wsi, enum lws_callback_reasons reason,
	      void *user, void *in, size_t len);
