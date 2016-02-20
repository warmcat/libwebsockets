/*
 * libwebsockets-test-server - libwebsockets test implementation
 *
 * Copyright (C) 2010-2016 Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The person who associated a work with this deed has dedicated
 * the work to the public domain by waiving all of his or her rights
 * to the work worldwide under copyright law, including all related
 * and neighboring rights, to the extent allowed by law. You can copy,
 * modify, distribute and perform the work, even for commercial purposes,
 * all without asking permission.
 *
 * The test apps are intended to be adapted for use in your code, which
 * may be proprietary.  So unlike the library itself, they are licensed
 * Public Domain.
 */

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

#include "../lib/libwebsockets.h"

#ifdef _WIN32
#include <io.h>
#include "gettimeofday.h"
#else
#include <syslog.h>
#include <sys/time.h>
#include <unistd.h>
#endif

extern int close_testing;
extern int max_poll_elements;

#ifdef EXTERNAL_POLL
extern struct lws_pollfd *pollfds;
extern int *fd_lookup;
extern int count_pollfds;
#endif
extern volatile int force_exit;
extern struct lws_context *context;
extern char *resource_path;

extern void test_server_lock(int care);
extern void test_server_unlock(int care);

#ifndef __func__
#define __func__ __FUNCTION__
#endif

struct per_session_data__http {
	lws_filefd_type fd;
};

/*
 * one of these is auto-created for each connection and a pointer to the
 * appropriate instance is passed to the callback in the user parameter
 *
 * for this example protocol we use it to individualize the count for each
 * connection.
 */

struct per_session_data__dumb_increment {
	int number;
};

struct per_session_data__lws_mirror {
	struct lws *wsi;
	int ringbuffer_tail;
};

struct per_session_data__echogen {
	size_t total;
	size_t total_rx;
	int fd;
	int fragsize;
	int wr;
};

struct per_session_data__lws_status {
	struct per_session_data__lws_status *list;
	struct timeval tv_established;
	int last;
	char ip[270];
	char user_agent[512];
	const char *pos;
	int len;
};

extern int
callback_http(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	      void *in, size_t len);
extern int
callback_lws_mirror(struct lws *wsi, enum lws_callback_reasons reason,
		    void *user, void *in, size_t len);
extern int
callback_dumb_increment(struct lws *wsi, enum lws_callback_reasons reason,
			void *user, void *in, size_t len);
extern int
callback_lws_echogen(struct lws *wsi, enum lws_callback_reasons reason,
			void *user, void *in, size_t len);
extern int
callback_lws_status(struct lws *wsi, enum lws_callback_reasons reason,
		    void *user, void *in, size_t len);


extern void
dump_handshake_info(struct lws *wsi);
