/*
 * fuzzing proxy - network-level fuzzing injection proxy
 *
 * Copyright (C) 2016 Andy Green <andy@warmcat.com>
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
 *
 * fuzxy is designed to go on the client path
 *
 * [ client <-> fuzxy ] <-> server
 *
 * you can arrange that with, eg,
 *
 *  http_proxy=localhost:8880
 *
 * env var before starting the client.
 *
 * Even though he is on the client side, he is able to see and change traffic
 * in both directions, and so fuzz both the client and the server.
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
#include <errno.h>
#include "../lib/libwebsockets.h"

#ifdef _WIN32
#include <io.h>
#include "gettimeofday.h"
#else
#include <syslog.h>
#include <sys/time.h>
#include <unistd.h>
#endif


enum types {
	FZY_S_DEAD		= 0,
	FZY_S_LISTENING		= 1,
	FZY_S_ACCEPTED		= 2,
	FZY_S_PROXIED		= 3,
	FZY_S_ONWARD		= 4,
};

enum proxy_parser_states {
	FZY_PP_CONNECT		= 0,
	FZY_PP_ADDRESS		= 1,
	FZY_PP_PORT		= 2,
	FZY_PP_CRLFS		= 3,
};

enum fuzzer_parser_states {
	FZY_FP_SEARCH		= 0,
	FZY_FP_SEARCH2		= 1,
	FZY_FP_INJECT		= 2,
	FZY_FP_PENDING		= 3,
};

struct ring {
	char buf[4096];
	int head;
	int tail;
};

struct state {
	enum types type;
	enum proxy_parser_states pp;
	int ppc;

	struct ring in;

	char address[256];
	int port;

	enum fuzzer_parser_states fp;
	int fuzc;
	int pending;

	int twin; /* must be fixed up when arrays lose guys */
	unsigned int outbound:1; /* from local -> remote */
};


int force_exit = 0;

static const int ring_size(struct ring *r)
{
	return sizeof(r->buf);
}
static const int ring_used(struct ring *r)
{
	return (r->head - r->tail) & (ring_size(r) - 1);
}
static const int ring_free(struct ring *r)
{
	return (ring_size(r) - 1) - ring_used(r);
}
static const int ring_get_one(struct ring *r)
{
	int n = r->buf[r->tail] & 255;

	if (r->tail == r->head)
		return -1;

	r->tail++;
	if (r->tail == ring_size(r))
		r->tail = 0;

	return n;
}

void sighandler(int sig)
{
	force_exit = 1;
}

static struct option options[] = {
	{ "help",	no_argument,		NULL, 'h' },
	{ "debug",	required_argument,	NULL, 'd' },
	{ "port",	required_argument,	NULL, 'p' },
	{ "ssl",	no_argument,		NULL, 's' },
	{ "allow-non-ssl",	no_argument,	NULL, 'a' },
	{ "interface",  required_argument,	NULL, 'i' },
	{ "closetest",  no_argument,		NULL, 'c' },
	{ "libev",  no_argument,		NULL, 'e' },
#ifndef LWS_NO_DAEMONIZE
	{ "daemonize", 	no_argument,		NULL, 'D' },
#endif
	{ "resource_path", required_argument,	NULL, 'r' },
	{ NULL, 0, 0, 0 }
};

static struct pollfd pfd[128];
static struct state state[128];
static int pfds = 0;

static void close_and_remove_fd(int index)
{
	int n;

	lwsl_notice("%s: closing index %d\n", __func__, index);
	close(pfd[index].fd);
	pfd[index].fd = -1;

	n = state[index].twin;
	if (n) {
		assert(state[n].twin == index);
	}
	state[index].type = FZY_S_DEAD;

	if (index == pfds - 1) {
		if (state[index].twin)
			state[state[index].twin].twin = 0;
		state[index].twin = 0;
		goto bail;
	}

	/* swap the end guy into the deleted guy and trim back one */

	if (state[pfds - 1].twin) {
		state[state[pfds - 1].twin].twin = index;
		if (n && n == pfds - 1)
			n = index;
	}

	/* swap the last guy into dead guy's place and trim by one */
	pfd[index] = pfd[pfds - 1];
	state[index] = state[pfds - 1];

	if (n) {
		pfds--;
		state[n].twin = 0;
		close_and_remove_fd(n);
		return;
	}

bail:
	pfds--;
}

static void construct_state(int n, enum types s, int flags)
{
	memset(&state[n], 0, sizeof state[n]);
	state[n].type = s;
	pfd[n].events = flags | POLLHUP;
}

static int
fuzxy_listen(const char *interface_name, int port, int *sockfd)
{
	struct sockaddr_in serv_addr4;
	socklen_t len = sizeof(struct sockaddr);
	struct sockaddr_in sin;
	int n, opt = 1;

	*sockfd = socket(AF_INET, SOCK_STREAM, 0);

	if (*sockfd == -1) {
		lwsl_err("ERROR opening socket\n");
		goto bail1;
	}

	if (setsockopt(*sockfd, SOL_SOCKET, SO_REUSEADDR,
		       (const void *)&opt, sizeof(opt)) < 0) {
		lwsl_err("unable to set listen socket options\n");
		goto bail2;
	}

	bzero((char *) &serv_addr4, sizeof(serv_addr4));
	serv_addr4.sin_addr.s_addr = INADDR_ANY;
	serv_addr4.sin_family = AF_INET;

	if (interface_name[0] &&
	    lws_interface_to_sa(0, interface_name, (struct sockaddr_in *)
			        (struct sockaddr *)&serv_addr4,
				sizeof(serv_addr4)) < 0) {
		lwsl_err("Unable to find interface %s\n", interface_name);
		goto bail2;
	}

	serv_addr4.sin_port = htons(port);

	n = bind(*sockfd, (struct sockaddr *)&serv_addr4,
				sizeof(serv_addr4));
	if (n < 0) {
		lwsl_err("ERROR on binding to port %d (%d %d)\n",
			 port, n, errno);
		goto bail2;
	}

	if (getsockname(*sockfd, (struct sockaddr *)&sin, &len) == -1)
		lwsl_warn("getsockname: %s\n", strerror(errno));
	else
		port = ntohs(sin.sin_port);

	listen(*sockfd, SOMAXCONN);

	return 0;
bail2:
	close(*sockfd);
bail1:
	return -1;
}

struct fuzxy_rule {
	const char *s[3];
	int len[3];
	int inject_len;
};

struct fuzxy_rule r = {
		{ "Host:", "\x0d", " \x0d" },
		{ 5, 1, 2 },
		65536
};

static int fuzz(int n, char *out, int len)
{
	struct state *s = &state[n];
	int m = 0;
	int c;

	while (m < len) {
		switch (s->fp) {
		case FZY_FP_SEARCH:
			c = ring_get_one(&state[s->twin].in);
			if (c < 0)
				return m;
			if (c == r.s[0][s->fuzc++]) {
				if (s->fuzc == r.len[0]) {
					s->fuzc = 0;
					s->fp = FZY_FP_SEARCH2;
				}
			} else
				s->fuzc = 0;
			out[m++] = c;
			break;

		case FZY_FP_SEARCH2:
			c = ring_get_one(&state[s->twin].in);
			if (c < 0)
				return m;
			if (c == r.s[1][s->fuzc++]) {
				if (s->fuzc == r.len[1]) {
					lwsl_notice("+++++++fuzzer hit...\n");
					s->fuzc = 0;
					s->fp = FZY_FP_INJECT;
					s->pending = c;
					goto inject;
				}
			} else
				s->fuzc = 0;
			out[m++] = c;
			break;
		case FZY_FP_INJECT:
inject:
			out[m++] = r.s[2][s->fuzc++ % r.len[2]];
			if (s->fuzc == r.inject_len)
				s->fp = FZY_FP_PENDING;
			break;

		case FZY_FP_PENDING:
			out[m++] = s->pending;
			s->fp = FZY_FP_SEARCH;
			s->fuzc = 0;
			break;
		}
	}

	return m;
}

static int
handle_accept(int n)
{
	struct addrinfo ai, *res, *result;
	struct sockaddr_in serv_addr4;
	struct state *s = &state[n];
	void *p = NULL;
	int m, sockfd;

	while (1) {
		m = ring_get_one(&s->in);
		if (m < 0)
			return 0;

		switch (s->pp) {
		case FZY_PP_CONNECT:
			if (m != "CONNECT "[s->ppc++]) {
				lwsl_notice("failed CONNECT match\n");
				return 1;
			}
			if (s->ppc == 8) {
				s->pp = FZY_PP_ADDRESS;
				s->ppc = 0;
			}
			break;
		case FZY_PP_ADDRESS:
			if (m == ':') {
				s->address[s->ppc++] = '\0';
				s->pp = FZY_PP_PORT;
				s->ppc = 0;
				break;
			}
			if (m == ' ') {
				s->address[s->ppc++] = '\0';
				s->pp = FZY_PP_CRLFS;
				s->ppc = 0;
				break;
			}


			s->address[s->ppc++] = m;
			if (s->ppc == sizeof(s->address)) {
				lwsl_notice("Failed on address length\n");
				return 1;
			}
			break;
		case FZY_PP_PORT:
			if (m == ' ') {
				s->pp = FZY_PP_CRLFS;
				s->ppc = 0;
				break;
			}
			if (m >= '0' && m <= '9') {
				s->port *= 10;
				s->port += m - '0';
				break;
			}
			return 1;

		case FZY_PP_CRLFS:
			if (m != "\x0d\x0a\x0d\x0a"[s->ppc++])
				s->ppc = 0;
			if (s->ppc != 4)
				break;
			s->type = FZY_S_PROXIED;

			memset (&ai, 0, sizeof ai);
			ai.ai_family = PF_UNSPEC;
			ai.ai_socktype = SOCK_STREAM;
			ai.ai_flags = AI_CANONNAME;

			if (getaddrinfo(s->address, NULL, &ai, &result)) {
				lwsl_notice("failed to lookup %s\n",
					    s->address);
				return 1;
			}

			res = result;
			while (!p && res) {
				switch (res->ai_family) {
				case AF_INET:
					p = &((struct sockaddr_in *)res->
					      ai_addr)->sin_addr;
					break;
				}

				res = res->ai_next;
			}

			if (!p) {
				lwsl_notice("Failed to get address result %s\n",
					    s->address);
				freeaddrinfo(result);
				return 1;
			}

			serv_addr4.sin_family = AF_INET;
			serv_addr4.sin_addr = *((struct in_addr *)p);
			serv_addr4.sin_port = htons(s->port);
			bzero(&serv_addr4.sin_zero, 8);
			freeaddrinfo(result);

			lwsl_err("Conn %d req '%s' port %d\n", n,
				 s->address, s->port);
			/* we need to open the associated onward connection */
			sockfd = socket(AF_INET, SOCK_STREAM, 0);

			if (connect(sockfd, (struct sockaddr *)&serv_addr4,
				    sizeof(struct sockaddr)) == -1 ||
			    errno == EISCONN) {
				lwsl_err("proxied onward connection failed\n");
				return 1;
			}
			s->twin = pfds;
			construct_state(pfds, FZY_S_ONWARD,
					POLLOUT | POLLIN | POLLERR);
			state[pfds].twin = n;
			lwsl_notice("binding conns %d and %d\n", n, pfds);
			state[pfds].outbound = s->outbound;
			state[pfds].ppc = 0;
			pfd[pfds++].fd = sockfd;

			lwsl_notice("onward connection in progress\n");
			if (ring_used(&s->in))
				pfd[s->twin].events |= POLLOUT;
			if (write(pfd[n].fd,
				  "HTTP/1.0 200 \x0d\x0a\x0d\x0a", 17) < 17)
				return 1;
		}
	}

	return 0;
}

static void sigpipe_handler(int x)
{
}

int
main(int argc, char **argv)
{
	char interface_name[128] = "", interface_name_local[128] = "lo";
	int port_local = 8880, accept_fd;
	struct sockaddr_in cli_addr;
	int debug_level = 7;
	socklen_t clilen;
	struct state *s;
	char out[4096];
	int opts = 0;
	int n = 0, m;

#ifndef _WIN32
	int syslog_options = LOG_PID | LOG_PERROR;
#endif
#ifndef LWS_NO_DAEMONIZE
 	int daemonize = 0;
#endif
	signal(SIGPIPE, sigpipe_handler);

	while (n >= 0) {
		n = getopt_long(argc, argv, "eci:hsap:d:Dr:", options, NULL);
		if (n < 0)
			continue;
		switch (n) {
		case 'e':
			opts |= LWS_SERVER_OPTION_LIBEV;
			break;
#ifndef LWS_NO_DAEMONIZE
		case 'D':
			daemonize = 1;
			#ifndef _WIN32
			syslog_options &= ~LOG_PERROR;
			#endif
			break;
#endif
		case 'd':
			debug_level = atoi(optarg);
			break;
		case 'p':
			port_local = atoi(optarg);
			break;
		case 'i':
			strncpy(interface_name, optarg, sizeof interface_name);
			interface_name[(sizeof interface_name) - 1] = '\0';
			break;
		case 'h':
			fprintf(stderr, "Usage: libwebsockets-test-fuzxy "
					"[--port=<p>] [--ssl] "
					"[-d <log bitfield>] "
					"[--resource_path <path>]\n");
			exit(1);
		}
	}

#if !defined(LWS_NO_DAEMONIZE) && !defined(WIN32)
	/*
	 * normally lock path would be /var/lock/lwsts or similar, to
	 * simplify getting started without having to take care about
	 * permissions or running as root, set to /tmp/.lwsts-lock
	 */
	if (daemonize && lws_daemonize("/tmp/.lwsts-lock")) {
		fprintf(stderr, "Failed to daemonize\n");
		return 1;
	}
#endif

	signal(SIGINT, sighandler);

#ifndef _WIN32
	/* we will only try to log things according to our debug_level */
	setlogmask(LOG_UPTO (LOG_DEBUG));
	openlog("fuzxy", syslog_options, LOG_DAEMON);
#endif

	/* tell the library what debug level to emit and to send it to syslog */
	lws_set_log_level(debug_level, lwsl_emit_syslog);

	lwsl_notice("%s\n(C) Copyright 2016 Andy Green <andy@warmcat.com> - "
		    "licensed under LGPL2.1\n", argv[0]);

	/* listen on local side */

	if (fuzxy_listen(interface_name, port_local, &pfd[pfds].fd)) {
		lwsl_err("Failed to listen on local side\n");
		goto bail1;
	}
	construct_state(pfds, FZY_S_LISTENING, POLLIN | POLLERR);
	pfds++;

	lwsl_notice("Local side listening on %s:%u\n",
		    interface_name_local, port_local);

	while (!force_exit) {

		m = poll(pfd, pfds, 50);
		if (m < 0)
			continue;
		for (n = 0; n < pfds; n++) {
			s = &state[n];
			if (s->type == FZY_S_LISTENING &&
			    (pfd[n].revents & POLLIN)) {
				/* first do the accept entry */

				clilen = sizeof(cli_addr);
				accept_fd = accept(pfd[0].fd,
					 (struct sockaddr *)&cli_addr, &clilen);
				if (accept_fd < 0) {
					if (errno == EAGAIN ||
					    errno == EWOULDBLOCK)
						continue;

					lwsl_warn("ERROR on accept: %s\n",
						  strerror(errno));
					continue;
				}
				construct_state(pfds, FZY_S_ACCEPTED,
						POLLIN | POLLERR);
				state[pfds].outbound = n == 0;
				state[pfds].pp = FZY_PP_CONNECT;
				state[pfds].ppc = 0;
				pfd[pfds++].fd = accept_fd;
				lwsl_notice("new connect accepted\n");
				continue;
			}
			if (pfd[n].revents & POLLIN) {
				assert(ring_free(&s->in));
				m = (ring_size(&s->in) - 1) -
				    s->in.head;
				if (s->in.head == ring_size(&s->in) - 1 &&
				    s->in.tail)
					m = 1;
				m = read(pfd[n].fd, s->in.buf + s->in.head, m);
//				lwsl_notice("read %d\n", m);
				if (m <= 0)
					goto drop;
				s->in.head += m;
				if (s->in.head == ring_size(&s->in))
					s->in.head = 0;

				switch (s->type) {
				case FZY_S_ACCEPTED: /* parse proxy CONNECT */
					if (handle_accept(n))
						goto drop;
					break;
				case FZY_S_PROXIED:
				case FZY_S_ONWARD:
					if (ring_used(&s->in))
						pfd[s->twin].events |= POLLOUT;
					break;
				default:
					assert(0);
					break;
				}
				if (s->in.head == s->in.tail) {
					s->in.head = s->in.tail = 0;
					pfd[n].events |= POLLIN;
				}
				if (!ring_free(&s->in))
					pfd[n].events &= ~POLLIN;
			}
			if (pfd[n].revents & POLLOUT) {
				switch (s->type) {
				case FZY_S_PROXIED:
				case FZY_S_ONWARD:
					/*
					 * draw down enough of the partner's
					 * in ring to either exhaust it
 					 * or fill an output buffer
 					 */
					m = fuzz(n, out, sizeof(out));
					if (m) {
						m = write(pfd[n].fd, out, m);
						if (m <= 0)
							goto drop;
					} else
						pfd[n].events &= ~POLLOUT;

					if (ring_free(&state[s->twin].in))
						pfd[s->twin].events |= POLLIN;

					break;
				default:
					break;
				}
			}

			continue;
drop:
			close_and_remove_fd(n);
			n--; /* redo this slot */
		}
	}

bail1:
	lwsl_notice("%s exited cleanly\n", argv[0]);

#ifndef _WIN32
	closelog();
#endif

	return 0;
}

