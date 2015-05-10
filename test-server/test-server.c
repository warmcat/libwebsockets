/*
 * libwebsockets-test-server - libwebsockets test implementation
 *
 * Copyright (C) 2010-2011 Andy Green <andy@warmcat.com>
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
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <signal.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>

#ifdef _WIN32
#include <io.h>
#ifdef EXTERNAL_POLL
#define poll WSAPoll
#endif
#else
#include <syslog.h>
#include <sys/time.h>
#include <unistd.h>
#endif

#include "../lib/libwebsockets.h"

static int close_testing;
int max_poll_elements;

#ifdef EXTERNAL_POLL
struct pollfd *pollfds;
int *fd_lookup;
int count_pollfds;
#endif
static volatile int force_exit = 0;
static struct libwebsocket_context *context;

/*
 * This demo server shows how to use libwebsockets for one or more
 * websocket protocols in the same server
 *
 * It defines the following websocket protocols:
 *
 *  dumb-increment-protocol:  once the socket is opened, an incrementing
 *				ascii string is sent down it every 50ms.
 *				If you send "reset\n" on the websocket, then
 *				the incrementing number is reset to 0.
 *
 *  lws-mirror-protocol: copies any received packet to every connection also
 *				using this protocol, including the sender
 */

enum demo_protocols {
	/* always first */
	PROTOCOL_HTTP = 0,

	PROTOCOL_DUMB_INCREMENT,
	PROTOCOL_LWS_MIRROR,

	/* always last */
	DEMO_PROTOCOL_COUNT
};


#define LOCAL_RESOURCE_PATH INSTALL_DATADIR"/libwebsockets-test-server"
char *resource_path = LOCAL_RESOURCE_PATH;

/*
 * We take a strict whitelist approach to stop ../ attacks
 */

struct serveable {
	const char *urlpath;
	const char *mimetype;
}; 

struct per_session_data__http {
	int fd;
};

/*
 * this is just an example of parsing handshake headers, you don't need this
 * in your code unless you will filter allowing connections by the header
 * content
 */

static void
dump_handshake_info(struct libwebsocket *wsi)
{
	int n = 0;
	char buf[256];
	const unsigned char *c;

	do {
		c = lws_token_to_string(n);
		if (!c) {
			n++;
			continue;
		}

		if (!lws_hdr_total_length(wsi, n)) {
			n++;
			continue;
		}

		lws_hdr_copy(wsi, buf, sizeof buf, n);

		fprintf(stderr, "    %s = %s\n", (char *)c, buf);
		n++;
	} while (c);
}

const char * get_mimetype(const char *file)
{
	int n = strlen(file);

	if (n < 5)
		return NULL;

	if (!strcmp(&file[n - 4], ".ico"))
		return "image/x-icon";

	if (!strcmp(&file[n - 4], ".png"))
		return "image/png";

	if (!strcmp(&file[n - 5], ".html"))
		return "text/html";

	return NULL;
}

/* this protocol server (always the first one) just knows how to do HTTP */

static int callback_http(struct libwebsocket_context *context,
		struct libwebsocket *wsi,
		enum libwebsocket_callback_reasons reason, void *user,
							   void *in, size_t len)
{
	char buf[256];
	char leaf_path[1024];
	char b64[64];
	struct timeval tv;
	int n, m;
	unsigned char *p;
	char *other_headers;
	static unsigned char buffer[4096];
	struct stat stat_buf;
	struct per_session_data__http *pss =
			(struct per_session_data__http *)user;
	const char *mimetype;
#ifdef EXTERNAL_POLL
	struct libwebsocket_pollargs *pa = (struct libwebsocket_pollargs *)in;
#endif
	unsigned char *end;
	switch (reason) {
	case LWS_CALLBACK_HTTP:

		dump_handshake_info(wsi);

		if (len < 1) {
			libwebsockets_return_http_status(context, wsi,
						HTTP_STATUS_BAD_REQUEST, NULL);
			goto try_to_reuse;
		}

		/* this example server has no concept of directories */
		if (strchr((const char *)in + 1, '/')) {
			libwebsockets_return_http_status(context, wsi,
						HTTP_STATUS_FORBIDDEN, NULL);
			goto try_to_reuse;
		}

		/* if a legal POST URL, let it continue and accept data */
		if (lws_hdr_total_length(wsi, WSI_TOKEN_POST_URI))
			return 0;

		/* check for the "send a big file by hand" example case */

		if (!strcmp((const char *)in, "/leaf.jpg")) {
			if (strlen(resource_path) > sizeof(leaf_path) - 10)
				return -1;
			sprintf(leaf_path, "%s/leaf.jpg", resource_path);

			/* well, let's demonstrate how to send the hard way */

			p = buffer + LWS_SEND_BUFFER_PRE_PADDING;
			end = p + sizeof(buffer) - LWS_SEND_BUFFER_PRE_PADDING;
#ifdef WIN32
			pss->fd = open(leaf_path, O_RDONLY | _O_BINARY);
#else
			pss->fd = open(leaf_path, O_RDONLY);
#endif

			if (pss->fd < 0)
				return -1;

			if (fstat(pss->fd, &stat_buf) < 0)
				return -1;

			/*
			 * we will send a big jpeg file, but it could be
			 * anything.  Set the Content-Type: appropriately
			 * so the browser knows what to do with it.
			 * 
			 * Notice we use the APIs to build the header, which
			 * will do the right thing for HTTP 1/1.1 and HTTP2
			 * depending on what connection it happens to be working
			 * on
			 */
			if (lws_add_http_header_status(context, wsi, 200, &p, end))
				return 1;
			if (lws_add_http_header_by_token(context, wsi,
					WSI_TOKEN_HTTP_SERVER,
				    	(unsigned char *)"libwebsockets",
					13, &p, end))
				return 1;
			if (lws_add_http_header_by_token(context, wsi,
					WSI_TOKEN_HTTP_CONTENT_TYPE,
				    	(unsigned char *)"image/jpeg",
					10, &p, end))
				return 1;
			if (lws_add_http_header_content_length(context, wsi,
						stat_buf.st_size, &p, end))
				return 1;
			if (lws_finalize_http_header(context, wsi, &p, end))
				return 1;

			/*
			 * send the http headers...
			 * this won't block since it's the first payload sent
			 * on the connection since it was established
			 * (too small for partial)
			 * 
			 * Notice they are sent using LWS_WRITE_HTTP_HEADERS
			 * which also means you can't send body too in one step,
			 * this is mandated by changes in HTTP2
			 */

			n = libwebsocket_write(wsi,
					buffer + LWS_SEND_BUFFER_PRE_PADDING,
					p - (buffer + LWS_SEND_BUFFER_PRE_PADDING),
					LWS_WRITE_HTTP_HEADERS);

			if (n < 0) {
				close(pss->fd);
				return -1;
			}
			/*
			 * book us a LWS_CALLBACK_HTTP_WRITEABLE callback
			 */
			libwebsocket_callback_on_writable(context, wsi);
			break;
		}

		/* if not, send a file the easy way */
		strcpy(buf, resource_path);
		if (strcmp(in, "/")) {
			if (*((const char *)in) != '/')
				strcat(buf, "/");
			strncat(buf, in, sizeof(buf) - strlen(resource_path));
		} else /* default file to serve */
			strcat(buf, "/test.html");
		buf[sizeof(buf) - 1] = '\0';

		/* refuse to serve files we don't understand */
		mimetype = get_mimetype(buf);
		if (!mimetype) {
			lwsl_err("Unknown mimetype for %s\n", buf);
			libwebsockets_return_http_status(context, wsi,
				      HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE, NULL);
			return -1;
		}

		/* demostrates how to set a cookie on / */

		other_headers = NULL;
		n = 0;
		if (!strcmp((const char *)in, "/") &&
			   !lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_COOKIE)) {
			/* this isn't very unguessable but it'll do for us */
			gettimeofday(&tv, NULL);
			n = sprintf(b64, "test=LWS_%u_%u_COOKIE;Max-Age=360000",
				(unsigned int)tv.tv_sec,
				(unsigned int)tv.tv_usec);

			p = (unsigned char *)leaf_path;

			if (lws_add_http_header_by_name(context, wsi, 
				(unsigned char *)"set-cookie:", 
				(unsigned char *)b64, n, &p,
				(unsigned char *)leaf_path + sizeof(leaf_path)))
				return 1;
			n = (char *)p - leaf_path;
			other_headers = leaf_path;
		}

		n = libwebsockets_serve_http_file(context, wsi, buf,
						mimetype, other_headers, n);
		if (n < 0 || ((n > 0) && lws_http_transaction_completed(wsi)))
			return -1; /* error or can't reuse connection: close the socket */

		/*
		 * notice that the sending of the file completes asynchronously,
		 * we'll get a LWS_CALLBACK_HTTP_FILE_COMPLETION callback when
		 * it's done
		 */

		break;

	case LWS_CALLBACK_HTTP_BODY:
		strncpy(buf, in, 20);
		buf[20] = '\0';
		if (len < 20)
			buf[len] = '\0';

		lwsl_notice("LWS_CALLBACK_HTTP_BODY: %s... len %d\n",
				(const char *)buf, (int)len);

		break;

	case LWS_CALLBACK_HTTP_BODY_COMPLETION:
		lwsl_notice("LWS_CALLBACK_HTTP_BODY_COMPLETION\n");
		/* the whole of the sent body arrived, close or reuse the connection */
		libwebsockets_return_http_status(context, wsi,
						HTTP_STATUS_OK, NULL);
		goto try_to_reuse;

	case LWS_CALLBACK_HTTP_FILE_COMPLETION:
//		lwsl_info("LWS_CALLBACK_HTTP_FILE_COMPLETION seen\n");
		/* kill the connection after we sent one file */
		goto try_to_reuse;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		/*
		 * we can send more of whatever it is we were sending
		 */
		do {
			/* we'd like the send this much */
			n = sizeof(buffer) - LWS_SEND_BUFFER_PRE_PADDING;
			
			/* but if the peer told us he wants less, we can adapt */
			m = lws_get_peer_write_allowance(wsi);

			/* -1 means not using a protocol that has this info */
			if (m == 0)
				/* right now, peer can't handle anything */
				goto later;

			if (m != -1 && m < n)
				/* he couldn't handle that much */
				n = m;
			
			n = read(pss->fd, buffer + LWS_SEND_BUFFER_PRE_PADDING,
									n);
			/* problem reading, close conn */
			if (n < 0)
				goto bail;
			/* sent it all, close conn */
			if (n == 0)
				goto flush_bail;
			/*
			 * To support HTTP2, must take care about preamble space
			 * 
			 * identification of when we send the last payload frame
			 * is handled by the library itself if you sent a
			 * content-length header
			 */
			m = libwebsocket_write(wsi,
					       buffer + LWS_SEND_BUFFER_PRE_PADDING,
					       n, LWS_WRITE_HTTP);
			if (m < 0)
				/* write failed, close conn */
				goto bail;

			/*
			 * http2 won't do this
			 */
			if (m != n)
				/* partial write, adjust */
				if (lseek(pss->fd, m - n, SEEK_CUR) < 0)
					goto bail;

			if (m) /* while still active, extend timeout */
				libwebsocket_set_timeout(wsi,
					PENDING_TIMEOUT_HTTP_CONTENT, 5);
			
			/* if we have indigestion, let him clear it before eating more */
			if (lws_partial_buffered(wsi))
				break;

		} while (!lws_send_pipe_choked(wsi));

later:
		libwebsocket_callback_on_writable(context, wsi);
		break;
flush_bail:
		/* true if still partial pending */
		if (lws_partial_buffered(wsi)) {
			libwebsocket_callback_on_writable(context, wsi);
			break;
		}
		close(pss->fd);
		goto try_to_reuse;

bail:
		close(pss->fd);
		return -1;

	/*
	 * callback for confirming to continue with client IP appear in
	 * protocol 0 callback since no websocket protocol has been agreed
	 * yet.  You can just ignore this if you won't filter on client IP
	 * since the default uhandled callback return is 0 meaning let the
	 * connection continue.
	 */

	case LWS_CALLBACK_FILTER_NETWORK_CONNECTION:

		/* if we returned non-zero from here, we kill the connection */
		break;

#ifdef EXTERNAL_POLL
	/*
	 * callbacks for managing the external poll() array appear in
	 * protocol 0 callback
	 */

	case LWS_CALLBACK_LOCK_POLL:
		/*
		 * lock mutex to protect pollfd state
		 * called before any other POLL related callback
		 */
		break;

	case LWS_CALLBACK_UNLOCK_POLL:
		/*
		 * unlock mutex to protect pollfd state when
		 * called after any other POLL related callback
		 */
		break;

	case LWS_CALLBACK_ADD_POLL_FD:

		if (count_pollfds >= max_poll_elements) {
			lwsl_err("LWS_CALLBACK_ADD_POLL_FD: too many sockets to track\n");
			return 1;
		}

		fd_lookup[pa->fd] = count_pollfds;
		pollfds[count_pollfds].fd = pa->fd;
		pollfds[count_pollfds].events = pa->events;
		pollfds[count_pollfds++].revents = 0;
		break;

	case LWS_CALLBACK_DEL_POLL_FD:
		if (!--count_pollfds)
			break;
		m = fd_lookup[pa->fd];
		/* have the last guy take up the vacant slot */
		pollfds[m] = pollfds[count_pollfds];
		fd_lookup[pollfds[count_pollfds].fd] = m;
		break;

	case LWS_CALLBACK_CHANGE_MODE_POLL_FD:
	        pollfds[fd_lookup[pa->fd]].events = pa->events;
		break;

#endif

	case LWS_CALLBACK_GET_THREAD_ID:
		/*
		 * if you will call "libwebsocket_callback_on_writable"
		 * from a different thread, return the caller thread ID
		 * here so lws can use this information to work out if it
		 * should signal the poll() loop to exit and restart early
		 */

		/* return pthread_getthreadid_np(); */

		break;

	default:
		break;
	}

	return 0;
	
try_to_reuse:
	if (lws_http_transaction_completed(wsi))
		return -1;

	return 0;
}


/* dumb_increment protocol */

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

static int
callback_dumb_increment(struct libwebsocket_context *context,
			struct libwebsocket *wsi,
			enum libwebsocket_callback_reasons reason,
					       void *user, void *in, size_t len)
{
	int n, m;
	unsigned char buf[LWS_SEND_BUFFER_PRE_PADDING + 512 +
						  LWS_SEND_BUFFER_POST_PADDING];
	unsigned char *p = &buf[LWS_SEND_BUFFER_PRE_PADDING];
	struct per_session_data__dumb_increment *pss = (struct per_session_data__dumb_increment *)user;

	switch (reason) {

	case LWS_CALLBACK_ESTABLISHED:
		lwsl_info("callback_dumb_increment: "
						 "LWS_CALLBACK_ESTABLISHED\n");
		pss->number = 0;
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		n = sprintf((char *)p, "%d", pss->number++);
		m = libwebsocket_write(wsi, p, n, LWS_WRITE_TEXT);
		if (m < n) {
			lwsl_err("ERROR %d writing to di socket\n", n);
			return -1;
		}
		if (close_testing && pss->number == 50) {
			lwsl_info("close tesing limit, closing\n");
			return -1;
		}
		break;

	case LWS_CALLBACK_RECEIVE:
//		fprintf(stderr, "rx %d\n", (int)len);
		if (len < 6)
			break;
		if (strcmp((const char *)in, "reset\n") == 0)
			pss->number = 0;
		break;
	/*
	 * this just demonstrates how to use the protocol filter. If you won't
	 * study and reject connections based on header content, you don't need
	 * to handle this callback
	 */

	case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
		dump_handshake_info(wsi);
		/* you could return non-zero here and kill the connection */
		break;

	default:
		break;
	}

	return 0;
}


/* lws-mirror_protocol */

#define MAX_MESSAGE_QUEUE 32

struct per_session_data__lws_mirror {
	struct libwebsocket *wsi;
	int ringbuffer_tail;
};

struct a_message {
	void *payload;
	size_t len;
};

static struct a_message ringbuffer[MAX_MESSAGE_QUEUE];
static int ringbuffer_head;

static int
callback_lws_mirror(struct libwebsocket_context *context,
			struct libwebsocket *wsi,
			enum libwebsocket_callback_reasons reason,
					       void *user, void *in, size_t len)
{
	int n;
	struct per_session_data__lws_mirror *pss = (struct per_session_data__lws_mirror *)user;

	switch (reason) {

	case LWS_CALLBACK_ESTABLISHED:
		lwsl_info("callback_lws_mirror: LWS_CALLBACK_ESTABLISHED\n");
		pss->ringbuffer_tail = ringbuffer_head;
		pss->wsi = wsi;
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		lwsl_notice("mirror protocol cleaning up\n");
		for (n = 0; n < sizeof ringbuffer / sizeof ringbuffer[0]; n++)
			if (ringbuffer[n].payload)
				free(ringbuffer[n].payload);
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		if (close_testing)
			break;
		while (pss->ringbuffer_tail != ringbuffer_head) {

			n = libwebsocket_write(wsi, (unsigned char *)
				   ringbuffer[pss->ringbuffer_tail].payload +
				   LWS_SEND_BUFFER_PRE_PADDING,
				   ringbuffer[pss->ringbuffer_tail].len,
								LWS_WRITE_TEXT);
			if (n < 0) {
				lwsl_err("ERROR %d writing to mirror socket\n", n);
				return -1;
			}
			if (n < ringbuffer[pss->ringbuffer_tail].len)
				lwsl_err("mirror partial write %d vs %d\n",
				       n, ringbuffer[pss->ringbuffer_tail].len);

			if (pss->ringbuffer_tail == (MAX_MESSAGE_QUEUE - 1))
				pss->ringbuffer_tail = 0;
			else
				pss->ringbuffer_tail++;

			if (((ringbuffer_head - pss->ringbuffer_tail) &
				  (MAX_MESSAGE_QUEUE - 1)) == (MAX_MESSAGE_QUEUE - 15))
				libwebsocket_rx_flow_allow_all_protocol(
					       libwebsockets_get_protocol(wsi));

			// lwsl_debug("tx fifo %d\n", (ringbuffer_head - pss->ringbuffer_tail) & (MAX_MESSAGE_QUEUE - 1));

			if (lws_partial_buffered(wsi) || lws_send_pipe_choked(wsi)) {
				libwebsocket_callback_on_writable(context, wsi);
				break;
			}
			/*
			 * for tests with chrome on same machine as client and
			 * server, this is needed to stop chrome choking
			 */
#ifdef _WIN32
			Sleep(1);
#else
			usleep(1);
#endif
		}
		break;

	case LWS_CALLBACK_RECEIVE:

		if (((ringbuffer_head - pss->ringbuffer_tail) &
				  (MAX_MESSAGE_QUEUE - 1)) == (MAX_MESSAGE_QUEUE - 1)) {
			lwsl_err("dropping!\n");
			goto choke;
		}

		if (ringbuffer[ringbuffer_head].payload)
			free(ringbuffer[ringbuffer_head].payload);

		ringbuffer[ringbuffer_head].payload =
				malloc(LWS_SEND_BUFFER_PRE_PADDING + len +
						  LWS_SEND_BUFFER_POST_PADDING);
		ringbuffer[ringbuffer_head].len = len;
		memcpy((char *)ringbuffer[ringbuffer_head].payload +
					  LWS_SEND_BUFFER_PRE_PADDING, in, len);
		if (ringbuffer_head == (MAX_MESSAGE_QUEUE - 1))
			ringbuffer_head = 0;
		else
			ringbuffer_head++;

		if (((ringbuffer_head - pss->ringbuffer_tail) &
				  (MAX_MESSAGE_QUEUE - 1)) != (MAX_MESSAGE_QUEUE - 2))
			goto done;

choke:
		lwsl_debug("LWS_CALLBACK_RECEIVE: throttling %p\n", wsi);
		libwebsocket_rx_flow_control(wsi, 0);

//		lwsl_debug("rx fifo %d\n", (ringbuffer_head - pss->ringbuffer_tail) & (MAX_MESSAGE_QUEUE - 1));
done:
		libwebsocket_callback_on_writable_all_protocol(
					       libwebsockets_get_protocol(wsi));
		break;

	/*
	 * this just demonstrates how to use the protocol filter. If you won't
	 * study and reject connections based on header content, you don't need
	 * to handle this callback
	 */

	case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
		dump_handshake_info(wsi);
		/* you could return non-zero here and kill the connection */
		break;

	default:
		break;
	}

	return 0;
}


/* list of supported protocols and callbacks */

static struct libwebsocket_protocols protocols[] = {
	/* first protocol must always be HTTP handler */

	{
		"http-only",		/* name */
		callback_http,		/* callback */
		sizeof (struct per_session_data__http),	/* per_session_data_size */
		0,			/* max frame size / rx buffer */
	},
	{
		"dumb-increment-protocol",
		callback_dumb_increment,
		sizeof(struct per_session_data__dumb_increment),
		10,
	},
	{
		"lws-mirror-protocol",
		callback_lws_mirror,
		sizeof(struct per_session_data__lws_mirror),
		128,
	},
	{ NULL, NULL, 0, 0 } /* terminator */
};

void sighandler(int sig)
{
	force_exit = 1;
	libwebsocket_cancel_service(context);
}

static struct option options[] = {
	{ "help",	no_argument,		NULL, 'h' },
	{ "debug",	required_argument,	NULL, 'd' },
	{ "port",	required_argument,	NULL, 'p' },
	{ "ssl",	no_argument,		NULL, 's' },
	{ "allow-non-ssl",	no_argument,		NULL, 'a' },
	{ "interface",  required_argument,	NULL, 'i' },
	{ "closetest",  no_argument,		NULL, 'c' },
	{ "libev",  no_argument,		NULL, 'e' },
	#ifndef LWS_NO_DAEMONIZE
	{ "daemonize", 	no_argument,		NULL, 'D' },
#endif
	{ "resource_path", required_argument,		NULL, 'r' },
	{ NULL, 0, 0, 0 }
};

int main(int argc, char **argv)
{
	char cert_path[1024];
	char key_path[1024];
	int n = 0;
	int use_ssl = 0;
	int opts = 0;
	char interface_name[128] = "";
	const char *iface = NULL;
#ifndef WIN32
	int syslog_options = LOG_PID | LOG_PERROR;
#endif
	unsigned int ms, oldms = 0;
	struct lws_context_creation_info info;

	int debug_level = 7;
#ifndef LWS_NO_DAEMONIZE
	int daemonize = 0;
#endif

	memset(&info, 0, sizeof info);
	info.port = 7681;

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
			#ifndef WIN32
			syslog_options &= ~LOG_PERROR;
			#endif
			break;
#endif
		case 'd':
			debug_level = atoi(optarg);
			break;
		case 's':
			use_ssl = 1;
			break;
		case 'a':
			opts |= LWS_SERVER_OPTION_ALLOW_NON_SSL_ON_SSL_PORT;
			break;
		case 'p':
			info.port = atoi(optarg);
			break;
		case 'i':
			strncpy(interface_name, optarg, sizeof interface_name);
			interface_name[(sizeof interface_name) - 1] = '\0';
			iface = interface_name;
			break;
		case 'c':
			close_testing = 1;
			fprintf(stderr, " Close testing mode -- closes on "
					   "client after 50 dumb increments"
					   "and suppresses lws_mirror spam\n");
			break;
		case 'r':
			resource_path = optarg;
			printf("Setting resource path to \"%s\"\n", resource_path);
			break;
		case 'h':
			fprintf(stderr, "Usage: test-server "
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

#ifndef WIN32
	/* we will only try to log things according to our debug_level */
	setlogmask(LOG_UPTO (LOG_DEBUG));
	openlog("lwsts", syslog_options, LOG_DAEMON);
#endif

	/* tell the library what debug level to emit and to send it to syslog */
	lws_set_log_level(debug_level, lwsl_emit_syslog);

	lwsl_notice("libwebsockets test server - "
			"(C) Copyright 2010-2015 Andy Green <andy@warmcat.com> - "
						    "licensed under LGPL2.1\n");

	printf("Using resource path \"%s\"\n", resource_path);
#ifdef EXTERNAL_POLL
	max_poll_elements = getdtablesize();
	pollfds = malloc(max_poll_elements * sizeof (struct pollfd));
	fd_lookup = malloc(max_poll_elements * sizeof (int));
	if (pollfds == NULL || fd_lookup == NULL) {
		lwsl_err("Out of memory pollfds=%d\n", max_poll_elements);
		return -1;
	}
#endif

	info.iface = iface;
	info.protocols = protocols;
#ifndef LWS_NO_EXTENSIONS
	info.extensions = libwebsocket_get_internal_extensions();
#endif
	if (!use_ssl) {
		info.ssl_cert_filepath = NULL;
		info.ssl_private_key_filepath = NULL;
	} else {
		if (strlen(resource_path) > sizeof(cert_path) - 32) {
			lwsl_err("resource path too long\n");
			return -1;
		}
		sprintf(cert_path, "%s/libwebsockets-test-server.pem",
								resource_path);
		if (strlen(resource_path) > sizeof(key_path) - 32) {
			lwsl_err("resource path too long\n");
			return -1;
		}
		sprintf(key_path, "%s/libwebsockets-test-server.key.pem",
								resource_path);

		info.ssl_cert_filepath = cert_path;
		info.ssl_private_key_filepath = key_path;
	}
	info.gid = -1;
	info.uid = -1;
	info.options = opts;

	context = libwebsocket_create_context(&info);
	if (context == NULL) {
		lwsl_err("libwebsocket init failed\n");
		return -1;
	}

	n = 0;
	while (n >= 0 && !force_exit) {
		struct timeval tv;

		gettimeofday(&tv, NULL);

		/*
		 * This provokes the LWS_CALLBACK_SERVER_WRITEABLE for every
		 * live websocket connection using the DUMB_INCREMENT protocol,
		 * as soon as it can take more packets (usually immediately)
		 */

		ms = (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
		if ((ms - oldms) > 50) {
			libwebsocket_callback_on_writable_all_protocol(&protocols[PROTOCOL_DUMB_INCREMENT]);
			oldms = ms;
		}

#ifdef EXTERNAL_POLL

		/*
		 * this represents an existing server's single poll action
		 * which also includes libwebsocket sockets
		 */

		n = poll(pollfds, count_pollfds, 50);
		if (n < 0)
			continue;


		if (n)
			for (n = 0; n < count_pollfds; n++)
				if (pollfds[n].revents)
					/*
					* returns immediately if the fd does not
					* match anything under libwebsockets
					* control
					*/
					if (libwebsocket_service_fd(context,
								  &pollfds[n]) < 0)
						goto done;
#else
		/*
		 * If libwebsockets sockets are all we care about,
		 * you can use this api which takes care of the poll()
		 * and looping through finding who needed service.
		 *
		 * If no socket needs service, it'll return anyway after
		 * the number of ms in the second argument.
		 */

		n = libwebsocket_service(context, 50);
#endif
	}

#ifdef EXTERNAL_POLL
done:
#endif

	libwebsocket_context_destroy(context);

	lwsl_notice("libwebsockets-test-server exited cleanly\n");

#ifndef WIN32
	closelog();
#endif

	return 0;
}
