/*
 * libwebsockets web server application
 *
 * Copyright (C) 2010-2016 Andy Green <andy@warmcat.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation:
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA  02110-1301  USA
 */
#include "lwsws.h"

/* http server gets files from this path */
#define LOCAL_RESOURCE_PATH INSTALL_DATADIR"/libwebsockets-test-server"
char *resource_path = LOCAL_RESOURCE_PATH;



/*
 * We take a strict whitelist approach to stop ../ attacks
 */
struct serveable {
	const char *urlpath;
	const char *mimetype;
};

const char * get_mimetype(const char *file)
{
	int n = strlen(file);

	if (n < 5)
		return NULL;

	if (!strcmp(&file[n - 4], ".ico"))
		return "image/x-icon";

	if (!strcmp(&file[n - 4], ".png"))
		return "image/png";

	if (!strcmp(&file[n - 4], ".jpg"))
		return "image/jpeg";

	if (!strcmp(&file[n - 5], ".html"))
		return "text/html";

	if (!strcmp(&file[n - 4], ".css"))
		return "text/css";

	return NULL;
}

/* this protocol server (always the first one) handles HTTP,
 *
 * Some misc callbacks that aren't associated with a protocol also turn up only
 * here on the first protocol server.
 */

int callback_http(struct lws *wsi, enum lws_callback_reasons reason, void *user,
		  void *in, size_t len)
{
	struct per_session_data__http *pss =
			(struct per_session_data__http *)user;
	unsigned char buffer[4096 + LWS_PRE];
	unsigned long amount, file_len, sent;
	char leaf_path[1024];
	const char *mimetype;
	char *other_headers;
	unsigned char *end;
	struct timeval tv;
	unsigned char *p;
#ifndef LWS_NO_CLIENT
	struct per_session_data__http *pss1;
	struct lws *wsi1;
#endif
	char buf[256];
	char b64[64];
	int n, m;
#ifdef EXTERNAL_POLL
	struct lws_pollargs *pa = (struct lws_pollargs *)in;
#endif

//	lwsl_err("%s: reason %d\n", __func__, reason);

	switch (reason) {
	case LWS_CALLBACK_HTTP:

		{
			char name[100], rip[50];
			lws_get_peer_addresses(wsi, lws_get_socket_fd(wsi), name,
					       sizeof(name), rip, sizeof(rip));
			sprintf(buf, "%s (%s)", name, rip);
			lwsl_notice("HTTP connect from %s\n", buf);
		}

		if (len < 1) {
			lws_return_http_status(wsi,
						HTTP_STATUS_BAD_REQUEST, NULL);
			goto try_to_reuse;
		}

#ifndef LWS_NO_CLIENT
		if (!strncmp(in, "/proxytest", 10)) {
			struct lws_client_connect_info i;
			char *rootpath = "/";
			const char *p = (const char *)in;

			if (lws_get_child(wsi))
				break;

			pss->client_finished = 0;
			memset(&i,0, sizeof(i));
			i.context = lws_get_context(wsi);
			i.address = "git.libwebsockets.org";
			i.port = 80;
			i.ssl_connection = 0;
			if (p[10])
				i.path = (char *)in + 10;
			else
				i.path = rootpath;
			i.host = "git.libwebsockets.org";
			i.origin = NULL;
			i.method = "GET";
			i.parent_wsi = wsi;
			i.uri_replace_from = "git.libwebsockets.org/";
			i.uri_replace_to = "/proxytest/";
			if (!lws_client_connect_via_info(&i)) {
				lwsl_err("proxy connect fail\n");
				break;
			}



			break;
		}
#endif

#if 1
		/* this example server has no concept of directories */
		if (strchr((const char *)in + 1, '/')) {
			lws_return_http_status(wsi, HTTP_STATUS_FORBIDDEN, NULL);
			goto try_to_reuse;
		}
#endif

#ifdef LWS_WITH_CGI
		if (!strncmp(in, "/cgitest", 8)) {
			static char *cmd[] = {
				"/bin/sh",
				"-c",
				INSTALL_DATADIR"/libwebsockets-test-server/lws-cgi-test.sh",
//				"/var/www/cgi-bin/cgit",
				NULL
			};

			lwsl_notice("%s: cgitest\n", __func__);
			n = lws_cgi(wsi, cmd, 8, 5);
			if (n) {
				lwsl_err("%s: cgi failed\n");
				return -1;
			}
			p = buffer + LWS_PRE;
			end = p + sizeof(buffer) - LWS_PRE;

			if (lws_add_http_header_status(wsi, 200, &p, end))
				return 1;
			if (lws_add_http_header_by_token(wsi, WSI_TOKEN_CONNECTION,
					(unsigned char *)"close", 5, &p, end))
				return 1;
			n = lws_write(wsi, buffer + LWS_PRE,
				      p - (buffer + LWS_PRE),
				      LWS_WRITE_HTTP_HEADERS);

			/* the cgi starts by outputting headers, we can't
			 *  finalize the headers until we see the end of that
			 */

			break;
		}
#endif

		/* if a legal POST URL, let it continue and accept data */
		if (lws_hdr_total_length(wsi, WSI_TOKEN_POST_URI))
			return 0;

		/* check for the "send a big file by hand" example case */
		lwsl_notice("%s\n", in);
		if (!strcmp((const char *)in, "/leaf.jpg")) {
			if (strlen(resource_path) > sizeof(leaf_path) - 10)
				return -1;
			sprintf(leaf_path, "%s/leaf.jpg", resource_path);

			/* well, let's demonstrate how to send the hard way */

			p = buffer + LWS_PRE;
			end = p + sizeof(buffer) - LWS_PRE;

			pss->fd = lws_plat_file_open(wsi, leaf_path, &file_len,
						     LWS_O_RDONLY);

			if (pss->fd == LWS_INVALID_FILE) {
				lwsl_err("faild to open file %s\n", leaf_path);
				return -1;
			}

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
			if (lws_add_http_header_status(wsi, 200, &p, end))
				return 1;
			if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_SERVER,
				    	(unsigned char *)"libwebsockets",
					13, &p, end))
				return 1;
			if (lws_add_http_header_by_token(wsi,
					WSI_TOKEN_HTTP_CONTENT_TYPE,
				    	(unsigned char *)"image/jpeg",
					10, &p, end))
				return 1;
			if (lws_add_http_header_content_length(wsi,
							       file_len, &p,
							       end))
				return 1;
			if (lws_finalize_http_header(wsi, &p, end))
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

			*p = '\0';
			lwsl_info("%s\n", buffer + LWS_PRE);

			n = lws_write(wsi, buffer + LWS_PRE,
				      p - (buffer + LWS_PRE),
				      LWS_WRITE_HTTP_HEADERS);
			if (n < 0) {
				lws_plat_file_close(wsi, pss->fd);
				return -1;
			}
			/*
			 * book us a LWS_CALLBACK_HTTP_WRITEABLE callback
			 */
			lws_callback_on_writable(wsi);
			break;
		}

		/* if not, send a file the easy way */
		if (!strncmp(in, "/cgit-data/", 11)) {
			in = (char *)in + 11;
			strcpy(buf, "/usr/share/cgit");
		} else
			strcpy(buf, resource_path);

		if (strcmp(in, "/")) {
			if (*((const char *)in) != '/')
				strcat(buf, "/");
			strncat(buf, in, sizeof(buf) - strlen(buf) - 1);
		} else /* default file to serve */
			strcat(buf, "/test.html");
		buf[sizeof(buf) - 1] = '\0';

		/* refuse to serve files we don't understand */
		mimetype = get_mimetype(buf);
		if (!mimetype) {
			lwsl_err("Unknown mimetype for %s\n", buf);
			lws_return_http_status(wsi,
				      HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE, NULL);
			return -1;
		}

		/* demonstrates how to set a cookie on / */

		other_headers = leaf_path;
		p = (unsigned char *)leaf_path;
		if (!strcmp((const char *)in, "/") &&
			   !lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_COOKIE)) {
			/* this isn't very unguessable but it'll do for us */
			gettimeofday(&tv, NULL);
			n = sprintf(b64, "test=LWS_%u_%u_COOKIE;Max-Age=360000",
				(unsigned int)tv.tv_sec,
				(unsigned int)tv.tv_usec);

			if (lws_add_http_header_by_name(wsi,
				(unsigned char *)"set-cookie:",
				(unsigned char *)b64, n, &p,
				(unsigned char *)leaf_path + sizeof(leaf_path)))
				return 1;
		}
		if (lws_is_ssl(wsi) && lws_add_http_header_by_name(wsi,
						(unsigned char *)
						"Strict-Transport-Security:",
						(unsigned char *)
						"max-age=15768000 ; "
						"includeSubDomains", 36, &p,
						(unsigned char *)leaf_path +
							sizeof(leaf_path)))
			return 1;
		n = (char *)p - leaf_path;

		n = lws_serve_http_file(wsi, buf, mimetype, other_headers, n);
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
		lws_return_http_status(wsi, HTTP_STATUS_OK, NULL);
		goto try_to_reuse;

	case LWS_CALLBACK_HTTP_FILE_COMPLETION:
		goto try_to_reuse;

	case LWS_CALLBACK_HTTP_WRITEABLE:
		lwsl_info("LWS_CALLBACK_HTTP_WRITEABLE\n");

		if (pss->client_finished)
			return -1;

		if (pss->fd == LWS_INVALID_FILE)
			goto try_to_reuse;
#ifdef LWS_WITH_CGI
		if (pss->reason_bf & 1) {
			if (lws_cgi_write_split_stdout_headers(wsi) < 0)
				goto bail;

			pss->reason_bf &= ~1;
			break;
		}
#endif
#ifndef LWS_NO_CLIENT
		if (pss->reason_bf & 2) {
			char *px = buf + LWS_PRE;
			int lenx = sizeof(buf) - LWS_PRE;
			/*
			 * our sink is writeable and our source has something
			 * to read.  So read a lump of source material of
			 * suitable size to send or what's available, whichever
			 * is the smaller.
			 */
			pss->reason_bf &= ~2;
			wsi1 = lws_get_child(wsi);
			if (!wsi1)
				break;
			if (lws_http_client_read(wsi1, &px, &lenx) < 0)
				goto bail;

			if (pss->client_finished)
				return -1;
			break;
		}
#endif
		/*
		 * we can send more of whatever it is we were sending
		 */
		sent = 0;
		do {
			/* we'd like the send this much */
			n = sizeof(buffer) - LWS_PRE;

			/* but if the peer told us he wants less, we can adapt */
			m = lws_get_peer_write_allowance(wsi);

			/* -1 means not using a protocol that has this info */
			if (m == 0)
				/* right now, peer can't handle anything */
				goto later;

			if (m != -1 && m < n)
				/* he couldn't handle that much */
				n = m;

			n = lws_plat_file_read(wsi, pss->fd,
					       &amount, buffer + LWS_PRE, n);
			/* problem reading, close conn */
			if (n < 0) {
				lwsl_err("problem reading file\n");
				goto bail;
			}
			n = (int)amount;
			/* sent it all, close conn */
			if (n == 0)
				goto penultimate;
			/*
			 * To support HTTP2, must take care about preamble space
			 *
			 * identification of when we send the last payload frame
			 * is handled by the library itself if you sent a
			 * content-length header
			 */
			m = lws_write(wsi, buffer + LWS_PRE, n, LWS_WRITE_HTTP);
			if (m < 0) {
				lwsl_err("write failed\n");
				/* write failed, close conn */
				goto bail;
			}
			if (m) /* while still active, extend timeout */
				lws_set_timeout(wsi, PENDING_TIMEOUT_HTTP_CONTENT, 5);
			sent += m;

		} while (!lws_send_pipe_choked(wsi) && (sent < 1024 * 1024));
later:
		lws_callback_on_writable(wsi);
		break;
penultimate:
		lws_plat_file_close(wsi, pss->fd);
		pss->fd = LWS_INVALID_FILE;
		goto try_to_reuse;

bail:
		lws_plat_file_close(wsi, pss->fd);

		return -1;

	/*
	 * callback for confirming to continue with client IP appear in
	 * protocol 0 callback since no websocket protocol has been agreed
	 * yet.  You can just ignore this if you won't filter on client IP
	 * since the default unhandled callback return is 0 meaning let the
	 * connection continue.
	 */
	case LWS_CALLBACK_FILTER_NETWORK_CONNECTION:
		/* if we returned non-zero from here, we kill the connection */
		break;

#ifndef LWS_NO_CLIENT
	case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP: {
		char ctype[64], ctlen = 0;
		lwsl_err("LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP\n");
		p = buffer + LWS_PRE;
		end = p + sizeof(buffer) - LWS_PRE;
		if (lws_add_http_header_status(lws_get_parent(wsi), 200, &p, end))
			return 1;
		if (lws_add_http_header_by_token(lws_get_parent(wsi),
				WSI_TOKEN_HTTP_SERVER,
			    	(unsigned char *)"libwebsockets",
				13, &p, end))
			return 1;

		ctlen = lws_hdr_copy(wsi, ctype, sizeof(ctype), WSI_TOKEN_HTTP_CONTENT_TYPE);
		if (ctlen > 0) {
			if (lws_add_http_header_by_token(lws_get_parent(wsi),
				WSI_TOKEN_HTTP_CONTENT_TYPE,
				(unsigned char *)ctype, ctlen, &p, end))
				return 1;
		}
#if 0
		if (lws_add_http_header_content_length(lws_get_parent(wsi),
						       file_len, &p, end))
			return 1;
#endif
		if (lws_finalize_http_header(lws_get_parent(wsi), &p, end))
			return 1;

		*p = '\0';
		lwsl_info("%s\n", buffer + LWS_PRE);

		n = lws_write(lws_get_parent(wsi), buffer + LWS_PRE,
			      p - (buffer + LWS_PRE),
			      LWS_WRITE_HTTP_HEADERS);
		if (n < 0)
			return -1;

		break; }
	case LWS_CALLBACK_CLOSED_CLIENT_HTTP:
		//lwsl_err("LWS_CALLBACK_CLOSED_CLIENT_HTTP\n");
		return -1;
		break;
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
		//lwsl_err("LWS_CALLBACK_RECEIVE_CLIENT_HTTP: wsi %p\n", wsi);
		assert(lws_get_parent(wsi));
		if (!lws_get_parent(wsi))
			break;
		// lwsl_err("LWS_CALLBACK_RECEIVE_CLIENT_HTTP: wsi %p: sock: %d, parent_wsi: %p, parent_sock:%d,  len %d\n",
		//		wsi, lws_get_socket_fd(wsi),
		//		lws_get_parent(wsi),
		//		lws_get_socket_fd(lws_get_parent(wsi)), len);
		pss1 = lws_wsi_user(lws_get_parent(wsi));
		pss1->reason_bf |= 2;
		lws_callback_on_writable(lws_get_parent(wsi));
		break;
	case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
		//lwsl_err("LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ len %d\n", len);
		assert(lws_get_parent(wsi));
		m = lws_write(lws_get_parent(wsi), (unsigned char *)in,
				len, LWS_WRITE_HTTP);
		if (m < 0)
			return -1;
		break;
	case LWS_CALLBACK_COMPLETED_CLIENT_HTTP:
		//lwsl_err("LWS_CALLBACK_COMPLETED_CLIENT_HTTP\n");
		assert(lws_get_parent(wsi));
		if (!lws_get_parent(wsi))
			break;
		pss1 = lws_wsi_user(lws_get_parent(wsi));
		pss1->client_finished = 1;
		break;
#endif

#ifdef LWS_WITH_CGI
	/* CGI IO events (POLLIN/OUT) appear here our demo user code policy is
	 *
	 *  - POST data goes on subprocess stdin
	 *  - subprocess stdout goes on http via writeable callback
	 *  - subprocess stderr goes to the logs
	 */
	case LWS_CALLBACK_CGI:
		pss->args = *((struct lws_cgi_args *)in);
		//lwsl_notice("LWS_CALLBACK_CGI: ch %d\n", pss->args.ch);
		switch (pss->args.ch) { /* which of stdin/out/err ? */
		case LWS_STDIN:
			/* TBD stdin rx flow control */
			break;
		case LWS_STDOUT:
			pss->reason_bf |= 1;
			/* when writing to MASTER would not block */
			lws_callback_on_writable(wsi);
			break;
		case LWS_STDERR:
			n = read(lws_get_socket_fd(pss->args.stdwsi[LWS_STDERR]),
					buf, 127);
			//lwsl_notice("stderr reads %d\n", n);
			if (n > 0) {
				if (buf[n - 1] != '\n')
					buf[n++] = '\n';
				buf[n] = '\0';
				lwsl_notice("CGI-stderr: %s\n", buf);
			}
			break;
		}
		break;

	case LWS_CALLBACK_CGI_TERMINATED:
		//lwsl_notice("LWS_CALLBACK_CGI_TERMINATED\n");
		/* because we sent on openended http, close the connection */
		return -1;

	case LWS_CALLBACK_CGI_STDIN_DATA:  /* POST body for stdin */
		//lwsl_notice("LWS_CALLBACK_CGI_STDIN_DATA\n");
		pss->args = *((struct lws_cgi_args *)in);
		n = write(lws_get_socket_fd(pss->args.stdwsi[LWS_STDIN]),
			  pss->args.data, pss->args.len);
		//lwsl_notice("LWS_CALLBACK_CGI_STDIN_DATA: write says %d", n);
		if (n < pss->args.len)
			lwsl_notice("LWS_CALLBACK_CGI_STDIN_DATA: sent %d only %d went",
					n, pss->args.len);
		return n;
#endif

	/*
	 * callbacks for managing the external poll() array appear in
	 * protocol 0 callback
	 */

	case LWS_CALLBACK_LOCK_POLL:
		/*
		 * lock mutex to protect pollfd state
		 * called before any other POLL related callback
		 * if protecting wsi lifecycle change, len == 1
		 */
		test_server_lock(len);
		break;

	case LWS_CALLBACK_UNLOCK_POLL:
		/*
		 * unlock mutex to protect pollfd state when
		 * called after any other POLL related callback
		 * if protecting wsi lifecycle change, len == 1
		 */
		test_server_unlock(len);
		break;

#ifdef EXTERNAL_POLL
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
		 * if you will call "lws_callback_on_writable"
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

	/* if we're on HTTP1.1 or 2.0, will keep the idle connection alive */
try_to_reuse:
	if (lws_http_transaction_completed(wsi))
		return -1;

	return 0;
}
