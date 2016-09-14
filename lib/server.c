/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2016 Andy Green <andy@warmcat.com>
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


#include "private-libwebsockets.h"

int
lws_context_init_server(struct lws_context_creation_info *info,
			struct lws_vhost *vhost)
{
#ifdef LWS_POSIX
	int n, opt = 1, limit = 1;
#endif
	lws_sockfd_type sockfd;
	struct lws_vhost *vh;
	struct lws *wsi;
	int m = 0;

	/* set up our external listening socket we serve on */

	if (info->port == CONTEXT_PORT_NO_LISTEN)
		return 0;

	vh = vhost->context->vhost_list;
	while (vh) {
		if (vh->listen_port == info->port) {
			if ((!info->iface && !vh->iface) ||
			    (info->iface && vh->iface &&
			    !strcmp(info->iface, vh->iface))) {
				vhost->listen_port = info->port;
				vhost->iface = info->iface;
				lwsl_notice(" using listen skt from vhost %s\n",
					    vh->name);
				return 0;
			}
		}
		vh = vh->vhost_next;
	}

#if LWS_POSIX
#if defined(__linux__)
	limit = vhost->context->count_threads;
#endif

	for (m = 0; m < limit; m++) {
#ifdef LWS_USE_UNIX_SOCK
	if (LWS_UNIX_SOCK_ENABLED(vhost))
		sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	else
#endif
#ifdef LWS_USE_IPV6
	if (LWS_IPV6_ENABLED(vhost->context))
		sockfd = socket(AF_INET6, SOCK_STREAM, 0);
	else
#endif
		sockfd = socket(AF_INET, SOCK_STREAM, 0);

	if (sockfd == -1) {
#else
	sockfd = mbed3_create_tcp_stream_socket();
	if (!lws_sockfd_valid(sockfd)) {
#endif
		lwsl_err("ERROR opening socket\n");
		return 1;
	}

#if LWS_POSIX
	/*
	 * allow us to restart even if old sockets in TIME_WAIT
	 */
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,
		       (const void *)&opt, sizeof(opt)) < 0) {
		compatible_close(sockfd);
		return 1;
	}
#if defined(__linux__) && defined(SO_REUSEPORT) && LWS_MAX_SMP > 1
	if (vhost->context->count_threads > 1)
		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT,
				(const void *)&opt, sizeof(opt)) < 0) {
			compatible_close(sockfd);
			return 1;
		}
#endif
#endif
	lws_plat_set_socket_options(vhost, sockfd);

#if LWS_POSIX
	n = lws_socket_bind(vhost, sockfd, info->port, info->iface);
	if (n < 0)
		goto bail;
	info->port = n;
#endif
	vhost->listen_port = info->port;
	vhost->iface = info->iface;

	wsi = lws_zalloc(sizeof(struct lws));
	if (wsi == NULL) {
		lwsl_err("Out of mem\n");
		goto bail;
	}
	wsi->context = vhost->context;
	wsi->sock = sockfd;
	wsi->mode = LWSCM_SERVER_LISTENER;
	wsi->protocol = vhost->protocols;
	wsi->tsi = m;
	wsi->vhost = vhost;
	wsi->listener = 1;

	vhost->context->pt[m].wsi_listening = wsi;
	if (insert_wsi_socket_into_fds(vhost->context, wsi))
		goto bail;

	vhost->context->count_wsi_allocated++;
	vhost->lserv_wsi = wsi;

#if LWS_POSIX
	listen(wsi->sock, LWS_SOMAXCONN);
	} /* for each thread able to independently listen */
#else
	mbed3_tcp_stream_bind(wsi->sock, info->port, wsi);
#endif
	if (!lws_check_opt(info->options, LWS_SERVER_OPTION_EXPLICIT_VHOSTS)) {
#ifdef LWS_USE_UNIX_SOCK
		if (LWS_UNIX_SOCK_ENABLED(vhost))
			lwsl_notice(" Listening on \"%s\"\n", info->iface);
		else
#endif
			lwsl_notice(" Listening on port %d\n", info->port);
        }

	return 0;

bail:
	compatible_close(sockfd);

	return 1;
}

int
_lws_server_listen_accept_flow_control(struct lws *twsi, int on)
{
	struct lws_context_per_thread *pt = &twsi->context->pt[(int)twsi->tsi];
	struct lws *wsi = pt->wsi_listening;
	int n;

	if (!wsi || twsi->context->being_destroyed)
		return 0;

	lwsl_debug("%s: Thr %d: LISTEN wsi %p: state %d\n",
		   __func__, twsi->tsi, (void *)wsi, on);

	if (on)
		n = lws_change_pollfd(wsi, 0, LWS_POLLIN);
	else
		n = lws_change_pollfd(wsi, LWS_POLLIN, 0);

	return n;
}

struct lws_vhost *
lws_select_vhost(struct lws_context *context, int port, const char *servername)
{
	struct lws_vhost *vhost = context->vhost_list;
	const char *p;
	int n, m, colon;

	n = strlen(servername);
	colon = n;
	p = strchr(servername, ':');
	if (p)
		colon = p - servername;

	/* first try exact matches */

	while (vhost) {
		if (port == vhost->listen_port &&
		    !strncmp(vhost->name, servername, colon)) {
			lwsl_info("SNI: Found: %s\n", servername);
			return vhost;
		}
		vhost = vhost->vhost_next;
	}

	/*
	 * if no exact matches, try matching *.vhost-name
	 * unintentional matches are possible but resolve to x.com for *.x.com
	 * which is reasonable.  If exact match exists we already chose it and
	 * never reach here.  SSL will still fail it if the cert doesn't allow
	 * *.x.com.
	 */

	vhost = context->vhost_list;
	while (vhost) {
		m = strlen(vhost->name);
		if (port == vhost->listen_port &&
		    m <= (colon - 2) &&
		    servername[colon - m - 1] == '.' &&
		    !strncmp(vhost->name, servername + colon - m, m)) {
			lwsl_info("SNI: Found %s on wildcard: %s\n",
				    servername, vhost->name);
			return vhost;
		}
		vhost = vhost->vhost_next;
	}

	return NULL;
}

static const char *
get_mimetype(const char *file, const struct lws_http_mount *m)
{
	int n = strlen(file);
	const struct lws_protocol_vhost_options *pvo = NULL;

	if (m)
		pvo = m->extra_mimetypes;

	if (n < 5)
		return NULL;

	if (!strcmp(&file[n - 4], ".ico"))
		return "image/x-icon";

	if (!strcmp(&file[n - 4], ".gif"))
		return "image/gif";

	if (!strcmp(&file[n - 3], ".js"))
		return "text/javascript";

	if (!strcmp(&file[n - 4], ".png"))
		return "image/png";

	if (!strcmp(&file[n - 4], ".jpg"))
		return "image/jpeg";

	if (!strcmp(&file[n - 3], ".gz"))
		return "application/gzip";

	if (!strcmp(&file[n - 4], ".JPG"))
		return "image/jpeg";

	if (!strcmp(&file[n - 5], ".html"))
		return "text/html";

	if (!strcmp(&file[n - 4], ".css"))
		return "text/css";

	if (!strcmp(&file[n - 4], ".txt"))
		return "text/plain";

	if (!strcmp(&file[n - 4], ".ttf"))
		return "application/x-font-ttf";

	if (!strcmp(&file[n - 5], ".woff"))
		return "application/font-woff";

	if (!strcmp(&file[n - 4], ".xml"))
		return "application/xml";

	while (pvo) {
		if (!strcmp(&file[n - strlen(pvo->name)], pvo->name))
			return pvo->value;

		pvo = pvo->next;
	}

	return NULL;
}

static int
lws_http_serve(struct lws *wsi, char *uri, const char *origin,
	       const struct lws_http_mount *m)
{
	const char *mimetype;
#ifndef _WIN32_WCE
	struct stat st;
#endif
	char path[256], sym[256];
	unsigned char *p = (unsigned char *)sym + 32 + LWS_PRE, *start = p;
	unsigned char *end = p + sizeof(sym) - 32 - LWS_PRE;
#if !defined(WIN32)
	size_t len;
#endif
	int n, spin = 0;

	lws_snprintf(path, sizeof(path) - 1, "%s/%s", origin, uri);

#ifndef _WIN32_WCE
	do {
		spin++;

		if (stat(path, &st)) {
			lwsl_info("unable to stat %s\n", path);
			goto bail;
		}

		lwsl_debug(" %s mode %d\n", path, S_IFMT & st.st_mode);
#if !defined(WIN32)
		if ((S_IFMT & st.st_mode) == S_IFLNK) {
			len = readlink(path, sym, sizeof(sym) - 1);
			if (len) {
				lwsl_err("Failed to read link %s\n", path);
				goto bail;
			}
			sym[len] = '\0';
			lwsl_debug("symlink %s -> %s\n", path, sym);
			lws_snprintf(path, sizeof(path) - 1, "%s", sym);
		}
#endif
		if ((S_IFMT & st.st_mode) == S_IFDIR) {
			lwsl_debug("default filename append to dir\n");
			lws_snprintf(path, sizeof(path) - 1, "%s/%s/index.html",
				 origin, uri);
		}

	} while ((S_IFMT & st.st_mode) != S_IFREG && spin < 5);

	if (spin == 5)
		lwsl_err("symlink loop %s \n", path);

	n = sprintf(sym, "%08lX%08lX", (unsigned long)st.st_size,
				   (unsigned long)st.st_mtime);

	if (lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_IF_NONE_MATCH)) {
		/*
		 * he thinks he has some version of it already,
		 * check if the tag matches
		 */
		if (!strcmp(sym, lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP_IF_NONE_MATCH))) {

			lwsl_debug("%s: ETAG match %s %s\n", __func__,
				   uri, origin);

			/* we don't need to send the payload */
			if (lws_add_http_header_status(wsi, 304, &p, end))
				return -1;
			if (lws_add_http_header_by_token(wsi,
					WSI_TOKEN_HTTP_ETAG,
					(unsigned char *)sym, n, &p, end))
				return -1;
			if (lws_finalize_http_header(wsi, &p, end))
				return -1;

			n = lws_write(wsi, start, p - start,
					LWS_WRITE_HTTP_HEADERS);
			if (n != (p - start)) {
				lwsl_err("_write returned %d from %d\n", n, p - start);
				return -1;
			}

			return lws_http_transaction_completed(wsi);
		}
	}

	if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_ETAG,
			(unsigned char *)sym, n, &p, end))
		return -1;
#endif

	mimetype = get_mimetype(path, m);
	if (!mimetype) {
		lwsl_err("unknown mimetype for %s", path);
		goto bail;
	}

	n = lws_serve_http_file(wsi, path, mimetype, (char *)start, p - start);

	if (n < 0 || ((n > 0) && lws_http_transaction_completed(wsi)))
		return -1; /* error or can't reuse connection: close the socket */

	return 0;
bail:

	return -1;
}

int
lws_http_action(struct lws *wsi)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];
	enum http_connection_type connection_type;
	enum http_version request_version;
	char content_length_str[32];
	const struct lws_http_mount *hm, *hit = NULL;
	unsigned int n, count = 0;
	char http_version_str[10];
	char http_conn_str[20];
	int http_version_len;
	char *uri_ptr = NULL;
	int uri_len = 0, best = 0;
	int meth = -1;

	static const unsigned char methods[] = {
		WSI_TOKEN_GET_URI,
		WSI_TOKEN_POST_URI,
		WSI_TOKEN_OPTIONS_URI,
		WSI_TOKEN_PUT_URI,
		WSI_TOKEN_PATCH_URI,
		WSI_TOKEN_DELETE_URI,
#ifdef LWS_USE_HTTP2
		WSI_TOKEN_HTTP_COLON_PATH,
#endif
	};
#if defined(_DEBUG) || defined(LWS_WITH_ACCESS_LOG)
	static const char * const method_names[] = {
		"GET", "POST", "OPTIONS", "PUT", "PATCH", "DELETE",
#ifdef LWS_USE_HTTP2
		":path",
#endif
	};
#endif

	/* it's not websocket.... shall we accept it as http? */

	for (n = 0; n < ARRAY_SIZE(methods); n++)
		if (lws_hdr_total_length(wsi, methods[n]))
			count++;
	if (!count) {
		lwsl_warn("Missing URI in HTTP request\n");
		goto bail_nuke_ah;
	}

	if (count != 1) {
		lwsl_warn("multiple methods?\n");
		goto bail_nuke_ah;
	}

	if (lws_ensure_user_space(wsi))
		goto bail_nuke_ah;

	for (n = 0; n < ARRAY_SIZE(methods); n++)
		if (lws_hdr_total_length(wsi, methods[n])) {
			uri_ptr = lws_hdr_simple_ptr(wsi, methods[n]);
			uri_len = lws_hdr_total_length(wsi, methods[n]);
			lwsl_info("Method: %s request for '%s'\n",
				  	method_names[n], uri_ptr);
			meth = n;
			break;
		}

	(void)meth;

	/* we insist on absolute paths */

	if (uri_ptr[0] != '/') {
		lws_return_http_status(wsi, HTTP_STATUS_FORBIDDEN, NULL);

		goto bail_nuke_ah;
	}

	/* HTTP header had a content length? */

	wsi->u.http.content_length = 0;
	if (lws_hdr_total_length(wsi, WSI_TOKEN_POST_URI) ||
		lws_hdr_total_length(wsi, WSI_TOKEN_PATCH_URI) ||
		lws_hdr_total_length(wsi, WSI_TOKEN_PUT_URI))
		wsi->u.http.content_length = 100 * 1024 * 1024;

	if (lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_CONTENT_LENGTH)) {
		lws_hdr_copy(wsi, content_length_str,
			     sizeof(content_length_str) - 1,
			     WSI_TOKEN_HTTP_CONTENT_LENGTH);
		wsi->u.http.content_length = atoi(content_length_str);
	}

	if (wsi->http2_substream) {
		wsi->u.http.request_version = HTTP_VERSION_2;
	} else {
		/* http_version? Default to 1.0, override with token: */
		request_version = HTTP_VERSION_1_0;

		/* Works for single digit HTTP versions. : */
		http_version_len = lws_hdr_total_length(wsi, WSI_TOKEN_HTTP);
		if (http_version_len > 7) {
			lws_hdr_copy(wsi, http_version_str,
					sizeof(http_version_str) - 1, WSI_TOKEN_HTTP);
			if (http_version_str[5] == '1' && http_version_str[7] == '1')
				request_version = HTTP_VERSION_1_1;
		}
		wsi->u.http.request_version = request_version;

		/* HTTP/1.1 defaults to "keep-alive", 1.0 to "close" */
		if (request_version == HTTP_VERSION_1_1)
			connection_type = HTTP_CONNECTION_KEEP_ALIVE;
		else
			connection_type = HTTP_CONNECTION_CLOSE;

		/* Override default if http "Connection:" header: */
		if (lws_hdr_total_length(wsi, WSI_TOKEN_CONNECTION)) {
			lws_hdr_copy(wsi, http_conn_str, sizeof(http_conn_str) - 1,
				     WSI_TOKEN_CONNECTION);
			http_conn_str[sizeof(http_conn_str) - 1] = '\0';
			if (!strcasecmp(http_conn_str, "keep-alive"))
				connection_type = HTTP_CONNECTION_KEEP_ALIVE;
			else
				if (!strcasecmp(http_conn_str, "close"))
					connection_type = HTTP_CONNECTION_CLOSE;
		}
		wsi->u.http.connection_type = connection_type;
	}

	n = wsi->protocol->callback(wsi, LWS_CALLBACK_FILTER_HTTP_CONNECTION,
				    wsi->user_space, uri_ptr, uri_len);
	if (n) {
		lwsl_info("LWS_CALLBACK_HTTP closing\n");

		return 1;
	}
	/*
	 * if there is content supposed to be coming,
	 * put a timeout on it having arrived
	 */
	lws_set_timeout(wsi, PENDING_TIMEOUT_HTTP_CONTENT,
			wsi->context->timeout_secs);
#ifdef LWS_OPENSSL_SUPPORT
	if (wsi->redirect_to_https) {
		/*
		 * we accepted http:// only so we could redirect to
		 * https://, so issue the redirect.  Create the redirection
		 * URI from the host: header and ignore the path part
		 */
		unsigned char *start = pt->serv_buf + LWS_PRE, *p = start,
			      *end = p + 512;

		if (!lws_hdr_total_length(wsi, WSI_TOKEN_HOST))
			goto bail_nuke_ah;

		n = sprintf((char *)end, "https://%s/",
			    lws_hdr_simple_ptr(wsi, WSI_TOKEN_HOST));

		n = lws_http_redirect(wsi, HTTP_STATUS_MOVED_PERMANENTLY,
				      end, n, &p, end);
		if ((int)n < 0)
			goto bail_nuke_ah;

		return lws_http_transaction_completed(wsi);
	}
#endif

#ifdef LWS_WITH_ACCESS_LOG
	/*
	 * Produce Apache-compatible log string for wsi, like this:
	 *
	 * 2.31.234.19 - - [27/Mar/2016:03:22:44 +0800]
	 * "GET /aep-screen.png HTTP/1.1"
	 * 200 152987 "https://libwebsockets.org/index.html"
	 * "Mozilla/5.0 (Macint... Chrome/49.0.2623.87 Safari/537.36"
	 *
	 */
	{
		static const char * const hver[] = {
			"http/1.0", "http/1.1", "http/2"
		};
#ifdef LWS_USE_IPV6
		char ads[INET6_ADDRSTRLEN];
#else
		char ads[INET_ADDRSTRLEN];
#endif
		char da[64];
		const char *pa, *me;
		struct tm *tmp;
		time_t t = time(NULL);
		int l = 256;

		if (wsi->access_log_pending)
			lws_access_log(wsi);

		wsi->access_log.header_log = lws_malloc(l);
		if (wsi->access_log.header_log) {

			tmp = localtime(&t);
			if (tmp)
				strftime(da, sizeof(da), "%d/%b/%Y:%H:%M:%S %z", tmp);
			else
				strcpy(da, "01/Jan/1970:00:00:00 +0000");

			pa = lws_get_peer_simple(wsi, ads, sizeof(ads));
			if (!pa)
				pa = "(unknown)";

			if (meth >= 0)
				me = method_names[meth];
			else
				me = "unknown";

			lws_snprintf(wsi->access_log.header_log, l,
				 "%s - - [%s] \"%s %s %s\"",
				 pa, da, me, uri_ptr,
				 hver[wsi->u.http.request_version]);

			l = lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_USER_AGENT);
			if (l) {
				wsi->access_log.user_agent = lws_malloc(l + 2);
				if (wsi->access_log.user_agent)
					lws_hdr_copy(wsi, wsi->access_log.user_agent,
							l + 1, WSI_TOKEN_HTTP_USER_AGENT);
				else
					lwsl_err("OOM getting user agent\n");
			}
			wsi->access_log_pending = 1;
		}
	}
#endif

	/* can we serve it from the mount list? */

	hm = wsi->vhost->mount_list;
	while (hm) {
		if (uri_len >= hm->mountpoint_len &&
		    !strncmp(uri_ptr, hm->mountpoint, hm->mountpoint_len) &&
		    (uri_ptr[hm->mountpoint_len] == '\0' ||
		     uri_ptr[hm->mountpoint_len] == '/' ||
		     hm->mountpoint_len == 1)
		    ) {
			if ((hm->origin_protocol == LWSMPRO_CGI ||
			     lws_hdr_total_length(wsi, WSI_TOKEN_GET_URI)) &&
			    hm->mountpoint_len > best) {
				best = hm->mountpoint_len;
				hit = hm;
			}
		}
		hm = hm->mount_next;
	}
	if (hit) {
		char *s = uri_ptr + hit->mountpoint_len;

		lwsl_debug("*** hit %d %d %s\n", hit->mountpoint_len,
			   hit->origin_protocol , hit->origin);

		/*
		 * if we have a mountpoint like https://xxx.com/yyy
		 * there is an implied / at the end for our purposes since
		 * we can only mount on a "directory".
		 *
		 * But if we just go with that, the browser cannot understand
		 * that he is actually looking down one "directory level", so
		 * even though we give him /yyy/abc.html he acts like the
		 * current directory level is /.  So relative urls like "x.png"
		 * wrongly look outside the mountpoint.
		 *
		 * Therefore if we didn't come in on a url with an explicit
		 * / at the end, we must redirect to add it so the browser
		 * understands he is one "directory level" down.
		 */
		if ((hit->mountpoint_len > 1 || (hit->origin_protocol & 4)) &&
		    (*s != '/' || (hit->origin_protocol & 4)) &&
		    (hit->origin_protocol != LWSMPRO_CGI)) {
			unsigned char *start = pt->serv_buf + LWS_PRE,
					      *p = start, *end = p + 512;
			static const char *oprot[] = {
				"http://", "https://"
			};

			lwsl_debug("Doing 301 '%s' org %s\n", s, hit->origin);

			if (!lws_hdr_total_length(wsi, WSI_TOKEN_HOST))
				goto bail_nuke_ah;

			/* > at start indicates deal with by redirect */
			if (hit->origin_protocol & 4)
				n = lws_snprintf((char *)end, 256, "%s%s",
					    oprot[hit->origin_protocol & 1],
					    hit->origin);
			else
				n = lws_snprintf((char *)end, 256,
				    "https://%s/%s/",
				    lws_hdr_simple_ptr(wsi, WSI_TOKEN_HOST),
				    uri_ptr);

			n = lws_http_redirect(wsi, HTTP_STATUS_MOVED_PERMANENTLY,
					      end, n, &p, end);
			if ((int)n < 0)
				goto bail_nuke_ah;

			return lws_http_transaction_completed(wsi);
		}

#ifdef LWS_WITH_CGI
		/* did we hit something with a cgi:// origin? */
		if (hit->origin_protocol == LWSMPRO_CGI) {
			const char *cmd[] = {
				NULL, /* replace with cgi path */
				NULL
			};
			unsigned char *p, *end, buffer[256];

			lwsl_debug("%s: cgi\n", __func__);
			cmd[0] = hit->origin;

			n = 5;
			if (hit->cgi_timeout)
				n = hit->cgi_timeout;

			n = lws_cgi(wsi, cmd, hit->mountpoint_len, n,
				    hit->cgienv);
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

			goto deal_body;
		}
#endif

		n = strlen(s);
		if (s[0] == '\0' || (n == 1 && s[n - 1] == '/'))
			s = (char *)hit->def;
		if (!s)
			s = "index.html";

		wsi->cache_secs = hit->cache_max_age;
		wsi->cache_reuse = hit->cache_reusable;
		wsi->cache_revalidate = hit->cache_revalidate;
		wsi->cache_intermediaries = hit->cache_intermediaries;

		n = lws_http_serve(wsi, s, hit->origin, hit);
		if (n) {
			/*
			 * 	lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND, NULL);
			 */
			n = wsi->protocol->callback(wsi, LWS_CALLBACK_HTTP,
					    wsi->user_space, uri_ptr, uri_len);
		}
	} else
		n = wsi->protocol->callback(wsi, LWS_CALLBACK_HTTP,
				    wsi->user_space, uri_ptr, uri_len);

	if (n) {
		lwsl_info("LWS_CALLBACK_HTTP closing\n");

		return 1;
	}

#ifdef LWS_WITH_CGI
deal_body:
#endif
	/*
	 * If we're not issuing a file, check for content_length or
	 * HTTP keep-alive. No keep-alive header allocation for
	 * ISSUING_FILE, as this uses HTTP/1.0.
	 *
	 * In any case, return 0 and let lws_read decide how to
	 * proceed based on state
	 */
	if (wsi->state != LWSS_HTTP_ISSUING_FILE)
		/* Prepare to read body if we have a content length: */
		if (wsi->u.http.content_length > 0)
			wsi->state = LWSS_HTTP_BODY;

	return 0;

bail_nuke_ah:
	/* we're closing, losing some rx is OK */
	wsi->u.hdr.ah->rxpos = wsi->u.hdr.ah->rxlen;
	lws_header_table_detach(wsi, 1);

	return 1;
}


int
lws_handshake_server(struct lws *wsi, unsigned char **buf, size_t len)
{
	struct lws_context *context = lws_get_context(wsi);
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	struct _lws_header_related hdr;
	struct allocated_headers *ah;
	int protocol_len, n, hit;
	char protocol_list[128];
	char protocol_name[64];
	char *p;

	if (len >= 10000000) {
		lwsl_err("%s: assert: len %ld\n", __func__, (long)len);
		assert(0);
	}

	if (!wsi->u.hdr.ah) {
		lwsl_err("%s: assert: NULL ah\n", __func__);
		assert(0);
	}

	while (len--) {
		wsi->more_rx_waiting = !!len;

		if (wsi->mode != LWSCM_HTTP_SERVING &&
		    wsi->mode != LWSCM_HTTP_SERVING_ACCEPTED) {
			lwsl_err("%s: bad wsi mode %d\n", __func__, wsi->mode);
			goto bail_nuke_ah;
		}

		if (lws_parse(wsi, *(*buf)++)) {
			lwsl_info("lws_parse failed\n");
			goto bail_nuke_ah;
		}

		if (wsi->u.hdr.parser_state != WSI_PARSING_COMPLETE)
			continue;

		lwsl_parser("%s: lws_parse sees parsing complete\n", __func__);
		lwsl_debug("%s: wsi->more_rx_waiting=%d\n", __func__,
				wsi->more_rx_waiting);

		/* select vhost */

		if (lws_hdr_total_length(wsi, WSI_TOKEN_HOST)) {
			struct lws_vhost *vhost = lws_select_vhost(
				context, wsi->vhost->listen_port,
				lws_hdr_simple_ptr(wsi, WSI_TOKEN_HOST));

			if (vhost)
				wsi->vhost = vhost;
		} else
			lwsl_info("no host\n");

		wsi->vhost->trans++;
		if (!wsi->conn_stat_done) {
			wsi->vhost->conn++;
			wsi->conn_stat_done = 1;
		}

		wsi->mode = LWSCM_PRE_WS_SERVING_ACCEPT;
		lws_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);

		/* is this websocket protocol or normal http 1.0? */

		if (lws_hdr_total_length(wsi, WSI_TOKEN_UPGRADE)) {
			if (!strcasecmp(lws_hdr_simple_ptr(wsi, WSI_TOKEN_UPGRADE),
					"websocket")) {
				wsi->vhost->ws_upgrades++;
				lwsl_info("Upgrade to ws\n");
				goto upgrade_ws;
			}
#ifdef LWS_USE_HTTP2
			if (!strcasecmp(lws_hdr_simple_ptr(wsi, WSI_TOKEN_UPGRADE),
					"h2c")) {
				wsi->vhost->http2_upgrades++;
				lwsl_info("Upgrade to h2c\n");
				goto upgrade_h2c;
			}
#endif
			lwsl_info("Unknown upgrade\n");
			/* dunno what he wanted to upgrade to */
			goto bail_nuke_ah;
		}

		/* no upgrade ack... he remained as HTTP */

		lwsl_info("No upgrade\n");
		ah = wsi->u.hdr.ah;

		lws_union_transition(wsi, LWSCM_HTTP_SERVING_ACCEPTED);
		wsi->state = LWSS_HTTP;
		wsi->u.http.fd = LWS_INVALID_FILE;

		/* expose it at the same offset as u.hdr */
		wsi->u.http.ah = ah;
		lwsl_debug("%s: wsi %p: ah %p\n", __func__, (void *)wsi,
			   (void *)wsi->u.hdr.ah);

		n = lws_http_action(wsi);

		return n;

#ifdef LWS_USE_HTTP2
upgrade_h2c:
		if (!lws_hdr_total_length(wsi, WSI_TOKEN_HTTP2_SETTINGS)) {
			lwsl_info("missing http2_settings\n");
			goto bail_nuke_ah;
		}

		lwsl_info("h2c upgrade...\n");

		p = lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP2_SETTINGS);
		/* convert the peer's HTTP-Settings */
		n = lws_b64_decode_string(p, protocol_list,
					  sizeof(protocol_list));
		if (n < 0) {
			lwsl_parser("HTTP2_SETTINGS too long\n");
			return 1;
		}

		/* adopt the header info */

		ah = wsi->u.hdr.ah;

		lws_union_transition(wsi, LWSCM_HTTP2_SERVING);

		/* http2 union member has http union struct at start */
		wsi->u.http.ah = ah;

		lws_http2_init(&wsi->u.http2.peer_settings);
		lws_http2_init(&wsi->u.http2.my_settings);

		/* HTTP2 union */

		lws_http2_interpret_settings_payload(&wsi->u.http2.peer_settings,
				(unsigned char *)protocol_list, n);

		strcpy(protocol_list,
		       "HTTP/1.1 101 Switching Protocols\x0d\x0a"
		      "Connection: Upgrade\x0d\x0a"
		      "Upgrade: h2c\x0d\x0a\x0d\x0a");
		n = lws_issue_raw(wsi, (unsigned char *)protocol_list,
					strlen(protocol_list));
		if (n != strlen(protocol_list)) {
			lwsl_debug("http2 switch: ERROR writing to socket\n");
			return 1;
		}

		wsi->state = LWSS_HTTP2_AWAIT_CLIENT_PREFACE;

		return 0;
#endif

upgrade_ws:
		if (!wsi->protocol)
			lwsl_err("NULL protocol at lws_read\n");

		/*
		 * It's websocket
		 *
		 * Select the first protocol we support from the list
		 * the client sent us.
		 *
		 * Copy it to remove header fragmentation
		 */

		if (lws_hdr_copy(wsi, protocol_list, sizeof(protocol_list) - 1,
				 WSI_TOKEN_PROTOCOL) < 0) {
			lwsl_err("protocol list too long");
			goto bail_nuke_ah;
		}

		protocol_len = lws_hdr_total_length(wsi, WSI_TOKEN_PROTOCOL);
		protocol_list[protocol_len] = '\0';
		p = protocol_list;
		hit = 0;

		while (*p && !hit) {
			n = 0;
			while (n < sizeof(protocol_name) - 1 && *p && *p !=',')
				protocol_name[n++] = *p++;
			protocol_name[n] = '\0';
			if (*p)
				p++;

			lwsl_info("checking %s\n", protocol_name);

			n = 0;
			while (wsi->vhost->protocols[n].callback) {
				if (wsi->vhost->protocols[n].name &&
				    !strcmp(wsi->vhost->protocols[n].name,
					    protocol_name)) {
					wsi->protocol = &wsi->vhost->protocols[n];
					hit = 1;
					break;
				}

				n++;
			}
		}

		/* we didn't find a protocol he wanted? */

		if (!hit) {
			if (lws_hdr_simple_ptr(wsi, WSI_TOKEN_PROTOCOL)) {
				lwsl_info("No protocol from \"%s\" supported\n",
					 protocol_list);
				goto bail_nuke_ah;
			}
			/*
			 * some clients only have one protocol and
			 * do not send the protocol list header...
			 * allow it and match to the vhost's default
			 * protocol (which itself defaults to zero)
			 */
			lwsl_info("defaulting to prot handler %d\n",
				wsi->vhost->default_protocol_index);
			n = 0;
			wsi->protocol = &wsi->vhost->protocols[
				      (int)wsi->vhost->default_protocol_index];
		}

		/* allocate wsi->user storage */
		if (lws_ensure_user_space(wsi))
			goto bail_nuke_ah;

		/*
		 * Give the user code a chance to study the request and
		 * have the opportunity to deny it
		 */
		if ((wsi->protocol->callback)(wsi,
				LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION,
				wsi->user_space,
			      lws_hdr_simple_ptr(wsi, WSI_TOKEN_PROTOCOL), 0)) {
			lwsl_warn("User code denied connection\n");
			goto bail_nuke_ah;
		}

		/*
		 * Perform the handshake according to the protocol version the
		 * client announced
		 */

		switch (wsi->ietf_spec_revision) {
		case 13:
			lwsl_parser("lws_parse calling handshake_04\n");
			if (handshake_0405(context, wsi)) {
				lwsl_info("hs0405 has failed the connection\n");
				goto bail_nuke_ah;
			}
			break;

		default:
			lwsl_info("Unknown client spec version %d\n",
				  wsi->ietf_spec_revision);
			goto bail_nuke_ah;
		}

		/*
		 * stitch protocol choice into the vh protocol linked list
		 * We always insert ourselves at the start of the list
		 *
		 * X <-> B
		 * X <-> pAn <-> pB
		 */
		//lwsl_err("%s: pre insert vhost start wsi %p, that wsi prev == %p\n",
		//		__func__,
		//		wsi->vhost->same_vh_protocol_list[n],
		//		wsi->same_vh_protocol_prev);
		wsi->same_vh_protocol_prev = /* guy who points to us */
			&wsi->vhost->same_vh_protocol_list[n];
		wsi->same_vh_protocol_next = /* old first guy is our next */
				wsi->vhost->same_vh_protocol_list[n];
		/* we become the new first guy */
		wsi->vhost->same_vh_protocol_list[n] = wsi;

		if (wsi->same_vh_protocol_next)
			/* old first guy points back to us now */
			wsi->same_vh_protocol_next->same_vh_protocol_prev =
					&wsi->same_vh_protocol_next;



		/* we are upgrading to ws, so http/1.1 and keepalive +
		 * pipelined header considerations about keeping the ah around
		 * no longer apply.  However it's common for the first ws
		 * protocol data to have been coalesced with the browser
		 * upgrade request and to already be in the ah rx buffer.
		 */

		lwsl_info("%s: %p: inheriting ah in ws mode (rxpos:%d, rxlen:%d)\n",
			  __func__, wsi, wsi->u.hdr.ah->rxpos,
			  wsi->u.hdr.ah->rxlen);
		lws_pt_lock(pt);
		hdr = wsi->u.hdr;

		lws_union_transition(wsi, LWSCM_WS_SERVING);
		/*
		 * first service is WS mode will notice this, use the RX and
		 * then detach the ah (caution: we are not in u.hdr union
		 * mode any more then... ah_temp member is at start the same
		 * though)
		 *
		 * Because rxpos/rxlen shows something in the ah, we will get
		 * service guaranteed next time around the event loop
		 *
		 * All union members begin with hdr, so we can use it even
		 * though we transitioned to ws union mode (the ah detach
		 * code uses it anyway).
		 */
		wsi->u.hdr = hdr;
		lws_pt_unlock(pt);

		/*
		 * create the frame buffer for this connection according to the
		 * size mentioned in the protocol definition.  If 0 there, use
		 * a big default for compatibility
		 */

		n = wsi->protocol->rx_buffer_size;
		if (!n)
			n = LWS_MAX_SOCKET_IO_BUF;
		n += LWS_PRE;
		wsi->u.ws.rx_ubuf = lws_malloc(n + 4 /* 0x0000ffff zlib */);
		if (!wsi->u.ws.rx_ubuf) {
			lwsl_err("Out of Mem allocating rx buffer %d\n", n);
			return 1;
		}
		wsi->u.ws.rx_ubuf_alloc = n;
		lwsl_info("Allocating RX buffer %d\n", n);
#if LWS_POSIX
		if (setsockopt(wsi->sock, SOL_SOCKET, SO_SNDBUF,
			       (const char *)&n, sizeof n)) {
			lwsl_warn("Failed to set SNDBUF to %d", n);
			return 1;
		}
#endif
		lwsl_parser("accepted v%02d connection\n",
			    wsi->ietf_spec_revision);

		return 0;
	} /* while all chars are handled */

	return 0;

bail_nuke_ah:
	/* drop the header info */
	/* we're closing, losing some rx is OK */
	wsi->u.hdr.ah->rxpos = wsi->u.hdr.ah->rxlen;
	lws_header_table_detach(wsi, 1);

	return 1;
}

static int
lws_get_idlest_tsi(struct lws_context *context)
{
	unsigned int lowest = ~0;
	int n = 0, hit = -1;

	for (; n < context->count_threads; n++) {
		if ((unsigned int)context->pt[n].fds_count !=
		    context->fd_limit_per_thread - 1 &&
		    (unsigned int)context->pt[n].fds_count < lowest) {
			lowest = context->pt[n].fds_count;
			hit = n;
		}
	}

	return hit;
}

struct lws *
lws_create_new_server_wsi(struct lws_vhost *vhost)
{
	struct lws *new_wsi;
	int n = lws_get_idlest_tsi(vhost->context);

	if (n < 0) {
		lwsl_err("no space for new conn\n");
		return NULL;
	}

	new_wsi = lws_zalloc(sizeof(struct lws));
	if (new_wsi == NULL) {
		lwsl_err("Out of memory for new connection\n");
		return NULL;
	}

	new_wsi->tsi = n;
	lwsl_info("Accepted %p to tsi %d\n", new_wsi, new_wsi->tsi);

	new_wsi->vhost = vhost;
	new_wsi->context = vhost->context;
	new_wsi->pending_timeout = NO_PENDING_TIMEOUT;
	new_wsi->rxflow_change_to = LWS_RXFLOW_ALLOW;

	/* intialize the instance struct */

	new_wsi->state = LWSS_HTTP;
	new_wsi->mode = LWSCM_HTTP_SERVING;
	new_wsi->hdr_parsing_completed = 0;

#ifdef LWS_OPENSSL_SUPPORT
	new_wsi->use_ssl = LWS_SSL_ENABLED(vhost);
#endif

	/*
	 * these can only be set once the protocol is known
	 * we set an unestablished connection's protocol pointer
	 * to the start of the supported list, so it can look
	 * for matching ones during the handshake
	 */
	new_wsi->protocol = vhost->protocols;
	new_wsi->user_space = NULL;
	new_wsi->ietf_spec_revision = 0;
	new_wsi->sock = LWS_SOCK_INVALID;
	vhost->context->count_wsi_allocated++;

	/*
	 * outermost create notification for wsi
	 * no user_space because no protocol selection
	 */
	vhost->protocols[0].callback(new_wsi, LWS_CALLBACK_WSI_CREATE,
				       NULL, NULL, 0);

	return new_wsi;
}

/**
 * lws_http_transaction_completed() - wait for new http transaction or close
 * @wsi:	websocket connection
 *
 *	Returns 1 if the HTTP connection must close now
 *	Returns 0 and resets connection to wait for new HTTP header /
 *	  transaction if possible
 */

LWS_VISIBLE int LWS_WARN_UNUSED_RESULT
lws_http_transaction_completed(struct lws *wsi)
{
	int n = NO_PENDING_TIMEOUT;

	lws_access_log(wsi);

	lwsl_debug("%s: wsi %p\n", __func__, wsi);
	/* if we can't go back to accept new headers, drop the connection */
	if (wsi->u.http.connection_type != HTTP_CONNECTION_KEEP_ALIVE) {
		lwsl_info("%s: %p: close connection\n", __func__, wsi);
		return 1;
	}

	/* otherwise set ourselves up ready to go again */
	wsi->state = LWSS_HTTP;
	wsi->mode = LWSCM_HTTP_SERVING;
	wsi->u.http.content_length = 0;
	wsi->hdr_parsing_completed = 0;
#ifdef LWS_WITH_ACCESS_LOG
	wsi->access_log.sent = 0;
#endif

	if (wsi->vhost->keepalive_timeout)
		n = PENDING_TIMEOUT_HTTP_KEEPALIVE_IDLE;
	lws_set_timeout(wsi, n, wsi->vhost->keepalive_timeout);

	/*
	 * We already know we are on http1.1 / keepalive and the next thing
	 * coming will be another header set.
	 *
	 * If there is no pending rx and we still have the ah, drop it and
	 * reacquire a new ah when the new headers start to arrive.  (Otherwise
	 * we needlessly hog an ah indefinitely.)
	 *
	 * However if there is pending rx and we know from the keepalive state
	 * that is already at least the start of another header set, simply
	 * reset the existing header table and keep it.
	 */
	if (wsi->u.hdr.ah) {
		lwsl_info("%s: wsi->more_rx_waiting=%d\n", __func__,
				wsi->more_rx_waiting);

		if (!wsi->more_rx_waiting) {
			wsi->u.hdr.ah->rxpos = wsi->u.hdr.ah->rxlen;
			lws_header_table_detach(wsi, 1);
		} else
			lws_header_table_reset(wsi, 1);
	}

	/* If we're (re)starting on headers, need other implied init */
	wsi->u.hdr.ues = URIES_IDLE;

	lwsl_info("%s: %p: keep-alive await new transaction\n", __func__, wsi);

	return 0;
}

static struct lws *
lws_adopt_socket_vhost(struct lws_vhost *vh, lws_sockfd_type accept_fd)
{
	struct lws_context *context = vh->context;
	struct lws *new_wsi = lws_create_new_server_wsi(vh);

	if (!new_wsi) {
		compatible_close(accept_fd);
		return NULL;
	}

	lwsl_info("%s: new wsi %p, sockfd %d\n", __func__, new_wsi, accept_fd);

	new_wsi->sock = accept_fd;

	/* the transport is accepted... give him time to negotiate */
	lws_set_timeout(new_wsi, PENDING_TIMEOUT_ESTABLISH_WITH_SERVER,
			context->timeout_secs);

#if LWS_POSIX == 0
	mbed3_tcp_stream_accept(accept_fd, new_wsi);
#endif

	/*
	 * A new connection was accepted. Give the user a chance to
	 * set properties of the newly created wsi. There's no protocol
	 * selected yet so we issue this to protocols[0]
	 */
	if ((context->vhost_list->protocols[0].callback)(new_wsi,
	     LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED, NULL, NULL, 0)) {
		/* force us off the timeout list by hand */
		lws_set_timeout(new_wsi, NO_PENDING_TIMEOUT, 0);
		compatible_close(new_wsi->sock);
		lws_free(new_wsi);
		return NULL;
	}

	lws_libev_accept(new_wsi, new_wsi->sock);
	lws_libuv_accept(new_wsi, new_wsi->sock);

	if (!LWS_SSL_ENABLED(new_wsi->vhost)) {
		if (insert_wsi_socket_into_fds(context, new_wsi)) {
			lwsl_err("%s: fail inserting socket\n", __func__);
			goto fail;
		}
	} else {
		new_wsi->mode = LWSCM_SSL_INIT;
		if (lws_server_socket_service_ssl(new_wsi, accept_fd)) {
			lwsl_err("%s: fail ssl negotiation\n", __func__);
			goto fail;
		}
	}

	if (!lws_header_table_attach(new_wsi, 0))
		lwsl_debug("Attached ah immediately\n");

	return new_wsi;

fail:
	lws_close_free_wsi(new_wsi, LWS_CLOSE_STATUS_NOSTATUS);

	return NULL;
}

/**
 * lws_adopt_socket() - adopt foreign socket as if listen socket accepted it
 * @context: lws context
 * @accept_fd: fd of already-accepted socket to adopt
 *
 * Either returns new wsi bound to accept_fd, or closes accept_fd and
 * returns NULL, having cleaned up any new wsi pieces.
 *
 * LWS adopts the socket in http serving mode, it's ready to accept an upgrade
 * to ws or just serve http.
 */

LWS_VISIBLE struct lws *
lws_adopt_socket(struct lws_context *context, lws_sockfd_type accept_fd)
{
	return lws_adopt_socket_vhost(context->vhost_list, accept_fd);
}


/**
 * lws_adopt_socket_readbuf() - adopt foreign socket and first rx as if listen socket accepted it
 * @context:	lws context
 * @accept_fd:	fd of already-accepted socket to adopt
 * @readbuf:	NULL or pointer to data that must be drained before reading from
 *		accept_fd
 * @len:	The length of the data held at @readbuf
 *
 * Either returns new wsi bound to accept_fd, or closes accept_fd and
 * returns NULL, having cleaned up any new wsi pieces.
 *
 * LWS adopts the socket in http serving mode, it's ready to accept an upgrade
 * to ws or just serve http.
 *
 * If your external code did not already read from the socket, you can use
 * lws_adopt_socket() instead.
 *
 * This api is guaranteed to use the data at @readbuf first, before reading from
 * the socket.
 *
 * @readbuf is limited to the size of the ah rx buf, currently 2048 bytes.
 */

LWS_VISIBLE LWS_EXTERN struct lws *
lws_adopt_socket_readbuf(struct lws_context *context, lws_sockfd_type accept_fd,
			 const char *readbuf, size_t len)
{
	struct lws *wsi = lws_adopt_socket(context, accept_fd);
	struct lws_context_per_thread *pt;
	struct allocated_headers *ah;
	struct lws_pollfd *pfd;

	if (!wsi)
		return NULL;

	if (!readbuf)
		return wsi;

	if (len > sizeof(ah->rx)) {
		lwsl_err("%s: rx in too big\n", __func__);
		goto bail;
	}
	/*
	 * we can't process the initial read data until we can attach an ah.
	 *
	 * if one is available, get it and place the data in his ah rxbuf...
	 * wsi with ah that have pending rxbuf get auto-POLLIN service.
	 *
	 * no autoservice because we didn't get a chance to attach the
	 * readbuf data to wsi or ah yet, and we will do it next if we get
	 * the ah.
	 */
	if (wsi->u.hdr.ah || !lws_header_table_attach(wsi, 0)) {
		ah = wsi->u.hdr.ah;
		memcpy(ah->rx, readbuf, len);
		ah->rxpos = 0;
		ah->rxlen = len;

		lwsl_notice("%s: calling service on readbuf ah\n", __func__);
		pt = &context->pt[(int)wsi->tsi];

		/* unlike a normal connect, we have the headers already
		 * (or the first part of them anyway).
		 * libuv won't come back and service us without a network
		 * event, so we need to do the header service right here.
		 */
		pfd = &pt->fds[wsi->position_in_fds_table];
		pfd->revents |= LWS_POLLIN;
		lwsl_err("%s: calling service\n", __func__);
		if (lws_service_fd_tsi(context, pfd, wsi->tsi))
			/* service closed us */
			return NULL;

		return wsi;
	}
	lwsl_err("%s: deferring handling ah\n", __func__);
	/*
	 * hum if no ah came, we are on the wait list and must defer
	 * dealing with this until the ah arrives.
	 *
	 * later successful lws_header_table_attach() will apply the
	 * below to the rx buffer (via lws_header_table_reset()).
	 */
	wsi->u.hdr.preamble_rx = lws_malloc(len);
	if (!wsi->u.hdr.preamble_rx) {
		lwsl_err("OOM\n");
		goto bail;
	}
	memcpy(wsi->u.hdr.preamble_rx, readbuf, len);
	wsi->u.hdr.preamble_rx_len = len;

	return wsi;

bail:
	lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS);

	return NULL;
}

LWS_VISIBLE int
lws_server_socket_service(struct lws_context *context, struct lws *wsi,
			  struct lws_pollfd *pollfd)
{
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	lws_sockfd_type accept_fd = LWS_SOCK_INVALID;
	struct allocated_headers *ah;
#if LWS_POSIX
	struct sockaddr_in cli_addr;
	socklen_t clilen;
#endif
	int n, len;

	switch (wsi->mode) {

	case LWSCM_HTTP_SERVING:
	case LWSCM_HTTP_SERVING_ACCEPTED:
	case LWSCM_HTTP2_SERVING:

		/* handle http headers coming in */

		/* pending truncated sends have uber priority */

		if (wsi->trunc_len) {
			if (!(pollfd->revents & LWS_POLLOUT))
				break;

			if (lws_issue_raw(wsi, wsi->trunc_alloc +
					       wsi->trunc_offset,
					  wsi->trunc_len) < 0)
				goto fail;
			/*
			 * we can't afford to allow input processing to send
			 * something new, so spin around he event loop until
			 * he doesn't have any partials
			 */
			break;
		}

		/* any incoming data ready? */

		if (!(pollfd->revents & pollfd->events & LWS_POLLIN))
			goto try_pollout;

		/*
		 * If we previously just did POLLIN when IN and OUT were
		 * signalled (because POLLIN processing may have used up
		 * the POLLOUT), don't let that happen twice in a row...
		 * next time we see the situation favour POLLOUT
		 */

		if (wsi->favoured_pollin &&
		    (pollfd->revents & pollfd->events & LWS_POLLOUT)) {
			wsi->favoured_pollin = 0;
			goto try_pollout;
		}

		/* these states imply we MUST have an ah attached */

		if (wsi->state == LWSS_HTTP ||
		    wsi->state == LWSS_HTTP_ISSUING_FILE ||
		    wsi->state == LWSS_HTTP_HEADERS) {
			if (!wsi->u.hdr.ah)
				/* no autoservice beacuse we will do it next */
				if (lws_header_table_attach(wsi, 0))
					goto try_pollout;

			ah = wsi->u.hdr.ah;

			lwsl_debug("%s: %p: rxpos:%d rxlen:%d\n", __func__, wsi,
				   ah->rxpos, ah->rxlen);

			/* if nothing in ah rx buffer, get some fresh rx */
			if (ah->rxpos == ah->rxlen) {
				ah->rxlen = lws_ssl_capable_read(wsi, ah->rx,
						   sizeof(ah->rx));
				ah->rxpos = 0;
				lwsl_debug("%s: wsi %p, ah->rxlen = %d\r\n",
					   __func__, wsi, ah->rxlen);
				switch (ah->rxlen) {
				case 0:
					lwsl_info("%s: read 0 len\n", __func__);
					/* lwsl_info("   state=%d\n", wsi->state); */
//					if (!wsi->hdr_parsing_completed)
//						lws_header_table_detach(wsi);
					/* fallthru */
				case LWS_SSL_CAPABLE_ERROR:
					goto fail;
				case LWS_SSL_CAPABLE_MORE_SERVICE:
					ah->rxlen = ah->rxpos = 0;
					goto try_pollout;
				}
			}
			if (!(ah->rxpos != ah->rxlen && ah->rxlen)) {
				lwsl_err("%s: assert: rxpos %d, rxlen %d\n",
					 __func__, ah->rxpos, ah->rxlen);

				assert(0);
			}
			/* just ignore incoming if waiting for close */
			if (wsi->state != LWSS_FLUSHING_STORED_SEND_BEFORE_CLOSE) {
				n = lws_read(wsi, ah->rx + ah->rxpos,
					     ah->rxlen - ah->rxpos);
				if (n < 0) /* we closed wsi */
					return 1;
				if (wsi->u.hdr.ah) {
					if ( wsi->u.hdr.ah->rxlen)
						 wsi->u.hdr.ah->rxpos += n;

					if (wsi->u.hdr.ah->rxpos == wsi->u.hdr.ah->rxlen &&
					    (wsi->mode != LWSCM_HTTP_SERVING &&
					     wsi->mode != LWSCM_HTTP_SERVING_ACCEPTED &&
					     wsi->mode != LWSCM_HTTP2_SERVING))
						lws_header_table_detach(wsi, 1);
				}
				break;
			}

			goto try_pollout;
		}

		len = lws_ssl_capable_read(wsi, pt->serv_buf,
					   LWS_MAX_SOCKET_IO_BUF);
		lwsl_debug("%s: wsi %p read %d\r\n", __func__, wsi, len);
		switch (len) {
		case 0:
			lwsl_info("%s: read 0 len\n", __func__);
			/* lwsl_info("   state=%d\n", wsi->state); */
//			if (!wsi->hdr_parsing_completed)
//				lws_header_table_detach(wsi);
			/* fallthru */
		case LWS_SSL_CAPABLE_ERROR:
			goto fail;
		case LWS_SSL_CAPABLE_MORE_SERVICE:
			goto try_pollout;
		}

		/* just ignore incoming if waiting for close */
		if (wsi->state != LWSS_FLUSHING_STORED_SEND_BEFORE_CLOSE) {
			/*
			 * this may want to send
			 * (via HTTP callback for example)
			 */
			n = lws_read(wsi, pt->serv_buf, len);
			if (n < 0) /* we closed wsi */
				return 1;
			/*
			 *  he may have used up the
			 * writability above, if we will defer POLLOUT
			 * processing in favour of POLLIN, note it
			 */
			if (pollfd->revents & LWS_POLLOUT)
				wsi->favoured_pollin = 1;
			break;
		}

try_pollout:
		/* this handles POLLOUT for http serving fragments */

		if (!(pollfd->revents & LWS_POLLOUT))
			break;

		/* one shot */
		if (lws_change_pollfd(wsi, LWS_POLLOUT, 0)) {
			lwsl_notice("%s a\n", __func__);
			goto fail;
		}

		if (!wsi->hdr_parsing_completed)
			break;

		if (wsi->state != LWSS_HTTP_ISSUING_FILE) {
			n = user_callback_handle_rxflow(wsi->protocol->callback,
					wsi, LWS_CALLBACK_HTTP_WRITEABLE,
					wsi->user_space, NULL, 0);
			if (n < 0) {
				lwsl_info("writeable_fail\n");
				goto fail;
			}
			break;
		}

		/* >0 == completion, <0 == error */
		n = lws_serve_http_file_fragment(wsi);
		if (n < 0 || (n > 0 && lws_http_transaction_completed(wsi))) {
			lwsl_info("completed\n");
			goto fail;
		}
		break;

	case LWSCM_SERVER_LISTENER:

#if LWS_POSIX
		/* pollin means a client has connected to us then */

		do {
			if (!(pollfd->revents & LWS_POLLIN) || !(pollfd->events & LWS_POLLIN))
				break;

			/* listen socket got an unencrypted connection... */

			clilen = sizeof(cli_addr);
			lws_latency_pre(context, wsi);
			accept_fd  = accept(pollfd->fd, (struct sockaddr *)&cli_addr,
					    &clilen);
			lws_latency(context, wsi, "listener accept", accept_fd,
				    accept_fd >= 0);
			if (accept_fd < 0) {
				if (LWS_ERRNO == LWS_EAGAIN ||
				    LWS_ERRNO == LWS_EWOULDBLOCK) {
					lwsl_err("accept asks to try again\n");
					break;
				}
				lwsl_err("ERROR on accept: %s\n", strerror(LWS_ERRNO));
				break;
			}

			lws_plat_set_socket_options(wsi->vhost, accept_fd);

			lwsl_debug("accepted new conn  port %u on fd=%d\n",
					  ntohs(cli_addr.sin_port), accept_fd);

#else
			/* not very beautiful... */
			accept_fd = (lws_sockfd_type)pollfd;
#endif
			/*
			 * look at who we connected to and give user code a chance
			 * to reject based on client IP.  There's no protocol selected
			 * yet so we issue this to protocols[0]
			 */
			if ((wsi->vhost->protocols[0].callback)(wsi,
					LWS_CALLBACK_FILTER_NETWORK_CONNECTION,
					NULL, (void *)(long)accept_fd, 0)) {
				lwsl_debug("Callback denied network connection\n");
				compatible_close(accept_fd);
				break;
			}

			if (!lws_adopt_socket_vhost(wsi->vhost, accept_fd))
				/* already closed cleanly as necessary */
				return 1;

#if LWS_POSIX
		} while (pt->fds_count < context->fd_limit_per_thread - 1 &&
			 lws_poll_listen_fd(&pt->fds[wsi->position_in_fds_table]) > 0);
#endif
		return 0;

	default:
		break;
	}

	if (!lws_server_socket_service_ssl(wsi, accept_fd))
		return 0;

fail:
	lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS);

	return 1;
}

/**
 * lws_serve_http_file() - Send a file back to the client using http
 * @wsi:		Websocket instance (available from user callback)
 * @file:		The file to issue over http
 * @content_type:	The http content type, eg, text/html
 * @other_headers:	NULL or pointer to header string
 * @other_headers_len:	length of the other headers if non-NULL
 *
 *	This function is intended to be called from the callback in response
 *	to http requests from the client.  It allows the callback to issue
 *	local files down the http link in a single step.
 *
 *	Returning <0 indicates error and the wsi should be closed.  Returning
 *	>0 indicates the file was completely sent and
 *	lws_http_transaction_completed() called on the wsi (and close if != 0)
 *	==0 indicates the file transfer is started and needs more service later,
 *	the wsi should be left alone.
 */

LWS_VISIBLE int
lws_serve_http_file(struct lws *wsi, const char *file, const char *content_type,
		    const char *other_headers, int other_headers_len)
{
	static const char * const intermediates[] = { "private", "public" };
	struct lws_context *context = lws_get_context(wsi);
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	char cache_control[50], *cc = "no-store";
	unsigned char *response = pt->serv_buf + LWS_PRE;
	unsigned char *p = response;
	unsigned char *end = p + LWS_MAX_SOCKET_IO_BUF - LWS_PRE;
	int ret = 0, cclen = 8;

	wsi->u.http.fd = lws_plat_file_open(wsi, file, &wsi->u.http.filelen,
					    O_RDONLY);

	if (wsi->u.http.fd == LWS_INVALID_FILE) {
		lwsl_err("Unable to open '%s'\n", file);
		lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND, NULL);

		return -1;
	}

	if (lws_add_http_header_status(wsi, 200, &p, end))
		return -1;
	if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE,
					 (unsigned char *)content_type,
					 strlen(content_type), &p, end))
		return -1;
	if (lws_add_http_header_content_length(wsi, wsi->u.http.filelen, &p, end))
		return -1;

	if (wsi->cache_secs && wsi->cache_reuse) {
		if (wsi->cache_revalidate) {
			cc = cache_control;
			cclen = sprintf(cache_control, "%s max-age: %u",
				    intermediates[wsi->cache_intermediaries],
				    wsi->cache_secs);
		} else {
			cc = "no-cache";
			cclen = 8;
		}
	}

	if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CACHE_CONTROL,
			(unsigned char *)cc, cclen, &p, end))
		return -1;

	if (other_headers) {
		if ((end - p) < other_headers_len)
			return -1;
		memcpy(p, other_headers, other_headers_len);
		p += other_headers_len;
	}

	if (lws_finalize_http_header(wsi, &p, end))
		return -1;

	ret = lws_write(wsi, response, p - response, LWS_WRITE_HTTP_HEADERS);
	if (ret != (p - response)) {
		lwsl_err("_write returned %d from %d\n", ret, (p - response));
		return -1;
	}

	wsi->u.http.filepos = 0;
	wsi->state = LWSS_HTTP_ISSUING_FILE;

	return lws_serve_http_file_fragment(wsi);
}

int
lws_interpret_incoming_packet(struct lws *wsi, unsigned char **buf, size_t len)
{
	int m;

	lwsl_parser("%s: received %d byte packet\n", __func__, (int)len);
#if 0
	lwsl_hexdump(*buf, len);
#endif

	/* let the rx protocol state machine have as much as it needs */

	while (len) {
		/*
		 * we were accepting input but now we stopped doing so
		 */
		if (!(wsi->rxflow_change_to & LWS_RXFLOW_ALLOW)) {
			lws_rxflow_cache(wsi, *buf, 0, len);
			lwsl_parser("%s: cached %d\n", __func__, len);
			return 1;
		}

		if (wsi->u.ws.rx_draining_ext) {
			m = lws_rx_sm(wsi, 0);
			if (m < 0)
				return -1;
			continue;
		}

		/* account for what we're using in rxflow buffer */
		if (wsi->rxflow_buffer)
			wsi->rxflow_pos++;

		/* consume payload bytes efficiently */
		if (wsi->lws_rx_parse_state ==
		    LWS_RXPS_PAYLOAD_UNTIL_LENGTH_EXHAUSTED) {
			m = lws_payload_until_length_exhausted(wsi, buf, &len);
			if (wsi->rxflow_buffer)
				wsi->rxflow_pos += m;
		}

		/* process the byte */
		m = lws_rx_sm(wsi, *(*buf)++);
		if (m < 0)
			return -1;
		len--;
	}

	lwsl_parser("%s: exit with %d unused\n", __func__, (int)len);

	return 0;
}

LWS_VISIBLE void
lws_server_get_canonical_hostname(struct lws_context *context,
				  struct lws_context_creation_info *info)
{
	if (lws_check_opt(info->options, LWS_SERVER_OPTION_SKIP_SERVER_CANONICAL_NAME))
		return;
#if LWS_POSIX
	/* find canonical hostname */
	gethostname((char *)context->canonical_hostname,
		    sizeof(context->canonical_hostname) - 1);

	lwsl_notice(" canonical_hostname = %s\n", context->canonical_hostname);
#else
	(void)context;
#endif
}
