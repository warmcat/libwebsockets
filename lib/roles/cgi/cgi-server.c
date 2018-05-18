/*
 * libwebsockets - CGI management
 *
 * Copyright (C) 2010-2017 Andy Green <andy@warmcat.com>
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

#include "core/private.h"

#if defined(WIN32) || defined(_WIN32)
#else
#include <sys/wait.h>
#endif

static const char *hex = "0123456789ABCDEF";

static int
urlencode(const char *in, int inlen, char *out, int outlen)
{
	char *start = out, *end = out + outlen;

	while (inlen-- && out < end - 4) {
		if ((*in >= 'A' && *in <= 'Z') ||
		    (*in >= 'a' && *in <= 'z') ||
		    (*in >= '0' && *in <= '9') ||
		    *in == '-' ||
		    *in == '_' ||
		    *in == '.' ||
		    *in == '~') {
			*out++ = *in++;
			continue;
		}
		if (*in == ' ') {
			*out++ = '+';
			in++;
			continue;
		}
		*out++ = '%';
		*out++ = hex[(*in) >> 4];
		*out++ = hex[(*in++) & 15];
	}
	*out = '\0';

	if (out >= end - 4)
		return -1;

	return out - start;
}

static struct lws *
lws_create_basic_wsi(struct lws_context *context, int tsi)
{
	struct lws *new_wsi;

	if (!context->vhost_list)
		return NULL;

	if ((unsigned int)context->pt[tsi].fds_count ==
	    context->fd_limit_per_thread - 1) {
		lwsl_err("no space for new conn\n");
		return NULL;
	}

	new_wsi = lws_zalloc(sizeof(struct lws), "new wsi");
	if (new_wsi == NULL) {
		lwsl_err("Out of memory for new connection\n");
		return NULL;
	}

	new_wsi->tsi = tsi;
	new_wsi->context = context;
	new_wsi->pending_timeout = NO_PENDING_TIMEOUT;
	new_wsi->rxflow_change_to = LWS_RXFLOW_ALLOW;

	/* initialize the instance struct */

	lws_role_transition(new_wsi, 0, LRS_ESTABLISHED, &role_ops_cgi);

	new_wsi->hdr_parsing_completed = 0;
	new_wsi->position_in_fds_table = LWS_NO_FDS_POS;

	/*
	 * these can only be set once the protocol is known
	 * we set an unestablished connection's protocol pointer
	 * to the start of the defauly vhost supported list, so it can look
	 * for matching ones during the handshake
	 */
	new_wsi->protocol = context->vhost_list->protocols;
	new_wsi->user_space = NULL;
	new_wsi->desc.sockfd = LWS_SOCK_INVALID;
	context->count_wsi_allocated++;

	return new_wsi;
}

LWS_VISIBLE LWS_EXTERN int
lws_cgi(struct lws *wsi, const char * const *exec_array, int script_uri_path_len,
	int timeout_secs, const struct lws_protocol_vhost_options *mp_cgienv)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];
	char *env_array[30], cgi_path[500], e[1024], *p = e,
	     *end = p + sizeof(e) - 1, tok[256], *t, *sum, *sumend;
	struct lws_cgi *cgi;
	int n, m = 0, i, uritok = -1, c;

	/*
	 * give the master wsi a cgi struct
	 */

	wsi->http.cgi = lws_zalloc(sizeof(*wsi->http.cgi), "new cgi");
	if (!wsi->http.cgi) {
		lwsl_err("%s: OOM\n", __func__);
		return -1;
	}

	wsi->http.cgi->response_code = HTTP_STATUS_OK;

	cgi = wsi->http.cgi;
	cgi->wsi = wsi; /* set cgi's owning wsi */
	sum = cgi->summary;
	sumend = sum + strlen(cgi->summary) - 1;

	/* create pipes for [stdin|stdout] and [stderr] */

	for (n = 0; n < 3; n++)
		if (pipe(cgi->pipe_fds[n]) == -1)
			goto bail1;

	/* create cgi wsis for each stdin/out/err fd */

	for (n = 0; n < 3; n++) {
		cgi->stdwsi[n] = lws_create_basic_wsi(wsi->context, wsi->tsi);
		if (!cgi->stdwsi[n])
			goto bail2;
		cgi->stdwsi[n]->cgi_channel = n;
		cgi->stdwsi[n]->vhost = wsi->vhost;

		lwsl_debug("%s: cgi %p: pipe fd %d -> fd %d / %d\n", __func__,
			   cgi->stdwsi[n], n, cgi->pipe_fds[n][!!(n == 0)],
			   cgi->pipe_fds[n][!(n == 0)]);

		/* read side is 0, stdin we want the write side, others read */
		cgi->stdwsi[n]->desc.sockfd = cgi->pipe_fds[n][!!(n == 0)];
		if (fcntl(cgi->pipe_fds[n][!!(n == 0)], F_SETFL,
		    O_NONBLOCK) < 0) {
			lwsl_err("%s: setting NONBLOCK failed\n", __func__);
			goto bail2;
		}
	}

	for (n = 0; n < 3; n++) {
		if (wsi->context->event_loop_ops->accept)
			wsi->context->event_loop_ops->accept(cgi->stdwsi[n]);

		if (__insert_wsi_socket_into_fds(wsi->context, cgi->stdwsi[n]))
			goto bail3;
		cgi->stdwsi[n]->parent = wsi;
		cgi->stdwsi[n]->sibling_list = wsi->child_list;
		wsi->child_list = cgi->stdwsi[n];
	}

	lws_change_pollfd(cgi->stdwsi[LWS_STDIN], LWS_POLLIN, LWS_POLLOUT);
	lws_change_pollfd(cgi->stdwsi[LWS_STDOUT], LWS_POLLOUT, LWS_POLLIN);
	lws_change_pollfd(cgi->stdwsi[LWS_STDERR], LWS_POLLOUT, LWS_POLLIN);

	lwsl_debug("%s: fds in %d, out %d, err %d\n", __func__,
		   cgi->stdwsi[LWS_STDIN]->desc.sockfd,
		   cgi->stdwsi[LWS_STDOUT]->desc.sockfd,
		   cgi->stdwsi[LWS_STDERR]->desc.sockfd);

	if (timeout_secs)
		lws_set_timeout(wsi, PENDING_TIMEOUT_CGI, timeout_secs);

	/* the cgi stdout is always sending us http1.x header data first */
	wsi->hdr_state = LCHS_HEADER;

	/* add us to the pt list of active cgis */
	lwsl_debug("%s: adding cgi %p to list\n", __func__, wsi->http.cgi);
	cgi->cgi_list = pt->http.cgi_list;
	pt->http.cgi_list = cgi;

	sum += lws_snprintf(sum, sumend - sum, "%s ", exec_array[0]);

	/* prepare his CGI env */

	n = 0;

	if (lws_is_ssl(wsi))
		env_array[n++] = "HTTPS=ON";
	if (wsi->http.ah) {
		static const unsigned char meths[] = {
			WSI_TOKEN_GET_URI,
			WSI_TOKEN_POST_URI,
			WSI_TOKEN_OPTIONS_URI,
			WSI_TOKEN_PUT_URI,
			WSI_TOKEN_PATCH_URI,
			WSI_TOKEN_DELETE_URI,
			WSI_TOKEN_CONNECT,
			WSI_TOKEN_HEAD_URI,
		#ifdef LWS_WITH_HTTP2
			WSI_TOKEN_HTTP_COLON_PATH,
		#endif
		};
		static const char * const meth_names[] = {
			"GET", "POST", "OPTIONS", "PUT", "PATCH", "DELETE",
			"CONNECT", "HEAD", ":path"
		};

		if (script_uri_path_len >= 0)
			for (m = 0; m < (int)ARRAY_SIZE(meths); m++)
				if (lws_hdr_total_length(wsi, meths[m]) >=
						script_uri_path_len) {
					uritok = meths[m];
					break;
				}

		if (script_uri_path_len < 0 && uritok < 0)
			goto bail3;
//		if (script_uri_path_len < 0)
//			uritok = 0;

		if (m >= 0) {
			env_array[n++] = p;
			if (m < 8) {
				p += lws_snprintf(p, end - p,
						  "REQUEST_METHOD=%s",
						  meth_names[m]);
				sum += lws_snprintf(sum, sumend - sum, "%s ",
						    meth_names[m]);
			} else {
				p += lws_snprintf(p, end - p,
						  "REQUEST_METHOD=%s",
			  lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP_COLON_METHOD));
				sum += lws_snprintf(sum, sumend - sum, "%s ",
					lws_hdr_simple_ptr(wsi,
						  WSI_TOKEN_HTTP_COLON_METHOD));
			}
			p++;
		}

		if (uritok >= 0)
			sum += lws_snprintf(sum, sumend - sum, "%s ",
					    lws_hdr_simple_ptr(wsi, uritok));

		env_array[n++] = p;
		p += lws_snprintf(p, end - p, "QUERY_STRING=");
		/* dump the individual URI Arg parameters */
		m = 0;
		while (script_uri_path_len >= 0) {
			i = lws_hdr_copy_fragment(wsi, tok, sizeof(tok),
					     WSI_TOKEN_HTTP_URI_ARGS, m);
			if (i < 0)
				break;
			t = tok;
			while (*t && *t != '=' && p < end - 4)
				*p++ = *t++;
			if (*t == '=')
				*p++ = *t++;
			i = urlencode(t, i- (t - tok), p, end - p);
			if (i > 0) {
				p += i;
				*p++ = '&';
			}
			m++;
		}
		if (m)
			p--;
		*p++ = '\0';

		if (uritok >= 0) {
			strcpy(cgi_path, "REQUEST_URI=");
			c = lws_hdr_copy(wsi, cgi_path + 12,
					 sizeof(cgi_path) - 12, uritok);
			if (c < 0)
				goto bail3;

			cgi_path[sizeof(cgi_path) - 1] = '\0';
			env_array[n++] = cgi_path;
		}

		sum += lws_snprintf(sum, sumend - sum, "%s", env_array[n - 1]);

		if (script_uri_path_len >= 0) {
			env_array[n++] = p;
			p += lws_snprintf(p, end - p, "PATH_INFO=%s",
				      cgi_path + 12 + script_uri_path_len);
			p++;
		}
	}
	if (script_uri_path_len >= 0 &&
	    lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_REFERER)) {
		env_array[n++] = p;
		p += lws_snprintf(p, end - p, "HTTP_REFERER=%s",
			      lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP_REFERER));
		p++;
	}
	if (script_uri_path_len >= 0 &&
	    lws_hdr_total_length(wsi, WSI_TOKEN_HOST)) {
		env_array[n++] = p;
		p += lws_snprintf(p, end - p, "HTTP_HOST=%s",
			      lws_hdr_simple_ptr(wsi, WSI_TOKEN_HOST));
		p++;
	}
	if (script_uri_path_len >= 0 &&
	    lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_COOKIE)) {
		env_array[n++] = p;
		p += lws_snprintf(p, end - p, "HTTP_COOKIE=");
		m = lws_hdr_copy(wsi, p, end - p, WSI_TOKEN_HTTP_COOKIE);
		if (m > 0)
			p += lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_COOKIE);
		*p++ = '\0';
	}
	if (script_uri_path_len >= 0 &&
	    lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_USER_AGENT)) {
		env_array[n++] = p;
		p += lws_snprintf(p, end - p, "USER_AGENT=%s",
			    lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP_USER_AGENT));
		p++;
	}
	if (script_uri_path_len >= 0 &&
	    uritok == WSI_TOKEN_POST_URI) {
		if (lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE)) {
			env_array[n++] = p;
			p += lws_snprintf(p, end - p, "CONTENT_TYPE=%s",
			  lws_hdr_simple_ptr(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE));
			p++;
		}
		if (lws_hdr_total_length(wsi, WSI_TOKEN_HTTP_CONTENT_LENGTH)) {
			env_array[n++] = p;
			p += lws_snprintf(p, end - p, "CONTENT_LENGTH=%s",
					  lws_hdr_simple_ptr(wsi,
					  WSI_TOKEN_HTTP_CONTENT_LENGTH));
			p++;
		}
	}
	env_array[n++] = "PATH=/bin:/usr/bin:/usr/local/bin:/var/www/cgi-bin";

	env_array[n++] = p;
	p += lws_snprintf(p, end - p, "SCRIPT_PATH=%s", exec_array[0]) + 1;

	while (mp_cgienv) {
		env_array[n++] = p;
		p += lws_snprintf(p, end - p, "%s=%s", mp_cgienv->name,
			      mp_cgienv->value);
		lwsl_info("   Applying mount-specific cgi env '%s'\n",
			   env_array[n - 1]);
		p++;
		mp_cgienv = mp_cgienv->next;
	}

	env_array[n++] = "SERVER_SOFTWARE=libwebsockets";
	env_array[n] = NULL;

#if 0
	for (m = 0; m < n; m++)
		lwsl_info("    %s\n", env_array[m]);
#endif

	/*
	 * Actually having made the env, as a cgi we don't need the ah
	 * any more
	 */
	if (script_uri_path_len >= 0)
		lws_header_table_detach(wsi, 0);

	/* we are ready with the redirection pipes... run the thing */
#if !defined(LWS_HAVE_VFORK) || !defined(LWS_HAVE_EXECVPE)
	cgi->pid = fork();
#else
	cgi->pid = vfork();
#endif
	if (cgi->pid < 0) {
		lwsl_err("fork failed, errno %d", errno);
		goto bail3;
	}

#if defined(__linux__)
	prctl(PR_SET_PDEATHSIG, SIGTERM);
#endif
	if (script_uri_path_len >= 0)
		/* stops non-daemonized main processess getting SIGINT
		 * from TTY */
		setpgrp();

	if (cgi->pid) {
		/* we are the parent process */
		wsi->context->count_cgi_spawned++;
		lwsl_debug("%s: cgi %p spawned PID %d\n", __func__,
			   cgi, cgi->pid);

		for (n = 0; n < 3; n++)
			close(cgi->pipe_fds[n][!(n == 0)]);

		/* inform cgi owner of the child PID */
		n = user_callback_handle_rxflow(wsi->protocol->callback, wsi,
					    LWS_CALLBACK_CGI_PROCESS_ATTACH,
					    wsi->user_space, NULL, cgi->pid);
		(void)n;

		return 0;
	}

	/* somewhere we can at least read things and enter it */
	if (chdir("/tmp"))
		lwsl_notice("%s: Failed to chdir\n", __func__);

	/* We are the forked process, redirect and kill inherited things.
	 *
	 * Because of vfork(), we cannot do anything that changes pages in
	 * the parent environment.  Stuff that changes kernel state for the
	 * process is OK.  Stuff that happens after the execvpe() is OK.
	 */

	for (n = 0; n < 3; n++) {
		if (dup2(cgi->pipe_fds[n][!(n == 0)], n) < 0) {
			lwsl_err("%s: stdin dup2 failed\n", __func__);
			goto bail3;
		}
		close(cgi->pipe_fds[n][!(n == 0)]);
	}

#if !defined(LWS_HAVE_VFORK) || !defined(LWS_HAVE_EXECVPE)
	for (m = 0; m < n; m++) {
		p = strchr(env_array[m], '=');
		*p++ = '\0';
		setenv(env_array[m], p, 1);
	}
	execvp(exec_array[0], (char * const *)&exec_array[0]);
#else
	execvpe(exec_array[0], (char * const *)&exec_array[0], &env_array[0]);
#endif

	exit(1);

bail3:
	/* drop us from the pt cgi list */
	pt->http.cgi_list = cgi->cgi_list;

	while (--n >= 0)
		__remove_wsi_socket_from_fds(wsi->http.cgi->stdwsi[n]);
bail2:
	for (n = 0; n < 3; n++)
		if (wsi->http.cgi->stdwsi[n])
			__lws_free_wsi(cgi->stdwsi[n]);

bail1:
	for (n = 0; n < 3; n++) {
		if (cgi->pipe_fds[n][0])
			close(cgi->pipe_fds[n][0]);
		if (cgi->pipe_fds[n][1])
			close(cgi->pipe_fds[n][1]);
	}

	lws_free_set_NULL(wsi->http.cgi);

	lwsl_err("%s: failed\n", __func__);

	return -1;
}

/* we have to parse out these headers in the CGI output */

static const char * const significant_hdr[SIGNIFICANT_HDR_COUNT] = {
	"content-length: ",
	"location: ",
	"status: ",
	"transfer-encoding: chunked",
};

enum header_recode {
	HR_NAME,
	HR_WHITESPACE,
	HR_ARG,
	HR_CRLF,
};

LWS_VISIBLE LWS_EXTERN int
lws_cgi_write_split_stdout_headers(struct lws *wsi)
{
	int n, m, cmd;
	unsigned char buf[LWS_PRE + 1024], *start = &buf[LWS_PRE], *p = start,
			*end = &buf[sizeof(buf) - 1 - LWS_PRE], *name,
			*value = NULL;
	char c, hrs;

	if (!wsi->http.cgi)
		return -1;

	while (wsi->hdr_state != LHCS_PAYLOAD) {
		/*
		 * We have to separate header / finalize and payload chunks,
		 * since they need to be handled separately
		 */
		switch (wsi->hdr_state) {
		case LHCS_RESPONSE:
			lwsl_debug("LHCS_RESPONSE: issuing response %d\n",
				   wsi->http.cgi->response_code);
			if (lws_add_http_header_status(wsi,
						       wsi->http.cgi->response_code,
						       &p, end))
				return 1;
			if (!wsi->http.cgi->explicitly_chunked &&
			    !wsi->http.cgi->content_length &&
				lws_add_http_header_by_token(wsi,
					WSI_TOKEN_HTTP_TRANSFER_ENCODING,
					(unsigned char *)"chunked", 7, &p, end))
				return 1;
			if (!(wsi->http2_substream))
				if (lws_add_http_header_by_token(wsi,
						WSI_TOKEN_CONNECTION,
						(unsigned char *)"close", 5,
						&p, end))
					return 1;
			n = lws_write(wsi, start, p - start,
				      LWS_WRITE_HTTP_HEADERS | LWS_WRITE_NO_FIN);

			/*
			 * so we have a bunch of http/1 style ascii headers
			 * starting from wsi->http.cgi->headers_buf through
			 * wsi->http.cgi->headers_pos.  These are OK for http/1
			 * connections, but they're no good for http/2 conns.
			 *
			 * Let's redo them at headers_pos forward using the
			 * correct coding for http/1 or http/2
			 */
			if (!wsi->http2_substream)
				goto post_hpack_recode;

			p = wsi->http.cgi->headers_start;
			wsi->http.cgi->headers_start = wsi->http.cgi->headers_pos;
			wsi->http.cgi->headers_dumped = wsi->http.cgi->headers_start;
			hrs = HR_NAME;
			name = buf;

			while (p < wsi->http.cgi->headers_start) {
				switch (hrs) {
				case HR_NAME:
					/*
					 * in http/2 upper-case header names
					 * are illegal.  So convert to lower-
					 * case.
					 */
					if (name - buf > 64)
						return -1;
					if (*p != ':') {
						if (*p >= 'A' && *p <= 'Z')
							*name++ = (*p++) +
								  ('a' - 'A');
						else
							*name++ = *p++;
					} else {
						p++;
						*name++ = '\0';
						value = name;
						hrs = HR_WHITESPACE;
					}
					break;
				case HR_WHITESPACE:
					if (*p == ' ') {
						p++;
						break;
					}
					hrs = HR_ARG;
					/* fallthru */
				case HR_ARG:
					if (name > end - 64)
						return -1;

					if (*p != '\x0a' && *p != '\x0d') {
						*name++ = *p++;
						break;
					}
					hrs = HR_CRLF;
					/* fallthru */
				case HR_CRLF:
					if ((*p != '\x0a' && *p != '\x0d') ||
					    p + 1 == wsi->http.cgi->headers_start) {
						*name = '\0';
						if ((strcmp((const char *)buf,
							    "transfer-encoding")
						)) {
							lwsl_debug("+ %s: %s\n",
								   buf, value);
							if (
					lws_add_http_header_by_name(wsi, buf,
					(unsigned char *)value, name - value,
					(unsigned char **)&wsi->http.cgi->headers_pos,
					(unsigned char *)wsi->http.cgi->headers_end))
								return 1;
							hrs = HR_NAME;
							name = buf;
							break;
						}
					}
					p++;
					break;
				}
			}
post_hpack_recode:
			/* finalize cached headers before dumping them */
			if (lws_finalize_http_header(wsi,
				      (unsigned char **)&wsi->http.cgi->headers_pos,
				      (unsigned char *)wsi->http.cgi->headers_end)) {

				lwsl_notice("finalize failed\n");
				return -1;
			}

			wsi->hdr_state = LHCS_DUMP_HEADERS;
			wsi->reason_bf |= LWS_CB_REASON_AUX_BF__CGI_HEADERS;
			lws_callback_on_writable(wsi);
			/* back to the loop for writeability again */
			return 0;

		case LHCS_DUMP_HEADERS:

			n = wsi->http.cgi->headers_pos - wsi->http.cgi->headers_dumped;
			if (n > 512)
				n = 512;

			lwsl_debug("LHCS_DUMP_HEADERS: %d\n", n);

			cmd = LWS_WRITE_HTTP_HEADERS_CONTINUATION;
			if (wsi->http.cgi->headers_dumped + n !=
			    wsi->http.cgi->headers_pos) {
				lwsl_notice("adding no fin flag\n");
				cmd |= LWS_WRITE_NO_FIN;
			}

			m = lws_write(wsi,
				      (unsigned char *)wsi->http.cgi->headers_dumped,
				      n, cmd);
			if (m < 0) {
				lwsl_debug("%s: write says %d\n", __func__, m);
				return -1;
			}
			wsi->http.cgi->headers_dumped += n;
			if (wsi->http.cgi->headers_dumped == wsi->http.cgi->headers_pos) {
				wsi->hdr_state = LHCS_PAYLOAD;
				lws_free_set_NULL(wsi->http.cgi->headers_buf);
				lwsl_debug("freed cgi headers\n");
			} else {
				wsi->reason_bf |= LWS_CB_REASON_AUX_BF__CGI_HEADERS;
				lws_callback_on_writable(wsi);
			}

			/* writeability becomes uncertain now we wrote
			 * something, we must return to the event loop
			 */
			return 0;
		}

		if (!wsi->http.cgi->headers_buf) {
			/* if we don't already have a headers buf, cook one up */
			n = 2048;
			if (wsi->http2_substream)
				n = 4096;
			wsi->http.cgi->headers_buf = lws_malloc(n + LWS_PRE,
							   "cgi hdr buf");
			if (!wsi->http.cgi->headers_buf) {
				lwsl_err("OOM\n");
				return -1;
			}

			lwsl_debug("allocated cgi hdrs\n");
			wsi->http.cgi->headers_start = wsi->http.cgi->headers_buf + LWS_PRE;
			wsi->http.cgi->headers_pos = wsi->http.cgi->headers_start;
			wsi->http.cgi->headers_dumped = wsi->http.cgi->headers_pos;
			wsi->http.cgi->headers_end = wsi->http.cgi->headers_buf + n - 1;

			for (n = 0; n < SIGNIFICANT_HDR_COUNT; n++) {
				wsi->http.cgi->match[n] = 0;
				wsi->http.cgi->lp = 0;
			}
		}

		n = lws_get_socket_fd(wsi->http.cgi->stdwsi[LWS_STDOUT]);
		if (n < 0)
			return -1;
		n = read(n, &c, 1);
		if (n < 0) {
			if (errno != EAGAIN) {
				lwsl_debug("%s: read says %d\n", __func__, n);
				return -1;
			}
			else
				n = 0;

			if (wsi->http.cgi->headers_pos >= wsi->http.cgi->headers_end - 4) {
				lwsl_notice("CGI hdrs > buf size\n");

				return -1;
			}
		}
		if (!n)
			goto agin;

		lwsl_debug("-- 0x%02X %c %d %d\n", (unsigned char)c, c,
			   wsi->http.cgi->match[1], wsi->hdr_state);
		if (!c)
			return -1;
		switch (wsi->hdr_state) {
		case LCHS_HEADER:
			hdr:
			for (n = 0; n < SIGNIFICANT_HDR_COUNT; n++) {
				/*
				 * significant headers with
				 * numeric decimal payloads
				 */
				if (!significant_hdr[n][wsi->http.cgi->match[n]] &&
				    (c >= '0' && c <= '9') &&
				    wsi->http.cgi->lp < (int)sizeof(wsi->http.cgi->l) - 1) {
					wsi->http.cgi->l[wsi->http.cgi->lp++] = c;
					wsi->http.cgi->l[wsi->http.cgi->lp] = '\0';
					switch (n) {
					case SIGNIFICANT_HDR_CONTENT_LENGTH:
						wsi->http.cgi->content_length =
							atoll(wsi->http.cgi->l);
						break;
					case SIGNIFICANT_HDR_STATUS:
						wsi->http.cgi->response_code =
							atol(wsi->http.cgi->l);
						lwsl_debug("Status set to %d\n",
						   wsi->http.cgi->response_code);
						break;
					default:
						break;
					}
				}
				/* hits up to the NUL are sticky until next hdr */
				if (significant_hdr[n][wsi->http.cgi->match[n]]) {
					if (tolower(c) ==
					    significant_hdr[n][wsi->http.cgi->match[n]])
						wsi->http.cgi->match[n]++;
					else
						wsi->http.cgi->match[n] = 0;
				}
			}

			/* some cgi only send us \x0a for EOL */
			if (c == '\x0a') {
				wsi->hdr_state = LCHS_SINGLE_0A;
				*wsi->http.cgi->headers_pos++ = '\x0d';
			}
			*wsi->http.cgi->headers_pos++ = c;
			if (c == '\x0d')
				wsi->hdr_state = LCHS_LF1;

			if (wsi->hdr_state != LCHS_HEADER &&
			    !significant_hdr[SIGNIFICANT_HDR_TRANSFER_ENCODING]
				    [wsi->http.cgi->match[
					 SIGNIFICANT_HDR_TRANSFER_ENCODING]]) {
				lwsl_debug("cgi produced chunked\n");
				wsi->http.cgi->explicitly_chunked = 1;
			}

			/* presence of Location: mandates 302 retcode */
			if (wsi->hdr_state != LCHS_HEADER &&
			    !significant_hdr[SIGNIFICANT_HDR_LOCATION][
				     wsi->http.cgi->match[SIGNIFICANT_HDR_LOCATION]]) {
				lwsl_debug("CGI: Location hdr seen\n");
				wsi->http.cgi->response_code = 302;
			}

			break;
		case LCHS_LF1:
			*wsi->http.cgi->headers_pos++ = c;
			if (c == '\x0a') {
				wsi->hdr_state = LCHS_CR2;
				break;
			}
			/* we got \r[^\n]... it's unreasonable */
			lwsl_debug("%s: funny CRLF 0x%02X\n", __func__,
				   (unsigned char)c);
			return -1;

		case LCHS_CR2:
			if (c == '\x0d') {
				/* drop the \x0d */
				wsi->hdr_state = LCHS_LF2;
				break;
			}
			wsi->hdr_state = LCHS_HEADER;
			for (n = 0; n < SIGNIFICANT_HDR_COUNT; n++)
				wsi->http.cgi->match[n] = 0;
			wsi->http.cgi->lp = 0;
			goto hdr;

		case LCHS_LF2:
		case LCHS_SINGLE_0A:
			m = wsi->hdr_state;
			if (c == '\x0a') {
				lwsl_debug("Content-Length: %lld\n",
					(unsigned long long)
					wsi->http.cgi->content_length);
				wsi->hdr_state = LHCS_RESPONSE;
				/*
				 * drop the \0xa ... finalize
				 * will add it if needed (HTTP/1)
				 */
				break;
			}
			if (m == LCHS_LF2)
				/* we got \r\n\r[^\n]... unreasonable */
				return -1;
			/* we got \x0anext header, it's reasonable */
			*wsi->http.cgi->headers_pos++ = c;
			wsi->hdr_state = LCHS_HEADER;
			for (n = 0; n < SIGNIFICANT_HDR_COUNT; n++)
				wsi->http.cgi->match[n] = 0;
			wsi->http.cgi->lp = 0;
			break;
		case LHCS_PAYLOAD:
			break;
		}

agin:
		/* ran out of input, ended the hdrs, or filled up the hdrs buf */
		if (!n || wsi->hdr_state == LHCS_PAYLOAD)
			return 0;
	}

	/* payload processing */

	m = !wsi->http.cgi->explicitly_chunked && !wsi->http.cgi->content_length;
	n = lws_get_socket_fd(wsi->http.cgi->stdwsi[LWS_STDOUT]);
	if (n < 0)
		return -1;
	n = read(n, start, sizeof(buf) - LWS_PRE -
			   (m ? LWS_HTTP_CHUNK_HDR_SIZE : 0));

	if (n < 0 && errno != EAGAIN) {
		lwsl_debug("%s: stdout read says %d\n", __func__, n);
		return -1;
	}
	if (n > 0) {
		if (!wsi->http2_substream && m) {
			char chdr[LWS_HTTP_CHUNK_HDR_SIZE];
			m = lws_snprintf(chdr, LWS_HTTP_CHUNK_HDR_SIZE - 3,
					 "%X\x0d\x0a", n);
			memmove(start + m, start, n);
			memcpy(start, chdr, m);
			memcpy(start + m + n, "\x0d\x0a", 2);
			n += m + 2;
		}
		cmd = LWS_WRITE_HTTP;
		if (wsi->http.cgi->content_length_seen + n == wsi->http.cgi->content_length)
			cmd = LWS_WRITE_HTTP_FINAL;
		m = lws_write(wsi, (unsigned char *)start, n, cmd);
		//lwsl_notice("write %d\n", m);
		if (m < 0) {
			lwsl_debug("%s: stdout write says %d\n", __func__, m);
			return -1;
		}
		wsi->http.cgi->content_length_seen += n;
	} else {
		if (wsi->cgi_stdout_zero_length) {
			lwsl_debug("%s: stdout is POLLHUP'd\n", __func__);
			if (wsi->http2_substream)
				m = lws_write(wsi, (unsigned char *)start, 0,
					      LWS_WRITE_HTTP_FINAL);
			return 1;
		}
		wsi->cgi_stdout_zero_length = 1;
	}
	return 0;
}

LWS_VISIBLE LWS_EXTERN int
lws_cgi_kill(struct lws *wsi)
{
	struct lws_cgi_args args;
	int status, n;

	lwsl_debug("%s: %p\n", __func__, wsi);

	if (!wsi->http.cgi)
		return 0;

	if (wsi->http.cgi->pid > 0) {
		n = waitpid(wsi->http.cgi->pid, &status, WNOHANG);
		if (n > 0) {
			lwsl_debug("%s: PID %d reaped\n", __func__,
				    wsi->http.cgi->pid);
			goto handled;
		}
		/* kill the process group */
		n = kill(-wsi->http.cgi->pid, SIGTERM);
		lwsl_debug("%s: SIGTERM child PID %d says %d (errno %d)\n",
			   __func__, wsi->http.cgi->pid, n, errno);
		if (n < 0) {
			/*
			 * hum seen errno=3 when process is listed in ps,
			 * it seems we don't always retain process grouping
			 *
			 * Direct these fallback attempt to the exact child
			 */
			n = kill(wsi->http.cgi->pid, SIGTERM);
			if (n < 0) {
				n = kill(wsi->http.cgi->pid, SIGPIPE);
				if (n < 0) {
					n = kill(wsi->http.cgi->pid, SIGKILL);
					if (n < 0)
						lwsl_err("%s: SIGKILL PID %d "
							 "failed errno %d "
							 "(maybe zombie)\n",
							 __func__,
							 wsi->http.cgi->pid, errno);
				}
			}
		}
		/* He could be unkillable because he's a zombie */
		n = 1;
		while (n > 0) {
			n = waitpid(-wsi->http.cgi->pid, &status, WNOHANG);
			if (n > 0)
				lwsl_debug("%s: reaped PID %d\n", __func__, n);
			if (n <= 0) {
				n = waitpid(wsi->http.cgi->pid, &status, WNOHANG);
				if (n > 0)
					lwsl_debug("%s: reaped PID %d\n",
						   __func__, n);
			}
		}
	}

handled:
	args.stdwsi = &wsi->http.cgi->stdwsi[0];

	if (wsi->http.cgi->pid != -1) {
		n = user_callback_handle_rxflow(wsi->protocol->callback, wsi,
						LWS_CALLBACK_CGI_TERMINATED,
						wsi->user_space,
						(void *)&args, wsi->http.cgi->pid);
		wsi->http.cgi->pid = -1;
		if (n && !wsi->http.cgi->being_closed)
			lws_close_free_wsi(wsi, 0, "lws_cgi_kill");
	}

	return 0;
}

LWS_EXTERN int
lws_cgi_kill_terminated(struct lws_context_per_thread *pt)
{
	struct lws_cgi **pcgi, *cgi = NULL;
	int status, n = 1;

	while (n > 0) {
		/* find finished guys but don't reap yet */
		n = waitpid(-1, &status, WNOHANG);
		if (n <= 0)
			continue;
		lwsl_debug("%s: observed PID %d terminated\n", __func__, n);

		pcgi = &pt->http.cgi_list;

		/* check all the subprocesses on the cgi list */
		while (*pcgi) {
			/* get the next one first as list may change */
			cgi = *pcgi;
			pcgi = &(*pcgi)->cgi_list;

			if (cgi->pid <= 0)
				continue;

			/* finish sending cached headers */
			if (cgi->headers_buf)
				continue;

			/* wait for stdout to be drained */
			if (cgi->content_length > cgi->content_length_seen)
				continue;

			if (cgi->content_length) {
				lwsl_debug("%s: wsi %p: expected content length seen: %lld\n",
					__func__, cgi->wsi,
					(unsigned long long)cgi->content_length_seen);
			}

			/* reap it */
			waitpid(n, &status, WNOHANG);
			/*
			 * he's already terminated so no need for kill()
			 * but we should do the terminated cgi callback
			 * and close him if he's not already closing
			 */
			if (n == cgi->pid) {
				lwsl_debug("%s: found PID %d on cgi list\n",
					    __func__, n);

				if (!cgi->content_length) {
					/*
					 * well, if he sends chunked...
					 * give him 2s after the
					 * cgi terminated to send buffered
					 */
					cgi->chunked_grace++;
					continue;
				}

				/* defeat kill() */
				cgi->pid = 0;
				lws_cgi_kill(cgi->wsi);

				break;
			}
			cgi = NULL;
		}
		/* if not found on the cgi list, as he's one of ours, reap */
		if (!cgi) {
			lwsl_debug("%s: reading PID %d although no cgi match\n",
					__func__, n);
			waitpid(n, &status, WNOHANG);
		}
	}

	pcgi = &pt->http.cgi_list;

	/* check all the subprocesses on the cgi list */
	while (*pcgi) {
		/* get the next one first as list may change */
		cgi = *pcgi;
		pcgi = &(*pcgi)->cgi_list;

		if (cgi->pid <= 0)
			continue;

		/* we deferred killing him after reaping his PID */
		if (cgi->chunked_grace) {
			cgi->chunked_grace++;
			if (cgi->chunked_grace < 2)
				continue;
			goto finish_him;
		}

		/* finish sending cached headers */
		if (cgi->headers_buf)
			continue;

		/* wait for stdout to be drained */
		if (cgi->content_length > cgi->content_length_seen)
			continue;

		if (cgi->content_length)
			lwsl_debug("%s: wsi %p: expected content length seen: %lld\n",
				__func__, cgi->wsi,
				(unsigned long long)cgi->content_length_seen);

		/* reap it */
		if (waitpid(cgi->pid, &status, WNOHANG) > 0) {

			if (!cgi->content_length) {
				/*
				 * well, if he sends chunked...
				 * give him 2s after the
				 * cgi terminated to send buffered
				 */
				cgi->chunked_grace++;
				continue;
			}
finish_him:
			lwsl_debug("%s: found PID %d on cgi list\n",
				    __func__, cgi->pid);

			/* defeat kill() */
			cgi->pid = 0;
			lws_cgi_kill(cgi->wsi);

			break;
		}
	}

	return 0;
}

LWS_VISIBLE LWS_EXTERN struct lws *
lws_cgi_get_stdwsi(struct lws *wsi, enum lws_enum_stdinouterr ch)
{
	if (!wsi->http.cgi)
		return NULL;

	return wsi->http.cgi->stdwsi[ch];
}

void
lws_cgi_remove_and_kill(struct lws *wsi)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];
	struct lws_cgi **pcgi = &pt->http.cgi_list;

	/* remove us from the cgi list */
	lwsl_debug("%s: remove cgi %p from list\n", __func__, wsi->http.cgi);
	while (*pcgi) {
		if (*pcgi == wsi->http.cgi) {
			/* drop us from the pt cgi list */
			*pcgi = (*pcgi)->cgi_list;
			break;
		}
		pcgi = &(*pcgi)->cgi_list;
	}
	if (wsi->http.cgi->headers_buf) {
		lwsl_debug("close: freed cgi headers\n");
		lws_free_set_NULL(wsi->http.cgi->headers_buf);
	}
	/* we have a cgi going, we must kill it */
	wsi->http.cgi->being_closed = 1;
	lws_cgi_kill(wsi);
}
