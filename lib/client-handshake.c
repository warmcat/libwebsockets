#include "private-libwebsockets.h"

struct lws *
lws_client_connect_2(struct lws *wsi)
{
#ifdef LWS_USE_IPV6
	struct sockaddr_in6 server_addr6;
	struct addrinfo hints, *result;
#endif
	struct lws_context *context = wsi->context;
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	struct sockaddr_in server_addr4;
	struct lws_pollfd pfd;
	struct sockaddr *v;
	const char *cce = "";
	int n, plen = 0;
	const char *ads;

	lwsl_client("%s\n", __func__);

	if (!wsi->u.hdr.ah) {
		cce = "ah was NULL at cc2";
		lwsl_err("%s\n", cce);
		goto oom4;
	}

	/* proxy? */

	if (wsi->vhost->http_proxy_port) {
		plen = sprintf((char *)pt->serv_buf,
			"CONNECT %s:%u HTTP/1.0\x0d\x0a"
			"User-agent: libwebsockets\x0d\x0a",
			lws_hdr_simple_ptr(wsi, _WSI_TOKEN_CLIENT_PEER_ADDRESS),
			wsi->u.hdr.c_port);

		if (wsi->vhost->proxy_basic_auth_token[0])
			plen += sprintf((char *)pt->serv_buf + plen,
					"Proxy-authorization: basic %s\x0d\x0a",
					wsi->vhost->proxy_basic_auth_token);

		plen += sprintf((char *)pt->serv_buf + plen, "\x0d\x0a");
		ads = wsi->vhost->http_proxy_address;

#ifdef LWS_USE_IPV6
		if (LWS_IPV6_ENABLED(wsi->vhost)) {
			memset(&server_addr6, 0, sizeof(struct sockaddr_in6));
			server_addr6.sin6_port = htons(wsi->vhost->http_proxy_port);
		} else
#endif
			server_addr4.sin_port = htons(wsi->vhost->http_proxy_port);

	} else {
		ads = lws_hdr_simple_ptr(wsi, _WSI_TOKEN_CLIENT_PEER_ADDRESS);
#ifdef LWS_USE_IPV6
		if (LWS_IPV6_ENABLED(wsi->vhost)) {
			memset(&server_addr6, 0, sizeof(struct sockaddr_in6));
			server_addr6.sin6_port = htons(wsi->u.hdr.c_port);
		} else
#endif
			server_addr4.sin_port = htons(wsi->u.hdr.c_port);
	}

	/*
	 * prepare the actual connection (to the proxy, if any)
	 */
       lwsl_client("%s: address %s\n", __func__, ads);

#ifdef LWS_USE_IPV6
	if (LWS_IPV6_ENABLED(wsi->vhost)) {
		memset(&hints, 0, sizeof(struct addrinfo));
#if !defined(__ANDROID__)
		hints.ai_family = AF_INET6;
		hints.ai_flags = AI_V4MAPPED;
#endif
		n = getaddrinfo(ads, NULL, &hints, &result);
		if (n) {
#ifdef _WIN32
			lwsl_err("getaddrinfo: %ls\n", gai_strerrorW(n));
#else
			lwsl_err("getaddrinfo: %s\n", gai_strerror(n));
#endif
			cce = "getaddrinfo (ipv6) failed";
			goto oom4;
		}

		server_addr6.sin6_family = AF_INET6;
		switch (result->ai_family) {
#if defined(__ANDROID__)
		case AF_INET:
			/* map IPv4 to IPv6 */
			bzero((char *)&server_addr6.sin6_addr,
						sizeof(struct in6_addr));
			server_addr6.sin6_addr.s6_addr[10] = 0xff;
			server_addr6.sin6_addr.s6_addr[11] = 0xff;
			memcpy(&server_addr6.sin6_addr.s6_addr[12],
				&((struct sockaddr_in *)result->ai_addr)->sin_addr,
							sizeof(struct in_addr));
			break;
#endif
		case AF_INET6:
			memcpy(&server_addr6.sin6_addr,
			  &((struct sockaddr_in6 *)result->ai_addr)->sin6_addr,
						sizeof(struct in6_addr));
			break;
		default:
			lwsl_err("Unknown address family\n");
			freeaddrinfo(result);
			cce = "unknown address family";
			goto oom4;
		}

		freeaddrinfo(result);
	} else
#endif
	{
		struct addrinfo ai, *res, *result = NULL;
		void *p = NULL;

		memset (&ai, 0, sizeof ai);
		ai.ai_family = PF_UNSPEC;
		ai.ai_socktype = SOCK_STREAM;
		ai.ai_flags = AI_CANONNAME;

		if (getaddrinfo(ads, NULL, &ai, &result)) {
			lwsl_err("getaddrinfo failed\n");
			cce = "getaddrinfo (ipv4) failed";
			goto oom4;
		}

		res = result;
		while (!p && res) {
			switch (res->ai_family) {
			case AF_INET:
				p = &((struct sockaddr_in *)res->ai_addr)->sin_addr;
				break;
			}
			res = res->ai_next;
		}

		if (!p) {
			lwsl_err("Couldn't identify address\n");
			freeaddrinfo(result);
			cce = "unable to lookup address";
			goto oom4;
		}

		server_addr4.sin_family = AF_INET;
		server_addr4.sin_addr = *((struct in_addr *)p);
		bzero(&server_addr4.sin_zero, 8);
		freeaddrinfo(result);
	}

	if (!lws_socket_is_valid(wsi->sock)) {

#ifdef LWS_USE_IPV6
		if (LWS_IPV6_ENABLED(wsi->vhost))
			wsi->sock = socket(AF_INET6, SOCK_STREAM, 0);
		else
#endif
			wsi->sock = socket(AF_INET, SOCK_STREAM, 0);

		if (!lws_socket_is_valid(wsi->sock)) {
			lwsl_warn("Unable to open socket\n");
			cce = "unable to open socket";
			goto oom4;
		}

		if (lws_plat_set_socket_options(wsi->vhost, wsi->sock)) {
			lwsl_err("Failed to set wsi socket options\n");
			compatible_close(wsi->sock);
			cce = "set socket opts failed";
			goto oom4;
		}

		wsi->mode = LWSCM_WSCL_WAITING_CONNECT;

		lws_libev_accept(wsi, wsi->sock);
		lws_libuv_accept(wsi, wsi->sock);
		if (insert_wsi_socket_into_fds(context, wsi)) {
			compatible_close(wsi->sock);
			cce = "insert wsi failed";
			goto oom4;
		}

		lws_change_pollfd(wsi, 0, LWS_POLLIN);

		/*
		 * past here, we can't simply free the structs as error
		 * handling as oom4 does.  We have to run the whole close flow.
		 */

		if (!wsi->protocol)
			wsi->protocol = &wsi->vhost->protocols[0];

		wsi->protocol->callback(wsi, LWS_CALLBACK_WSI_CREATE,
					wsi->user_space, NULL, 0);

		lws_set_timeout(wsi, PENDING_TIMEOUT_AWAITING_CONNECT_RESPONSE,
				AWAITING_TIMEOUT);

		n = lws_socket_bind(wsi->vhost, wsi->sock, 0, wsi->vhost->iface);
		if (n < 0) {
			cce = "unable to bind socket";
			goto failed;
		}
	}

#ifdef LWS_USE_IPV6
	if (LWS_IPV6_ENABLED(wsi->vhost)) {
		v = (struct sockaddr *)&server_addr6;
		n = sizeof(struct sockaddr_in6);
	} else
#endif
	{
		v = (struct sockaddr *)&server_addr4;
		n = sizeof(struct sockaddr);
	}

	if (connect(wsi->sock, v, n) == -1 || LWS_ERRNO == LWS_EISCONN) {
		if (LWS_ERRNO == LWS_EALREADY ||
		    LWS_ERRNO == LWS_EINPROGRESS ||
		    LWS_ERRNO == LWS_EWOULDBLOCK
#ifdef _WIN32
			|| LWS_ERRNO == WSAEINVAL
#endif
		) {
			lwsl_client("nonblocking connect retry (errno = %d)\n",
				    LWS_ERRNO);

			if (lws_plat_check_connection_error(wsi)) {
				cce = "socket connect failed";
				goto failed;
			}

			/*
			 * must do specifically a POLLOUT poll to hear
			 * about the connect completion
			 */
			if (lws_change_pollfd(wsi, 0, LWS_POLLOUT)) {
				cce = "POLLOUT set failed";
				goto failed;
			}

			return wsi;
		}

		if (LWS_ERRNO != LWS_EISCONN) {
			lwsl_notice("Connect failed errno=%d\n", LWS_ERRNO);
			cce = "connect failed";
			goto failed;
		}
	}

	lwsl_client("connected\n");

	/* we are connected to server, or proxy */

	if (wsi->vhost->http_proxy_port) {

		/*
		 * OK from now on we talk via the proxy, so connect to that
		 *
		 * (will overwrite existing pointer,
		 * leaving old string/frag there but unreferenced)
		 */
		if (lws_hdr_simple_create(wsi, _WSI_TOKEN_CLIENT_PEER_ADDRESS,
					  wsi->vhost->http_proxy_address))
			goto failed;
		wsi->u.hdr.c_port = wsi->vhost->http_proxy_port;

		n = send(wsi->sock, (char *)pt->serv_buf, plen,
			 MSG_NOSIGNAL);
		if (n < 0) {
			lwsl_debug("ERROR writing to proxy socket\n");
			cce = "proxy write failed";
			goto failed;
		}

		lws_set_timeout(wsi, PENDING_TIMEOUT_AWAITING_PROXY_RESPONSE,
				AWAITING_TIMEOUT);

		wsi->mode = LWSCM_WSCL_WAITING_PROXY_REPLY;

		return wsi;
	}

	/*
	 * provoke service to issue the handshake directly
	 * we need to do it this way because in the proxy case, this is the
	 * next state and executed only if and when we get a good proxy
	 * response inside the state machine... but notice in SSL case this
	 * may not have sent anything yet with 0 return, and won't until some
	 * many retries from main loop.  To stop that becoming endless,
	 * cover with a timeout.
	 */

	lws_set_timeout(wsi, PENDING_TIMEOUT_SENT_CLIENT_HANDSHAKE,
			AWAITING_TIMEOUT);

	wsi->mode = LWSCM_WSCL_ISSUE_HANDSHAKE;
	pfd.fd = wsi->sock;
	pfd.events = LWS_POLLIN;
	pfd.revents = LWS_POLLIN;

	n = lws_service_fd(context, &pfd);
	if (n < 0) {
		cce = "first service failed";
		goto failed;
	}
	if (n) /* returns 1 on failure after closing wsi */
		return NULL;

	return wsi;

oom4:
	/* we're closing, losing some rx is OK */
	if (wsi->u.hdr.ah)
		wsi->u.hdr.ah->rxpos = wsi->u.hdr.ah->rxlen;
	if (wsi->mode == LWSCM_HTTP_CLIENT ||
	    wsi->mode == LWSCM_HTTP_CLIENT_ACCEPTED ||
	    wsi->mode == LWSCM_WSCL_WAITING_CONNECT) {
		wsi->vhost->protocols[0].callback(wsi,
			LWS_CALLBACK_CLIENT_CONNECTION_ERROR,
			wsi->user_space, (void *)cce, strlen(cce));
		wsi->already_did_cce = 1;
	}
	/* take care that we might be inserted in fds already */
	if (wsi->position_in_fds_table != -1)
		goto failed1;
	lws_header_table_detach(wsi, 0);
	lws_free(wsi);

	return NULL;

failed:
	wsi->vhost->protocols[0].callback(wsi,
		LWS_CALLBACK_CLIENT_CONNECTION_ERROR,
		wsi->user_space, (void *)cce, strlen(cce));
	wsi->already_did_cce = 1;
failed1:
	lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS);

	return NULL;
}

/**
 * lws_client_reset() - retarget a connected wsi to start over with a new connection (ie, redirect)
 *			this only works if still in HTTP, ie, not upgraded yet
 * wsi:		connection to reset
 * address:	network address of the new server
 * port:	port to connect to
 * path:	uri path to connect to on the new server
 * host:	host header to send to the new server
 */
LWS_VISIBLE struct lws *
lws_client_reset(struct lws *wsi, int ssl, const char *address, int port, const char *path, const char *host)
{
	if (wsi->u.hdr.redirects == 3) {
		lwsl_err("%s: Too many redirects\n", __func__);
		return NULL;
	}
	wsi->u.hdr.redirects++;

#ifdef LWS_OPENSSL_SUPPORT
	wsi->use_ssl = ssl;
#else
	if (ssl) {
		lwsl_err("%s: not configured for ssl\n", __func__);
		return NULL;
	}
#endif

	lwsl_notice("redirect ads='%s', port=%d, path='%s'\n", address, port, path);

	if (lws_hdr_simple_create(wsi, _WSI_TOKEN_CLIENT_PEER_ADDRESS, address))
		return NULL;

	if (lws_hdr_simple_create(wsi, _WSI_TOKEN_CLIENT_URI, path))
		return NULL;

	if (lws_hdr_simple_create(wsi, _WSI_TOKEN_CLIENT_HOST, host))
		return NULL;

	compatible_close(wsi->sock);
	remove_wsi_socket_from_fds(wsi);
	wsi->sock = LWS_SOCK_INVALID;
	wsi->state = LWSS_CLIENT_UNCONNECTED;
	wsi->protocol = NULL;
	wsi->pending_timeout = NO_PENDING_TIMEOUT;
	wsi->u.hdr.c_port = port;

	return lws_client_connect_2(wsi);
}

#ifdef LWS_WITH_HTTP_PROXY
static hubbub_error
html_parser_cb(const hubbub_token *token, void *pw)
{
	struct lws_rewrite *r = (struct lws_rewrite *)pw;
	char buf[1024], *start = buf + LWS_PRE, *p = start,
	     *end = &buf[sizeof(buf) - 1];
	size_t i;

	switch (token->type) {
	case HUBBUB_TOKEN_DOCTYPE:

		p += lws_snprintf(p, end - p, "<!DOCTYPE %.*s %s ",
				(int) token->data.doctype.name.len,
				token->data.doctype.name.ptr,
				token->data.doctype.force_quirks ?
						"(force-quirks) " : "");

		if (token->data.doctype.public_missing)
			printf("\tpublic: missing\n");
		else
			p += lws_snprintf(p, end - p, "PUBLIC \"%.*s\"\n",
				(int) token->data.doctype.public_id.len,
				token->data.doctype.public_id.ptr);

		if (token->data.doctype.system_missing)
			printf("\tsystem: missing\n");
		else
			p += lws_snprintf(p, end - p, " \"%.*s\">\n",
				(int) token->data.doctype.system_id.len,
				token->data.doctype.system_id.ptr);

		break;
	case HUBBUB_TOKEN_START_TAG:
		p += lws_snprintf(p, end - p, "<%.*s", (int)token->data.tag.name.len,
				token->data.tag.name.ptr);

/*				(token->data.tag.self_closing) ?
						"(self-closing) " : "",
				(token->data.tag.n_attributes > 0) ?
						"attributes:" : "");
*/
		for (i = 0; i < token->data.tag.n_attributes; i++) {
			if (!hstrcmp(&token->data.tag.attributes[i].name, "href", 4) ||
			    !hstrcmp(&token->data.tag.attributes[i].name, "action", 6) ||
			    !hstrcmp(&token->data.tag.attributes[i].name, "src", 3)) {
				const char *pp = (const char *)token->data.tag.attributes[i].value.ptr;
				int plen = (int) token->data.tag.attributes[i].value.len;

				if (!hstrcmp(&token->data.tag.attributes[i].value,
					     r->from, r->from_len)) {
					pp += r->from_len;
					plen -= r->from_len;
				}
				p += lws_snprintf(p, end - p, " %.*s=\"%s/%.*s\"",
				       (int) token->data.tag.attributes[i].name.len,
				       token->data.tag.attributes[i].name.ptr,
				       r->to, plen, pp);

			} else

				p += lws_snprintf(p, end - p, " %.*s=\"%.*s\"",
					(int) token->data.tag.attributes[i].name.len,
					token->data.tag.attributes[i].name.ptr,
					(int) token->data.tag.attributes[i].value.len,
					token->data.tag.attributes[i].value.ptr);
		}
		p += lws_snprintf(p, end - p, ">\n");
		break;
	case HUBBUB_TOKEN_END_TAG:
		p += lws_snprintf(p, end - p, "</%.*s", (int) token->data.tag.name.len,
				token->data.tag.name.ptr);
/*
				(token->data.tag.self_closing) ?
						"(self-closing) " : "",
				(token->data.tag.n_attributes > 0) ?
						"attributes:" : "");
*/
		for (i = 0; i < token->data.tag.n_attributes; i++) {
			p += lws_snprintf(p, end - p, " %.*s='%.*s'\n",
				(int) token->data.tag.attributes[i].name.len,
				token->data.tag.attributes[i].name.ptr,
				(int) token->data.tag.attributes[i].value.len,
				token->data.tag.attributes[i].value.ptr);
		}
		p += lws_snprintf(p, end - p, ">\n");
		break;
	case HUBBUB_TOKEN_COMMENT:
		p += lws_snprintf(p, end - p, "<!-- %.*s -->\n",
				(int) token->data.comment.len,
				token->data.comment.ptr);
		break;
	case HUBBUB_TOKEN_CHARACTER:
		p += lws_snprintf(p, end - p, "%.*s", (int) token->data.character.len,
				token->data.character.ptr);
		break;
	case HUBBUB_TOKEN_EOF:
		p += lws_snprintf(p, end - p, "\n");
		break;
	}

	if (user_callback_handle_rxflow(r->wsi->protocol->callback,
			r->wsi, LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ,
			r->wsi->user_space, start, p - start))
		return -1;

	return HUBBUB_OK;
}
#endif

LWS_VISIBLE struct lws *
lws_client_connect_via_info(struct lws_client_connect_info *i)
{
	struct lws *wsi;
	int v = SPEC_LATEST_SUPPORTED;

	if (i->context->requested_kill)
		return NULL;

	if (!i->context->protocol_init_done)
		lws_protocol_init(i->context);

	wsi = lws_zalloc(sizeof(struct lws));
	if (wsi == NULL)
		goto bail;

	wsi->context = i->context;
	/* assert the mode and union status (hdr) clearly */
	lws_union_transition(wsi, LWSCM_HTTP_CLIENT);
	wsi->sock = LWS_SOCK_INVALID;

	/* 1) fill up the wsi with stuff from the connect_info as far as it
	 * can go.  It's because not only is our connection async, we might
	 * not even be able to get ahold of an ah at this point.
	 */

	/* -1 means just use latest supported */
	if (i->ietf_version_or_minus_one != -1 && i->ietf_version_or_minus_one)
		v = i->ietf_version_or_minus_one;

	wsi->ietf_spec_revision = v;
	wsi->user_space = NULL;
	wsi->state = LWSS_CLIENT_UNCONNECTED;
	wsi->protocol = NULL;
	wsi->pending_timeout = NO_PENDING_TIMEOUT;
	wsi->position_in_fds_table = -1;
	wsi->u.hdr.c_port = i->port;
	wsi->vhost = i->vhost;
	if (!wsi->vhost)
		wsi->vhost = i->context->vhost_list;

	wsi->protocol = &wsi->vhost->protocols[0];
	if (wsi && !wsi->user_space && i->userdata) {
		wsi->user_space_externally_allocated = 1;
		wsi->user_space = i->userdata;
	} else
		/* if we stay in http, we can assign the user space now,
		 * otherwise do it after the protocol negotiated
		 */
		if (i->method)
			if (lws_ensure_user_space(wsi))
				goto bail;

#ifdef LWS_OPENSSL_SUPPORT
	wsi->use_ssl = i->ssl_connection;
#else
	if (i->ssl_connection) {
		lwsl_err("libwebsockets not configured for ssl\n");
		goto bail;
	}
#endif

	/* 2) stash the things from connect_info that we can't process without
	 * an ah.  Because if no ah, we will go on the ah waiting list and
	 * process those things later (after the connect_info and maybe the
	 * things pointed to have gone out of scope.
	 */

	wsi->u.hdr.stash = lws_malloc(sizeof(*wsi->u.hdr.stash));
	if (!wsi->u.hdr.stash) {
		lwsl_err("%s: OOM\n", __func__);
		goto bail;
	}

	wsi->u.hdr.stash->origin[0] = '\0';
	wsi->u.hdr.stash->protocol[0] = '\0';
	wsi->u.hdr.stash->method[0] = '\0';

	strncpy(wsi->u.hdr.stash->address, i->address,
		sizeof(wsi->u.hdr.stash->address) - 1);
	strncpy(wsi->u.hdr.stash->path, i->path,
		sizeof(wsi->u.hdr.stash->path) - 1);
	strncpy(wsi->u.hdr.stash->host, i->host,
		sizeof(wsi->u.hdr.stash->host) - 1);
	if (i->origin)
		strncpy(wsi->u.hdr.stash->origin, i->origin,
			sizeof(wsi->u.hdr.stash->origin) - 1);
	if (i->protocol)
		strncpy(wsi->u.hdr.stash->protocol, i->protocol,
			sizeof(wsi->u.hdr.stash->protocol) - 1);
	if (i->method)
		strncpy(wsi->u.hdr.stash->method, i->method,
			sizeof(wsi->u.hdr.stash->method) - 1);

	wsi->u.hdr.stash->address[sizeof(wsi->u.hdr.stash->address) - 1] = '\0';
	wsi->u.hdr.stash->path[sizeof(wsi->u.hdr.stash->path) - 1] = '\0';
	wsi->u.hdr.stash->host[sizeof(wsi->u.hdr.stash->host) - 1] = '\0';
	wsi->u.hdr.stash->origin[sizeof(wsi->u.hdr.stash->origin) - 1] = '\0';
	wsi->u.hdr.stash->protocol[sizeof(wsi->u.hdr.stash->protocol) - 1] = '\0';
	wsi->u.hdr.stash->method[sizeof(wsi->u.hdr.stash->method) - 1] = '\0';

	if (i->pwsi)
		*i->pwsi = wsi;

	/* if we went on the waiting list, no probs just return the wsi
	 * when we get the ah, now or later, he will call
	 * lws_client_connect_via_info2() below.
	 */
	if (lws_header_table_attach(wsi, 0) < 0) {
		/*
		 * if we failed here, the connection is already closed
		 * and freed.
		 */
		goto bail1;
	}

	if (i->parent_wsi) {
		lwsl_info("%s: created child %p of parent %p\n", __func__,
				wsi, i->parent_wsi);
		wsi->parent = i->parent_wsi;
		wsi->sibling_list = i->parent_wsi->child_list;
		i->parent_wsi->child_list = wsi;
	}
#ifdef LWS_WITH_HTTP_PROXY
	if (i->uri_replace_to)
		wsi->rw = lws_rewrite_create(wsi, html_parser_cb,
					     i->uri_replace_from,
					     i->uri_replace_to);
#endif

	return wsi;

bail:
	lws_free(wsi);

bail1:
	if (i->pwsi)
		*i->pwsi = NULL;

	return NULL;
}

struct lws *
lws_client_connect_via_info2(struct lws *wsi)
{
	struct client_info_stash *stash = wsi->u.hdr.stash;

	if (!stash)
		return wsi;

	/*
	 * we're not necessarily in a position to action these right away,
	 * stash them... we only need during connect phase so u.hdr is fine
	 */
	if (lws_hdr_simple_create(wsi, _WSI_TOKEN_CLIENT_PEER_ADDRESS,
				  stash->address))
		goto bail1;

	/* these only need u.hdr lifetime as well */

	if (lws_hdr_simple_create(wsi, _WSI_TOKEN_CLIENT_URI, stash->path))
		goto bail1;

	if (lws_hdr_simple_create(wsi, _WSI_TOKEN_CLIENT_HOST, stash->host))
		goto bail1;

	if (stash->origin[0])
		if (lws_hdr_simple_create(wsi, _WSI_TOKEN_CLIENT_ORIGIN,
					  stash->origin))
			goto bail1;
	/*
	 * this is a list of protocols we tell the server we're okay with
	 * stash it for later when we compare server response with it
	 */
	if (stash->protocol[0])
		if (lws_hdr_simple_create(wsi, _WSI_TOKEN_CLIENT_SENT_PROTOCOLS,
					  stash->protocol))
			goto bail1;
	if (stash->method[0])
		if (lws_hdr_simple_create(wsi, _WSI_TOKEN_CLIENT_METHOD,
					  stash->method))
			goto bail1;

	lws_free_set_NULL(wsi->u.hdr.stash);

	/*
	 * Check with each extension if it is able to route and proxy this
	 * connection for us.  For example, an extension like x-google-mux
	 * can handle this and then we don't need an actual socket for this
	 * connection.
	 */

	if (lws_ext_cb_all_exts(wsi->context, wsi,
				LWS_EXT_CB_CAN_PROXY_CLIENT_CONNECTION,
				(void *)stash->address,
				wsi->u.hdr.c_port) > 0) {
		lwsl_client("lws_client_connect: ext handling conn\n");

		lws_set_timeout(wsi,
			PENDING_TIMEOUT_AWAITING_EXTENSION_CONNECT_RESPONSE,
			        AWAITING_TIMEOUT);

		wsi->mode = LWSCM_WSCL_WAITING_EXTENSION_CONNECT;
		return wsi;
	}
	lwsl_client("lws_client_connect: direct conn\n");
	wsi->context->count_wsi_allocated++;

	return lws_client_connect_2(wsi);

bail1:
	lws_free_set_NULL(wsi->u.hdr.stash);

	return NULL;
}

LWS_VISIBLE struct lws *
lws_client_connect_extended(struct lws_context *context, const char *address,
			    int port, int ssl_connection, const char *path,
			    const char *host, const char *origin,
			    const char *protocol, int ietf_version_or_minus_one,
			    void *userdata)
{
	struct lws_client_connect_info i;

	memset(&i, 0, sizeof(i));

	i.context = context;
	i.address = address;
	i.port = port;
	i.ssl_connection = ssl_connection;
	i.path = path;
	i.host = host;
	i.origin = origin;
	i.protocol = protocol;
	i.ietf_version_or_minus_one = ietf_version_or_minus_one;
	i.userdata = userdata;

	return lws_client_connect_via_info(&i);
}

LWS_VISIBLE struct lws *
lws_client_connect(struct lws_context *context, const char *address,
			    int port, int ssl_connection, const char *path,
			    const char *host, const char *origin,
			    const char *protocol, int ietf_version_or_minus_one)
{
	struct lws_client_connect_info i;

	memset(&i, 0, sizeof(i));

	i.context = context;
	i.address = address;
	i.port = port;
	i.ssl_connection = ssl_connection;
	i.path = path;
	i.host = host;
	i.origin = origin;
	i.protocol = protocol;
	i.ietf_version_or_minus_one = ietf_version_or_minus_one;
	i.userdata = NULL;

	return lws_client_connect_via_info(&i);
}

