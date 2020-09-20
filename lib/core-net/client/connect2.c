/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2020 Andy Green <andy@warmcat.com>
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
 */

#include "private-lib-core.h"

#if !defined(LWS_WITH_SYS_ASYNC_DNS)
static int
lws_getaddrinfo46(struct lws *wsi, const char *ads, struct addrinfo **result)
{
	struct addrinfo hints;
	int n;

	memset(&hints, 0, sizeof(hints));
	*result = NULL;

	hints.ai_socktype = SOCK_STREAM;

#ifdef LWS_WITH_IPV6
	if (wsi->ipv6) {

#if !defined(__ANDROID__)
		hints.ai_family = AF_UNSPEC;
		hints.ai_flags = AI_V4MAPPED;
#endif
	} else
#endif
	{
		hints.ai_family = PF_UNSPEC;
	}

	n = getaddrinfo(ads, NULL, &hints, result);

	lwsl_info("%s: getaddrinfo '%s' says %d\n", __func__, ads, n);

	return n;
}
#endif

struct lws *
lws_client_connect_2_dnsreq(struct lws *wsi)
{
	struct addrinfo *result = NULL;
	const char *meth = NULL, *ads;
#if defined(LWS_WITH_IPV6)
	struct sockaddr_in addr;
	const char *iface;
#endif
	const char *adsin;
	int n, port = 0;
	struct lws *w;

	if (lwsi_state(wsi) == LRS_WAITING_DNS ||
	    lwsi_state(wsi) == LRS_WAITING_CONNECT) {
		lwsl_info("%s: LRS_WAITING_DNS / CONNECT\n", __func__);

		return wsi;
	}

	/*
	 * The first job is figure out if we want to pipeline on or just join
	 * an existing "active connection" to the same place
	 */

	meth = lws_wsi_client_stash_item(wsi, CIS_METHOD,
					 _WSI_TOKEN_CLIENT_METHOD);

	/* we only pipeline connections that said it was okay */

	if (!wsi->client_pipeline) {
		lwsl_debug("%s: new conn on no pipeline flag\n", __func__);

		goto solo;
	}

	/* only pipeline things we associate with being a stream */

	if (meth && strcmp(meth, "RAW") && strcmp(meth, "GET") &&
		    strcmp(meth, "POST") && strcmp(meth, "PUT") &&
		    strcmp(meth, "UDP") && strcmp(meth, "MQTT"))
		goto solo;

	/* consult active connections to find out disposition */

	adsin = lws_wsi_client_stash_item(wsi, CIS_ADDRESS,
					  _WSI_TOKEN_CLIENT_PEER_ADDRESS);

	if (!adsin)
		/*
		 * This cannot happen since user code must provide the client
		 * address to get this far, it's here to satisfy Coverity
		 */
		return NULL;

	switch (lws_vhost_active_conns(wsi, &w, adsin)) {
	case ACTIVE_CONNS_SOLO:
		break;
	case ACTIVE_CONNS_MUXED:
		lwsl_notice("%s: ACTIVE_CONNS_MUXED\n", __func__);
		if (lwsi_role_h2(wsi)) {

			if (wsi->a.protocol->callback(wsi,
					LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP,
					wsi->user_space, NULL, 0))
				goto failed1;

			//lwsi_set_state(wsi, LRS_H1C_ISSUE_HANDSHAKE2);
			//lwsi_set_state(w, LRS_ESTABLISHED);
			lws_callback_on_writable(wsi);
		}

		return wsi;
	case ACTIVE_CONNS_QUEUED:
		lwsl_debug("%s: ACTIVE_CONNS_QUEUED st 0x%x: \n", __func__,
			   lwsi_state(wsi));
		if (lwsi_state(wsi) == LRS_UNCONNECTED) {
			if (lwsi_role_h2(w))
				lwsi_set_state(wsi,
					       LRS_H2_WAITING_TO_SEND_HEADERS);
			else
				lwsi_set_state(wsi, LRS_H1C_ISSUE_HANDSHAKE2);
		}

		return lws_client_connect_4_established(wsi, w, 0);
	}

solo:

	/*
	 * clients who will create their own fresh connection keep a copy of
	 * the hostname they originally connected to, in case other connections
	 * want to use it too
	 */

	if (!wsi->cli_hostname_copy) {
		if (wsi->stash && wsi->stash->cis[CIS_HOST])
			wsi->cli_hostname_copy =
					lws_strdup(wsi->stash->cis[CIS_HOST]);
#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
		else {
			char *pa = lws_hdr_simple_ptr(wsi,
					      _WSI_TOKEN_CLIENT_PEER_ADDRESS);
			if (pa)
				wsi->cli_hostname_copy = lws_strdup(pa);
		}
#endif
	}

	/*
	 * If we made our own connection, and we're doing a method that can
	 * take a pipeline, we are an "active client connection".
	 *
	 * Add ourselves to the vhost list of those so that others can
	 * piggyback on our transaction queue
	 */

	if (meth && (!strcmp(meth, "RAW") || !strcmp(meth, "GET") ||
		     !strcmp(meth, "POST") || !strcmp(meth, "PUT") ||
		     !strcmp(meth, "MQTT")) &&
	    lws_dll2_is_detached(&wsi->dll2_cli_txn_queue) &&
	    lws_dll2_is_detached(&wsi->dll_cli_active_conns)) {
		lws_vhost_lock(wsi->a.vhost);
		lwsl_info("%s: adding active conn %p\n", __func__, wsi);
		/* caution... we will have to unpick this on oom4 path */
		lws_dll2_add_head(&wsi->dll_cli_active_conns,
				 &wsi->a.vhost->dll_cli_active_conns_owner);
		lws_vhost_unlock(wsi->a.vhost);
	}

	/*
	 * unix socket destination?
	 */

	if (wsi->stash)
		ads = wsi->stash->cis[CIS_ADDRESS];
	else
		ads = lws_hdr_simple_ptr(wsi, _WSI_TOKEN_CLIENT_PEER_ADDRESS);

	/*
	 * Since address must be given at client creation, should not be
	 * possible, but necessary to satisfy coverity
	 */
	if (!ads)
		return NULL;

#if defined(LWS_WITH_UNIX_SOCK)
	if (*ads == '+') {
		wsi->unix_skt = 1;
		n = 0;
		goto next_step;
	}
#endif

	/*
	 * start off allowing ipv6 on connection if vhost allows it
	 */
	wsi->ipv6 = LWS_IPV6_ENABLED(wsi->a.vhost);
#ifdef LWS_WITH_IPV6
	if (wsi->stash)
		iface = wsi->stash->cis[CIS_IFACE];
	else
		iface = lws_hdr_simple_ptr(wsi, _WSI_TOKEN_CLIENT_IFACE);

	if (wsi->ipv6 && iface &&
	    inet_pton(AF_INET, iface, &addr.sin_addr) == 1) {
		lwsl_notice("%s: client connection forced to IPv4\n", __func__);
		wsi->ipv6 = 0;
	}
#endif

#if defined(LWS_WITH_DETAILED_LATENCY)
	if (lwsi_state(wsi) == LRS_WAITING_DNS &&
	    wsi->a.context->detailed_latency_cb) {
		wsi->detlat.type = LDLT_NAME_RESOLUTION;
		wsi->detlat.latencies[LAT_DUR_PROXY_CLIENT_REQ_TO_WRITE] =
			lws_now_usecs() -
			wsi->detlat.earliest_write_req_pre_write;
		wsi->detlat.latencies[LAT_DUR_USERCB] = 0;
		lws_det_lat_cb(wsi->a.context, &wsi->detlat);
		wsi->detlat.earliest_write_req_pre_write = lws_now_usecs();
	}
#endif

#if defined(LWS_CLIENT_HTTP_PROXYING) && \
	(defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2))

	/* Decide what it is we need to connect to:
	 *
	 * Priority 1: connect to http proxy */

	if (wsi->a.vhost->http.http_proxy_port) {
		ads = wsi->a.vhost->http.http_proxy_address;
		port = wsi->a.vhost->http.http_proxy_port;
#else
		if (0) {
#endif

#if defined(LWS_WITH_SOCKS5)

	/* Priority 2: Connect to SOCK5 Proxy */

	} else if (wsi->a.vhost->socks_proxy_port) {
		lwsl_client("Sending SOCKS Greeting\n");
		ads = wsi->a.vhost->socks_proxy_address;
		port = wsi->a.vhost->socks_proxy_port;
#endif
	} else {

		/* Priority 3: Connect directly */

		/* ads already set */
		port = wsi->c_port;
	}

	/*
	 * prepare the actual connection
	 * to whatever we decided to connect to
	 */
	lwsi_set_state(wsi, LRS_WAITING_DNS);

	lwsl_info("%s: %p: lookup %s:%u\n", __func__, wsi, ads, port);
	(void)port;

#if defined(LWS_WITH_DETAILED_LATENCY)
	wsi->detlat.earliest_write_req_pre_write = lws_now_usecs();
#endif
#if !defined(LWS_WITH_SYS_ASYNC_DNS)
	n = 0;
	if (!wsi->dns_sorted_list.count) {
		/*
		 * blocking dns resolution
		 */
		n = lws_getaddrinfo46(wsi, ads, &result);
	}
#else
	lwsi_set_state(wsi, LRS_WAITING_DNS);
	/* this is either FAILED, CONTINUING, or already called connect_4 */

	n = lws_async_dns_query(wsi->a.context, wsi->tsi, ads,
				LWS_ADNS_RECORD_A, lws_client_connect_3_connect,
				wsi, NULL);
	if (n == LADNS_RET_FAILED_WSI_CLOSED)
		return NULL;

	if (n == LADNS_RET_FAILED)
		goto failed1;

	return wsi;
#endif

#if defined(LWS_WITH_UNIX_SOCK)
next_step:
#endif
	return lws_client_connect_3_connect(wsi, ads, result, n, NULL);

//#if defined(LWS_WITH_SYS_ASYNC_DNS)
failed1:
	lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS, "client_connect2");

	return NULL;
//#endif
}
