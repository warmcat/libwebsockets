/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2018 Andy Green <andy@warmcat.com>
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

#include <private-libwebsockets.h>

/*
 * In-place str to lower case
 */

static void
strtolower(char *s)
{
	while (*s) {
#ifdef LWS_PLAT_OPTEE
		int tolower_optee(int c);
		*s = tolower_optee((int)*s);
#else
		*s = tolower((int)*s);
#endif
		s++;
	}
}

int
lws_client_ws_upgrade(struct lws *wsi, const char **cce)
{
	int n, len, okay = 0;
	struct lws_context *context = wsi->context;
	const char *pc;
	char *p;
#if !defined(LWS_WITHOUT_EXTENSIONS)
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	char *sb = (char *)&pt->serv_buf[0];
	const struct lws_ext_options *opts;
	const struct lws_extension *ext;
	char ext_name[128];
	const char *c, *a;
	char ignore;
	int more = 1;
	void *v;
#endif

	if (wsi->client_h2_substream) {/* !!! client ws-over-h2 not there yet */
		lwsl_warn("%s: client ws-over-h2 upgrade not supported yet\n",
			  __func__);
		*cce = "HS: h2 / ws upgrade unsupported";
		goto bail3;
	}

	if (wsi->ah->http_response != 401) {
		lwsl_warn(
		       "lws_client_handshake: got bad HTTP response '%d'\n",
		       wsi->ah->http_response);
		*cce = "HS: ws upgrade unauthorized";
		goto bail3;
	}

	if (wsi->ah->http_response != 101) {
		lwsl_warn(
		       "lws_client_handshake: got bad HTTP response '%d'\n",
		       wsi->ah->http_response);
		*cce = "HS: ws upgrade response not 101";
		goto bail3;
	}

	if (lws_hdr_total_length(wsi, WSI_TOKEN_ACCEPT) == 0) {
		lwsl_info("no ACCEPT\n");
		*cce = "HS: ACCEPT missing";
		goto bail3;
	}

	p = lws_hdr_simple_ptr(wsi, WSI_TOKEN_UPGRADE);
	if (!p) {
		lwsl_info("no UPGRADE\n");
		*cce = "HS: UPGRADE missing";
		goto bail3;
	}
	strtolower(p);
	if (strcmp(p, "websocket")) {
		lwsl_warn(
		      "lws_client_handshake: got bad Upgrade header '%s'\n", p);
		*cce = "HS: Upgrade to something other than websocket";
		goto bail3;
	}

	p = lws_hdr_simple_ptr(wsi, WSI_TOKEN_CONNECTION);
	if (!p) {
		lwsl_info("no Connection hdr\n");
		*cce = "HS: CONNECTION missing";
		goto bail3;
	}
	strtolower(p);
	if (strcmp(p, "upgrade")) {
		lwsl_warn("lws_client_int_s_hs: bad header %s\n", p);
		*cce = "HS: UPGRADE malformed";
		goto bail3;
	}

	pc = lws_hdr_simple_ptr(wsi, _WSI_TOKEN_CLIENT_SENT_PROTOCOLS);
	if (!pc) {
		lwsl_parser("lws_client_int_s_hs: no protocol list\n");
	} else
		lwsl_parser("lws_client_int_s_hs: protocol list '%s'\n", pc);

	/*
	 * confirm the protocol the server wants to talk was in the list
	 * of protocols we offered
	 */

	len = lws_hdr_total_length(wsi, WSI_TOKEN_PROTOCOL);
	if (!len) {
		lwsl_info("%s: WSI_TOKEN_PROTOCOL is null\n", __func__);
		/*
		 * no protocol name to work from,
		 * default to first protocol
		 */
		n = 0;
		wsi->protocol = &wsi->vhost->protocols[0];
		goto check_extensions;
	}

	p = lws_hdr_simple_ptr(wsi, WSI_TOKEN_PROTOCOL);
	len = (int)strlen(p);

	while (pc && *pc && !okay) {
		if (!strncmp(pc, p, len) &&
		    (pc[len] == ',' || pc[len] == '\0')) {
			okay = 1;
			continue;
		}
		while (*pc && *pc++ != ',')
			;
		while (*pc && *pc == ' ')
			pc++;
	}

	if (!okay) {
		lwsl_info("%s: got bad protocol %s\n", __func__, p);
		*cce = "HS: PROTOCOL malformed";
		goto bail2;
	}

	/*
	 * identify the selected protocol struct and set it
	 */
	n = 0;
	/* keep client connection pre-bound protocol */
	if (!lwsi_role_client(wsi))
		wsi->protocol = NULL;

	while (wsi->vhost->protocols[n].callback) {
		if (!wsi->protocol &&
		    strcmp(p, wsi->vhost->protocols[n].name) == 0) {
			wsi->protocol = &wsi->vhost->protocols[n];
			break;
		}
		n++;
	}

	if (!wsi->vhost->protocols[n].callback) { /* no match */
		/* if server, that's already fatal */
		if (!lwsi_role_client(wsi)) {
			lwsl_info("%s: fail protocol %s\n", __func__, p);
			*cce = "HS: Cannot match protocol";
			goto bail2;
		}

		/* for client, find the index of our pre-bound protocol */

		n = 0;
		while (wsi->vhost->protocols[n].callback) {
			if (wsi->protocol && strcmp(wsi->protocol->name,
				   wsi->vhost->protocols[n].name) == 0) {
				wsi->protocol = &wsi->vhost->protocols[n];
				break;
			}
			n++;
		}

		if (!wsi->vhost->protocols[n].callback) {
			if (wsi->protocol)
				lwsl_err("Failed to match protocol %s\n",
						wsi->protocol->name);
			else
				lwsl_err("No protocol on client\n");
			goto bail2;
		}
	}

	lwsl_debug("Selected protocol %s\n", wsi->protocol->name);

check_extensions:
	/*
	 * stitch protocol choice into the vh protocol linked list
	 * We always insert ourselves at the start of the list
	 *
	 * X <-> B
	 * X <-> pAn <-> pB
	 */

	lws_vhost_lock(wsi->vhost);

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
	wsi->on_same_vh_list = 1;

	lws_vhost_unlock(wsi->vhost);

#if !defined(LWS_WITHOUT_EXTENSIONS)
	/* instantiate the accepted extensions */

	if (!lws_hdr_total_length(wsi, WSI_TOKEN_EXTENSIONS)) {
		lwsl_ext("no client extensions allowed by server\n");
		goto check_accept;
	}

	/*
	 * break down the list of server accepted extensions
	 * and go through matching them or identifying bogons
	 */

	if (lws_hdr_copy(wsi, sb, context->pt_serv_buf_size,
			 WSI_TOKEN_EXTENSIONS) < 0) {
		lwsl_warn("ext list from server failed to copy\n");
		*cce = "HS: EXT: list too big";
		goto bail2;
	}

	c = sb;
	n = 0;
	ignore = 0;
	a = NULL;
	while (more) {

		if (*c && (*c != ',' && *c != '\t')) {
			if (*c == ';') {
				ignore = 1;
				if (!a)
					a = c + 1;
			}
			if (ignore || *c == ' ') {
				c++;
				continue;
			}

			ext_name[n] = *c++;
			if (n < (int)sizeof(ext_name) - 1)
				n++;
			continue;
		}
		ext_name[n] = '\0';
		ignore = 0;
		if (!*c)
			more = 0;
		else {
			c++;
			if (!n)
				continue;
		}

		/* check we actually support it */

		lwsl_notice("checking client ext %s\n", ext_name);

		n = 0;
		ext = wsi->vhost->extensions;
		while (ext && ext->callback) {
			if (strcmp(ext_name, ext->name)) {
				ext++;
				continue;
			}

			n = 1;
			lwsl_notice("instantiating client ext %s\n", ext_name);

			/* instantiate the extension on this conn */

			wsi->active_extensions[wsi->count_act_ext] = ext;

			/* allow him to construct his ext instance */

			if (ext->callback(lws_get_context(wsi), ext, wsi,
				   LWS_EXT_CB_CLIENT_CONSTRUCT,
				   (void *)&wsi->act_ext_user[wsi->count_act_ext],
				   (void *)&opts, 0)) {
				lwsl_info(" ext %s failed construction\n",
					  ext_name);
				ext++;
				continue;
			}

			/*
			 * allow the user code to override ext defaults if it
			 * wants to
			 */
			ext_name[0] = '\0';
			if (user_callback_handle_rxflow(wsi->protocol->callback,
					wsi, LWS_CALLBACK_WS_EXT_DEFAULTS,
					(char *)ext->name, ext_name,
					sizeof(ext_name))) {
				*cce = "HS: EXT: failed setting defaults";
				goto bail2;
			}

			if (ext_name[0] &&
			    lws_ext_parse_options(ext, wsi, wsi->act_ext_user[
						  wsi->count_act_ext], opts, ext_name,
						  (int)strlen(ext_name))) {
				lwsl_err("%s: unable to parse user defaults '%s'",
					 __func__, ext_name);
				*cce = "HS: EXT: failed parsing defaults";
				goto bail2;
			}

			/*
			 * give the extension the server options
			 */
			if (a && lws_ext_parse_options(ext, wsi,
					wsi->act_ext_user[wsi->count_act_ext],
					opts, a, lws_ptr_diff(c, a))) {
				lwsl_err("%s: unable to parse remote def '%s'",
					 __func__, a);
				*cce = "HS: EXT: failed parsing options";
				goto bail2;
			}

			if (ext->callback(lws_get_context(wsi), ext, wsi,
					LWS_EXT_CB_OPTION_CONFIRM,
				      wsi->act_ext_user[wsi->count_act_ext],
				      NULL, 0)) {
				lwsl_err("%s: ext %s rejects server options %s",
					 __func__, ext->name, a);
				*cce = "HS: EXT: Rejects server options";
				goto bail2;
			}

			wsi->count_act_ext++;

			ext++;
		}

		if (n == 0) {
			lwsl_warn("Unknown ext '%s'!\n", ext_name);
			*cce = "HS: EXT: unknown ext";
			goto bail2;
		}

		a = NULL;
		n = 0;
	}

check_accept:
#endif

	/*
	 * Confirm his accept token is the one we precomputed
	 */

	p = lws_hdr_simple_ptr(wsi, WSI_TOKEN_ACCEPT);
	if (strcmp(p, wsi->ah->initial_handshake_hash_base64)) {
		lwsl_warn("lws_client_int_s_hs: accept '%s' wrong vs '%s'\n", p,
				  wsi->ah->initial_handshake_hash_base64);
		*cce = "HS: Accept hash wrong";
		goto bail2;
	}

	/* allocate the per-connection user memory (if any) */
	if (lws_ensure_user_space(wsi)) {
		lwsl_err("Problem allocating wsi user mem\n");
		*cce = "HS: OOM";
		goto bail2;
	}

	/*
	 * we seem to be good to go, give client last chance to check
	 * headers and OK it
	 */
	if (wsi->protocol->callback(wsi,
				    LWS_CALLBACK_CLIENT_FILTER_PRE_ESTABLISH,
				    wsi->user_space, NULL, 0)) {
		*cce = "HS: Rejected by filter cb";
		goto bail2;
	}

	/* clear his proxy connection timeout */
	lws_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);

	/* free up his parsing allocations */
	lws_header_table_detach(wsi, 0);

	lws_role_transition(wsi, LWSI_ROLE_WS1_CLIENT, LRS_ESTABLISHED,
			    &wire_ops_ws);
	lws_restart_ws_ping_pong_timer(wsi);

	wsi->rxflow_change_to = LWS_RXFLOW_ALLOW;

	/*
	 * create the frame buffer for this connection according to the
	 * size mentioned in the protocol definition.  If 0 there, then
	 * use a big default for compatibility
	 */
	n = (int)wsi->protocol->rx_buffer_size;
	if (!n)
		n = context->pt_serv_buf_size;
	n += LWS_PRE;
	wsi->ws->rx_ubuf = lws_malloc(n + 4 /* 0x0000ffff zlib */,
				"client frame buffer");
	if (!wsi->ws->rx_ubuf) {
		lwsl_err("Out of Mem allocating rx buffer %d\n", n);
		*cce = "HS: OOM";
		goto bail2;
	}
	wsi->ws->rx_ubuf_alloc = n;
	lwsl_info("Allocating client RX buffer %d\n", n);

#if !defined(LWS_WITH_ESP32)
	if (setsockopt(wsi->desc.sockfd, SOL_SOCKET, SO_SNDBUF,
		       (const char *)&n, sizeof n)) {
		lwsl_warn("Failed to set SNDBUF to %d", n);
		*cce = "HS: SO_SNDBUF failed";
		goto bail3;
	}
#endif

	lwsl_debug("handshake OK for protocol %s\n", wsi->protocol->name);

	/* call him back to inform him he is up */

	if (wsi->protocol->callback(wsi, LWS_CALLBACK_CLIENT_ESTABLISHED,
				    wsi->user_space, NULL, 0)) {
		*cce = "HS: Rejected at CLIENT_ESTABLISHED";
		goto bail3;
	}
#if !defined(LWS_WITHOUT_EXTENSIONS)
	/*
	 * inform all extensions, not just active ones since they
	 * already know
	 */
	ext = wsi->vhost->extensions;

	while (ext && ext->callback) {
		v = NULL;
		for (n = 0; n < wsi->count_act_ext; n++)
			if (wsi->active_extensions[n] == ext)
				v = wsi->act_ext_user[n];

		ext->callback(context, ext, wsi,
			  LWS_EXT_CB_ANY_WSI_ESTABLISHED, v, NULL, 0);
		ext++;
	}
#endif

	return 0;

bail3:
	return 3;

bail2:
	return 2;
}
