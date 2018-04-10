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

#define LWS_CPYAPP(ptr, str) { strcpy(ptr, str); ptr += strlen(str); }

#if !defined(LWS_WITHOUT_EXTENSIONS)
static int
lws_extension_server_handshake(struct lws *wsi, char **p, int budget)
{
	struct lws_context *context = wsi->context;
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	char ext_name[64], *args, *end = (*p) + budget - 1;
	const struct lws_ext_options *opts, *po;
	const struct lws_extension *ext;
	struct lws_ext_option_arg oa;
	int n, m, more = 1;
	int ext_count = 0;
	char ignore;
	char *c;

	/*
	 * Figure out which extensions the client has that we want to
	 * enable on this connection, and give him back the list
	 */
	if (!lws_hdr_total_length(wsi, WSI_TOKEN_EXTENSIONS))
		return 0;

	/*
	 * break down the list of client extensions
	 * and go through them
	 */

	if (lws_hdr_copy(wsi, (char *)pt->serv_buf, context->pt_serv_buf_size,
			 WSI_TOKEN_EXTENSIONS) < 0)
		return 1;

	c = (char *)pt->serv_buf;
	lwsl_parser("WSI_TOKEN_EXTENSIONS = '%s'\n", c);
	wsi->count_act_ext = 0;
	ignore = 0;
	n = 0;
	args = NULL;

	/*
	 * We may get a simple request
	 *
	 * Sec-WebSocket-Extensions: permessage-deflate
	 *
	 * or an elaborated one with requested options
	 *
	 * Sec-WebSocket-Extensions: permessage-deflate; \
	 *			     server_no_context_takeover; \
	 *			     client_no_context_takeover
	 */

	while (more) {

		if (*c && (*c != ',' && *c != '\t')) {
			if (*c == ';') {
				ignore = 1;
				args = c + 1;
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

		while (args && *args && *args == ' ')
			args++;

		/* check a client's extension against our support */

		ext = wsi->vhost->extensions;

		while (ext && ext->callback) {

			if (strcmp(ext_name, ext->name)) {
				ext++;
				continue;
			}

			/*
			 * oh, we do support this one he asked for... but let's
			 * confirm he only gave it once
			 */
			for (m = 0; m < wsi->count_act_ext; m++)
				if (wsi->active_extensions[m] == ext) {
					lwsl_info("extension mentioned twice\n");
					return 1; /* shenanigans */
				}

			/*
			 * ask user code if it's OK to apply it on this
			 * particular connection + protocol
			 */
			m = (wsi->protocol->callback)(wsi,
				LWS_CALLBACK_CONFIRM_EXTENSION_OKAY,
				wsi->user_space, ext_name, 0);

			/*
			 * zero return from callback means go ahead and allow
			 * the extension, it's what we get if the callback is
			 * unhandled
			 */
			if (m) {
				ext++;
				continue;
			}

			/* apply it */

			ext_count++;

			/* instantiate the extension on this conn */

			wsi->active_extensions[wsi->count_act_ext] = ext;

			/* allow him to construct his context */

			if (ext->callback(lws_get_context(wsi), ext, wsi,
					  LWS_EXT_CB_CONSTRUCT,
					  (void *)&wsi->act_ext_user[
					                    wsi->count_act_ext],
					  (void *)&opts, 0)) {
				lwsl_info("ext %s failed construction\n",
					    ext_name);
				ext_count--;
				ext++;

				continue;
			}

			if (ext_count > 1)
				*(*p)++ = ',';
			else
				LWS_CPYAPP(*p,
					  "\x0d\x0aSec-WebSocket-Extensions: ");
			*p += lws_snprintf(*p, (end - *p), "%s", ext_name);

			/*
			 *  go through the options trying to apply the
			 * recognized ones
			 */

			lwsl_debug("ext args %s", args);

			while (args && *args && *args != ',') {
				while (*args == ' ')
					args++;
				po = opts;
				while (po->name) {
					/* only support arg-less options... */
					if (po->type != EXTARG_NONE ||
					    strncmp(args, po->name,
						    strlen(po->name))) {
						po++;
						continue;
					}
					oa.option_name = NULL;
					oa.option_index = (int)(po - opts);
					oa.start = NULL;
					lwsl_debug("setting %s\n", po->name);
					if (!ext->callback(
						lws_get_context(wsi), ext, wsi,
							  LWS_EXT_CB_OPTION_SET,
							  wsi->act_ext_user[
								 wsi->count_act_ext],
							  &oa, (end - *p))) {

						*p += lws_snprintf(*p, (end - *p),
							"; %s", po->name);
						lwsl_debug("adding option %s\n",
								po->name);
					}
					po++;
				}
				while (*args && *args != ',' && *args != ';')
					args++;
			}

			wsi->count_act_ext++;
			lwsl_parser("cnt_act_ext <- %d\n", wsi->count_act_ext);

			ext++;
		}

		n = 0;
		args = NULL;
	}

	return 0;
}
#endif



int
lws_process_ws_upgrade(struct lws *wsi)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];
	char protocol_list[128], protocol_name[64], *p;
	int protocol_len, hit, n = 0, non_space_char_found = 0;

	if (!wsi->protocol)
		lwsl_err("NULL protocol at lws_read\n");

	/*
	 * It's either websocket or h2->websocket
	 *
	 * Select the first protocol we support from the list
	 * the client sent us.
	 *
	 * Copy it to remove header fragmentation
	 */

	if (lws_hdr_copy(wsi, protocol_list, sizeof(protocol_list) - 1,
			 WSI_TOKEN_PROTOCOL) < 0) {
		lwsl_err("protocol list too long");
		return 1;
	}

	protocol_len = lws_hdr_total_length(wsi, WSI_TOKEN_PROTOCOL);
	protocol_list[protocol_len] = '\0';
	p = protocol_list;
	hit = 0;

	while (*p && !hit) {
		n = 0;
		non_space_char_found = 0;
		while (n < (int)sizeof(protocol_name) - 1 &&
		       *p && *p != ',') {
			/* ignore leading spaces */
			if (!non_space_char_found && *p == ' ') {
				n++;
				continue;
			}
			non_space_char_found = 1;
			protocol_name[n++] = *p++;
		}
		protocol_name[n] = '\0';
		if (*p)
			p++;

		lwsl_debug("checking %s\n", protocol_name);

		n = 0;
		while (wsi->vhost->protocols[n].callback) {
			lwsl_debug("try %s\n",
				  wsi->vhost->protocols[n].name);

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
			lwsl_notice("No protocol from \"%s\" supported\n",
				 protocol_list);
			return 1;
		}
		/*
		 * some clients only have one protocol and
		 * do not send the protocol list header...
		 * allow it and match to the vhost's default
		 * protocol (which itself defaults to zero)
		 */
		lwsl_info("defaulting to prot handler %d\n",
			wsi->vhost->default_protocol_index);
		n = wsi->vhost->default_protocol_index;
		wsi->protocol = &wsi->vhost->protocols[
			      (int)wsi->vhost->default_protocol_index];
	}

	/* allocate the ws struct for the wsi */
	wsi->ws = lws_zalloc(sizeof(*wsi->ws), "ws struct");
	if (!wsi->ws) {
		lwsl_notice("OOM\n");
		return 1;
	}

	if (lws_hdr_total_length(wsi, WSI_TOKEN_VERSION))
		wsi->ws->ietf_spec_revision =
			       atoi(lws_hdr_simple_ptr(wsi, WSI_TOKEN_VERSION));

	/* allocate wsi->user storage */
	if (lws_ensure_user_space(wsi)) {
		lwsl_notice("problem with user space\n");
		return 1;
	}

	/*
	 * Give the user code a chance to study the request and
	 * have the opportunity to deny it
	 */
	if ((wsi->protocol->callback)(wsi,
			LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION,
			wsi->user_space,
		      lws_hdr_simple_ptr(wsi, WSI_TOKEN_PROTOCOL), 0)) {
		lwsl_warn("User code denied connection\n");
		return 1;
	}

	/*
	 * Perform the handshake according to the protocol version the
	 * client announced
	 */

	switch (wsi->ws->ietf_spec_revision) {
	default:
		lwsl_notice("Unknown client spec version %d\n",
			  wsi->ws->ietf_spec_revision);
		wsi->ws->ietf_spec_revision = 13;
		//return 1;
		/* fallthru */
	case 13:
#if defined(LWS_WITH_HTTP2)
		if (wsi->h2_stream_carries_ws) {
			if (lws_h2_ws_handshake(wsi)) {
				lwsl_notice("h2 ws handshake failed\n");
				return 1;
			}
		} else
#endif
		{
			lwsl_parser("lws_parse calling handshake_04\n");
			if (handshake_0405(wsi->context, wsi)) {
				lwsl_notice("hs0405 has failed the connection\n");
				return 1;
			}
		}
		break;
	}

	lws_same_vh_protocol_insert(wsi, n);

	/*
	 * We are upgrading to ws, so http/1.1 + h2 and keepalive + pipelined
	 * header considerations about keeping the ah around no longer apply.
	 *
	 * However it's common for the first ws protocol data to have been
	 * coalesced with the browser upgrade request and to already be in the
	 * ah rx buffer.
	 */

	lwsl_debug("%s: %p: inheriting ws ah (rxpos:%d, rxlen:%d)\n",
		  __func__, wsi, wsi->ah->rxpos, wsi->ah->rxlen);
	lws_pt_lock(pt, __func__);

	if (wsi->h2_stream_carries_ws)
		lws_role_transition(wsi, LWSI_ROLE_WS2_SERVER, LRS_ESTABLISHED,
				    &role_ops_ws);
	else
		lws_role_transition(wsi, LWSI_ROLE_WS1_SERVER, LRS_ESTABLISHED,
				    &role_ops_ws);
	/*
	 * Because rxpos/rxlen shows something in the ah, we will get
	 * service guaranteed next time around the event loop
	 */

	lws_pt_unlock(pt);

	lws_server_init_wsi_for_ws(wsi);
	lwsl_parser("accepted v%02d connection\n", wsi->ws->ietf_spec_revision);

	/* !!! drop ah unreservedly after ESTABLISHED */
	if (wsi->ah->rxpos == wsi->ah->rxlen) {
		lwsl_info("%s: %p: dropping ah on ws upgrade\n", __func__, wsi);
		lws_header_table_force_to_detachable_state(wsi);
		lws_header_table_detach(wsi, 1);
	} else
		lwsl_info("%s: %p: unable to drop ah at ws upgrade %d vs %d\n",
			    __func__, wsi, wsi->ah->rxpos, wsi->ah->rxlen);

	return 0;
}

int
handshake_0405(struct lws_context *context, struct lws *wsi)
{
	struct lws_context_per_thread *pt = &context->pt[(int)wsi->tsi];
	struct lws_process_html_args args;
	unsigned char hash[20];
	int n, accept_len;
	char *response;
	char *p;

	if (!lws_hdr_total_length(wsi, WSI_TOKEN_HOST) ||
	    !lws_hdr_total_length(wsi, WSI_TOKEN_KEY)) {
		lwsl_info("handshake_04 missing pieces\n");
		/* completed header processing, but missing some bits */
		goto bail;
	}

	if (lws_hdr_total_length(wsi, WSI_TOKEN_KEY) >= MAX_WEBSOCKET_04_KEY_LEN) {
		lwsl_warn("Client key too long %d\n", MAX_WEBSOCKET_04_KEY_LEN);
		goto bail;
	}

	/*
	 * since key length is restricted above (currently 128), cannot
	 * overflow
	 */
	n = sprintf((char *)pt->serv_buf,
		    "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11",
		    lws_hdr_simple_ptr(wsi, WSI_TOKEN_KEY));

	lws_SHA1(pt->serv_buf, n, hash);

	accept_len = lws_b64_encode_string((char *)hash, 20,
			(char *)pt->serv_buf, context->pt_serv_buf_size);
	if (accept_len < 0) {
		lwsl_warn("Base64 encoded hash too long\n");
		goto bail;
	}

	/* allocate the per-connection user memory (if any) */
	if (lws_ensure_user_space(wsi))
		goto bail;

	/* create the response packet */

	/* make a buffer big enough for everything */

	response = (char *)pt->serv_buf + MAX_WEBSOCKET_04_KEY_LEN + LWS_PRE;
	p = response;
	LWS_CPYAPP(p, "HTTP/1.1 101 Switching Protocols\x0d\x0a"
		      "Upgrade: WebSocket\x0d\x0a"
		      "Connection: Upgrade\x0d\x0a"
		      "Sec-WebSocket-Accept: ");
	strcpy(p, (char *)pt->serv_buf);
	p += accept_len;

	/* we can only return the protocol header if:
	 *  - one came in, and ... */
	if (lws_hdr_total_length(wsi, WSI_TOKEN_PROTOCOL) &&
	    /*  - it is not an empty string */
	    wsi->protocol->name &&
	    wsi->protocol->name[0]) {
		LWS_CPYAPP(p, "\x0d\x0aSec-WebSocket-Protocol: ");
		p += lws_snprintf(p, 128, "%s", wsi->protocol->name);
	}

#if !defined(LWS_WITHOUT_EXTENSIONS)
	/*
	 * Figure out which extensions the client has that we want to
	 * enable on this connection, and give him back the list.
	 *
	 * Give him a limited write bugdet
	 */
	if (lws_extension_server_handshake(wsi, &p, 192))
		goto bail;
#endif
	LWS_CPYAPP(p, "\x0d\x0a");

	args.p = p;
	args.max_len = lws_ptr_diff((char *)pt->serv_buf +
				    context->pt_serv_buf_size, p);
	if (user_callback_handle_rxflow(wsi->protocol->callback, wsi,
					LWS_CALLBACK_ADD_HEADERS,
					wsi->user_space, &args, 0))
		goto bail;

	p = args.p;

	/* end of response packet */

	LWS_CPYAPP(p, "\x0d\x0a");

	if (!lws_any_extension_handled(wsi, LWS_EXT_CB_HANDSHAKE_REPLY_TX,
				       response, p - response)) {

		/* okay send the handshake response accepting the connection */

		lwsl_parser("issuing resp pkt %d len\n",
			    lws_ptr_diff(p, response));
#if defined(DEBUG)
		fwrite(response, 1,  p - response, stderr);
#endif
		n = lws_write(wsi, (unsigned char *)response, p - response,
			      LWS_WRITE_HTTP_HEADERS);
		if (n != (p - response)) {
			lwsl_info("%s: ERROR writing to socket %d\n", __func__, n);
			goto bail;
		}

	}

	/* alright clean up and set ourselves into established state */

	lwsi_set_state(wsi, LRS_ESTABLISHED);
	wsi->lws_rx_parse_state = LWS_RXPS_NEW;

	{
		const char * uri_ptr =
			lws_hdr_simple_ptr(wsi, WSI_TOKEN_GET_URI);
		int uri_len = lws_hdr_total_length(wsi, WSI_TOKEN_GET_URI);
		const struct lws_http_mount *hit =
			lws_find_mount(wsi, uri_ptr, uri_len);
		if (hit && hit->cgienv &&
		    wsi->protocol->callback(wsi, LWS_CALLBACK_HTTP_PMO,
			wsi->user_space, (void *)hit->cgienv, 0))
			return 1;
	}

	return 0;


bail:
	/* caller will free up his parsing allocations */
	return -1;
}


int
lws_interpret_incoming_packet(struct lws *wsi, unsigned char **buf, size_t len)
{
	int m;

	lwsl_parser("%s: received %d byte packet\n", __func__, (int)len);

	/* let the rx protocol state machine have as much as it needs */

	while (len) {
		/*
		 * we were accepting input but now we stopped doing so
		 */
		if (wsi->rxflow_bitmap) {
			lws_rxflow_cache(wsi, *buf, 0, (int)len);
			lwsl_parser("%s: cached %ld\n", __func__, (long)len);
			return 1;
		}

		if (wsi->ws->rx_draining_ext) {
			m = lws_ws_rx_sm(wsi, 0);
			if (m < 0)
				return -1;
			continue;
		}

		/* account for what we're using in rxflow buffer */
		if (wsi->rxflow_buffer) {
			wsi->rxflow_pos++;
			if (wsi->rxflow_pos > wsi->rxflow_len)
				assert(0);
		}

		/* consume payload bytes efficiently */
		if (wsi->lws_rx_parse_state ==
		    LWS_RXPS_PAYLOAD_UNTIL_LENGTH_EXHAUSTED) {
			m = lws_payload_until_length_exhausted(wsi, buf, &len);
			if (wsi->rxflow_buffer)
				wsi->rxflow_pos += m;
		}

		/* process the byte */
		m = lws_ws_rx_sm(wsi, *(*buf)++);
		if (m < 0)
			return -1;
		len--;

		if (wsi->rxflow_buffer && wsi->rxflow_pos == wsi->rxflow_len) {
			lwsl_debug("%s: %p flow buf: drained\n", __func__, wsi);
			lws_free_set_NULL(wsi->rxflow_buffer);
			/* having drained the rxflow buffer, can rearm POLLIN */
#ifdef LWS_NO_SERVER
			m =
#endif
			__lws_rx_flow_control(wsi);
			/* m ignored, needed for NO_SERVER case */
		}
	}

	lwsl_parser("%s: exit with %d unused\n", __func__, (int)len);

	return 0;
}
