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

/*
 * sansIO rx for mqtt: the parser takes everything it is given and keeps
 * its own place in a packet, so all of it is consumed.  A failure while a
 * client awaits its CONNACK is reported to the user as a connection
 * failure; any other failure closes.  len 0 is the peer closing.
 */
static int
rops_rx_mqtt(struct lws *wsi, const uint8_t *buf, size_t len,
	     int from_transport)
{
	(void)from_transport;

#if defined(LWS_WITH_CLIENT) && defined(LWS_WITH_SOCKS5)
	if (lwsi_in_socks5_leg(wsi))
		return lws_mqtt_client_socks_rx(wsi, buf, len);
#endif

	if (!len) {
		lwsl_wsi_info(wsi, "zero length read");

		return LWS_RX_CLOSE;
	}

	if (lws_read_mqtt(wsi, (unsigned char *)buf, len) < 0) {
#if defined(LWS_WITH_CLIENT)
		if (lwsi_role_client(wsi) &&
		    lwsi_state(wsi) == LRS_MQTTC_AWAIT_CONNACK)
			return lws_mqtt_client_connack_failed(wsi);
#endif
		lwsl_wsi_notice(wsi, "lws_read_mqtt failed");

		return LWS_RX_CLOSE;
	}

	return (int)len;
}

/*
 * How an mqtt connection is read: not until it is established (the client's
 * transport phases and CONNACK wait are its handler's), then while tls holds
 * more.
 */
static int
rops_rx_policy_mqtt(struct lws *wsi, int *flags, size_t *max)
{
	if (lwsi_state(wsi) != LRS_ESTABLISHED)
		return LWS_RXPOL_ROLE;

	*flags = 0;
	*max = 0;

	return LWS_RXPOL_PUMP_LOOP;
}

static lws_handling_result_t
rops_handle_POLLIN_mqtt(struct lws_context_per_thread *pt, struct lws *wsi,
			   struct lws_pollfd *pollfd)
{
	int n = 0;

	lwsl_debug("%s: wsistate 0x%x, %s pollout %d\n", __func__,
		   (unsigned int)wsi->wsistate,  wsi->a.protocol->name,
		   pollfd->revents);

	/*
	 * After the CONNACK and nwsi establishment, the first logical
	 * stream is migrated out of the nwsi to be child sid 1, and the
	 * nwsi no longer has a wsi->mqtt of its own.
	 *
	 * RX events on the nwsi must be converted to events seen or not
	 * seen by one or more child streams.
	 *
	 * SUBACK - reflected to child stream that asked for it
	 * PUBACK - routed to child that did the related publish
	 */

	if (lwsi_state(wsi) != LRS_ESTABLISHED) {
#if defined(LWS_WITH_CLIENT)

		if (lwsi_transport(wsi) == LTS_WAITING_SSL &&
		    ((pollfd->revents & LWS_POLLOUT)) &&
		    lws_change_pollfd(wsi, LWS_POLLOUT, 0)) {
			lwsl_info("failed at set pollfd\n");
			return LWS_HPI_RET_PLEASE_CLOSE_ME;
		}

		if (pollfd->revents & LWS_POLLOUT) {
			int hr = lws_handle_POLLOUT_event(wsi, pollfd);

			if (hr < 0) {
				/* connect racing already closed+freed the wsi */
				return LWS_HPI_RET_WSI_ALREADY_DIED;
			}
			if (hr) {
				lwsl_debug("POLLOUT event closed it\n");
				return LWS_HPI_RET_PLEASE_CLOSE_ME;
			}
		}

		n = lws_mqtt_client_socket_service(wsi, pollfd, NULL);
		if (n)
			return LWS_HPI_RET_WSI_ALREADY_DIED;
#endif
		return LWS_HPI_RET_HANDLED;
	}

	/* 1: the pass's POLLOUT was served by IO's rx stage */

	/* the reading was done by IO's rx stage */

	if (!lws_buflist_next_segment_len(&wsi->buflist, NULL))
		/*
		 * nothing parked (any more): a pending rx flow change can be
		 * applied, which re-arms POLLIN after a drain
		 */
		__lws_rx_flow_control(wsi);

	return LWS_HPI_RET_HANDLED;
}

#if 0 /* defined(LWS_WITH_SERVER) */

static int
rops_adoption_bind_mqtt(struct lws *wsi, int type, const char *vh_prot_name)
{
	/* no http but socket... must be mqtt */
	if ((type & LWS_ADOPT_HTTP) || !(type & LWS_ADOPT_SOCKET) ||
	    (type & _LWS_ADOPT_FINISH))
		return 0; /* no match */

	lws_wsi_event_role(wsi, (type & LWS_ADOPT_ALLOW_SSL) ?
				LWS_WSIEV_ADOPTED_TLS : LWS_WSIEV_ADOPTED,
			   &role_ops_mqtt);

	if (vh_prot_name)
		lws_bind_protocol(wsi, wsi->a.protocol, __func__);
	else
		/* this is the only time he will transition */
		lws_bind_protocol(wsi,
			&wsi->a.vhost->protocols[wsi->a.vhost->mqtt_protocol_index],
			__func__);

	return 1; /* bound */
}
#endif

static int
rops_client_bind_mqtt(struct lws *wsi, const struct lws_client_connect_info *i)
{
	lwsl_debug("%s: i = %p\n", __func__, i);
	if (!i) {

		/* finalize */

		if (!wsi->user_space && wsi->stash->cis[CIS_METHOD])
			if (lws_ensure_user_space(wsi))
				return 1;

		if (!wsi->stash->cis[CIS_METHOD] && !wsi->stash->cis[CIS_ALPN])
			wsi->stash->cis[CIS_ALPN] = "x-amzn-mqtt-ca";

		/* if we went on the ah waiting list, it's ok, we can
		 * wait.
		 *
		 * When we do get the ah, now or later, he will end up
		 * at lws_http_client_connect_via_info2().
		 */
		if (lws_header_table_attach(wsi, 0) ==
						LWS_AH_ATTACH_WSI_GONE)
			/*
			 * The attach went on to do the connect and it failed:
			 * the wsi is already closed and freed.  -1 is this
			 * op's "gone" answer, our caller must not touch or
			 * close him either.
			 */
			return -1;

		return 0;
	}

	/* if a recognized mqtt method, bind to it */
	if (strcmp(i->method, "MQTT"))
		return 0; /* no match */

	/*
	 * Returning nonzero here means "this role took it", ie, success; we
	 * must return < 0 for failure, otherwise the connect proceeds with the
	 * default role and a half-initialized wsi->mqtt nothing will free.
	 */
	if (lws_create_client_mqtt_object(i, wsi))
		return -1;

	lws_wsi_event_role(wsi, LWS_WSIEV_CLIENT_BIND, &role_ops_mqtt);
	return 1; /* matched */
}

static lws_handling_result_t
rops_handle_POLLOUT_mqtt(struct lws *wsi)
{
	lwsl_debug("%s\n", __func__);

#if defined(LWS_WITH_CLIENT)
	if (wsi->mqtt && wsi->mqtt->send_pingreq && !wsi->mqtt->inside_payload) {
		uint8_t buf[LWS_PRE + 2];

		/*
		 * We are swallowing this POLLOUT in order to send a PINGREQ
		 * autonomously
		 */

		wsi->mqtt->send_pingreq = 0;

		lwsl_notice("%s: issuing PINGREQ\n", __func__);

		buf[LWS_PRE] = LMQCP_CTOS_PINGREQ << 4;
		buf[LWS_PRE + 1] = 0;

		if (lws_write(wsi, (uint8_t *)&buf[LWS_PRE], 2,
			      LWS_WRITE_BINARY) != 2)
			return LWS_HP_RET_BAIL_DIE;

		return LWS_HP_RET_BAIL_OK;
	}
#endif
	if (wsi->mqtt && !wsi->mqtt->inside_payload &&
	    (wsi->mqtt->send_pubrec || wsi->mqtt->send_pubrel ||
	     wsi->mqtt->send_pubcomp)) {
		uint8_t buf[LWS_PRE + 4];
		/* Remaining len = 2 */
		buf[LWS_PRE + 1] = 2;
		if (wsi->mqtt->send_pubrec) {
			lwsl_notice("%s: issuing PUBREC for pkt id: %d\n",
				    __func__, wsi->mqtt->peer_ack_pkt_id);
			buf[LWS_PRE] = LMQCP_PUBREC << 4 | 0x2;
			/* Packet ID */
			lws_ser_wu16be(&buf[LWS_PRE + 2],
				       wsi->mqtt->peer_ack_pkt_id);
			wsi->mqtt->send_pubrec = 0;
		} else if (wsi->mqtt->send_pubrel) {
			lwsl_notice("%s: issuing PUBREL for pkt id: %d\n",
				    __func__, wsi->mqtt->ack_pkt_id);
			buf[LWS_PRE] = LMQCP_PUBREL << 4 | 0x2;
			lws_ser_wu16be(&buf[LWS_PRE + 2],
				       wsi->mqtt->ack_pkt_id);
			wsi->mqtt->send_pubrel = 0;
		} else {
			lwsl_notice("%s: issuing PUBCOMP for pkt id: %d\n",
				    __func__, wsi->mqtt->pubcomp_pkt_id);
			buf[LWS_PRE] = LMQCP_PUBCOMP << 4 | 0x2;
			lws_ser_wu16be(&buf[LWS_PRE + 2],
				       wsi->mqtt->pubcomp_pkt_id);
			wsi->mqtt->send_pubcomp = 0;
		}
		if (lws_write(wsi, (uint8_t *)&buf[LWS_PRE], 4,
			      LWS_WRITE_BINARY) != 4)
			return LWS_HP_RET_BAIL_DIE;
		return LWS_HP_RET_BAIL_OK;
	}

	wsi = lws_get_network_wsi(wsi);

	wsi->mux.requested_POLLOUT = 0;

	if(lws_dll2_is_empty(&wsi->mux.child_list_owner)) {
		lwsl_debug("%s: no children\n", __func__);
		return LWS_HP_RET_DROP_POLLOUT;
	}

	if (!wsi->mqtt)
		return LWS_HP_RET_BAIL_DIE;

	lws_wsi_mux_dump_waiting_children(wsi);

	/*
	 * Fair-share POLLOUT service via a forward walk; see
	 * rops_perform_user_POLLOUT_h2() for the rationale.  _safe caches
	 * next before the body so relocating/closing the current child is
	 * safe and the walk terminates after one pass over the children
	 * present at entry.  The choke test is post-tested (first iteration
	 * skips it) so a pipe that already looks choked on entry cannot
	 * starve every child.
	 */
	int first_iteration = 1;
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
			lws_dll2_get_head(&wsi->mux.child_list_owner)) {
		struct lws *w = lws_container_of(d, struct lws, mux.sibling_list);

		if (!first_iteration && lws_send_pipe_choked(wsi))
			break;
		first_iteration = 0;

		if (!w->mux.requested_POLLOUT)
			continue;

		if (!lwsi_state_can_handle_POLLOUT(wsi))
			continue;

		/*
		 * If the nwsi is in the middle of a frame, we can only
		 * continue to send that
		 */
		if (wsi->mqtt->inside_payload && !w->mqtt->inside_payload)
			continue;

		/*
		 * we're going to do writable callback for this child.
		 * move him to be the last child (fair share); cached d1
		 * stays valid across the relocate.
		 */
		lws_dll2_remove(&w->mux.sibling_list);
		lws_dll2_add_tail(&w->mux.sibling_list,
				  &wsi->mux.child_list_owner);

		/*
		 * Clear the POLLOUT request we acted on, as
		 * lws_wsi_mux_move_child_to_tail() did when it was the
		 * rotation primitive.  The body below re-arms explicitly
		 * (PUBACK path) when it wants another cycle; without this
		 * clear the normal path leaves it set and the post-loop
		 * lws_wsi_mux_action_pending_writeable_reqs() re-arms POLLOUT
		 * every pass -> level-triggered event loops spin at 100% CPU
		 * on an always-writable socket.  See ops-h2.c.
		 */
		w->mux.requested_POLLOUT = 0;

		lwsl_debug("%s: child %s (wsistate 0x%x)\n", __func__,
			   lws_wsi_tag(w), (unsigned int)w->wsistate);

		if (lwsi_state(wsi) == LRS_ESTABLISHED &&
		    !wsi->mqtt->inside_payload &&
		    wsi->mqtt->send_puback) {
			uint8_t buf[LWS_PRE + 4];
			lwsl_notice("%s: issuing PUBACK for pkt id: %d\n",
				    __func__, wsi->mqtt->ack_pkt_id);

			/* Fixed header */
			buf[LWS_PRE] = LMQCP_PUBACK << 4;
			/* Remaining len = 2 */
			buf[LWS_PRE + 1] = 2;
			/* Packet ID */
			lws_ser_wu16be(&buf[LWS_PRE + 2], wsi->mqtt->peer_ack_pkt_id);

			if (lws_write(wsi, (uint8_t *)&buf[LWS_PRE], 4,
				      LWS_WRITE_BINARY) != 4)
				return LWS_HP_RET_BAIL_DIE;

			wsi->mqtt->send_puback = 0;
			w->mux.requested_POLLOUT = 1;

			continue;
		}

		if (lws_callback_as_writeable(w)) {
			lwsl_notice("%s: Closing child %s\n", __func__, lws_wsi_tag(w));
			lws_close_free_wsi(w, LWS_CLOSE_STATUS_NOSTATUS,
					   "mqtt pollout handle");
		}

	} lws_end_foreach_dll_safe(d, d1);

	// lws_wsi_mux_dump_waiting_children(wsi);

	if (lws_wsi_mux_action_pending_writeable_reqs(wsi))
		return LWS_HP_RET_BAIL_DIE;

	return LWS_HP_RET_BAIL_OK;
}

#if defined(LWS_WITH_CLIENT)
static int
rops_issue_keepalive_mqtt(struct lws *wsi, int isvalid)
{
	struct lws *nwsi = lws_get_network_wsi(wsi);

	if (isvalid) {
		_lws_validity_confirmed_role(nwsi);

		return 0;
	}

	nwsi->mqtt->send_pingreq = 1;
	lws_callback_on_writable(nwsi);

	return 0;
}
#endif

static int
rops_close_role_mqtt(struct lws_context_per_thread *pt, struct lws *wsi)
{
	struct lws *nwsi = lws_get_network_wsi(wsi);
	lws_mqtt_subs_t	*s, *mysub;
	lws_mqttc_t *c;

	if (!wsi->mqtt)
		return 0;

	c = &wsi->mqtt->client;

	/*
	 * These suls are owned by wsi->mqtt which is about to be freed; if
	 * left linked into the pt sul owner they would fire on freed memory
	 * after the timeout that armed them (eg, peer never sent UNSUBACK or
	 * accepted the device shadow update before the connection died).
	 */
	lws_sul_cancel(&wsi->mqtt->sul_qos_puback_pubrec_wait);
	lws_sul_cancel(&wsi->mqtt->sul_unsuback_wait);
	lws_sul_cancel(&wsi->mqtt->sul_shadow_wait);

	lws_mqtt_str_free(&c->username);
	lws_mqtt_str_free(&c->password);
	lws_mqtt_str_free(&c->will.message);
	lws_mqtt_str_free(&c->will.topic);
	lws_mqtt_str_free(&c->id);

	/* clean up any subscription allocations */

	lws_start_foreach_dll_safe(struct lws_dll2 *, p, tp,
				   lws_dll2_get_head(&wsi->mqtt->subs_owner)) {
		s = lws_container_of(p, lws_mqtt_subs_t, list);

		/*
		 * Account for children no longer using nwsi subscription
		 */
		mysub = lws_mqtt_find_sub(nwsi->mqtt, (const char *)&s[1]);
//		assert(mysub); /* if child subscribed, nwsi must feel the same */
		if (mysub) {
			assert(mysub->ref_count);
			mysub->ref_count--;
		}
		lws_dll2_remove(p);
		lws_free(s);
	} lws_end_foreach_dll_safe(p, tp);

	/* clean up QoS2 rx list */
	{
		lws_mqtt_qos2_rx_t *rx;

		lws_start_foreach_dll_safe(struct lws_dll2 *, p, tp, lws_dll2_get_head(
			&wsi->mqtt->qos2_rx_list)) {
			rx = lws_container_of(p, lws_mqtt_qos2_rx_t, list);
			lws_dll2_remove(&rx->list);
			lws_free(rx);
		} lws_end_foreach_dll_safe(p, tp);
	}

	lws_mqtt_publish_param_t *pub =
			(lws_mqtt_publish_param_t *)
				wsi->mqtt->rx_cpkt_param;

	if (pub)
		lws_free_set_NULL(pub->topic);

	lws_free_set_NULL(wsi->mqtt->rx_cpkt_param);

	lws_free_set_NULL(wsi->mqtt);

	return 0;
}

static int
rops_callback_on_writable_mqtt(struct lws *wsi)
{
#if defined(LWS_WITH_CLIENT)
	struct lws *network_wsi;
#endif
	int already;

	lwsl_debug("%s: %s (wsistate 0x%x)\n", __func__, lws_wsi_tag(wsi),
			(unsigned int)wsi->wsistate);

	if (wsi->mux.requested_POLLOUT) {
		lwsl_debug("already pending writable\n");
		// return 1;
	}
#if 0
	/* is this for DATA or for control messages? */
	if (lws_wsi_is_mux_nwsi(wsi) && !wsi->h2.h2n->pps &&
	    !lws_h2_tx_cr_get(wsi)) {
		/*
		 * other side is not able to cope with us sending DATA
		 * anything so no matter if we have POLLOUT on our side if it's
		 * DATA we want to send.
		 *
		 * Delay waiting for our POLLOUT until peer indicates he has
		 * space for more using tx window command in http2 layer
		 */
		lwsl_notice("%s: %p: skint (%d)\n", __func__, wsi,
			    wsi->h2.tx_cr);
		wsi->h2.skint = 1;
		return 0;
	}

	wsi->h2.skint = 0;
#endif
#if defined(LWS_WITH_CLIENT)
	network_wsi = lws_get_network_wsi(wsi);
#endif
	already = lws_wsi_mux_mark_parents_needing_writeable(wsi);

	/* for network action, act only on the network wsi */

	if (already
#if defined(LWS_WITH_CLIENT)
			&& !network_wsi->client_mux_substream
#endif
			)
		return 1;

	return 0;
}

static int
rops_close_kill_connection_mqtt(struct lws *wsi, enum lws_close_status reason)
{
	lwsl_info(" %s, his parent %s: child list %p, siblings:\n",
			lws_wsi_tag(wsi),
			lws_wsi_tag(wsi->mux.parent_wsi),
			(void *)lws_dll2_get_head(&wsi->mux.child_list_owner));
	//lws_wsi_mux_dump_children(wsi);

	if (wsi->mux_substream
#if defined(LWS_WITH_CLIENT)
			|| wsi->client_mux_substream
#endif
			/*
			 * The connection wsi itself is not marked as a
			 * substream, but it owns the mux children (the wsi
			 * created at CONNACK that holds the connection-level
			 * state, and anything adopted under it).  If we don't
			 * close them here, they are orphaned with a dangling
			 * mux.parent_wsi, and only get found (and set loose on
			 * it) at context destroy.  h2 covers the same case for
			 * its nwsi via lws_wsi_is_mux_nwsi() in its own gate.
			 */
			|| !lws_dll2_is_empty(&wsi->mux.child_list_owner)
		) {
		lwsl_info("closing %s: parent %s: first child %p\n",
				lws_wsi_tag(wsi),
				lws_wsi_tag(wsi->mux.parent_wsi),
				(void *)lws_dll2_get_head(&wsi->mux.child_list_owner));

		if (lws_dll2_get_head(&wsi->mux.child_list_owner) && lwsl_visible(LLL_INFO)) {
			lwsl_info(" parent %s: closing children: list:\n", lws_wsi_tag(wsi));
			lws_wsi_mux_dump_children(wsi);
		}

		lws_wsi_mux_close_children(wsi, (int)reason);
	}

	if ((
#if defined(LWS_WITH_CLIENT)
			wsi->client_mux_substream ||
#endif
			wsi->mux_substream) &&
	     wsi->mux.parent_wsi) {
		lws_wsi_mux_sibling_disconnect(wsi);
	}

	return 0;
}

#if defined(LWS_WITH_CLIENT)
static int
rops_client_transport_up_mqtt(struct lws *wsi)
{
	int n;

	/* clear his established timeout */
	lws_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);

	n = user_callback_handle_rxflow(wsi->a.protocol->callback, wsi,
			(enum lws_callback_reasons)wsi->role_ops->adoption_cb[0],
			wsi->user_space, NULL, 0);
	if (n < 0)
		return -1;

#if defined(LWS_WITH_TLS)
	if (wsi->tls.use_ssl & LCCSCF_USE_SSL) {
		lws_wsi_event(wsi, LWS_WSIEV_TLS_START);

		return 0;
	}
#endif
	lws_wsi_event(wsi, LWS_WSIEV_TRANSPORT_UP);

	/* get the CONNECT out now rather than next time round the loop */
	lws_set_timeout(wsi, PENDING_TIMEOUT_SENT_CLIENT_HANDSHAKE,
			(int)wsi->a.context->timeout_secs);

	return lws_service_wsi_as_writable(wsi);
}
#endif

static const lws_rops_t rops_table_mqtt[] = {
	/*  1 */ { .handle_POLLIN	  = rops_handle_POLLIN_mqtt },
	/*  2 */ { .handle_POLLOUT	  = rops_handle_POLLOUT_mqtt },
	/*  3 */ { .callback_on_writable  = rops_callback_on_writable_mqtt },
	/*  4 */ { .close_role		  = rops_close_role_mqtt },
	/*  5 */ { .close_kill_connection = rops_close_kill_connection_mqtt },
#if defined(LWS_WITH_CLIENT)
	/*  6 */ { .client_bind		  = rops_client_bind_mqtt },
	/*  7 */ { .issue_keepalive	  = rops_issue_keepalive_mqtt },
	/*  8 */ { .client_transport_up	  = rops_client_transport_up_mqtt },
#endif
	/*  9, or 6 with no client */
	{ .rx				  = rops_rx_mqtt },
	/* 10, or 7 with no client */
	{ .rx_policy			  = rops_rx_policy_mqtt },
};

struct lws_role_ops role_ops_mqtt = {
	/* role name */			"mqtt",
	/* alpn id */			"x-amzn-mqtt-ca", /* "mqtt/3.1.1" */

	/* rops_table */		rops_table_mqtt,
	/* rops_idx */			{
	  /* LWS_ROPS_check_upgrades */
	  /* LWS_ROPS_pt_init_destroy */		0x00, 0x00,
	  /* LWS_ROPS_init_vhost */
	  /* LWS_ROPS_destroy_vhost */			0x00, 0x00,
	  /* LWS_ROPS_service_flag_pending */
	  /* LWS_ROPS_handle_POLLIN */			0x00, 0x01,
	  /* LWS_ROPS_handle_POLLOUT */
	  /* LWS_ROPS_perform_user_POLLOUT */		0x02, 0x00,
	  /* LWS_ROPS_callback_on_writable */
	  /* LWS_ROPS_tx_credit */			0x03, 0x00,
	  /* LWS_ROPS_write_role_protocol */
	  /* LWS_ROPS_encapsulation_parent */		0x00, 0x00,
	  /* LWS_ROPS_alpn_negotiated */
	  /* LWS_ROPS_close_via_role_protocol */	0x00, 0x00,
	  /* LWS_ROPS_close_role */
	  /* LWS_ROPS_close_kill_connection */		0x04, 0x05,
	  /* LWS_ROPS_destroy_role */
	  /* LWS_ROPS_adoption_bind */			0x00, 0x00,

	  /* LWS_ROPS_client_bind */
#if defined(LWS_WITH_CLIENT)
	  /* LWS_ROPS_issue_keepalive */		0x06, 0x07,
	  /* LWS_ROPS_client_transport_up */
	  /* LWS_ROPS_rx */				0x08, 0x09,
	  /* LWS_ROPS_rx_dgram */
	  /* LWS_ROPS_rx_policy */			0x00, 0x0A,
#else
	  /* LWS_ROPS_issue_keepalive */		0x00, 0x00,
	  /* LWS_ROPS_client_transport_up */
	  /* LWS_ROPS_rx */				0x00, 0x06,
	  /* LWS_ROPS_rx_dgram */
	  /* LWS_ROPS_rx_policy */			0x00, 0x07,
#endif
					},

	.adoption_cb =			{ LWS_CALLBACK_MQTT_NEW_CLIENT_INSTANTIATED,
					  LWS_CALLBACK_MQTT_NEW_CLIENT_INSTANTIATED },
	.rx_cb =			{ LWS_CALLBACK_MQTT_CLIENT_RX,
					  LWS_CALLBACK_MQTT_CLIENT_RX },
	.writeable_cb =			{ LWS_CALLBACK_MQTT_CLIENT_WRITEABLE,
					  LWS_CALLBACK_MQTT_CLIENT_WRITEABLE },
	.close_cb =			{ LWS_CALLBACK_MQTT_CLIENT_CLOSED,
					  LWS_CALLBACK_MQTT_CLIENT_CLOSED },
	.protocol_bind_cb =		{ LWS_CALLBACK_MQTT_IDLE,
					  LWS_CALLBACK_MQTT_IDLE },
	.protocol_unbind_cb =		{ LWS_CALLBACK_MQTT_DROP_PROTOCOL,
					  LWS_CALLBACK_MQTT_DROP_PROTOCOL },
	.file_handle =			0,
};
