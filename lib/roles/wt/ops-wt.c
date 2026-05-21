/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
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

#include <libwebsockets.h>
#include <libwebsockets/lws-webtransport.h>
#include <private-lib-core.h>

static lws_handling_result_t
rops_handle_POLLIN_wt(struct lws_context_per_thread *pt, struct lws *wsi,
		      struct lws_pollfd *pollfd)
{
	/* 
	 * Payload receiving for WT streams and Session datagrams is 
	 * typically pushed from the QUIC/H3 layers via LWS_CALLBACK_RECEIVE
	 * or through lws_buflist.
	 */
	return LWS_HPI_RET_HANDLED;
}

static int
rops_write_role_protocol_wt(struct lws *wsi, unsigned char *buf, size_t len,
			    enum lws_write_protocol *wp)
{
	struct lws *nwsi = lws_get_network_wsi(wsi);

	if (!nwsi)
		return -1;

	/* 
	 * If we are the WT Session WSI (the upgraded CONNECT stream),
	 * writes to this WSI are sent as QUIC DATAGRAMs.
	 */
	if (wsi->wt.is_session) {
		/* Datagram payload requires Quarter Session ID prefix */
		uint8_t qsid_buf[8];
		size_t qsid_len;
		uint64_t qsid = wsi->mux.my_sid / 4;
		
		qsid_len = lws_quic_write_varint(qsid_buf, sizeof(qsid_buf), qsid);
		
		/* We must insert the quarter session ID at the start.
		 * Fortunately, LWS_PRE gives us space before 'buf' */
		if (len > 0) {
			buf -= qsid_len;
			len += qsid_len;
			memcpy(buf, qsid_buf, qsid_len);
		}
		
		/* Flag to send as DATAGRAM frame */
		*wp = (enum lws_write_protocol)(((unsigned int)*wp & ~0x1fu) | (unsigned int)LWS_WRITE_QUIC_DATAGRAM);
		
		return lws_rops_func_fidx(nwsi->role_ops, LWS_ROPS_write_role_protocol).
			write_role_protocol(nwsi, buf, len, wp);
	}

	/* 
	 * Otherwise it's a WT Child Stream. Just pass it down to QUIC,
	 * as it maps 1:1 to a QUIC stream.
	 */
	return lws_rops_func_fidx(nwsi->role_ops, LWS_ROPS_write_role_protocol).
		write_role_protocol(wsi, buf, len, wp);
}

static int
rops_close_kill_connection_wt(struct lws *wsi, enum lws_close_status reason)
{
	if (wsi->wt.wtn) {
		lws_free_set_NULL(wsi->wt.wtn);
	}
	return 0;
}

LWS_VISIBLE struct lws *
lws_wt_create_stream(struct lws *wsi_session, int unidi)
{
	struct lws *nwsi = lws_get_network_wsi(wsi_session);
	struct lws_quic_netconn *qn = nwsi ? nwsi->quic.qn : NULL;
	struct lws *cwsi;

	if (!qn || !wsi_session->wt.is_session)
		return NULL;

	cwsi = lws_create_new_server_wsi(nwsi->a.vhost, nwsi->tsi, 0, "wt_stream");
	if (!cwsi)
		return NULL;

	lws_role_transition(cwsi, LWSIFR_CLIENT, LRS_ESTABLISHED, &role_ops_wt);
	cwsi->mux_substream = 1;
#if defined(LWS_WITH_CLIENT)
	cwsi->client_mux_substream = 1;
#endif

	cwsi->quic.qs = lws_zalloc(sizeof(*cwsi->quic.qs), "quic stream");
	if (!cwsi->quic.qs) {
		lws_close_free_wsi(cwsi, LWS_CLOSE_STATUS_NOSTATUS, "oom");
		return NULL;
	}

	cwsi->quic.qs->wsi = cwsi;

	if (unidi) {
		cwsi->wt.is_unidi = 1;
		cwsi->quic.qs->is_unidirectional = 1;
		cwsi->quic.qs->stream_id = qn->next_stream_id_unidi_local;
		qn->next_stream_id_unidi_local += 4;
		
		if (qn->peer_initial_max_stream_data_uni) {
			cwsi->txc.tx_cr = (int32_t)qn->peer_initial_max_stream_data_uni;
			cwsi->txc.peer_tx_cr_est = (int32_t)qn->peer_initial_max_stream_data_uni;
		} else {
			cwsi->txc.tx_cr = 65535;
			cwsi->txc.peer_tx_cr_est = 65535;
		}
	} else {
		cwsi->wt.is_unidi = 0;
		cwsi->quic.qs->is_unidirectional = 0;
		cwsi->quic.qs->stream_id = qn->next_stream_id_bidi_local;
		qn->next_stream_id_bidi_local += 4;
		
		if (qn->peer_initial_max_stream_data_bidi_remote) {
			cwsi->txc.tx_cr = (int32_t)qn->peer_initial_max_stream_data_bidi_remote;
			cwsi->txc.peer_tx_cr_est = (int32_t)qn->peer_initial_max_stream_data_bidi_remote;
		} else {
			cwsi->txc.tx_cr = 65535;
			cwsi->txc.peer_tx_cr_est = 65535;
		}
	}

	cwsi->quic.qs->is_server_initiated = qn->is_server ? 1u : 0u;
	cwsi->quic.qs->rx_max_data = LWS_QUIC_DEFAULT_WINDOW;
	cwsi->quic.qs->rx_window_size = LWS_QUIC_DEFAULT_WINDOW;
	cwsi->quic.qs->last_rx_update_us = lws_now_usecs();

	lws_wsi_mux_insert(cwsi, nwsi, (unsigned int)cwsi->quic.qs->stream_id);
	cwsi->mux.my_sid = (unsigned int)cwsi->quic.qs->stream_id;
	
	cwsi->a.protocol = wsi_session->a.protocol;
	
	/* Send WebTransport Stream Header (Type + Quarter Session ID) */
	{
		uint8_t pre[LWS_PRE + 16];
		uint8_t *p = &pre[LWS_PRE];
		size_t hlen = 0;
		uint64_t qsid = wsi_session->mux.my_sid / 4;
		
		hlen += lws_quic_write_varint(p, 16, unidi ? LWS_WT_STREAM_TYPE_UNIDI : LWS_WT_STREAM_TYPE_BIDI);
		hlen += lws_quic_write_varint(p + hlen, 16 - hlen, qsid);
		
		lws_write(cwsi, p, hlen, LWS_WRITE_BINARY | LWS_WRITE_NO_FIN);
	}

	return cwsi;
}

LWS_VISIBLE int
lws_wt_is_session(struct lws *wsi)
{
	return wsi->wt.is_session;
}

static const lws_rops_t rops_table_wt[] = {
	/*  1 */ { .handle_POLLIN	  = rops_handle_POLLIN_wt },
	/*  2 */ { .write_role_protocol	  = rops_write_role_protocol_wt },
	/*  3 */ { .close_kill_connection = rops_close_kill_connection_wt },
};

const struct lws_role_ops role_ops_wt = {
	/* role name */			"wt",
	/* alpn id */			"wt",

	/* rops_table */		rops_table_wt,
	/* rops_idx */			{
	  /* LWS_ROPS_check_upgrades */
	  /* LWS_ROPS_pt_init_destroy */		0x00,
	  /* LWS_ROPS_init_vhost */
	  /* LWS_ROPS_destroy_vhost */			0x00,
	  /* LWS_ROPS_service_flag_pending */
	  /* LWS_ROPS_handle_POLLIN */			0x10,
	  /* LWS_ROPS_handle_POLLOUT */
	  /* LWS_ROPS_perform_user_POLLOUT */		0x00,
	  /* LWS_ROPS_callback_on_writable */
	  /* LWS_ROPS_tx_credit */			0x00,
	  /* LWS_ROPS_write_role_protocol */
	  /* LWS_ROPS_encapsulation_parent */		0x02,
	  /* LWS_ROPS_alpn_negotiated */
	  /* LWS_ROPS_close_via_role_protocol */	0x00,
	  /* LWS_ROPS_close_role */
	  /* LWS_ROPS_close_kill_connection */		0x30,
	  /* LWS_ROPS_destroy_role */
	  /* LWS_ROPS_adoption_bind */			0x00,
	  /* LWS_ROPS_client_bind */
	  /* LWS_ROPS_issue_keepalive */		0x00,
	},

	/* adoption_cb clnt, srv */	{ LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED, LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED },
	/* rx_cb clnt, srv */		{ LWS_CALLBACK_RECEIVE, LWS_CALLBACK_RECEIVE },
	/* writeable cb clnt, srv */	{ LWS_CALLBACK_CLIENT_WRITEABLE, LWS_CALLBACK_SERVER_WRITEABLE },
	/* close cb clnt, srv */	{ LWS_CALLBACK_CLOSED, LWS_CALLBACK_CLOSED },
	/* protocol_bind_cb c,s */	{ 0, 0 },
	/* protocol_unbind_cb c,s */	{ 0, 0 },
	/* file_handle */		0,
};
