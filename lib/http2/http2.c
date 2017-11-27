/*
 * libwebsockets - small server side websockets and web server implementation
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


#include "private-libwebsockets.h"

/*
 * bitmap of control messages that are valid to receive for each http2 state
 */

static const uint16_t http2_rx_validity[] = {
	/* LWS_H2S_IDLE */
		(1 << LWS_H2_FRAME_TYPE_SETTINGS) |
		(1 << LWS_H2_FRAME_TYPE_PRIORITY) |
//		(1 << LWS_H2_FRAME_TYPE_WINDOW_UPDATE)| /* ignore */
		(1 << LWS_H2_FRAME_TYPE_HEADERS) |
		(1 << LWS_H2_FRAME_TYPE_CONTINUATION),
	/* LWS_H2S_RESERVED_LOCAL */
		(1 << LWS_H2_FRAME_TYPE_SETTINGS) |
		(1 << LWS_H2_FRAME_TYPE_RST_STREAM) |
		(1 << LWS_H2_FRAME_TYPE_PRIORITY) |
		(1 << LWS_H2_FRAME_TYPE_WINDOW_UPDATE),
	/* LWS_H2S_RESERVED_REMOTE */
		(1 << LWS_H2_FRAME_TYPE_SETTINGS) |
		(1 << LWS_H2_FRAME_TYPE_HEADERS) |
		(1 << LWS_H2_FRAME_TYPE_CONTINUATION) |
		(1 << LWS_H2_FRAME_TYPE_RST_STREAM) |
		(1 << LWS_H2_FRAME_TYPE_PRIORITY),
	/* LWS_H2S_OPEN */
		(1 << LWS_H2_FRAME_TYPE_DATA) |
		(1 << LWS_H2_FRAME_TYPE_HEADERS) |
		(1 << LWS_H2_FRAME_TYPE_PRIORITY) |
		(1 << LWS_H2_FRAME_TYPE_RST_STREAM) |
		(1 << LWS_H2_FRAME_TYPE_SETTINGS) |
		(1 << LWS_H2_FRAME_TYPE_PUSH_PROMISE) |
		(1 << LWS_H2_FRAME_TYPE_PING) |
		(1 << LWS_H2_FRAME_TYPE_GOAWAY) |
		(1 << LWS_H2_FRAME_TYPE_WINDOW_UPDATE) |
		(1 << LWS_H2_FRAME_TYPE_CONTINUATION),
	/* LWS_H2S_HALF_CLOSED_REMOTE */
		(1 << LWS_H2_FRAME_TYPE_SETTINGS) |
		(1 << LWS_H2_FRAME_TYPE_WINDOW_UPDATE) |
		(1 << LWS_H2_FRAME_TYPE_PRIORITY) |
		(1 << LWS_H2_FRAME_TYPE_RST_STREAM),
	/* LWS_H2S_HALF_CLOSED_LOCAL */
		(1 << LWS_H2_FRAME_TYPE_DATA) |
		(1 << LWS_H2_FRAME_TYPE_HEADERS) |
		(1 << LWS_H2_FRAME_TYPE_PRIORITY) |
		(1 << LWS_H2_FRAME_TYPE_RST_STREAM) |
		(1 << LWS_H2_FRAME_TYPE_SETTINGS) |
		(1 << LWS_H2_FRAME_TYPE_PUSH_PROMISE) |
		(1 << LWS_H2_FRAME_TYPE_PING) |
		(1 << LWS_H2_FRAME_TYPE_GOAWAY) |
		(1 << LWS_H2_FRAME_TYPE_WINDOW_UPDATE) |
		(1 << LWS_H2_FRAME_TYPE_CONTINUATION),
	/* LWS_H2S_CLOSED */
		(1 << LWS_H2_FRAME_TYPE_SETTINGS) |
		(1 << LWS_H2_FRAME_TYPE_PRIORITY) |
		(1 << LWS_H2_FRAME_TYPE_WINDOW_UPDATE) |
		(1 << LWS_H2_FRAME_TYPE_RST_STREAM),
};

static const char *preface = "PRI * HTTP/2.0\x0d\x0a\x0d\x0aSM\x0d\x0a\x0d\x0a";

static const char * const h2_state_names[] = {
	"LWS_H2S_IDLE",
	"LWS_H2S_RESERVED_LOCAL",
	"LWS_H2S_RESERVED_REMOTE",
	"LWS_H2S_OPEN",
	"LWS_H2S_HALF_CLOSED_REMOTE",
	"LWS_H2S_HALF_CLOSED_LOCAL",
	"LWS_H2S_CLOSED",
};

#if 0
static const char * const h2_setting_names[] = {
	"",
	"H2SET_HEADER_TABLE_SIZE",
	"H2SET_ENABLE_PUSH",
	"H2SET_MAX_CONCURRENT_STREAMS",
	"H2SET_INITIAL_WINDOW_SIZE",
	"H2SET_MAX_FRAME_SIZE",
	"H2SET_MAX_HEADER_LIST_SIZE",
};

void
lws_h2_dump_settings(struct http2_settings *set)
{
	int n;

	for (n = 1; n < H2SET_COUNT; n++)
		lwsl_notice("   %30s: %10d\n", h2_setting_names[n], set->s[n]);
}
#else
void
lws_h2_dump_settings(struct http2_settings *set)
{
}
#endif

void lws_h2_init(struct lws *wsi)
{
	wsi->u.h2.h2n->set = wsi->vhost->set;
}

static void
lws_h2_state(struct lws *wsi, enum lws_h2_states s)
{
	if (!wsi)
		return;
	lwsl_info("%s: wsi %p: state %s -> %s\n", __func__, wsi,
			h2_state_names[wsi->u.h2.h2_state],
			h2_state_names[s]);

	(void)h2_state_names;
	wsi->u.h2.h2_state = (uint8_t)s;
}

struct lws *
lws_wsi_server_new(struct lws_vhost *vh, struct lws *parent_wsi,
			    unsigned int sid)
{
	struct lws *wsi;
	struct lws *nwsi = lws_get_network_wsi(parent_wsi);
	struct lws_h2_netconn *h2n = nwsi->u.h2.h2n;

	/*
	 * The identifier of a newly established stream MUST be numerically
   	 * greater than all streams that the initiating endpoint has opened or
   	 * reserved.  This governs streams that are opened using a HEADERS frame
   	 * and streams that are reserved using PUSH_PROMISE.  An endpoint that
   	 * receives an unexpected stream identifier MUST respond with a
   	 * connection error (Section 5.4.1) of type PROTOCOL_ERROR.
	 */
	if (sid <= h2n->highest_sid_opened) {
		lws_h2_goaway(nwsi, H2_ERR_PROTOCOL_ERROR, "Bad sid");
		return NULL;
	}

	/* no more children allowed by parent */
	if (parent_wsi->u.h2.child_count + 1 >
	    parent_wsi->u.h2.h2n->set.s[H2SET_MAX_CONCURRENT_STREAMS]) {
		lwsl_notice("reached concurrent stream limit\n");
		return NULL;
	}
	wsi = lws_create_new_server_wsi(vh);
	if (!wsi) {
		lwsl_notice("new server wsi failed (vh %p)\n", vh);
		return NULL;
	}

	h2n->highest_sid_opened = sid;
	wsi->u.h2.my_sid = sid;
	wsi->http2_substream = 1;
	wsi->seen_nonpseudoheader = 0;

	wsi->u.h2.parent_wsi = parent_wsi;
	/* new guy's sibling is whoever was the first child before */
	wsi->u.h2.sibling_list = parent_wsi->u.h2.child_list;
	/* first child is now the new guy */
	parent_wsi->u.h2.child_list = wsi;
	parent_wsi->u.h2.child_count++;

	wsi->u.h2.my_priority = 16;
	wsi->u.h2.tx_cr = nwsi->u.h2.h2n->set.s[H2SET_INITIAL_WINDOW_SIZE];
	wsi->u.h2.peer_tx_cr_est = nwsi->vhost->set.s[H2SET_INITIAL_WINDOW_SIZE];

	wsi->state = LWSS_HTTP2_ESTABLISHED;
	wsi->mode = parent_wsi->mode;

	wsi->protocol = &vh->protocols[0];
	if (lws_ensure_user_space(wsi))
		goto bail1;

	wsi->vhost->conn_stats.h2_subs++;

	lwsl_info("%s: %p new ch %p, sid %d, usersp=%p, tx cr %d, "
		  "peer_credit %d (nwsi tx_cr %d)\n",
		  __func__, parent_wsi, wsi, sid, wsi->user_space,
		  wsi->u.h2.tx_cr, wsi->u.h2.peer_tx_cr_est, nwsi->u.h2.tx_cr);

	return wsi;

bail1:
	/* undo the insert */
	parent_wsi->u.h2.child_list = wsi->u.h2.sibling_list;
	parent_wsi->u.h2.child_count--;

	if (wsi->user_space)
		lws_free_set_NULL(wsi->user_space);
	vh->protocols[0].callback(wsi, LWS_CALLBACK_WSI_DESTROY, NULL, NULL, 0);
	lws_free(wsi);

	return NULL;
}

struct lws *
lws_h2_wsi_from_id(struct lws *parent_wsi, unsigned int sid)
{
	lws_start_foreach_ll(struct lws *, wsi, parent_wsi->u.h2.child_list) {
		if (wsi->u.h2.my_sid == sid)
			return wsi;
	} lws_end_foreach_ll(wsi, u.h2.sibling_list);

	return NULL;
}

int lws_remove_server_child_wsi(struct lws_context *context, struct lws *wsi)
{
	lws_start_foreach_llp(struct lws **, w, wsi->u.h2.child_list) {
		if (*w == wsi) {
			*w = wsi->u.h2.sibling_list;
			(wsi->u.h2.parent_wsi)->u.h2.child_count--;
			return 0;
		}
	} lws_end_foreach_llp(w, u.h2.sibling_list);

	lwsl_err("%s: can't find %p\n", __func__, wsi);

	return 1;
}

void
lws_pps_schedule(struct lws *wsi, struct lws_h2_protocol_send *pps)
{
	struct lws *nwsi = lws_get_network_wsi(wsi);
	struct lws_h2_netconn *h2n = nwsi->u.h2.h2n;

	pps->next = h2n->pps;
	h2n->pps = pps;
	lws_rx_flow_control(wsi, LWS_RXFLOW_REASON_APPLIES_DISABLE |
				 LWS_RXFLOW_REASON_H2_PPS_PENDING);
	lws_callback_on_writable(wsi);
}

static struct lws_h2_protocol_send *
lws_h2_new_pps(enum lws_h2_protocol_send_type type)
{
	struct lws_h2_protocol_send *pps = lws_malloc(sizeof(*pps), "pps");

	if (pps)
		pps->type = type;

	return pps;
}

int
lws_h2_goaway(struct lws *wsi, uint32_t err, const char *reason)
{
	struct lws_h2_netconn *h2n = wsi->u.h2.h2n;
	struct lws_h2_protocol_send *pps;

	if (h2n->type == LWS_H2_FRAME_TYPE_COUNT)
		return 0;

	pps = lws_h2_new_pps(LWS_H2_PPS_GOAWAY);
	if (!pps)
		return 1;

	lwsl_info("%s: %p: ERR 0x%x, '%s'\n", __func__, wsi, err, reason);

	pps->u.ga.err = err;
	pps->u.ga.highest_sid = h2n->highest_sid;
	strncpy(pps->u.ga.str, reason, sizeof(pps->u.ga.str) - 1);
	pps->u.ga.str[sizeof(pps->u.ga.str) - 1] = '\0';
	lws_pps_schedule(wsi, pps);

	h2n->type = LWS_H2_FRAME_TYPE_COUNT; /* ie, IGNORE */

	return 0;
}

int
lws_h2_rst_stream(struct lws *wsi, uint32_t err, const char *reason)
{
	struct lws *nwsi = lws_get_network_wsi(wsi);
	struct lws_h2_netconn *h2n = nwsi->u.h2.h2n;
	struct lws_h2_protocol_send *pps;

	if (h2n->type == LWS_H2_FRAME_TYPE_COUNT)
		return 0;

	pps = lws_h2_new_pps(LWS_H2_PPS_RST_STREAM);
	if (!pps)
		return 1;

	lwsl_info("%s: RST_STREAM 0x%x, REASON '%s'\n", __func__, err, reason);

	pps->u.rs.sid = h2n->sid;
	pps->u.rs.err = err;
	lws_pps_schedule(wsi, pps);

	h2n->type = LWS_H2_FRAME_TYPE_COUNT; /* ie, IGNORE */
	lws_h2_state(wsi, LWS_H2_STATE_CLOSED);

	return 0;
}

int
lws_h2_settings(struct lws *wsi, struct http2_settings *settings,
			unsigned char *buf, int len)
{
	struct lws *nwsi = lws_get_network_wsi(wsi);
	unsigned int a, b;

	if (!len)
		return 0;

	if (len < LWS_H2_SETTINGS_LEN)
		return 1;

	while (len >= LWS_H2_SETTINGS_LEN) {
		a = (buf[0] << 8) | buf[1];
		if (!a || a >= H2SET_COUNT)
			goto skip;
		b = buf[2] << 24 | buf[3] << 16 | buf[4] << 8 | buf[5];

		switch (a) {
		case H2SET_HEADER_TABLE_SIZE:
			break;
		case H2SET_ENABLE_PUSH:
			if (b > 1) {
				lws_h2_goaway(nwsi, H2_ERR_PROTOCOL_ERROR,
					      "ENABLE_PUSH invalid arg");
				return 1;
			}
			break;
		case H2SET_MAX_CONCURRENT_STREAMS:
			break;
		case H2SET_INITIAL_WINDOW_SIZE:
			if (b > 0x7fffffff) {
				lws_h2_goaway(nwsi, H2_ERR_FLOW_CONTROL_ERROR,
					      "Inital Window beyond max");
				return 1;
			}
			/*
			 * In addition to changing the flow-control window for
			 * streams that are not yet active, a SETTINGS frame
			 * can alter the initial flow-control window size for
			 * streams with active flow-control windows (that is,
			 * streams in the "open" or "half-closed (remote)"
			 * state).  When the value of
			 * SETTINGS_INITIAL_WINDOW_SIZE changes, a receiver
			 * MUST adjust the size of all stream flow-control
			 * windows that it maintains by the difference between
			 * the new value and the old value.
			 */

			lws_start_foreach_ll(struct lws *, w,
					     nwsi->u.h2.child_list) {
				lwsl_info("%s: adi child tc cr %d +%d -> %d",
					    __func__,
					    w->u.h2.tx_cr, b - settings->s[a],
					    w->u.h2.tx_cr + b - settings->s[a]);
				w->u.h2.tx_cr += b - settings->s[a];
				if (w->u.h2.tx_cr > 0 &&
				    w->u.h2.tx_cr <= b - settings->s[a])
					lws_callback_on_writable(w);
			} lws_end_foreach_ll(w, u.h2.sibling_list);

			break;
		case H2SET_MAX_FRAME_SIZE:
			if (b < wsi->vhost->set.s[H2SET_MAX_FRAME_SIZE]) {
				lws_h2_goaway(nwsi, H2_ERR_PROTOCOL_ERROR,
					      "Frame size < initial");
				return 1;
			}
			if (b > 0x007fffff) {
				lws_h2_goaway(nwsi, H2_ERR_PROTOCOL_ERROR,
					      "Settings Frame size above max");
				return 1;
			}
			break;
		case H2SET_MAX_HEADER_LIST_SIZE:
			break;
		}
		settings->s[a] = b;
		lwsl_info("http2 settings %d <- 0x%x\n", a, b);
skip:
		len -= LWS_H2_SETTINGS_LEN;
		buf += LWS_H2_SETTINGS_LEN;
	}

	if (len)
		return 1;

	lws_h2_dump_settings(settings);

	return 0;
}

/* RFC7640 Sect 6.9
 *
 * The WINDOW_UPDATE frame can be specific to a stream or to the entire
 * connection.  In the former case, the frame's stream identifier
 * indicates the affected stream; in the latter, the value "0" indicates
 * that the entire connection is the subject of the frame.
 *
 * ...
 *
 * Two flow-control windows are applicable: the stream flow-control
 * window and the connection flow-control window.  The sender MUST NOT
 * send a flow-controlled frame with a length that exceeds the space
 * available in either of the flow-control windows advertised by the
 * receiver.  Frames with zero length with the END_STREAM flag set (that
 * is, an empty DATA frame) MAY be sent if there is no available space
 * in either flow-control window.
 */

int
lws_h2_tx_cr_get(struct lws *wsi)
{
	int c = wsi->u.h2.tx_cr;
	struct lws *nwsi;

	if (!wsi->http2_substream && !wsi->upgraded_to_http2)
		return ~0x80000000;

	nwsi = lws_get_network_wsi(wsi);

	lwsl_info ("%s: %p: own tx credit %d: nwsi credit %d\n",
		     __func__, wsi, c, nwsi->u.h2.tx_cr);

	if (nwsi->u.h2.tx_cr < c)
		c = nwsi->u.h2.tx_cr;

	if (c < 0)
		return 0;

	return c;
}

void
lws_h2_tx_cr_consume(struct lws *wsi, int consumed)
{
	struct lws *nwsi = lws_get_network_wsi(wsi);

	wsi->u.h2.tx_cr -= consumed;

	if (nwsi != wsi)
		nwsi->u.h2.tx_cr -= consumed;
}

int lws_h2_frame_write(struct lws *wsi, int type, int flags,
		       unsigned int sid, unsigned int len, unsigned char *buf)
{
	struct lws *nwsi = lws_get_network_wsi(wsi);
	unsigned char *p = &buf[-LWS_H2_FRAME_HEADER_LENGTH];
	int n;

	*p++ = len >> 16;
	*p++ = len >> 8;
	*p++ = len;
	*p++ = type;
	*p++ = flags;
	*p++ = sid >> 24;
	*p++ = sid >> 16;
	*p++ = sid >> 8;
	*p++ = sid;

	lwsl_debug("%s: %p (eff %p). typ %d, fl 0x%x, sid=%d, len=%d, "
		  "txcr=%d, nwsi->txcr=%d\n", __func__, wsi, nwsi, type, flags,
		  sid, len, wsi->u.h2.tx_cr, nwsi->u.h2.tx_cr);

	if (type == LWS_H2_FRAME_TYPE_DATA) {
		if (wsi->u.h2.tx_cr < len)
			lwsl_err("%s: %p: sending payload len %d"
				 " but tx_cr only %d!\n", __func__, wsi,
				 len, wsi->u.h2.tx_cr);
		lws_h2_tx_cr_consume(wsi, len);
	}

	n = lws_issue_raw(nwsi, &buf[-LWS_H2_FRAME_HEADER_LENGTH],
			  len + LWS_H2_FRAME_HEADER_LENGTH);
	if (n < 0)
		return n;

	if (n >= LWS_H2_FRAME_HEADER_LENGTH)
		return n - LWS_H2_FRAME_HEADER_LENGTH;

	return n;
}

static void lws_h2_set_bin(struct lws *wsi, int n, unsigned char *buf)
{
	*buf++ = n >> 8;
	*buf++ = n;
	*buf++ = wsi->u.h2.h2n->set.s[n] >> 24;
	*buf++ = wsi->u.h2.h2n->set.s[n] >> 16;
	*buf++ = wsi->u.h2.h2n->set.s[n] >> 8;
	*buf = wsi->u.h2.h2n->set.s[n];
}

int lws_h2_do_pps_send(struct lws *wsi)
{
	struct lws_h2_netconn *h2n = wsi->u.h2.h2n;
	struct lws_h2_protocol_send *pps = NULL;
	struct lws *cwsi;
	uint8_t set[LWS_PRE + 64], *p = &set[LWS_PRE], *q;
	int n, m = 0;

	if (!h2n)
		return 1;

	/* get the oldest pps */

	lws_start_foreach_llp(struct lws_h2_protocol_send **, pps1, h2n->pps) {
		if ((*pps1)->next == NULL) { /* we are the oldest in the list */
			pps = *pps1; /* remove us from the list */
			*pps1 = NULL;
			continue;
		}
	} lws_end_foreach_llp(pps1, next);

	if (!pps)
		return 1;

	lwsl_info("%s: %p: %d\n", __func__, wsi, pps->type);

	switch (pps->type) {

	case LWS_H2_PPS_MY_SETTINGS:
		/*
		 * if any of our settings varies from h2 "default defaults"
		 * then we must inform the perr
		 */
		for (n = 1; n < H2SET_COUNT; n++)
			if (h2n->set.s[n] != lws_h2_defaults.s[n]) {
				lwsl_debug("sending SETTING %d 0x%x\n", n,
						wsi->u.h2.h2n->set.s[n]);
				lws_h2_set_bin(wsi, n, &set[LWS_PRE + m]);
				m += sizeof(h2n->one_setting);
			}
		n = lws_h2_frame_write(wsi, LWS_H2_FRAME_TYPE_SETTINGS,
		     		       0, LWS_H2_STREAM_ID_MASTER, m,
		     		       &set[LWS_PRE]);
		if (n != m) {
			lwsl_info("send %d %d\n", n, m);
			goto bail;
		}
		break;

	case LWS_H2_PPS_ACK_SETTINGS:
		/* send ack ... always empty */
		n = lws_h2_frame_write(wsi, LWS_H2_FRAME_TYPE_SETTINGS, 1,
				       LWS_H2_STREAM_ID_MASTER, 0, &set[LWS_PRE]);
		if (n) {
			lwsl_err("ack tells %d\n", n);
			goto bail;
		}
		/* this is the end of the preface dance then? */
		if (wsi->state == LWSS_HTTP2_ESTABLISHED_PRE_SETTINGS) {
			wsi->state = LWSS_HTTP2_ESTABLISHED;
			wsi->u.http.fop_fd = NULL;
			if (lws_is_ssl(lws_get_network_wsi(wsi)))
				break;
			/*
			 * we need to treat the headers from the upgrade as the
			 * first job.  So these need to get shifted to sid 1.
			 */
			h2n->swsi = lws_wsi_server_new(wsi->vhost, wsi, 1);
			if (!h2n->swsi)
				goto bail;

			/* pass on the initial headers to SID 1 */
			h2n->swsi->u.http.ah = wsi->u.http.ah;
			wsi->u.http.ah = NULL;

			lwsl_info("%s: inherited headers %p\n", __func__,
				  h2n->swsi->u.http.ah);
			h2n->swsi->u.h2.tx_cr =
				h2n->set.s[H2SET_INITIAL_WINDOW_SIZE];
			lwsl_info("initial tx credit on conn %p: %d\n",
				  h2n->swsi, h2n->swsi->u.h2.tx_cr);
			h2n->swsi->u.h2.initialized = 1;
			/* demanded by HTTP2 */
			h2n->swsi->u.h2.END_STREAM = 1;
			lwsl_info("servicing initial http request\n");

			wsi->vhost->conn_stats.h2_trans++;

			if (lws_http_action(h2n->swsi))
				goto bail;

			break;
		}
		break;
	case LWS_H2_PPS_PONG:
		lwsl_debug("sending PONG\n");
		memcpy(&set[LWS_PRE], pps->u.ping.ping_payload, 8);
		n = lws_h2_frame_write(wsi, LWS_H2_FRAME_TYPE_PING,
		     		       LWS_H2_FLAG_SETTINGS_ACK,
				       LWS_H2_STREAM_ID_MASTER, 8,
				       &set[LWS_PRE]);
		if (n != 8) {
			lwsl_info("send %d %d\n", n, m);
			goto bail;
		}
		break;

	case LWS_H2_PPS_GOAWAY:
		lwsl_info("LWS_H2_PPS_GOAWAY\n");
		*p++ = pps->u.ga.highest_sid >> 24;
		*p++ = pps->u.ga.highest_sid >> 16;
		*p++ = pps->u.ga.highest_sid >> 8;
		*p++ = pps->u.ga.highest_sid;
		*p++ = pps->u.ga.err >> 24;
		*p++ = pps->u.ga.err >> 16;
		*p++ = pps->u.ga.err >> 8;
		*p++ = pps->u.ga.err;
		q = (unsigned char *)pps->u.ga.str;
		n = 0;
		while (*q && n++ < sizeof(pps->u.ga.str))
			*p++ = *q++;
		h2n->we_told_goaway = 1;
		n = lws_h2_frame_write(wsi, LWS_H2_FRAME_TYPE_GOAWAY, 0,
				       LWS_H2_STREAM_ID_MASTER,
				       p - &set[LWS_PRE], &set[LWS_PRE]);
		if (n != 4) {
			lwsl_info("send %d %d\n", n, m);
			goto bail;
		}
		goto bail;

	case LWS_H2_PPS_RST_STREAM:
		lwsl_info("LWS_H2_PPS_RST_STREAM\n");
		*p++ = pps->u.rs.err >> 24;
		*p++ = pps->u.rs.err >> 16;
		*p++ = pps->u.rs.err >> 8;
		*p++ = pps->u.rs.err;
		n = lws_h2_frame_write(wsi, LWS_H2_FRAME_TYPE_RST_STREAM,
				       0, pps->u.rs.sid, 4, &set[LWS_PRE]);
		if (n != 4) {
			lwsl_info("send %d %d\n", n, m);
			goto bail;
		}
		cwsi = lws_h2_wsi_from_id(wsi, pps->u.rs.sid);
		if (cwsi)
			lws_close_free_wsi(cwsi, 0);
		break;

	case LWS_H2_PPS_UPDATE_WINDOW:
		lwsl_notice("LWS_H2_PPS_UPDATE_WINDOW: sid %d: add %d\n",
			    pps->u.update_window.sid,
			    pps->u.update_window.credit);
		*p++ = pps->u.update_window.credit >> 24;
		*p++ = pps->u.update_window.credit >> 16;
		*p++ = pps->u.update_window.credit >> 8;
		*p++ = pps->u.update_window.credit;
		n = lws_h2_frame_write(wsi, LWS_H2_FRAME_TYPE_WINDOW_UPDATE,
				       0, pps->u.update_window.sid, 4,
				       &set[LWS_PRE]);
		if (n != 4) {
			lwsl_info("send %d %d\n", n, m);
			goto bail;
		}
		break;

	default:
		break;
	}

	lws_free(pps);

	return 0;

bail:
	lws_free(pps);

	return 1;
}

/*
 * The frame header part has just completely arrived.
 * Perform actions for frame completion.
 */
static int
lws_h2_parse_frame_header(struct lws *wsi)
{
	struct lws_h2_netconn *h2n = wsi->u.h2.h2n;
	struct lws_h2_protocol_send *pps;
	int n;

	/*
	 * We just got the frame header
	 */
	h2n->count = 0;
	h2n->swsi = wsi;
	/* b31 is a reserved bit */
	h2n->sid = h2n->sid & 0x7fffffff;

	if (h2n->sid && !(h2n->sid & 1)) {
		lws_h2_goaway(wsi, H2_ERR_PROTOCOL_ERROR, "Even Stream ID");

		return 0;
	}

	/* let the network wsi live a bit longer if subs are active */
	lws_set_timeout(wsi, PENDING_TIMEOUT_HTTP_KEEPALIVE_IDLE, 10);

	/* let the network wsi live a bit longer if subs are active */
	lws_set_timeout(wsi, PENDING_TIMEOUT_HTTP_KEEPALIVE_IDLE, 10);

	if (h2n->sid)
		h2n->swsi = lws_h2_wsi_from_id(wsi, h2n->sid);

	lwsl_info("%p (%p): fr hdr: typ 0x%x, flags 0x%x, sid 0x%x, len 0x%x\n",
		  wsi, h2n->swsi, h2n->type, h2n->flags, h2n->sid,
		  h2n->length);

	if (h2n->we_told_goaway && h2n->sid > h2n->highest_sid)
		h2n->type = LWS_H2_FRAME_TYPE_COUNT; /* ie, IGNORE */

	if (h2n->type == LWS_H2_FRAME_TYPE_COUNT)
		return 0;

	if (h2n->length > h2n->set.s[H2SET_MAX_FRAME_SIZE]) {
		/*
		 * peer sent us something bigger than we told
		 * it we would allow
		 */
		lws_h2_goaway(wsi, H2_ERR_FRAME_SIZE_ERROR,
			      "Peer ignored our frame size setting");
		return 0;
	}

	if (h2n->swsi)
		lwsl_info("%s: wsi %p, State: %s, received cmd %d\n",
		  __func__, h2n->swsi,
		  h2_state_names[h2n->swsi->u.h2.h2_state], h2n->type);
	else {
		/* if it's data, either way no swsi means CLOSED state */
		if (h2n->type == LWS_H2_FRAME_TYPE_DATA) {
			lws_h2_goaway(wsi, H2_ERR_STREAM_CLOSED,
				      "Data for nonexistent sid");
			return 0;
		}
		/* if the sid is credible, treat as wsi for it closed */
		if (h2n->sid > h2n->highest_sid_opened &&
		    h2n->type != LWS_H2_FRAME_TYPE_HEADERS &&
		    h2n->type != LWS_H2_FRAME_TYPE_PRIORITY) {
			/* if not credible, reject it */
			lwsl_info("%s: wsi %p, No child for sid %d, rx cmd %d\n",
			  __func__, h2n->swsi, h2n->sid, h2n->type);
			lws_h2_goaway(wsi, H2_ERR_STREAM_CLOSED,
				     "Data for nonexistent sid");
			return 0;
		}
	}

	if (h2n->swsi && h2n->sid &&
	    !(http2_rx_validity[h2n->swsi->u.h2.h2_state] & (1 << h2n->type))) {
		lwsl_info("%s: wsi %p, State: %s, ILLEGAL cmdrx %d (OK 0x%x)\n",
			  __func__, h2n->swsi,
			  h2_state_names[h2n->swsi->u.h2.h2_state], h2n->type,
			  http2_rx_validity[h2n->swsi->u.h2.h2_state]);

		if (h2n->swsi->u.h2.h2_state == LWS_H2_STATE_CLOSED ||
		    h2n->swsi->u.h2.h2_state == LWS_H2_STATE_HALF_CLOSED_REMOTE)
			n = H2_ERR_STREAM_CLOSED;
		else
			n = H2_ERR_PROTOCOL_ERROR;
		lws_h2_goaway(wsi, n, "invalid rx for state");

		return 0;
	}

	if (h2n->cont_exp && (h2n->cont_exp_sid != h2n->sid ||
			      h2n->type != LWS_H2_FRAME_TYPE_CONTINUATION)) {
		lwsl_info("%s: expected cont on sid %d (got %d on sid %d)\n",
			  __func__, h2n->cont_exp_sid, h2n->type, h2n->sid);
		h2n->cont_exp = 0;
		if (h2n->cont_exp_headers)
			n = H2_ERR_COMPRESSION_ERROR;
		else
			n = H2_ERR_PROTOCOL_ERROR;
		lws_h2_goaway(wsi, n, "Continuation hdrs State");

		return 0;
	}

	switch (h2n->type) {
	case LWS_H2_FRAME_TYPE_DATA:
		lwsl_info("seen incoming LWS_H2_FRAME_TYPE_DATA start\n");
		if (!h2n->sid) {
			lws_h2_goaway(wsi, H2_ERR_PROTOCOL_ERROR, "DATA 0 sid");
			break;
		}
		lwsl_info("Frame header DATA: sid %d\n", h2n->sid);

		if (!h2n->swsi)
			break;

		h2n->swsi->u.h2.peer_tx_cr_est -= h2n->length;
		lwsl_debug("   peer_tx_cr_est %d\n",
			   h2n->swsi->u.h2.peer_tx_cr_est);
		if (h2n->swsi->u.h2.peer_tx_cr_est < 32768) {
			h2n->swsi->u.h2.peer_tx_cr_est += 65536;
			pps = lws_h2_new_pps(LWS_H2_PPS_UPDATE_WINDOW);
			if (!pps)
				return 1;
			pps->u.update_window.sid = h2n->sid;
			pps->u.update_window.credit = 65536;
			lws_pps_schedule(wsi, pps);
			pps = lws_h2_new_pps(LWS_H2_PPS_UPDATE_WINDOW);
			if (!pps)
				return 1;
			pps->u.update_window.sid = 0;
			pps->u.update_window.credit = 65536;
			lws_pps_schedule(wsi, pps);
		}

		if (
		    h2n->swsi->u.h2.h2_state == LWS_H2_STATE_HALF_CLOSED_REMOTE ||
		    h2n->swsi->u.h2.h2_state == LWS_H2_STATE_CLOSED) {
			lws_h2_goaway(wsi, H2_ERR_STREAM_CLOSED, "conn closed");
			break;
		}
		break;
	case LWS_H2_FRAME_TYPE_PRIORITY:
		lwsl_info("LWS_H2_FRAME_TYPE_PRIORITY complete frame\n");
		if (!h2n->sid) {
			lws_h2_goaway(wsi, H2_ERR_PROTOCOL_ERROR,
				      "Priority has 0 sid");
			break;
		}
		if (h2n->length != 5) {
			lws_h2_goaway(wsi, H2_ERR_FRAME_SIZE_ERROR,
				      "Priority has length other than 5");
			break;
		}
		break;
	case LWS_H2_FRAME_TYPE_PUSH_PROMISE:
		lwsl_info("LWS_H2_FRAME_TYPE_PUSH_PROMISE complete frame\n");
		lws_h2_goaway(wsi, H2_ERR_PROTOCOL_ERROR, "Server only");
		break;

	case LWS_H2_FRAME_TYPE_GOAWAY:
		break;

	case LWS_H2_FRAME_TYPE_RST_STREAM:
		if (!h2n->sid)
			return 1;
		if (!h2n->swsi) {
			if (h2n->sid <= h2n->highest_sid_opened)
				break;
			lws_h2_goaway(wsi, H2_ERR_PROTOCOL_ERROR,
				      "crazy sid on RST_STREAM");
			return 1;
		}
		if (h2n->length != 4) {
			lws_h2_goaway(wsi, H2_ERR_FRAME_SIZE_ERROR,
				      "RST_STREAM can only be length 4");
			break;
		}
		lws_h2_state(h2n->swsi, LWS_H2_STATE_CLOSED);
		break;

	case LWS_H2_FRAME_TYPE_SETTINGS:
		lwsl_info("LWS_H2_FRAME_TYPE_SETTINGS complete frame\n");
		/* nonzero sid on settings is illegal */
		if (h2n->sid) {
			lws_h2_goaway(wsi, H2_ERR_PROTOCOL_ERROR,
					 "Settings has nonzero sid");
			break;
		}

		if (!(h2n->flags & LWS_H2_FLAG_SETTINGS_ACK)) {
			if ((!h2n->length) || h2n->length % 6) {
				lws_h2_goaway(wsi, H2_ERR_FRAME_SIZE_ERROR,
						 "Settings length error");
				break;
			}
			lwsl_info("scheduled settings ack PPS\n");
			/* non-ACK coming in means we must ACK it */


			if (h2n->type == LWS_H2_FRAME_TYPE_COUNT)
				return 0;

			pps = lws_h2_new_pps(LWS_H2_PPS_ACK_SETTINGS);
			if (!pps)
				return 1;
			lws_pps_schedule(wsi, pps);
			break;
		}
		/* came to us with ACK set... not allowed to have payload */

		if (h2n->length) {
			lws_h2_goaway(wsi, H2_ERR_FRAME_SIZE_ERROR,
				      "Settings with ACK not allowed payload");
			break;
		}
		break;
	case LWS_H2_FRAME_TYPE_PING:
		if (h2n->sid) {
			lws_h2_goaway(wsi, H2_ERR_PROTOCOL_ERROR,
				      "Ping has nonzero sid");
			break;
		}
		if (h2n->length != 8) {
			lws_h2_goaway(wsi, H2_ERR_FRAME_SIZE_ERROR,
				      "Ping payload can only be 8");
			break;
		}
		break;
	case LWS_H2_FRAME_TYPE_CONTINUATION:
		lwsl_info("LWS_H2_FRAME_TYPE_CONTINUATION: sid = %d\n",
			  h2n->sid);

		if (!h2n->cont_exp ||
		     h2n->cont_exp_sid != h2n->sid ||
		     !h2n->sid ||
		     !h2n->swsi) {
			lws_h2_goaway(wsi, H2_ERR_PROTOCOL_ERROR,
				      "unexpected CONTINUATION");
			break;
		}
		if (h2n->swsi->u.h2.END_HEADERS) {
			lws_h2_goaway(wsi, H2_ERR_PROTOCOL_ERROR,
				      "END_HEADERS already seen");
			break;
		}
		/* END_STREAM is in HEADERS, skip resetting it */
		goto update_end_headers;

	case LWS_H2_FRAME_TYPE_HEADERS:
		lwsl_info("HEADERS: frame header: sid = %d\n", h2n->sid);
		if (!h2n->sid) {
			lws_h2_goaway(wsi, H2_ERR_PROTOCOL_ERROR, "sid 0");
			return 1;
		}

		if (!h2n->swsi) {
			/* no more children allowed by parent */
			if (wsi->u.h2.child_count + 1 >
			    wsi->u.h2.h2n->set.s[H2SET_MAX_CONCURRENT_STREAMS]) {
				lws_h2_goaway(wsi, H2_ERR_PROTOCOL_ERROR,
				"Another stream not allowed");

				return 1;
			}

			h2n->swsi = lws_wsi_server_new(wsi->vhost, wsi,
						       h2n->sid);
			if (!h2n->swsi) {
				lws_h2_goaway(wsi, H2_ERR_PROTOCOL_ERROR, "OOM");

				return 1;
			}
		}

		/*
		 * ah needs attaching to child wsi, even though
		 * we only fill it from network wsi
		 */
		if (!h2n->swsi->u.hdr.ah)
			if (lws_header_table_attach(h2n->swsi, 0)) {
				lwsl_err("%s: Failed to get ah\n", __func__);
				return 1;
			}

		/*
		 * The first use of a new stream identifier implicitly closes
		 * all streams in the "idle" state that might have been
		 * initiated by that peer with a lower-valued stream identifier.
		 *
		 * For example, if a client sends a HEADERS frame on stream 7
		 * without ever sending a frame on stream 5, then stream 5
		 * transitions to the "closed" state when the first frame for
		 * stream 7 is sent or received.
		 */
		lws_start_foreach_ll(struct lws *, w, wsi->u.h2.child_list) {
			if (w->u.h2.my_sid < h2n->sid &&
			    w->u.h2.h2_state == LWS_H2_STATE_IDLE)
				lws_close_free_wsi(w, 0);
		} lws_end_foreach_ll(w, u.h2.sibling_list);


		/* END_STREAM means after servicing this, close the stream */
		h2n->swsi->u.h2.END_STREAM =
					!!(h2n->flags & LWS_H2_FLAG_END_STREAM);
		lwsl_info("%s: hdr END_STREAM = %d\n",__func__,
			  h2n->swsi->u.h2.END_STREAM);

		h2n->cont_exp = !(h2n->flags & LWS_H2_FLAG_END_HEADERS);
		h2n->cont_exp_sid = h2n->sid;
		h2n->cont_exp_headers = 1;
		lws_header_table_reset(h2n->swsi, 0);

update_end_headers:
		/* no END_HEADERS means CONTINUATION must come */
		h2n->swsi->u.h2.END_HEADERS =
				!!(h2n->flags & LWS_H2_FLAG_END_HEADERS);
		if (h2n->swsi->u.h2.END_HEADERS)
			h2n->cont_exp = 0;
		lwsl_debug("END_HEADERS %d\n", h2n->swsi->u.h2.END_HEADERS);
		break;

	case LWS_H2_FRAME_TYPE_WINDOW_UPDATE:
		if (h2n->length != 4) {
			lws_h2_goaway(wsi, H2_ERR_FRAME_SIZE_ERROR,
				      "window update frame not 4");
			break;
		}
		lwsl_info("LWS_H2_FRAME_TYPE_WINDOW_UPDATE\n");
		break;
	default:
		lwsl_info("%s: ILLEGAL FRAME TYPE %d\n", __func__, h2n->type);
		h2n->type = LWS_H2_FRAME_TYPE_COUNT; /* ie, IGNORE */
		break;
	}
	if (h2n->length == 0)
		h2n->frame_state = 0;

	return 0;
}

/*
 * The last byte of the whole frame has been handled.
 * Perform actions for frame completion.
 */
static int
lws_h2_parse_end_of_frame(struct lws *wsi)
{
	struct lws_h2_netconn *h2n = wsi->u.h2.h2n;
	struct lws_h2_protocol_send *pps;
	struct lws *eff_wsi = wsi;
	const char *p;
	int n;

	h2n->frame_state = 0;
	h2n->count = 0;

	if (h2n->sid)
		h2n->swsi = lws_h2_wsi_from_id(wsi, h2n->sid);

	if (h2n->sid > h2n->highest_sid)
		h2n->highest_sid = h2n->sid;

	/* set our initial window size */
	if (!wsi->u.h2.initialized) {
		wsi->u.h2.tx_cr = h2n->set.s[H2SET_INITIAL_WINDOW_SIZE];
		lwsl_info("initial tx credit on master %p: %d\n", wsi,
			  wsi->u.h2.tx_cr);
		wsi->u.h2.initialized = 1;
	}

	if (h2n->collected_priority && (h2n->dep & ~(1 << 31)) == h2n->sid) {
		lws_h2_goaway(wsi, H2_ERR_PROTOCOL_ERROR, "depends on own sid");
		return 0;
	}

	switch (h2n->type) {
	case LWS_H2_FRAME_TYPE_CONTINUATION:
	case LWS_H2_FRAME_TYPE_HEADERS:

		/* service the http request itself */

		if (h2n->last_action_dyntable_resize) {
			lws_h2_goaway(wsi, H2_ERR_COMPRESSION_ERROR,
				"dyntable resize last in headers");
			break;
		}

		if (!h2n->swsi->u.h2.END_HEADERS) {
			/* we are not finished yet */
			lwsl_info("witholding http action for continuation\n");
			break;
		}

		/* confirm the hpack stream state is reasonable for finishing */

		if (h2n->hpack != HPKS_TYPE) {
			/* hpack incomplete */
			lwsl_info("hpack incomplete %d (type %d, len %d)\n",
				  h2n->hpack, h2n->type, h2n->hpack_len);
			lws_h2_goaway(wsi, H2_ERR_COMPRESSION_ERROR,
				      "hpack incomplete");
			break;
		}

		/* this is the last part of HEADERS */
		switch (h2n->swsi->u.h2.h2_state) {
		case LWS_H2_STATE_IDLE:
			lws_h2_state(h2n->swsi, LWS_H2_STATE_OPEN);
			break;
		case LWS_H2_STATE_RESERVED_REMOTE:
			lws_h2_state(h2n->swsi, LWS_H2_STATE_HALF_CLOSED_LOCAL);
			break;
		}

		lwsl_info("http req, wsi=%p, h2n->swsi=%p\n", wsi, h2n->swsi);
		h2n->swsi->hdr_parsing_completed = 1;

		if (lws_hdr_extant(h2n->swsi, WSI_TOKEN_HTTP_CONTENT_LENGTH)) {
			h2n->swsi->u.http.rx_content_length  = atoll(
				lws_hdr_simple_ptr(h2n->swsi,
				      WSI_TOKEN_HTTP_CONTENT_LENGTH));
			h2n->swsi->u.http.rx_content_remain =
					h2n->swsi->u.http.rx_content_length;
			lwsl_info("setting rx_content_length %lld\n",
				   (long long)h2n->swsi->u.http.rx_content_length);
		}

		{
			int n = 0, len;
			char buf[256];
			const unsigned char *c;

			do {
				c = lws_token_to_string(n);
				if (!c) {
					n++;
					continue;
				}

				len = lws_hdr_total_length(h2n->swsi, n);
				if (!len || len > sizeof(buf) - 1) {
					n++;
					continue;
				}

				lws_hdr_copy(h2n->swsi, buf, sizeof buf, n);
				buf[sizeof(buf) - 1] = '\0';

				lwsl_info("    %s = %s\n", (char *)c, buf);
				n++;
			} while (c);
		}

		if (h2n->swsi->u.h2.h2_state == LWS_H2_STATE_HALF_CLOSED_REMOTE ||
		    h2n->swsi->u.h2.h2_state == LWS_H2_STATE_CLOSED) {
			lws_h2_goaway(wsi, H2_ERR_STREAM_CLOSED,
				      "Banning service on CLOSED_REMOTE");
			break;
		}

		switch (h2n->swsi->u.h2.h2_state) {
		case LWS_H2_STATE_OPEN:
			if (h2n->swsi->u.h2.END_STREAM)
				lws_h2_state(h2n->swsi,
					     LWS_H2_STATE_HALF_CLOSED_REMOTE);
			break;
		case LWS_H2_STATE_HALF_CLOSED_LOCAL:
			if (h2n->swsi->u.h2.END_STREAM)
				lws_h2_state(h2n->swsi, LWS_H2_STATE_CLOSED);
			break;
		}

		if (!lws_hdr_total_length(h2n->swsi, WSI_TOKEN_HTTP_COLON_PATH) ||
		    !lws_hdr_total_length(h2n->swsi, WSI_TOKEN_HTTP_COLON_METHOD) ||
		    !lws_hdr_total_length(h2n->swsi, WSI_TOKEN_HTTP_COLON_SCHEME) ||
		     lws_hdr_total_length(h2n->swsi, WSI_TOKEN_HTTP_COLON_STATUS) ||
		     lws_hdr_extant(h2n->swsi, WSI_TOKEN_CONNECTION)) {
			lws_h2_goaway(wsi, H2_ERR_PROTOCOL_ERROR,
				      "Pseudoheader checks");
			break;
		}

		if (lws_hdr_extant(h2n->swsi, WSI_TOKEN_TE)) {
			n = lws_hdr_total_length(h2n->swsi, WSI_TOKEN_TE);

			if (n != 8 ||
			    strncmp(lws_hdr_simple_ptr(h2n->swsi, WSI_TOKEN_TE),
				  "trailers", n)) {
				lws_h2_goaway(wsi, H2_ERR_PROTOCOL_ERROR,
					      "Illegal transfer-encoding");
				break;
			}
		}

		p = lws_hdr_simple_ptr(h2n->swsi, WSI_TOKEN_HTTP_COLON_METHOD);
		if (!strcmp(p, "POST"))
			h2n->swsi->u.hdr.ah->frag_index[WSI_TOKEN_POST_URI] =
				h2n->swsi->u.hdr.ah->frag_index[WSI_TOKEN_HTTP_COLON_PATH];

		wsi->vhost->conn_stats.h2_trans++;

		lwsl_info("  action start...\n");
		n = lws_http_action(h2n->swsi);
		lwsl_info("  action result %d "
			  "(wsi->u.http.rx_content_remain %lld)\n",
			  n, h2n->swsi->u.http.rx_content_remain);

		/*
		 * Commonly we only managed to start a larger transfer that will
		 * complete asynchronously.  In those cases we will hear about
		 * END_STREAM going out in the POLLOUT handler.
		 */
		if (n || h2n->swsi->u.h2.send_END_STREAM) {
			lws_close_free_wsi(h2n->swsi, 0);
			h2n->swsi = NULL;
			break;
		}
		break;

	case LWS_H2_FRAME_TYPE_DATA:
		if (!h2n->swsi)
			break;

		if (lws_hdr_total_length(h2n->swsi, WSI_TOKEN_HTTP_CONTENT_LENGTH) &&
		    h2n->swsi->u.h2.END_STREAM &&
		    h2n->swsi->u.http.rx_content_length &&
		    h2n->swsi->u.http.rx_content_remain) {
			lws_h2_rst_stream(h2n->swsi, H2_ERR_PROTOCOL_ERROR,
					  "Not enough rx content");
			break;
		}

		if (h2n->swsi->u.h2.END_STREAM &&
		    h2n->swsi->u.h2.h2_state == LWS_H2_STATE_OPEN)
			lws_h2_state(h2n->swsi, LWS_H2_STATE_HALF_CLOSED_REMOTE);

		if (h2n->swsi->u.h2.END_STREAM &&
		    h2n->swsi->u.h2.h2_state == LWS_H2_STATE_HALF_CLOSED_LOCAL)
			lws_h2_state(h2n->swsi, LWS_H2_STATE_CLOSED);
		break;

	case LWS_H2_FRAME_TYPE_PING:
		if (h2n->flags & LWS_H2_FLAG_SETTINGS_ACK) { // ack
		} else {/* they're sending us a ping request */
			lwsl_info("rx ping, preparing pong\n");
			pps = lws_h2_new_pps(LWS_H2_PPS_PONG);
			if (!pps)
				return 1;
			memcpy(pps->u.ping.ping_payload, h2n->ping_payload, 8);
			lws_pps_schedule(wsi, pps);
		}

		break;

	case LWS_H2_FRAME_TYPE_WINDOW_UPDATE:
		h2n->hpack_e_dep &= ~(1 << 31);
		lwsl_info("WINDOW_UPDATE: sid %d %u (0x%x)\n", h2n->sid,
			    h2n->hpack_e_dep, h2n->hpack_e_dep);

		if (h2n->sid)
			eff_wsi = h2n->swsi;

		if (!eff_wsi) {
			if (h2n->sid > h2n->highest_sid_opened)
				lws_h2_goaway(wsi, H2_ERR_PROTOCOL_ERROR,
					      "alien sid");
			break; /* ignore */
		}

		if ((uint64_t)eff_wsi->u.h2.tx_cr + (uint64_t)h2n->hpack_e_dep >
		    (uint64_t)0x7fffffff) {
			if (h2n->sid)
				lws_h2_rst_stream(h2n->swsi,
						  H2_ERR_FLOW_CONTROL_ERROR,
						  "Flow control exceeded max");
			else
				lws_h2_goaway(wsi, H2_ERR_FLOW_CONTROL_ERROR,
					      "Flow control exceeded max");
			break;
		}

		if (!h2n->hpack_e_dep) {
			lws_h2_goaway(wsi, H2_ERR_PROTOCOL_ERROR,
				      "Zero length window update");
			break;
		}
		n = eff_wsi->u.h2.tx_cr;
		eff_wsi->u.h2.tx_cr += h2n->hpack_e_dep;

		if (n <= 0 && eff_wsi->u.h2.tx_cr <= 0)
			/* it helps, but won't change sendability for anyone */
			break;

		/*
		 * It did change sendability... for us and any children waiting
		 * on us... reassess blockage for all children first
		 */
		lws_start_foreach_ll(struct lws *, w, wsi->u.h2.child_list) {
			lws_callback_on_writable(w);
		} lws_end_foreach_ll(w, u.h2.sibling_list);

		if (eff_wsi->u.h2.skint && lws_h2_tx_cr_get(eff_wsi)) {
			lwsl_info("%s: %p: skint\n", __func__, wsi);
			eff_wsi->u.h2.skint = 0;
			lws_callback_on_writable(eff_wsi);
		}
		break;

	case LWS_H2_FRAME_TYPE_GOAWAY:
		lwsl_info("GOAWAY: last sid %d, error 0x%08X, string '%s'\n",
			  h2n->goaway_last_sid, h2n->goaway_err,
			  h2n->goaway_str);
		wsi->u.h2.GOING_AWAY = 1;

		return 1;

	case LWS_H2_FRAME_TYPE_COUNT: /* IGNORING FRAME */
		break;
	}

	return 0;
}

int
lws_h2_parser(struct lws *wsi, unsigned char c)
{
	struct lws_h2_netconn *h2n = wsi->u.h2.h2n;
	struct lws_h2_protocol_send *pps;
	int n;

	if (!h2n)
		return 1;

	switch (wsi->state) {
	case LWSS_HTTP2_AWAIT_CLIENT_PREFACE:
		if (preface[h2n->count++] != c)
			return 1;

		if (preface[h2n->count])
			break;

		lwsl_info("http2: %p: established\n", wsi);
		wsi->state = LWSS_HTTP2_ESTABLISHED_PRE_SETTINGS;
		h2n->count = 0;
		wsi->u.h2.tx_cr = 65535;

		/*
		 * we must send a settings frame -- empty one is OK...
		 * that must be the first thing sent by server
		 * and the peer must send a SETTINGS with ACK flag...
		 */
		pps = lws_h2_new_pps(LWS_H2_PPS_MY_SETTINGS);
		if (!pps)
			return 1;
		lws_pps_schedule(wsi, pps);
		break;

	case LWSS_HTTP2_ESTABLISHED_PRE_SETTINGS:
	case LWSS_HTTP2_ESTABLISHED:
		if (h2n->frame_state != LWS_H2_FRAME_HEADER_LENGTH)
			goto try_frame_start;

		/*
		 * post-header, preamble / payload / padding part
		 */
		h2n->count++;

		if (h2n->flags & LWS_H2_FLAG_PADDED && !h2n->pad_length) {
			/*
			 * Get the padding count... actual padding is
			 * at the end of the frame.
			 */
			h2n->padding = c;
			h2n->pad_length = 1;
			h2n->preamble++;

			if (h2n->padding > h2n->length - 1)
				lws_h2_goaway(wsi, H2_ERR_PROTOCOL_ERROR,
					      "execssive padding");
			break; /* we consumed this */
		}

		if (h2n->flags & LWS_H2_FLAG_PRIORITY &&
		    !h2n->collected_priority) {
			/* going to be 5 preamble bytes */

			lwsl_debug("PRIORITY FLAG:  0x%x\n", c);

			if (h2n->preamble++ - h2n->pad_length < 4) {
				h2n->dep = ((h2n->dep) << 8) | c;
				break; /* we consumed this */
			}
			h2n->weight_temp = c;
			h2n->collected_priority = 1;
			lwsl_debug("PRI FL: dep 0x%x, weight 0x%02X\n",
				   h2n->dep, h2n->weight_temp);
			break; /* we consumed this */
		}
		if (h2n->padding && h2n->count > (h2n->length - h2n->padding)) {
			if (c) {
				lws_h2_goaway(wsi, H2_ERR_PROTOCOL_ERROR,
					      "nonzero padding");
				break;
			}
			goto frame_end;
		}

		/* applies to wsi->u.h2.swsi which may be wsi */
		switch(h2n->type) {

		case LWS_H2_FRAME_TYPE_SETTINGS:
			n = (h2n->count - 1 - h2n->preamble) %
			     LWS_H2_SETTINGS_LEN;
			h2n->one_setting[n] = c;
			if (n != LWS_H2_SETTINGS_LEN - 1)
				break;
			lws_h2_settings(wsi, &h2n->set, h2n->one_setting,
					LWS_H2_SETTINGS_LEN);
			break;

		case LWS_H2_FRAME_TYPE_CONTINUATION:
		case LWS_H2_FRAME_TYPE_HEADERS:
			if (!h2n->swsi)
				break;
			if (lws_hpack_interpret(h2n->swsi, c)) {
				lwsl_info("%s: hpack failed\n", __func__);
				return 1;
			}
			break;

		case LWS_H2_FRAME_TYPE_GOAWAY:
			switch (h2n->inside++) {
			case 0:
			case 1:
			case 2:
			case 3:
				h2n->goaway_last_sid <<= 8;
				h2n->goaway_last_sid |= c;
				h2n->goaway_str[0] = '\0';
				break;

			case 4:
			case 5:
			case 6:
			case 7:
				h2n->goaway_err <<= 8;
				h2n->goaway_err |= c;
				break;

			default:
				if (h2n->inside - 9 <
				    sizeof(h2n->goaway_str) - 1)
					h2n->goaway_str[h2n->inside - 9] = c;
				h2n->goaway_str[sizeof(h2n->goaway_str) - 1] = '\0';
				break;
			}
			break;

		case LWS_H2_FRAME_TYPE_DATA:
			//lwsl_notice("incoming LWS_H2_FRAME_TYPE_DATA content\n");
			if (!h2n->swsi) {
				//lwsl_notice("data sid %d has no swsi\n", h2n->sid);
				break;
			}

			h2n->swsi->state = LWSS_HTTP_BODY;
			h2n->inside++;
			if (lws_hdr_total_length(h2n->swsi,
						 WSI_TOKEN_HTTP_CONTENT_LENGTH) &&
			    h2n->swsi->u.http.rx_content_length &&
			    h2n->swsi->u.http.rx_content_remain == 1 && /* last */
			    h2n->inside < h2n->length) { /* unread data in frame */
				lws_h2_goaway(wsi, H2_ERR_PROTOCOL_ERROR,
					      "More rx than content_length told");
				break;
			}

			n = lws_read(h2n->swsi, &c, 1);
			if (n < 0) {
			//	lws_h2_rst_stream(wsi, LWS_H2_PPS_RST_STREAM,
			//			  "post body done");
				break;
			}
			break;

		case LWS_H2_FRAME_TYPE_PRIORITY:
			if (h2n->count <= 4) {
				h2n->dep <<= 8;
				h2n->dep |= c;
			} else {
				h2n->weight_temp = c;
				lwsl_info("PRIORITY: dep 0x%x, weight 0x%02X\n",
					  h2n->dep, h2n->weight_temp);

				if ((h2n->dep & ~(1 << 31)) == h2n->sid) {
					lws_h2_goaway(wsi, H2_ERR_PROTOCOL_ERROR,
						      "cant depend on own sid");
					break;
				}
			}
			break;

		case LWS_H2_FRAME_TYPE_RST_STREAM:
			break;

		case LWS_H2_FRAME_TYPE_PUSH_PROMISE:
			break;

		case LWS_H2_FRAME_TYPE_PING:
			if (h2n->flags & LWS_H2_FLAG_SETTINGS_ACK) { // ack
			} else { /* they're sending us a ping request */
				if (h2n->count > 8)
					return 1;
				h2n->ping_payload[h2n->count - 1] = c;
			}
			break;

		case LWS_H2_FRAME_TYPE_WINDOW_UPDATE:
			h2n->hpack_e_dep <<= 8;
			h2n->hpack_e_dep |= c;
			break;

		case LWS_H2_FRAME_TYPE_COUNT: /* IGNORING FRAME */
			break;

		default:
			lwsl_notice("%s: unhandled frame type %d\n",
				    __func__, h2n->type);

			return 1;
		}

frame_end:
		if (h2n->count != h2n->length)
			break;

		/*
		 * end of frame just happened
		 */
		if (lws_h2_parse_end_of_frame(wsi))
			return 1;
		break;

try_frame_start:
		if (h2n->frame_state <= 8) {

			switch (h2n->frame_state++) {
			case 0:
				h2n->pad_length = 0;
				h2n->collected_priority = 0;
				h2n->padding = 0;
				h2n->preamble = 0;
				h2n->length = c;
				h2n->inside = 0;
				break;
			case 1:
			case 2:
				h2n->length <<= 8;
				h2n->length |= c;
				break;
			case 3:
				h2n->type = c;
				break;
			case 4:
				h2n->flags = c;
				break;

			case 5:
			case 6:
			case 7:
			case 8:
				h2n->sid <<= 8;
				h2n->sid |= c;
				break;
			}
		}
		if (h2n->frame_state == LWS_H2_FRAME_HEADER_LENGTH)
			if (lws_h2_parse_frame_header(wsi))
				return 1;
		break;
	}

	return 0;
}

