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

const struct http2_settings lws_http2_default_settings = { {
	1,
	/* LWS_HTTP2_SETTINGS__HEADER_TABLE_SIZE */		4096,
	/* LWS_HTTP2_SETTINGS__ENABLE_PUSH */			   1,
	/* LWS_HTTP2_SETTINGS__MAX_CONCURRENT_STREAMS */	 128,
	/* LWS_HTTP2_SETTINGS__INITIAL_WINDOW_SIZE */	       65535,
	/* LWS_HTTP2_SETTINGS__MAX_FRAME_SIZE */	       16384,
	/* LWS_HTTP2_SETTINGS__MAX_HEADER_LIST_SIZE */		  ~0,
}};

/*
 * bitmap of control messages that are valid to receive for each http2 state
 */

static const uint16_t http2_rx_validity[] = {
	/* LWS_HTTP2_STATE_IDLE */
		(1 << LWS_HTTP2_FRAME_TYPE_SETTINGS) |
		(1 << LWS_HTTP2_FRAME_TYPE_PRIORITY) |
//		(1 << LWS_HTTP2_FRAME_TYPE_WINDOW_UPDATE)| /* ignore */
		(1 << LWS_HTTP2_FRAME_TYPE_HEADERS) |
		(1 << LWS_HTTP2_FRAME_TYPE_CONTINUATION),
	/* LWS_HTTP2_STATE_RESERVED_LOCAL */
		(1 << LWS_HTTP2_FRAME_TYPE_SETTINGS) |
		(1 << LWS_HTTP2_FRAME_TYPE_RST_STREAM) |
		(1 << LWS_HTTP2_FRAME_TYPE_PRIORITY) |
		(1 << LWS_HTTP2_FRAME_TYPE_WINDOW_UPDATE),
	/* LWS_HTTP2_STATE_RESERVED_REMOTE */
		(1 << LWS_HTTP2_FRAME_TYPE_SETTINGS) |
		(1 << LWS_HTTP2_FRAME_TYPE_HEADERS) |
		(1 << LWS_HTTP2_FRAME_TYPE_CONTINUATION) |
		(1 << LWS_HTTP2_FRAME_TYPE_RST_STREAM) |
		(1 << LWS_HTTP2_FRAME_TYPE_PRIORITY),
	/* LWS_HTTP2_STATE_OPEN */
		(1 << LWS_HTTP2_FRAME_TYPE_DATA) |
		(1 << LWS_HTTP2_FRAME_TYPE_HEADERS) |
		(1 << LWS_HTTP2_FRAME_TYPE_PRIORITY) |
		(1 << LWS_HTTP2_FRAME_TYPE_RST_STREAM) |
		(1 << LWS_HTTP2_FRAME_TYPE_SETTINGS) |
		(1 << LWS_HTTP2_FRAME_TYPE_PUSH_PROMISE) |
		(1 << LWS_HTTP2_FRAME_TYPE_PING) |
		(1 << LWS_HTTP2_FRAME_TYPE_GOAWAY) |
		(1 << LWS_HTTP2_FRAME_TYPE_WINDOW_UPDATE) |
		(1 << LWS_HTTP2_FRAME_TYPE_CONTINUATION),
	/* LWS_HTTP2_STATE_HALF_CLOSED_REMOTE */
		(1 << LWS_HTTP2_FRAME_TYPE_SETTINGS) |
		(1 << LWS_HTTP2_FRAME_TYPE_WINDOW_UPDATE) |
		(1 << LWS_HTTP2_FRAME_TYPE_PRIORITY) |
		(1 << LWS_HTTP2_FRAME_TYPE_RST_STREAM),
	/* LWS_HTTP2_STATE_HALF_CLOSED_LOCAL */
		(1 << LWS_HTTP2_FRAME_TYPE_DATA) |
		(1 << LWS_HTTP2_FRAME_TYPE_HEADERS) |
		(1 << LWS_HTTP2_FRAME_TYPE_PRIORITY) |
		(1 << LWS_HTTP2_FRAME_TYPE_RST_STREAM) |
		(1 << LWS_HTTP2_FRAME_TYPE_SETTINGS) |
		(1 << LWS_HTTP2_FRAME_TYPE_PUSH_PROMISE) |
		(1 << LWS_HTTP2_FRAME_TYPE_PING) |
		(1 << LWS_HTTP2_FRAME_TYPE_GOAWAY) |
		(1 << LWS_HTTP2_FRAME_TYPE_WINDOW_UPDATE) |
		(1 << LWS_HTTP2_FRAME_TYPE_CONTINUATION),
	/* LWS_HTTP2_STATE_CLOSED */
		(1 << LWS_HTTP2_FRAME_TYPE_SETTINGS) |
		(1 << LWS_HTTP2_FRAME_TYPE_PRIORITY) |
		(1 << LWS_HTTP2_FRAME_TYPE_WINDOW_UPDATE) |
		(1 << LWS_HTTP2_FRAME_TYPE_RST_STREAM),
};

void lws_http2_init(struct http2_settings *settings)
{
	memcpy(settings, lws_http2_default_settings.setting, sizeof(*settings));
}

static const char * const http2_state_names[] = {
	"LWS_HTTP2_STATE_IDLE",
	"LWS_HTTP2_STATE_RESERVED_LOCAL",
	"LWS_HTTP2_STATE_RESERVED_REMOTE",
	"LWS_HTTP2_STATE_OPEN",
	"LWS_HTTP2_STATE_HALF_CLOSED_REMOTE",
	"LWS_HTTP2_STATE_HALF_CLOSED_LOCAL",
	"LWS_HTTP2_STATE_CLOSED",
};

static void
lws_http2_state_transition(struct lws *wsi, enum lws_http2_states s)
{
	lwsl_info("%s: wsi %p: state %s -> %s\n", __func__, wsi,
			http2_state_names[wsi->u.http2.http2_state],
			http2_state_names[s]);
	wsi->u.http2.http2_state = (uint8_t)s;
}

struct lws *
lws_create_server_child_wsi(struct lws_vhost *vhost, struct lws *parent_wsi,
			    unsigned int sid)
{
	struct lws *wsi = lws_create_new_server_wsi(vhost);

	if (!wsi) {
		lwsl_notice("new server wsi failed (vh %p)\n", vhost);
		return NULL;
	}

	/* no more children allowed by parent */
	if (parent_wsi->u.http2.child_count + 1 ==
	    parent_wsi->u.http2.h2n->peer_settings.setting[
			LWS_HTTP2_SETTINGS__MAX_CONCURRENT_STREAMS]) {
		lwsl_notice("reached concurrent stream limit\n");
		goto bail;
	}

	wsi->u.http2.my_stream_id = sid;
	wsi->http2_substream = 1;

	wsi->u.http2.parent_wsi = parent_wsi;
	/* new guy's sibling is whoever was the first child before */
	wsi->u.http2.sibling_list = parent_wsi->u.http2.child_list;
	/* first child is now the new guy */
	parent_wsi->u.http2.child_list = wsi;
	parent_wsi->u.http2.child_count++;

	wsi->u.http2.my_priority = 16;
	wsi->u.http2.tx_credit = 65535;

	wsi->state = LWSS_HTTP2_ESTABLISHED;
	wsi->mode = parent_wsi->mode;

	wsi->protocol = &vhost->protocols[0];
	if (lws_ensure_user_space(wsi))
		goto bail;

	lwsl_info("%s: %p new child %p, sid %d, user_space=%p\n", __func__,
		  parent_wsi, wsi, sid, wsi->user_space);

	return wsi;

bail:
	vhost->protocols[0].callback(wsi, LWS_CALLBACK_WSI_DESTROY,
			       NULL, NULL, 0);
	lws_free(wsi);

	return NULL;
}

struct lws *
lws_http2_wsi_from_id(struct lws *parent_wsi, unsigned int sid)
{
	lws_start_foreach_ll(struct lws *, wsi, parent_wsi->u.http2.child_list) {
		if (wsi->u.http2.my_stream_id == sid)
			return wsi;
	} lws_end_foreach_ll(wsi, sibling_list);

	return lws_create_server_child_wsi(parent_wsi->vhost, parent_wsi, sid);
}

int lws_remove_server_child_wsi(struct lws_context *context, struct lws *wsi)
{
	lws_start_foreach_llp(struct lws **, w, wsi->u.http2.child_list) {
		if (*w == wsi) {
			*w = wsi->u.http2.sibling_list;
			(wsi->u.http2.parent_wsi)->u.http2.child_count--;
			return 0;
		}
	} lws_end_foreach_llp(w, sibling_list);

	lwsl_err("%s: can't find %p\n", __func__, wsi);

	return 1;
}


struct lws *lws_http2_get_network_wsi(struct lws *wsi)
{
	while (wsi->u.http2.parent_wsi)
		wsi = wsi->u.http2.parent_wsi;

	return wsi;
}

void
lws_http2_goaway(struct lws *wsi, uint32_t err, const char *reason)
{
	struct lws_http2_netconn *h2n = wsi->u.http2.h2n;

	if (h2n->type == LWS_HTTP2_FRAME_TYPE_COUNT)
		return;
	lwsl_info("%s: ERR 0x%x, REASON '%s'\n", __func__, err, reason);

	h2n->goaway_error_code = err;
	strncpy(h2n->goaway_error_string, reason, sizeof(h2n->goaway_error_string) - 1);
	h2n->goaway_error_string[sizeof(h2n->goaway_error_string) - 1] = '\0';
	lws_set_protocol_write_pending(wsi, LWS_PPS_HTTP2_GOAWAY);
	h2n->type = LWS_HTTP2_FRAME_TYPE_COUNT; /* ie, IGNORE */
}

void
lws_http2_rst_stream(struct lws *wsi, uint32_t err, const char *reason)
{
	struct lws *nwsi = lws_http2_get_network_wsi(wsi);
	struct lws_http2_netconn *h2n = nwsi->u.http2.h2n;

	if (h2n->type == LWS_HTTP2_FRAME_TYPE_COUNT)
		return;
	lwsl_info("%s: RST_STREAM 0x%x, REASON '%s'\n", __func__, err, reason);

	h2n->goaway_error_code = err;
	lws_set_protocol_write_pending(nwsi, LWS_PPS_HTTP2_RST_STREAM);
	h2n->type = LWS_HTTP2_FRAME_TYPE_COUNT; /* ie, IGNORE */
	lws_http2_state_transition(wsi, LWS_HTTP2_STATE_CLOSED);
}

int
lws_http2_interpret_settings_payload(struct lws *nwsi, struct http2_settings *settings,
				     unsigned char *buf, int len)
{
	unsigned int a, b;

	if (!len)
		return 0;

	if (len < LWS_HTTP2_SETTINGS_LENGTH)
		return 1;

	while (len >= LWS_HTTP2_SETTINGS_LENGTH) {
		a = (buf[0] << 8) | buf[1];
		if (!a || a >= LWS_HTTP2_SETTINGS__COUNT)
			goto skip;
		b = buf[2] << 24 | buf[3] << 16 | buf[4] << 8 | buf[5];

		switch (a) {
		case LWS_HTTP2_SETTINGS__HEADER_TABLE_SIZE:
			break;
		case LWS_HTTP2_SETTINGS__ENABLE_PUSH:
			if (b > 1) {
				lws_http2_goaway(nwsi, LWS_HTTP2_ERR_PROTOCOL_ERROR, "ENABLE_PUSH invalid arg");
				return 1;
			}
			break;
		case LWS_HTTP2_SETTINGS__MAX_CONCURRENT_STREAMS:
			break;
		case LWS_HTTP2_SETTINGS__INITIAL_WINDOW_SIZE:
			if (b > 0x7fffffff) {
				lws_http2_goaway(nwsi, LWS_HTTP2_ERR_FLOW_CONTROL_ERROR, "Inital Window beyond max");
				return 1;
			}
			break;
		case LWS_HTTP2_SETTINGS__MAX_FRAME_SIZE:
			if (b < lws_http2_default_settings.setting[LWS_HTTP2_SETTINGS__MAX_FRAME_SIZE]) {
				lws_http2_goaway(nwsi, LWS_HTTP2_ERR_PROTOCOL_ERROR, "Settings Frame size cannot go below initial");
				return 1;
			}
			if (b > 0x007fffff) {
				lws_http2_goaway(nwsi, LWS_HTTP2_ERR_PROTOCOL_ERROR, "Settings Frame size above max");
				return 1;
			}
			break;
		case LWS_HTTP2_SETTINGS__MAX_HEADER_LIST_SIZE:
			break;
		}
		settings->setting[a] = b;
		lwsl_info("http2 settings %d <- 0x%x\n", a, b);
skip:
		len -= LWS_HTTP2_SETTINGS_LENGTH;
		buf += LWS_HTTP2_SETTINGS_LENGTH;
	}

	if (len)
		return 1;

	return 0;
}

int lws_http2_frame_write(struct lws *wsi, int type, int flags,
			  unsigned int sid, unsigned int len, unsigned char *buf)
{
	struct lws *wsi_eff = lws_http2_get_network_wsi(wsi);
	unsigned char *p = &buf[-LWS_HTTP2_FRAME_HEADER_LENGTH];
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

	lwsl_info("%s: %p (eff %p). type %d, flags 0x%x, sid=%d, len=%d, tx_credit=%d\n",
		  __func__, wsi, wsi_eff, type, flags, sid, len,
		  wsi->u.http2.tx_credit);

	if (type == LWS_HTTP2_FRAME_TYPE_DATA) {
		if (wsi->u.http2.tx_credit < len)
			lwsl_err("%s: %p: sending payload len %d"
				 " but tx_credit only %d!\n", __func__, wsi, len,
				 wsi->u.http2.tx_credit);
		wsi->u.http2.tx_credit -= len;
	}

	n = lws_issue_raw(wsi_eff, &buf[-LWS_HTTP2_FRAME_HEADER_LENGTH],
			  len + LWS_HTTP2_FRAME_HEADER_LENGTH);
	if (n < 0)
		return n;
	if (n >= LWS_HTTP2_FRAME_HEADER_LENGTH)
		return n - LWS_HTTP2_FRAME_HEADER_LENGTH;

	return n;
}

static void lws_http2_settings_write(struct lws *wsi, int n, unsigned char *buf)
{
	*buf++ = n >> 8;
	*buf++ = n;
	*buf++ = wsi->u.http2.h2n->my_settings.setting[n] >> 24;
	*buf++ = wsi->u.http2.h2n->my_settings.setting[n] >> 16;
	*buf++ = wsi->u.http2.h2n->my_settings.setting[n] >> 8;
	*buf = wsi->u.http2.h2n->my_settings.setting[n];
}

static const char * https_client_preface =
	"PRI * HTTP/2.0\x0d\x0a\x0d\x0aSM\x0d\x0a\x0d\x0a";

int
lws_http2_parser(struct lws *wsi, unsigned char c)
{
	struct lws_http2_netconn *h2n = wsi->u.http2.h2n;
	struct lws *swsi;
	int n;

	if (!h2n)
		return 1;

	//lwsl_notice(" %02X\n", c);

	switch (wsi->state) {
	case LWSS_HTTP2_AWAIT_CLIENT_PREFACE:
		if (https_client_preface[h2n->count++] != c)
			return 1;

		if (!https_client_preface[h2n->count]) {
			lwsl_info("http2: %p: established\n", wsi);
			wsi->state = LWSS_HTTP2_ESTABLISHED_PRE_SETTINGS;
			h2n->count = 0;
			wsi->u.http2.tx_credit = 65535;

			/*
			 * we must send a settings frame -- empty one is OK...
			 * that must be the first thing sent by server
			 * and the peer must send a SETTINGS with ACK flag...
			 */

			lws_set_protocol_write_pending(wsi,
						       LWS_PPS_HTTP2_MY_SETTINGS);
		}
		break;

	case LWSS_HTTP2_ESTABLISHED_PRE_SETTINGS:
	case LWSS_HTTP2_ESTABLISHED:

		if (h2n->frame_state == LWS_HTTP2_FRAME_HEADER_LENGTH) { // payload or padding length
			/*
			 * post-header, payload part
			 */
			h2n->count++;
			swsi = h2n->stream_wsi;

			if (h2n->flags & LWS_HTTP2_FLAG_PADDED &&
			    !h2n->collected_padding_length) {
				/*
				 * Get the padding count... actual padding is
				 * at the end of the frame.
				 */
				// lwsl_notice("padding: %d\n", c);
				h2n->padding = c;
				h2n->collected_padding_length = 1;
				h2n->preamble++;

				if (h2n->padding > h2n->length - 1) {
					lws_http2_goaway(wsi,
						LWS_HTTP2_ERR_PROTOCOL_ERROR,
						"padding length greater than frame length");
					break;
				}
				break; /* we consumed this */
			}

			if (h2n->flags & LWS_HTTP2_FLAG_PRIORITY &&
			    !h2n->collected_priority) {
				/* going to be 5 preamble bytes */

				lwsl_debug("PRIORITY FLAG:  0x%x\n", c);

				if (h2n->preamble - h2n->collected_padding_length < 4) {
					h2n->dep_temp = ((h2n->dep_temp) << 8) | c;
				} else {
					h2n->weight_temp = c;
					h2n->collected_priority = 1;
					lwsl_debug("PRIORITY FLAG: dependency 0x%x, weight 0x%02X\n", h2n->dep_temp, h2n->weight_temp);
				}
				h2n->preamble++;
				break; /* we consumed this */
			}

			// lwsl_notice("   %d %d %d\n", h2n->count, h2n->length, h2n->padding);

			if (h2n->count > (h2n->length - h2n->padding) && h2n->padding) {
				lwsl_info("eating frame padding %d %d\n", h2n->count, h2n->length);
				if (c) {
					lws_http2_goaway(wsi,
						LWS_HTTP2_ERR_PROTOCOL_ERROR,
						"nonzero padding");
					break;
				}
				goto frame_end;
			}

			/* applies to wsi->u.http2.stream_wsi which may be wsi */
			switch(h2n->type) {

			case LWS_HTTP2_FRAME_TYPE_SETTINGS:
				// lwsl_info(" LWS_HTTP2_FRAME_TYPE_SETTINGS: %02X -> %d\n", c, (h2n->count - 1 - h2n->preamble) % LWS_HTTP2_SETTINGS_LENGTH);
				h2n->one_setting[(h2n->count - 1 - h2n->preamble) % LWS_HTTP2_SETTINGS_LENGTH] = c;
				if ((h2n->count - 1 - !!(h2n->flags & LWS_HTTP2_FLAG_PADDED)) % LWS_HTTP2_SETTINGS_LENGTH == LWS_HTTP2_SETTINGS_LENGTH - 1)
					if (lws_http2_interpret_settings_payload(wsi,
					     &h2n->peer_settings,
					     h2n->one_setting,
					     LWS_HTTP2_SETTINGS_LENGTH))
						break;
				break;

			case LWS_HTTP2_FRAME_TYPE_CONTINUATION:
			case LWS_HTTP2_FRAME_TYPE_HEADERS:
				//lwsl_notice(" LWS_HTTP2_FRAME_TYPE_HEADERS: %02X\n", c);

				if (lws_hpack_interpret(h2n->stream_wsi, c)) {
					lwsl_info("%s: lws_hpack_interpret failed\n", __func__);
					return 1;
				}
				break;

			case LWS_HTTP2_FRAME_TYPE_GOAWAY:
				switch (h2n->inside++) {
				case 0:
				case 1:
				case 2:
				case 3:
					h2n->goaway_last_sid <<= 8;
					h2n->goaway_last_sid |= c;
					h2n->goaway_error_string[0] = '\0';
					break;

				case 4:
				case 5:
				case 6:
				case 7:
					h2n->goaway_error_code <<= 8;
					h2n->goaway_error_code |= c;
					break;

				default:
					if (h2n->inside - 9 < sizeof(h2n->goaway_error_string) - 1)
						h2n->goaway_error_string[h2n->inside - 9] = c;
					h2n->goaway_error_string[sizeof(h2n->goaway_error_string) - 1] = '\0';
					break;
				}
				break;
			case LWS_HTTP2_FRAME_TYPE_DATA:
				break;
			case LWS_HTTP2_FRAME_TYPE_PRIORITY:
				if (h2n->count <= 4) {
					h2n->dep_temp <<= 8;
					h2n->dep_temp |= c;
				} else {
					h2n->weight_temp = c;
					lwsl_info("PRIORITY: dependency 0x%x, weight 0x%02X\n", h2n->dep_temp, h2n->weight_temp);

					if ((h2n->dep_temp & ~(1 << 31)) == h2n->stream_id) {
						lws_http2_goaway(wsi,
								LWS_HTTP2_ERR_PROTOCOL_ERROR,
								"cant depend on own sid");
						break;
					}
				}
				break;
			case LWS_HTTP2_FRAME_TYPE_RST_STREAM:
				break;
			case LWS_HTTP2_FRAME_TYPE_PUSH_PROMISE:
				break;
			case LWS_HTTP2_FRAME_TYPE_PING:
				if (h2n->flags & LWS_HTTP2_FLAG_SETTINGS_ACK) { // ack
				} else { /* they're sending us a ping request */
					if (h2n->count > 8)
						return 1;
					h2n->ping_payload[h2n->count - 1] = c;
				}
				break;
			case LWS_HTTP2_FRAME_TYPE_WINDOW_UPDATE:
				h2n->hpack_e_dep <<= 8;
				h2n->hpack_e_dep |= c;
				break;

			case LWS_HTTP2_FRAME_TYPE_COUNT: /* IGNORING FRAME */
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

			h2n->frame_state = 0;
			h2n->count = 0;
			swsi = h2n->stream_wsi;
			/* set our initial window size */
			if (!wsi->u.http2.initialized) {
				wsi->u.http2.tx_credit = h2n->peer_settings.setting[LWS_HTTP2_SETTINGS__INITIAL_WINDOW_SIZE];
				lwsl_info("initial tx credit on master conn %p: %d\n", wsi, wsi->u.http2.tx_credit);
				wsi->u.http2.initialized = 1;
			}

			if (h2n->collected_priority && (h2n->dep_temp & ~(1 << 31)) == h2n->stream_id) {
				lws_http2_goaway(wsi,
						LWS_HTTP2_ERR_PROTOCOL_ERROR,
						"cant depend on own sid");
				break;
			}

			switch (h2n->type) {
			case LWS_HTTP2_FRAME_TYPE_CONTINUATION:
			case LWS_HTTP2_FRAME_TYPE_HEADERS:

				//lwsl_notice("HEADERS / CONTINUATION EOF\n");
				/* service the http request itself */

				if (h2n->last_action_dyntable_resize) {
					lws_http2_goaway(wsi,
						LWS_HTTP2_ERR_COMPRESSION_ERROR,
						"dyntable resize last in headers");
				}

				if (!wsi->u.http2.END_HEADERS) {
					/* we are not finished yet */
					lwsl_info("witholding http action for continuation\n");
					break;
				}

				/* confirm the hpack stream state is reasonable for finishing */

				if (h2n->hpack != HPKS_TYPE) {
					/* hpack incomplete */
					lwsl_info("hpack incomplete %d (type %d, h2n->hpack_len %d)\n", h2n->hpack, h2n->type, h2n->hpack_len);
					lws_http2_goaway(wsi,
						LWS_HTTP2_ERR_COMPRESSION_ERROR,
						"hpack incomplete");
					break;
				}

				/* this is the last part of HEADERS */
				switch (swsi->u.http2.http2_state) {
				case LWS_HTTP2_STATE_IDLE:
					lws_http2_state_transition(swsi, LWS_HTTP2_STATE_OPEN);
					break;
				case LWS_HTTP2_STATE_RESERVED_REMOTE:
					lws_http2_state_transition(swsi, LWS_HTTP2_STATE_HALF_CLOSED_LOCAL);
					break;
				}

				lwsl_info("servicing initial http request, wsi=%p, stream wsi=%p\n", wsi, swsi);
				swsi->hdr_parsing_completed = 1;

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

						len = lws_hdr_total_length(swsi, n);
						if (!len || len > sizeof(buf) - 1) {
							n++;
							continue;
						}

						lws_hdr_copy(swsi, buf, sizeof buf, n);
						buf[sizeof(buf) - 1] = '\0';

						lwsl_info("    %s = %s\n", (char *)c, buf);
						n++;
					} while (c);
				}

				if (swsi->u.http2.http2_state == LWS_HTTP2_STATE_HALF_CLOSED_REMOTE ||
				    swsi->u.http2.http2_state == LWS_HTTP2_STATE_CLOSED) {
					lws_http2_goaway(wsi,
						LWS_HTTP2_ERR_STREAM_CLOSED,
						"Banning service on LWS_HTTP2_STATE_HALF_CLOSED_REMOTE");
					break;
				}

				switch (swsi->u.http2.http2_state) {
				case LWS_HTTP2_STATE_OPEN:
					if (wsi->u.http2.END_STREAM)
						lws_http2_state_transition(swsi, LWS_HTTP2_STATE_HALF_CLOSED_REMOTE);
					break;
				case LWS_HTTP2_STATE_HALF_CLOSED_LOCAL:
					if (wsi->u.http2.END_STREAM)
						lws_http2_state_transition(swsi, LWS_HTTP2_STATE_CLOSED);
					break;
				}

				if (!lws_hdr_total_length(swsi, WSI_TOKEN_HTTP_COLON_PATH) ||
				    !lws_hdr_total_length(swsi, WSI_TOKEN_HTTP_COLON_METHOD) ||
				    !lws_hdr_total_length(swsi, WSI_TOKEN_HTTP_COLON_SCHEME) ||
				     lws_hdr_total_length(swsi, WSI_TOKEN_HTTP_COLON_STATUS)) {
					lws_http2_goaway(wsi, LWS_HTTP2_ERR_PROTOCOL_ERROR, "Pseudoheader checks");
					break;
				}
#if 0
				n = lws_hdr_total_length(swsi, WSI_TOKEN_HTTP_TRANSFER_ENCODING);
				if (n && (n != 8 || strncmp(lws_hdr_simple_ptr(swsi, WSI_TOKEN_HTTP_TRANSFER_ENCODING), "trailers", n))) {
					lws_http2_goaway(wsi, LWS_HTTP2_ERR_PROTOCOL_ERROR, "Illegal transfer-encoding");
					break;
				}
#endif
				n = lws_http_action(swsi);
				(void)n;
				lwsl_info("  action result %d\n", n);
				if (n)
					if (lws_http_transaction_completed(swsi))
						return 1;

				break;
			case LWS_HTTP2_FRAME_TYPE_DATA:
				if (wsi->u.http2.END_STREAM && swsi->u.http2.http2_state == LWS_HTTP2_STATE_OPEN)
					lws_http2_state_transition(swsi, LWS_HTTP2_STATE_HALF_CLOSED_REMOTE);

				if (wsi->u.http2.END_STREAM && swsi->u.http2.http2_state == LWS_HTTP2_STATE_HALF_CLOSED_LOCAL)
					lws_http2_state_transition(swsi, LWS_HTTP2_STATE_CLOSED);
				break;
			case LWS_HTTP2_FRAME_TYPE_PING:

				if (h2n->flags & LWS_HTTP2_FLAG_SETTINGS_ACK) { // ack
				} else {/* they're sending us a ping request */
					lwsl_info("rx ping, preparing pong\n");
					lws_set_protocol_write_pending(wsi, LWS_PPS_HTTP2_PONG);
				}

				break;
			case LWS_HTTP2_FRAME_TYPE_WINDOW_UPDATE:
				h2n->hpack_e_dep &= ~(1 << 31);
				lwsl_info("LWS_HTTP2_FRAME_TYPE_WINDOW_UPDATE: %u\n", h2n->hpack_e_dep);

				if ((lws_intptr_t)swsi->u.http2.tx_credit + (lws_intptr_t)h2n->hpack_e_dep > (lws_intptr_t)(~((uint32_t)1 << 31))) {
					lws_http2_rst_stream(swsi, LWS_HTTP2_ERR_FLOW_CONTROL_ERROR, "Flow control exceeded max");
					break;
				}

				if (!h2n->hpack_e_dep) {
					lws_http2_goaway(wsi, LWS_HTTP2_ERR_PROTOCOL_ERROR, "Zero length window update");
					break;
				}
				swsi->u.http2.tx_credit += h2n->hpack_e_dep;
				if (swsi->u.http2.waiting_tx_credit && swsi->u.http2.tx_credit > 0) {
					lwsl_info("%s: %p: waiting_tx_credit -> wait on writeable\n", __func__, wsi);
					swsi->u.http2.waiting_tx_credit = 0;
					lws_callback_on_writable(swsi);
				}
				break;
			case LWS_HTTP2_FRAME_TYPE_GOAWAY:
				lwsl_info("GOAWAY: last sid %d, error code 0x%08X, string '%s'\n",
						h2n->goaway_last_sid,
						h2n->goaway_error_code,
						h2n->goaway_error_string);
				swsi->u.http2.GOING_AWAY = 1;
				return 1;
			case LWS_HTTP2_FRAME_TYPE_COUNT: /* IGNORING FRAME */
				break;
			}
			break;
		} else
			h2n->inside = 0;

		if (h2n->frame_state <= 8) {

			switch (h2n->frame_state++) {
			case 0:
				h2n->collected_padding_length = 0;
				h2n->collected_priority = 0;
				h2n->padding = 0;
				h2n->preamble = 0;
				h2n->length = c;
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
				h2n->stream_id <<= 8;
				h2n->stream_id |= c;
				break;
			}
		}
		if (h2n->frame_state == LWS_HTTP2_FRAME_HEADER_LENGTH) {
			/*
			 * We just got the frame header
			 */
			h2n->count = 0;
			h2n->stream_wsi = wsi;
			/* b31 is a reserved bit */
			h2n->stream_id = h2n->stream_id & 0x7fffffff;

			if (h2n->stream_id && !(h2n->stream_id & 1)) {
				lws_http2_goaway(wsi,
					LWS_HTTP2_ERR_PROTOCOL_ERROR,
					"Even Stream ID");
				break;
			}

			if (!h2n->we_told_goaway && h2n->stream_id > h2n->highest_stream_id)
				h2n->highest_stream_id = h2n->stream_id;

			if (h2n->stream_id)
				h2n->stream_wsi = lws_http2_wsi_from_id(wsi, h2n->stream_id);

			swsi = h2n->stream_wsi;

			lwsl_info("%p (%p): frame header: type 0x%x, flags 0x%x, sid 0x%x, len 0x%x\n", wsi, h2n->stream_wsi,
					h2n->type, h2n->flags, h2n->stream_id, h2n->length);

			if (h2n->we_told_goaway && h2n->stream_id > h2n->highest_stream_id)
				h2n->type = LWS_HTTP2_FRAME_TYPE_COUNT; /* ie, IGNORE */


			if (h2n->type == LWS_HTTP2_FRAME_TYPE_COUNT)
				return 0;

			if (h2n->length > h2n->my_settings.setting[LWS_HTTP2_SETTINGS__MAX_FRAME_SIZE]) {
				/*
				 * peer sent us something bigger than we told
				 * it we would allow
				 */
				lws_http2_goaway(wsi,
					LWS_HTTP2_ERR_FRAME_SIZE_ERROR,
					"Peer ignored our frame size setting");
				break;
			}

			if (swsi && h2n->stream_id) { /* directed at a substream */
				if (!(http2_rx_validity[swsi->u.http2.http2_state] & (1 << h2n->type))) {
					lwsl_info("%s: wsi %p, State: %s, ILLEGAL cmd rx %d (valid mask 0x%x)\n",
							__func__, h2n->stream_wsi,
							http2_state_names[swsi->u.http2.http2_state],
							h2n->type, http2_rx_validity[swsi->u.http2.http2_state]);
					if (swsi->u.http2.http2_state == LWS_HTTP2_STATE_CLOSED ||
					    swsi->u.http2.http2_state == LWS_HTTP2_STATE_HALF_CLOSED_REMOTE)
						h2n->goaway_error_code = LWS_HTTP2_ERR_STREAM_CLOSED;
					else
						h2n->goaway_error_code = LWS_HTTP2_ERR_PROTOCOL_ERROR;
					lws_http2_goaway(wsi,
						h2n->goaway_error_code,
						"invalid rx");
					break;
				}
			}

			if (h2n->continuation_expected && (
			     h2n->continuation_expected_stream_id != h2n->stream_id ||
			     h2n->type != LWS_HTTP2_FRAME_TYPE_CONTINUATION)
			    ) {
				lwsl_info("%s: expected continuation on sid %d (got %d on sid %d)\n", __func__, h2n->continuation_expected_stream_id, h2n->type, h2n->stream_id);
				h2n->continuation_expected = 0;
				if (h2n->continuation_expected_headers)
					h2n->goaway_error_code = LWS_HTTP2_ERR_COMPRESSION_ERROR;
				else
					h2n->goaway_error_code = LWS_HTTP2_ERR_PROTOCOL_ERROR;
				lws_http2_goaway(wsi,
					h2n->goaway_error_code,
					"Continuation Headers State");
				break;
			}

			switch (h2n->type) {
			case LWS_HTTP2_FRAME_TYPE_DATA:
				lwsl_info("Frame header LWS_HTTP2_FRAME_TYPE_DATA\n");
				if (swsi->u.http2.http2_state == LWS_HTTP2_STATE_HALF_CLOSED_REMOTE ||
				    swsi->u.http2.http2_state == LWS_HTTP2_STATE_CLOSED) {
					lws_http2_goaway(wsi,
						LWS_HTTP2_ERR_STREAM_CLOSED,
						"Banning service on LWS_HTTP2_STATE_HALF_CLOSED_REMOTE");
					break;
				}
				if (!h2n->stream_id) {
					lws_http2_goaway(wsi,
						LWS_HTTP2_ERR_PROTOCOL_ERROR,
						"DATA has 0 sid");
					break;
				}
				break;
			case LWS_HTTP2_FRAME_TYPE_PRIORITY:
				lwsl_info("LWS_HTTP2_FRAME_TYPE_PRIORITY complete frame\n");
				if (!h2n->stream_id) {
					lws_http2_goaway(wsi, LWS_HTTP2_ERR_PROTOCOL_ERROR,
							 "Priority has 0 sid");
					break;
				}
				if (h2n->length != 5) {
					lws_http2_goaway(wsi, LWS_HTTP2_ERR_FRAME_SIZE_ERROR,
							 "Priority has length other than 5");
					break;
				}
				break;
			case LWS_HTTP2_FRAME_TYPE_PUSH_PROMISE:
				lwsl_info("LWS_HTTP2_FRAME_TYPE_PUSH_PROMISE complete frame\n");
				break;
			case LWS_HTTP2_FRAME_TYPE_GOAWAY:
				break;

			case LWS_HTTP2_FRAME_TYPE_RST_STREAM:
				if (!h2n->stream_id || !h2n->stream_wsi)
					return 1;
				if (h2n->length != 4) {
					lws_http2_goaway(wsi, LWS_HTTP2_ERR_FRAME_SIZE_ERROR,
							 "RST_STREAM can only be length 4");
					break;
				}
				lws_http2_state_transition(h2n->stream_wsi, LWS_HTTP2_STATE_CLOSED);
				break;

			case LWS_HTTP2_FRAME_TYPE_SETTINGS:
				lwsl_info("LWS_HTTP2_FRAME_TYPE_SETTINGS complete frame\n");
				/* nonzero sid on settings is illegal */
				if (h2n->stream_id) {
					lws_http2_goaway(wsi, LWS_HTTP2_ERR_PROTOCOL_ERROR,
							 "Settings has nonzero sid");
					break;
				}

				if (!(h2n->flags & LWS_HTTP2_FLAG_SETTINGS_ACK)) {
					if ((!h2n->length) || h2n->length % 6) {
						lws_http2_goaway(wsi, LWS_HTTP2_ERR_FRAME_SIZE_ERROR,
								 "Settings length error");
						break;
					}
					lwsl_info("scheduled settings ack PPS\n");
					/* non-ACK coming in means we must ACK it */
					lws_set_protocol_write_pending(wsi, LWS_PPS_HTTP2_ACK_SETTINGS);
					break;
				}
				/* came to us with ACK set... not allowed to have payload */

				if (h2n->length) {
					lws_http2_goaway(wsi, LWS_HTTP2_ERR_FRAME_SIZE_ERROR,
							 "Settings with ACK not allowed payload");
					break;
				}
				break;
			case LWS_HTTP2_FRAME_TYPE_PING:
				if (h2n->stream_id) {
					lws_http2_goaway(wsi, LWS_HTTP2_ERR_PROTOCOL_ERROR,
							 "Ping has nonzero sid");
					break;
				}
				if (h2n->length != 8) {
					lws_http2_goaway(wsi, LWS_HTTP2_ERR_FRAME_SIZE_ERROR,
							 "Ping payload can only be 8");
					break;
				}
				break;
			case LWS_HTTP2_FRAME_TYPE_CONTINUATION:
				lwsl_info("LWS_HTTP2_FRAME_TYPE_CONTINUATION: stream_id = %d\n", h2n->stream_id);
				if (wsi->u.http2.END_HEADERS)
					return 1;

				if (!h2n->continuation_expected ||
				     h2n->continuation_expected_stream_id != h2n->stream_id ||
				     !h2n->stream_id) {
					lws_http2_goaway(wsi, LWS_HTTP2_ERR_PROTOCOL_ERROR,
							 "unexpected CONTINUATION");
					break;
				}
				swsi = h2n->stream_wsi;
				/* END_STREAM is in HEADERS, skip resetting it */
				goto update_end_headers;

			case LWS_HTTP2_FRAME_TYPE_HEADERS:
				lwsl_info("LWS_HTTP2_FRAME_TYPE_HEADERS: frame header: stream_id = %d\n", h2n->stream_id);
				if (!h2n->stream_id)
					return 1;

				if (!h2n->stream_wsi)
					h2n->stream_wsi = lws_create_server_child_wsi(wsi->vhost, wsi, h2n->stream_id);

				if (!h2n->stream_wsi) {
					lwsl_notice("failed to create child wsi\n");
					return 1;
				}

				swsi = h2n->stream_wsi;
				/*
				 * ah needs attaching to child wsi, even though
				 * we only fill it from network wsi
				 */
				if (!swsi->u.hdr.ah)
					if (lws_header_table_attach(swsi, 0)) {
						lwsl_err("%s: Failed to get ah\n", __func__);
						return 1;
					}
#if 0
				if (wsi->u.http2.END_HEADERS) {
					lws_http2_goaway(wsi, LWS_HTTP2_ERR_STREAM_CLOSED,
							 "Headers already done");
					break;
				}
#endif
				/* END_STREAM means after servicing this, close the stream */
				wsi->u.http2.END_STREAM = !!(h2n->flags & LWS_HTTP2_FLAG_END_STREAM);
				lwsl_info("%s: headers END_STREAM = %d\n",__func__, wsi->u.http2.END_STREAM);

				h2n->continuation_expected = !(h2n->flags & LWS_HTTP2_FLAG_END_HEADERS);
				h2n->continuation_expected_stream_id = h2n->stream_id;
				h2n->continuation_expected_headers = 1;

update_end_headers:
				/* no END_HEADERS means CONTINUATION must come */
				wsi->u.http2.END_HEADERS = !!(h2n->flags & LWS_HTTP2_FLAG_END_HEADERS);
				if (wsi->u.http2.END_HEADERS)
					h2n->continuation_expected = 0;
				lwsl_debug("END_HEADERS %d\n", wsi->u.http2.END_HEADERS);

				if (h2n->type != LWS_HTTP2_FRAME_TYPE_CONTINUATION) {
					/* prepare the hpack parser at the right start */

					lwsl_info("resetting hpack\n");
					lws_header_table_reset(swsi, 0);
					h2n->seen_nonpseudoheader = 0;
					h2n->hpack = HPKS_TYPE;
				} else
					lwsl_debug("skipping resetting hpack\n");
				break;

			case LWS_HTTP2_FRAME_TYPE_WINDOW_UPDATE:
				if (h2n->length != 4) {
					lws_http2_goaway(wsi, LWS_HTTP2_ERR_FRAME_SIZE_ERROR,
						 "window update frame not 4");
					break;
				}
				lwsl_info("LWS_HTTP2_FRAME_TYPE_WINDOW_UPDATE\n");
				break;
			default:
				lwsl_notice("%s: ILLEGAL FRAME TYPE %d\n", __func__, h2n->type);
				h2n->type = LWS_HTTP2_FRAME_TYPE_COUNT; /* ie, IGNORE */
				break;
			}
			if (h2n->length == 0)
				h2n->frame_state = 0;

		}
		break;
	}

	return 0;
}

int lws_http2_do_pps_send(struct lws *wsi)
{
	struct lws_http2_netconn *h2n = wsi->u.http2.h2n;
	unsigned char settings[LWS_PRE + 64],
			*p = &settings[LWS_PRE], *q;
	struct lws *swsi;
	int n, m = 0;

	lwsl_info("%s: %p: %d\n", __func__, wsi, wsi->pps);

	switch (wsi->pps) {

	case LWS_PPS_HTTP2_MY_SETTINGS:
		for (n = 1; n < LWS_HTTP2_SETTINGS__COUNT; n++)
			if (h2n->my_settings.setting[n] != lws_http2_default_settings.setting[n]) {
				lws_http2_settings_write(wsi, n,
							 &settings[LWS_PRE + m]);
				m += sizeof(h2n->one_setting);
			}
		n = lws_http2_frame_write(wsi, LWS_HTTP2_FRAME_TYPE_SETTINGS,
		     			  0, LWS_HTTP2_STREAM_ID_MASTER, m,
		     			  &settings[LWS_PRE]);
		if (n != m) {
			lwsl_info("send %d %d\n", n, m);
			return 1;
		}
		break;

	case LWS_PPS_HTTP2_ACK_SETTINGS:
		/* send ack ... always empty */
		n = lws_http2_frame_write(wsi, LWS_HTTP2_FRAME_TYPE_SETTINGS,
			1, LWS_HTTP2_STREAM_ID_MASTER, 0,
			&settings[LWS_PRE]);
		if (n) {
			lwsl_err("ack tells %d\n", n);
			return 1;
		}
		/* this is the end of the preface dance then? */
		if (wsi->state == LWSS_HTTP2_ESTABLISHED_PRE_SETTINGS) {
			wsi->state = LWSS_HTTP2_ESTABLISHED;

			wsi->u.http.fop_fd = NULL;

			if (lws_is_ssl(lws_http2_get_network_wsi(wsi))) {
				lwsl_info("skipping nonexistent ssl upgrade headers\n");
				break;
			}

			/*
			 * we need to treat the headers from this upgrade
			 * as the first job.  These need to get
			 * shifted to stream ID 1
			 */
			swsi = h2n->stream_wsi =
					lws_create_server_child_wsi(wsi->vhost, wsi, 1);

			/* pass on the initial headers to SID 1 */
			swsi->u.http.ah = wsi->u.http.ah;
			wsi->u.http.ah = NULL;

			lwsl_info("%s: inherited headers %p\n", __func__, swsi->u.http.ah);
			swsi->u.http2.tx_credit = h2n->peer_settings.setting[LWS_HTTP2_SETTINGS__INITIAL_WINDOW_SIZE];
			lwsl_info("initial tx credit on conn %p: %d\n", swsi, swsi->u.http2.tx_credit);
			swsi->u.http2.initialized = 1;
			/* demanded by HTTP2 */
			swsi->u.http2.END_STREAM = 1;
			lwsl_info("servicing initial http request\n");

			return lws_http_action(swsi);
		}
		break;
	case LWS_PPS_HTTP2_PONG:
		lwsl_debug("sending PONG\n");
		memcpy(&settings[LWS_PRE], h2n->ping_payload, 8);
		n = lws_http2_frame_write(wsi, LWS_HTTP2_FRAME_TYPE_PING,
		     			  LWS_HTTP2_FLAG_SETTINGS_ACK,
			    		  LWS_HTTP2_STREAM_ID_MASTER, 8,
		     			  &settings[LWS_PRE]);
		if (n != 8) {
			lwsl_info("send %d %d\n", n, m);
			return 1;
		}
		break;

	case LWS_PPS_HTTP2_GOAWAY:
		lwsl_info("LWS_PPS_HTTP2_GOAWAY\n");
		*p++ = h2n->highest_stream_id >> 24;
		*p++ = h2n->highest_stream_id >> 16;
		*p++ = h2n->highest_stream_id >> 8;
		*p++ = h2n->highest_stream_id;
		*p++ = h2n->goaway_error_code >> 24;
		*p++ = h2n->goaway_error_code >> 16;
		*p++ = h2n->goaway_error_code >> 8;
		*p++ = h2n->goaway_error_code;
		q = (unsigned char *)h2n->goaway_error_string;
		n = 0;
		while (*q && n++ < sizeof(h2n->goaway_error_string))
			*p++ = *q++;
		h2n->we_told_goaway = 1;
		n = lws_http2_frame_write(wsi, LWS_HTTP2_FRAME_TYPE_GOAWAY,
		     			  0, LWS_HTTP2_STREAM_ID_MASTER,
		     			  p - &settings[LWS_PRE],
		     			  &settings[LWS_PRE]);
		if (n != m) {
			lwsl_info("send %d %d\n", n, m);
			return 1;
		}
		return 1;

	case LWS_PPS_HTTP2_RST_STREAM:
		lwsl_info("LWS_PPS_HTTP2_GOAWAY\n");
		*p++ = h2n->goaway_error_code >> 24;
		*p++ = h2n->goaway_error_code >> 16;
		*p++ = h2n->goaway_error_code >> 8;
		*p++ = h2n->goaway_error_code;
		n = lws_http2_frame_write(wsi, LWS_HTTP2_FRAME_TYPE_RST_STREAM,
		     			  0, LWS_HTTP2_STREAM_ID_MASTER, 4,
		     			  &settings[LWS_PRE]);
		if (n != m) {
			lwsl_info("send %d %d\n", n, m);
			return 1;
		}
		break;

	default:
		break;
	}

	return 0;
}
