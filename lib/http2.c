/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2013 Andy Green <andy@warmcat.com>
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
	0,
	/* LWS_HTTP2_SETTINGS__HEADER_TABLE_SIZE */		4096,
	/* LWS_HTTP2_SETTINGS__ENABLE_PUSH */			   1,
	/* LWS_HTTP2_SETTINGS__MAX_CONCURRENT_STREAMS */	 100,
	/* LWS_HTTP2_SETTINGS__INITIAL_WINDOW_SIZE */	       65535,
	/* LWS_HTTP2_SETTINGS__MAX_FRAME_SIZE */	       16384,
	/* LWS_HTTP2_SETTINGS__MAX_HEADER_LIST_SIZE */		  ~0,
}};


void lws_http2_init(struct http2_settings *settings)
{
	memcpy(settings, lws_http2_default_settings.setting, sizeof(*settings));
}

struct libwebsocket *
lws_http2_wsi_from_id(struct libwebsocket *wsi, unsigned int sid)
{
	do {
		if (wsi->u.http2.my_stream_id == sid)
			return wsi;
		
		wsi = wsi->u.http2.next_child_wsi;
	} while (wsi);
	
	return NULL;
}

struct libwebsocket *
lws_create_server_child_wsi(struct libwebsocket_context *context, struct libwebsocket *parent_wsi, unsigned int sid)
{
	struct libwebsocket *wsi = libwebsocket_create_new_server_wsi(context);
	
	if (!wsi)
		return NULL;
	
	/* no more children allowed by parent */
	if (parent_wsi->u.http2.child_count + 1 == parent_wsi->u.http2.peer_settings.setting[LWS_HTTP2_SETTINGS__MAX_CONCURRENT_STREAMS])
		return NULL;
	
	lws_http2_init(&wsi->u.http2.peer_settings);
	lws_http2_init(&wsi->u.http2.my_settings);
	wsi->u.http2.stream_id = sid;
	wsi->u.http2.my_stream_id = sid;

	wsi->u.http2.parent_wsi = parent_wsi;
	wsi->u.http2.next_child_wsi = parent_wsi->u.http2.next_child_wsi;
	parent_wsi->u.http2.next_child_wsi = wsi;
	parent_wsi->u.http2.child_count++;
	
	wsi->u.http2.my_priority = 16;
	
	wsi->state = WSI_STATE_HTTP2_ESTABLISHED;
	wsi->mode = parent_wsi->mode;

	lwsl_info("%s: %p new child %p, sid %d\n", __func__, parent_wsi, wsi, sid);
	
	return wsi;
}

int lws_remove_server_child_wsi(struct libwebsocket_context *context, struct libwebsocket *wsi)
{
	struct libwebsocket **w = &wsi->u.http2.parent_wsi;
	do {
		if (*w == wsi) {
			*w = wsi->u.http2.next_child_wsi;
			(wsi->u.http2.parent_wsi)->u.http2.child_count--;
			return 0;
		}
		
		w = &((*w)->u.http2.next_child_wsi);
	} while (*w);
	
	lwsl_err("%s: can't find %p\n", __func__, wsi);
	return 1;
}

int
lws_http2_interpret_settings_payload(struct http2_settings *settings, unsigned char *buf, int len)
{
	unsigned int a, b;
	
	if (!len)
		return 0;
	
	if (len < LWS_HTTP2_SETTINGS_LENGTH)
		return 1;
	
	while (len >= LWS_HTTP2_SETTINGS_LENGTH) {
		a = (buf[0] << 8) | buf[1];
		if (a < LWS_HTTP2_SETTINGS__COUNT) {
			b = buf[2] << 24 | buf[3] << 16 | buf[4] << 8 | buf[5];
			settings->setting[a] = b;
			lwsl_info("http2 settings %d <- 0x%x\n", a, b);
		}
		len -= LWS_HTTP2_SETTINGS_LENGTH;
		buf += LWS_HTTP2_SETTINGS_LENGTH;
	}
	
	if (len)
		return 1;
	
	return 0;
}

struct libwebsocket *lws_http2_get_network_wsi(struct libwebsocket *wsi)
{
	while (wsi->u.http2.parent_wsi)
		wsi = wsi->u.http2.parent_wsi;
	
	return wsi;
}

int lws_http2_frame_write(struct libwebsocket *wsi, int type, int flags, unsigned int sid, unsigned int len, unsigned char *buf)
{
	struct libwebsocket *wsi_eff = lws_http2_get_network_wsi(wsi);
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
	
	lwsl_info("%s: %p (eff %p). type %d, flags 0x%x, sid=%d, len=%d\n",
		  __func__, wsi, wsi_eff, type, flags, sid, len);

	n = lws_issue_raw(wsi_eff, &buf[-LWS_HTTP2_FRAME_HEADER_LENGTH], len + LWS_HTTP2_FRAME_HEADER_LENGTH);
	if (n >= LWS_HTTP2_FRAME_HEADER_LENGTH)
		return n - LWS_HTTP2_FRAME_HEADER_LENGTH;
	
	return n;
}

static void lws_http2_settings_write(struct libwebsocket *wsi, int n, unsigned char *buf)
{
	*buf++ = n >> 8;
	*buf++ = n;
	*buf++ = wsi->u.http2.my_settings.setting[n] >> 24;
	*buf++ = wsi->u.http2.my_settings.setting[n] >> 16;
	*buf++ = wsi->u.http2.my_settings.setting[n] >> 8;
	*buf = wsi->u.http2.my_settings.setting[n];
}

static const char const * https_client_preface =
	"PRI * HTTP/2.0\x0d\x0a\x0d\x0aSM\x0d\x0a\x0d\x0a";

int
lws_http2_parser(struct libwebsocket_context *context,
		     struct libwebsocket *wsi, unsigned char c)
{
	struct libwebsocket *swsi;
	int n;
	//dstruct libwebsocket *wsi_new;

	switch (wsi->state) {
	case WSI_STATE_HTTP2_AWAIT_CLIENT_PREFACE:
		if (https_client_preface[wsi->u.http2.count++] != c)
			return 1;

		if (!https_client_preface[wsi->u.http2.count]) {
			lwsl_err("http2: %p: established\n", wsi);
			wsi->state = WSI_STATE_HTTP2_ESTABLISHED_PRE_SETTINGS;
			wsi->u.http2.count = 0;
			
			/* 
			 * we must send a settings frame -- empty one is OK...
			 * that must be the first thing sent by server
			 * and the peer must send a SETTINGS with ACK flag...
			 */
			
			lws_set_protocol_write_pending(context, wsi, LWS_PPS_HTTP2_MY_SETTINGS);
		}
		break;

	case WSI_STATE_HTTP2_ESTABLISHED_PRE_SETTINGS:
	case WSI_STATE_HTTP2_ESTABLISHED:
		if (wsi->u.http2.frame_state == LWS_HTTP2_FRAME_HEADER_LENGTH) { // payload
			wsi->u.http2.count++;
			wsi->u.http2.stream_wsi->u.http2.count = wsi->u.http2.count;
			/* applies to wsi->u.http2.stream_wsi which may be wsi*/
			switch(wsi->u.http2.type) {
			case LWS_HTTP2_FRAME_TYPE_SETTINGS:
				wsi->u.http2.stream_wsi->u.http2.one_setting[wsi->u.http2.count % LWS_HTTP2_SETTINGS_LENGTH] = c;
				if (wsi->u.http2.count % LWS_HTTP2_SETTINGS_LENGTH == LWS_HTTP2_SETTINGS_LENGTH - 1)
					if (lws_http2_interpret_settings_payload(
					     &wsi->u.http2.stream_wsi->u.http2.peer_settings,
					     wsi->u.http2.one_setting,
					     LWS_HTTP2_SETTINGS_LENGTH))
						return 1;
				break;
			case LWS_HTTP2_FRAME_TYPE_HEADERS:
				lwsl_info(" %02X\n", c);
				if (lws_hpack_interpret(context, wsi->u.http2.stream_wsi, c))
					return 1;
				break;
			}
			if (wsi->u.http2.count != wsi->u.http2.length)
				break;
			
			/* end of frame */

			wsi->u.http2.frame_state = 0;
			wsi->u.http2.count = 0;
			/* set our initial window size */
			if (!wsi->u.http2.initialized) {
				wsi->u.http2.tx_credit = wsi->u.http2.peer_settings.setting[LWS_HTTP2_SETTINGS__INITIAL_WINDOW_SIZE];
				lwsl_info("initial tx credit on master conn %p: %d\n", wsi, wsi->u.http2.tx_credit);
				wsi->u.http2.initialized = 1;
			}
			switch (wsi->u.http2.type) {
			case LWS_HTTP2_FRAME_TYPE_HEADERS:
				/* service the http request itself */
				lwsl_info("servicing initial http request\n");
				n = lws_http_action(context, wsi->u.http2.stream_wsi);
				lwsl_info("  action result %d\n", n);
				break;
			}
			break;
		}
		switch (wsi->u.http2.frame_state++) {
		case 0:
			wsi->u.http2.length = c;
			break;
		case 1:
		case 2:
			wsi->u.http2.length <<= 8;
			wsi->u.http2.length |= c;
			break;
		case 3:
			wsi->u.http2.type = c;
			break;
		case 4:
			wsi->u.http2.flags = c;
			break;
		case 5:
		case 6:
		case 7:
		case 8:
			wsi->u.http2.stream_id <<= 8;
			wsi->u.http2.stream_id |= c;
			wsi->u.http2.stream_wsi = wsi;
			break;
		}
		if (wsi->u.http2.frame_state == LWS_HTTP2_FRAME_HEADER_LENGTH) { /* frame header complete */
			lwsl_info("frame: type 0x%x, flags 0x%x, sid 0x%x, len 0x%x\n",
				  wsi->u.http2.type, wsi->u.http2.flags, wsi->u.http2.stream_id, wsi->u.http2.length);
			wsi->u.http2.count = 0;
			
			
			switch (wsi->u.http2.type) {
			case LWS_HTTP2_FRAME_TYPE_SETTINGS:
				/* nonzero sid on settings is illegal */
				if (wsi->u.http2.stream_id)
					return 1;
				
				if (wsi->u.http2.flags & LWS_HTTP2_FLAG_SETTINGS_ACK) { // ack
				} else
					/* non-ACK coming in means we must ACK it */
					lws_set_protocol_write_pending(context, wsi, LWS_PPS_HTTP2_ACK_SETTINGS);
				break;
			case LWS_HTTP2_FRAME_TYPE_CONTINUATION:
				if (wsi->u.http2.END_HEADERS)
					return 1;
				goto update_end_headers;

			case LWS_HTTP2_FRAME_TYPE_HEADERS:
				lwsl_info("LWS_HTTP2_FRAME_TYPE_HEADERS: stream_id = %d\n", wsi->u.http2.stream_id);
				if (!wsi->u.http2.stream_id)
					return 1;
				wsi->u.http2.stream_wsi = lws_http2_wsi_from_id(wsi, wsi->u.http2.stream_id);
				if (!wsi->u.http2.stream_wsi)
					wsi->u.http2.stream_wsi = lws_create_server_child_wsi(context, wsi, wsi->u.http2.stream_id);
								
				/* END_STREAM means after servicing this, close the stream */
				wsi->u.http2.END_STREAM = !!(wsi->u.http2.flags & LWS_HTTP2_FLAG_END_STREAM);
				lwsl_info("%s: headers END_STREAM = %d\n",__func__, wsi->u.http2.END_STREAM);
update_end_headers:
				/* no END_HEADERS means CONTINUATION must come */
				wsi->u.http2.END_HEADERS = !!(wsi->u.http2.flags & LWS_HTTP2_FLAG_END_HEADERS);
				
				swsi = wsi->u.http2.stream_wsi;
				if (!swsi)
					return 1;

				
				/* prepare the hpack parser at the right start */
				
				swsi->u.http2.flags = wsi->u.http2.flags;
				swsi->u.http2.length = wsi->u.http2.length;
				swsi->u.http2.END_STREAM = wsi->u.http2.END_STREAM;

				if (swsi->u.http2.flags & LWS_HTTP2_FLAG_PADDED)
					swsi->u.http2.hpack = HPKS_OPT_PADDING;
				else
					if (swsi->u.http2.flags & LWS_HTTP2_FLAG_PRIORITY) {
						swsi->u.http2.hpack = HKPS_OPT_E_DEPENDENCY;
						swsi->u.http2.hpack_m = 4;
					} else
						swsi->u.http2.hpack = HPKS_TYPE;
				lwsl_info("initial hpack state %d\n", swsi->u.http2.hpack);
				break;
			}
			if (wsi->u.http2.length == 0)
				wsi->u.http2.frame_state = 0;

		}
		break;
	}
	
	return 0;
}

int lws_http2_do_pps_send(struct libwebsocket_context *context, struct libwebsocket *wsi)
{
	unsigned char settings[LWS_SEND_BUFFER_PRE_PADDING + 6 * LWS_HTTP2_SETTINGS__COUNT];
	int n, m = 0;

	switch (wsi->pps) {
	case LWS_PPS_HTTP2_MY_SETTINGS:
		for (n = 1; n < LWS_HTTP2_SETTINGS__COUNT; n++)
			if (wsi->u.http2.my_settings.setting[n] != lws_http2_default_settings.setting[n]) {
				lws_http2_settings_write(wsi, n,
							 &settings[LWS_SEND_BUFFER_PRE_PADDING + m]);
				m += sizeof(wsi->u.http2.one_setting);
			}
		n = lws_http2_frame_write(wsi, LWS_HTTP2_FRAME_TYPE_SETTINGS,
		     			  0, LWS_HTTP2_STREAM_ID_MASTER, m,
		     			  &settings[LWS_SEND_BUFFER_PRE_PADDING]);
		if (n != m) {
			lwsl_info("send %d %d\n", n, m);
			return 1;
		}
		break;
	case LWS_PPS_HTTP2_ACK_SETTINGS:
		/* send ack ... always empty */
		n = lws_http2_frame_write(wsi, LWS_HTTP2_FRAME_TYPE_SETTINGS,
			1, LWS_HTTP2_STREAM_ID_MASTER, 0,
			&settings[LWS_SEND_BUFFER_PRE_PADDING]);
		if (n) {
			lwsl_err("ack tells %d\n", n);
			return 1;
		}
		/* this is the end of the preface dance then? */
		if (wsi->state == WSI_STATE_HTTP2_ESTABLISHED_PRE_SETTINGS) {
			wsi->state = WSI_STATE_HTTP2_ESTABLISHED;
			
			wsi->u.http.fd = LWS_INVALID_FILE;

			return 0;
		}
		break;
	default:
		break;
	}
	
	return 0;
}