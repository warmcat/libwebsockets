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

int
lws_handshake_client(struct lws *wsi, unsigned char **buf, size_t len)
{
	int m;

	if ((lwsi_state(wsi) != LRS_WAITING_PROXY_REPLY) &&
	    (lwsi_state(wsi) != LRS_H1C_ISSUE_HANDSHAKE) &&
	    (lwsi_state(wsi) != LRS_WAITING_SERVER_REPLY) &&
	    !lwsi_role_client(wsi))
		return 0;

	while (len) {
		/*
		 * we were accepting input but now we stopped doing so
		 */
		if (lws_is_flowcontrolled(wsi)) {
			lwsl_debug("%s: caching %ld\n", __func__, (long)len);
			lws_rxflow_cache(wsi, *buf, 0, (int)len);
			return 0;
		}
		if (wsi->ws->rx_draining_ext) {
#if !defined(LWS_NO_CLIENT)
			if (lwsi_role_client(wsi))
				m = lws_client_rx_sm(wsi, 0);
			else
#endif
				m = lws_ws_rx_sm(wsi, 0);
			if (m < 0)
				return -1;
			continue;
		}
		/* account for what we're using in rxflow buffer */
		if (lws_buflist_next_segment_len(&wsi->buflist_rxflow, NULL) &&
		    !lws_buflist_use_segment(&wsi->buflist_rxflow, 1)) {
			lwsl_debug("%s: removed wsi %p from rxflow list\n", __func__, wsi);
			lws_dll_lws_remove(&wsi->dll_rxflow);
		}

		if (lws_client_rx_sm(wsi, *(*buf)++)) {
			lwsl_debug("client_rx_sm exited\n");
			return -1;
		}
		len--;
	}
	lwsl_debug("%s: finished with %ld\n", __func__, (long)len);

	return 0;
}

