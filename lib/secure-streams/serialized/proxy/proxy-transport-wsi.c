/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2019 - 2021 Andy Green <andy@warmcat.com>
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
 *
 *
 * Proxy side of Client <-> Proxy wsi connection, usually on Unix Domain Socket
 */

#include <private-lib-core.h>

struct raw_pss {
	struct lws_sss_proxy_conn		*conn;
};

static int
lws_sss_proxy_transport_wsi_cb(struct lws *wsi, enum lws_callback_reasons reason,
			       void *user, void *in, size_t len)
{
	struct raw_pss *pss = (struct raw_pss *)user;
	struct lws_sss_proxy_conn *conn = NULL;

	if (pss)
		conn = pss->conn;

	switch (reason) {

	/* callbacks related to raw socket descriptor "accepted side" */

        case LWS_CALLBACK_RAW_ADOPT:
		lwsl_user("LWS_CALLBACK_RAW_ADOPT %s\n", lws_txp_inside_proxy.name);

		if (!pss)
			return -1;

		if (lws_txp_inside_proxy.event_new_conn(
				wsi->a.context,
				&lws_txp_inside_proxy,
				(lws_transport_priv_t)conn,
#if defined(LWS_WITH_SYS_FAULT_INJECTION)
				&wsi->fic,
#endif
				&pss->conn,
				(lws_transport_priv_t)wsi)) {
			lwsl_err("%s: hangup from new_conn\n", __func__);
			return -1;
		}

		/* dsh is allocated when the onward ss is done */

		wsi->bound_ss_proxy_conn = 1; /* opaque is conn */
		lws_set_opaque_user_data(wsi, pss->conn);

		pss->conn->state = LPCSPROX_WAIT_INITIAL_TX;

		/*
		 * Client is expected to follow the unix domain socket
		 * acceptance up rapidly with an initial tx containing the
		 * streamtype name.  We can't create the stream until then.
		 */
		lws_set_timeout(wsi, PENDING_TIMEOUT_AWAITING_CLIENT_HS_SEND, 3);
		lwsl_user("%s: ADOPT: accepted\n", __func__);
                break;

	case LWS_CALLBACK_RAW_CLOSE:
		lwsl_info("LWS_CALLBACK_RAW_CLOSE:\n");

		if (!conn)
			break;

		/*
		 * the client unix domain socket connection (wsi / conn->wsi)
		 * has closed... eg, client has exited or otherwise has
		 * definitively finished with the proxying and onward connection
		 *
		 * But right now, the SS and possibly the SS onward wsi are
		 * still live...
		 */

		assert(conn->txp_path.priv_onw == wsi);

//		if (conn->ss)
//			conn->ss = NULL;

		/* sever relationship with conn */
		lws_set_opaque_user_data(wsi, NULL);

		lws_txp_inside_proxy.event_close_conn(conn);

		/* pss is about to be deleted */
		if (pss)
			pss->conn = NULL;
		lwsl_notice("%s: close finished ok\n", __func__);
		break;

	case LWS_CALLBACK_RAW_RX:
		/*
		 * ie, the proxy is receiving something from a client
		 */
		lwsl_info("%s: RX: rx %d\n", __func__, (int)len);

		if (!conn) {
			lwsl_err("%s: rx with conn NULL\n", __func__);

			return -1;
		}

		if (conn->txp_path.ops_in->proxy_read(conn, in, len))
			return -1;

		break;

	case LWS_CALLBACK_RAW_WRITEABLE:

		lwsl_debug("%s: %s: LWS_CALLBACK_RAW_WRITEABLE, state 0x%x\n",
				__func__, lws_wsi_tag(wsi), lwsi_state(wsi));

		/*
		 * We can transmit something back to the client from the dsh
		 * of stuff we received on its behalf from the ss
		 */

		if (!conn)
			break;

		assert_is_conn(conn);

		if (lws_txp_inside_proxy.event_proxy_can_write(conn
#if defined(LWS_WITH_SYS_FAULT_INJECTION)
				, &wsi->fic
#endif
				))
			return -1;
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);
}

static const struct lws_protocols protocols[] = {
	{
		"ssproxy-protocol",
		lws_sss_proxy_transport_wsi_cb,
		sizeof(struct raw_pss),
		2048, 2048, NULL, 0
	},
	{ NULL, NULL, 0, 0, 0, NULL, 0 }
};

static void
lws_sss_proxy_wsi_onward_bind(lws_transport_priv_t priv, lws_ss_handle_t *h)
{
	struct lws *wsi = (struct lws *)priv;

	__lws_lc_tag_append(&wsi->lc, lws_ss_tag(h));
}

static void
lws_sss_proxy_wsi_req_write(lws_transport_priv_t priv)
{
	struct lws *wsi = (struct lws *)priv;

	if (wsi)
		lws_callback_on_writable(wsi);
}

#if defined(LWS_WITH_SYS_FAULT_INJECTION)
static const lws_fi_ctx_t *
lws_sss_proxy_wsi_fault_context(lws_transport_priv_t priv)
{
	struct lws *wsi = (struct lws *)priv;

	if (!wsi)
		return NULL;

	return &wsi->fic;
}
#endif

static int
lws_sss_proxy_wsi_write(lws_transport_priv_t priv, uint8_t *buf, size_t *len)
{
	struct lws *wsi = (struct lws *)priv;

	if (lws_write(wsi, buf, *len, LWS_WRITE_RAW) != (ssize_t)*len) {
		lwsl_wsi_notice(wsi, "failed");

		return -1;
	}

	/* leave *len alone */

	return 0;
}


int
lws_sss_proxy_wsi_init_proxy_server(struct lws_context *context,
			      const struct lws_transport_proxy_ops *txp_ops_inward,
			      lws_transport_priv_t txp_priv_inward,
			      lws_txp_path_proxy_t *txp_ppath,
			      const void *txp_info,
			      const char *bind, int port)
{
	struct lws_context_creation_info info;

	memset(&info, 0, sizeof(info));

	info.vhost_name			= "ssproxy";
	info.options = LWS_SERVER_OPTION_ADOPT_APPLY_LISTEN_ACCEPT_CONFIG |
			LWS_SERVER_OPTION_SS_PROXY;
	info.port = port;
	if (!port) {
		if (!bind)
#if defined(__linux__)
			bind = "@proxy.ss.lws";
#else
			bind = "/tmp/proxy.ss.lws";
#endif
		info.options |= LWS_SERVER_OPTION_UNIX_SOCK;
	}
	info.iface			= bind;
#if defined(__linux__)
	info.unix_socket_perms		= "root:root";
#else
#endif
	info.listen_accept_role		= "raw-skt";
	info.listen_accept_protocol	= "ssproxy-protocol";
	info.protocols			= protocols;

	if (!lws_create_vhost(context, &info)) {
		lwsl_err("%s: Failed to create ss proxy vhost\n", __func__);

		return 1;
	}

	return 0;
}

static void
lws_sss_proxy_wsi_client_up(lws_transport_priv_t priv)
{
	struct lws *wsi = (struct lws *)priv;

	lws_set_timeout(wsi, 0, 0);
}

static int
lws_sss_proxy_check_write_more(lws_transport_priv_t priv)
{
	struct lws *wsi = (struct lws *)priv;

	if (lws_send_pipe_choked(wsi))
		return 0;

	return 1;
}

const lws_transport_proxy_ops_t txp_ops_ssproxy_wsi = {
	.name				= "txp_proxy_wsi",
	.init_proxy_server		= lws_sss_proxy_wsi_init_proxy_server,
	.proxy_req_write		= lws_sss_proxy_wsi_req_write,
	.proxy_write			= lws_sss_proxy_wsi_write,

	.event_onward_bind		= lws_sss_proxy_wsi_onward_bind,
#if defined(LWS_WITH_SYS_FAULT_INJECTION)
	.fault_context			= lws_sss_proxy_wsi_fault_context,
#endif
	.event_client_up		= lws_sss_proxy_wsi_client_up,
	.proxy_check_write_more		= lws_sss_proxy_check_write_more,
};
