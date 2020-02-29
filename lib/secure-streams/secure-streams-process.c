/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2019 - 2020 Andy Green <andy@warmcat.com>
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
 * When the user code is in a different process, a non-tls unix domain socket
 * proxy is used to asynchronusly transfer buffers in each direction via the
 * network stack, without explicit IPC
 *
 *     user_process{ [user code] | shim | socket-}------ lws_process{ lws }
 *
 * Lws exposes a listening unix domain socket in this case, the user processes
 * connect to it and pass just info.streamtype in an initial tx packet.  All
 * packets are prepended by a 1-byte type field when used in this mode.  See
 * lws-secure-streams.h for documentation and definitions.
 *
 * Proxying in either direction can face the situation it cannot send the onward
 * packet immediately and is subject to separating the write request from the
 * write action.  To make the best use of memory, a single preallocated buffer
 * stashes pending packets in all four directions (c->p, p->c, p->ss, ss->p).
 * This allows it to adapt to different traffic patterns without wasted areas
 * dedicated to traffic that isn't coming in a particular application.
 *
 * A shim is provided to monitor the process' unix domain socket and regenerate
 * the secure sockets api there with callbacks happening in the process thread
 * context.
 *
 * This file implements the listening unix domain socket proxy... this code is
 * only going to run on a Linux-class device with its implications about memory
 * availability.
 */

#include <private-lib-core.h>

/*
 * Because both sides of the connection share the conn, we allocate it
 * during accepted adoption, and both sides point to it.
 *
 * The last one of the accepted side and the onward side to close frees it.
 */

struct conn {
	struct lws_ss_serialization_parser parser;

	lws_dsh_t		*dsh;	/* unified buffer for both sides */
	struct lws		*wsi;	/* the client side */
	lws_ss_handle_t		*ss;	/* the onward, ss side */

	lws_ss_conn_states_t	state;
};

struct raw_pss {
	struct conn		*conn;
};

/*
 * Proxy - onward secure-stream handler
 */

typedef struct ss_proxy_onward {
	lws_ss_handle_t 	*ss;
	struct conn		*conn;
} ss_proxy_t;


/* secure streams payload interface */

static int
ss_proxy_onward_rx(void *userobj, const uint8_t *buf, size_t len, int flags)
{
	ss_proxy_t *m = (ss_proxy_t *)userobj;
	const char *rsp = NULL;
	int n;

	/*
	 * The onward secure stream connection has received something.
	 */

	if (m->ss->rideshare != m->ss->policy && m->ss->rideshare) {
		rsp = m->ss->rideshare->streamtype;
		flags |= LWSSS_FLAG_RIDESHARE;
	}

	n = lws_ss_serialize_rx_payload(m->conn->dsh, buf, len, flags, rsp);
	if (n)
		return n;

	if (m->conn->wsi) /* if possible, request client conn write */
		lws_callback_on_writable(m->conn->wsi);

	return 0;
}

/*
 * we are transmitting buffered payload originally from the client on to the ss
 */

static int
ss_proxy_onward_tx(void *userobj, lws_ss_tx_ordinal_t ord, uint8_t *buf,
		   size_t *len, int *flags)
{
	ss_proxy_t *m = (ss_proxy_t *)userobj;
	void *p;
	size_t si;

	if (!m->conn->ss || m->conn->state != LPCS_OPERATIONAL) {
		lwsl_notice("%s: ss not ready\n", __func__);
		*len = 0;

		return 1;
	}

	/*
	 * The onward secure stream says that we could send something to it
	 * (by putting it in buf, and setting *len and *flags)
	 */

	if (lws_ss_deserialize_tx_payload(m->conn->dsh, m->ss->wsi,
					  ord, buf, len, flags))
		return 1;

	if (!lws_dsh_get_head(m->conn->dsh, KIND_C_TO_P, (void **)&p, &si))
		lws_ss_request_tx(m->conn->ss);

	if (!*len && !*flags)
		return 1; /* we don't actually want to send anything */

	lwsl_info("%s: onward tx %d fl 0x%x\n", __func__, (int)*len, *flags);

#if 0
	{
		int ff = open("/tmp/z", O_RDWR | O_CREAT | O_APPEND, 0666);
		if (ff == -1)
			lwsl_err("%s: errno %d\n", __func__, errno);
		write(ff, buf, *len);
		close(ff);
	}
#endif

	return 0;
}

static int
ss_proxy_onward_state(void *userobj, void *sh,
		      lws_ss_constate_t state, lws_ss_tx_ordinal_t ack)
{
	ss_proxy_t *m = (ss_proxy_t *)userobj;

	switch (state) {
	case LWSSSCS_CREATING:
		break;

	case LWSSSCS_DESTROYING:
		if (!m->conn)
			break;
		if (!m->conn->wsi) {
			/*
			 * Our onward secure stream is closing and our client
			 * connection has already gone away... destroy the conn.
			 */
			lwsl_info("%s: Destroying conn\n", __func__);
			lws_dsh_destroy(&m->conn->dsh);
			free(m->conn);
			m->conn = NULL;
			return 0;
		} else
			lwsl_info("%s: ss DESTROYING, wsi up\n", __func__);
		break;

	default:
		break;
	}
	if (!m->conn) {
		lwsl_warn("%s: dropping state due to conn not up\n", __func__);

		return 0;
	}

	lws_ss_serialize_state(m->conn->dsh, state, ack);

	if (m->conn->wsi) /* if possible, request client conn write */
		lws_callback_on_writable(m->conn->wsi);

	return 0;
}

void
ss_proxy_onward_txcr(void *userobj, int bump)
{
	ss_proxy_t *m = (ss_proxy_t *)userobj;

	if (!m->conn)
		return;

	lws_ss_serialize_txcr(m->conn->dsh, bump);

	if (m->conn->wsi) /* if possible, request client conn write */
		lws_callback_on_writable(m->conn->wsi);
}

/*
 * Client - Proxy connection on unix domain socket
 */

static int
callback_ss_proxy(struct lws *wsi, enum lws_callback_reasons reason,
		  void *user, void *in, size_t len)
{
	struct lws_context_per_thread *pt = &wsi->context->pt[(int)wsi->tsi];
	struct raw_pss *pss = (struct raw_pss *)user;
	const lws_ss_policy_t *rsp;
	struct conn *conn = NULL;
	lws_ss_info_t ssi;
	const uint8_t *cp;
#if defined(LWS_WITH_DETAILED_LATENCY)
	lws_usec_t us;
#endif
	char s[128];
	uint8_t *p;
	size_t si;
	char pay;
	int n;

	if (pss)
		conn = pss->conn;

	switch (reason) {
	case LWS_CALLBACK_PROTOCOL_INIT:
		break;

	case LWS_CALLBACK_PROTOCOL_DESTROY:
		break;

	/* callbacks related to raw socket descriptor "accepted side" */

        case LWS_CALLBACK_RAW_ADOPT:
		lwsl_info("LWS_CALLBACK_RAW_ADOPT\n");
		if (!pss)
			return -1;
		pss->conn = malloc(sizeof(struct conn));
		if (!pss->conn)
			return -1;
		memset(pss->conn, 0, sizeof(*pss->conn));

		pss->conn->dsh = lws_dsh_create(&pt->ss_dsh_owner,
						LWS_SS_MTU * 160, 2);
		if (!pss->conn->dsh) {
			free(pss->conn);

			return -1;
		}

		pss->conn->wsi = wsi;
		pss->conn->state = LPCS_WAIT_INITIAL_TX;

		/*
		 * Client is expected to follow the unix domain socket
		 * acceptance up rapidly with an initial tx containing the
		 * streamtype name.  We can't create the stream until then.
		 */
		lws_set_timeout(wsi,
				PENDING_TIMEOUT_AWAITING_CLIENT_HS_SEND, 3);
                break;

	case LWS_CALLBACK_RAW_CLOSE:
		lwsl_info("LWS_CALLBACK_RAW_CLOSE:\n");

		/*
		 * the client unix domain socket connection has closed...
		 * eg, client has exited or otherwise has definitively finished
		 * with the proxying and onward connection
		 */

		if (!conn)
			break;

		if (conn->ss) {
			lwsl_info("%s: destroying ss\n", __func__);
			/* sever relationship with ss about to be deleted */
			lws_set_opaque_user_data(wsi, NULL);

			conn->wsi = NULL;


			lws_ss_destroy(&conn->ss);
			/* conn may have gone */
			break;
		}

		if (conn->state == LPCS_DESTROYED || !conn->ss) {
			/*
			 * There's no onward secure stream and our client
			 * connection is closing.  Destroy the conn.
			 */
			lws_dsh_destroy(&conn->dsh);
			free(conn);
			pss->conn = NULL;
		} else
			lwsl_debug("%s: CLOSE; ss=%p\n", __func__, conn->ss);

		break;

	case LWS_CALLBACK_RAW_RX:
		lwsl_info("%s: RX: rx %d\n", __func__, (int)len);

		if (!conn || !conn->wsi) {
			lwsl_err("%s: rx with bad conn state\n", __func__);

			return -1;
		}

		// lwsl_hexdump_info(in, len);

		if (conn->state == LPCS_WAIT_INITIAL_TX) {
			memset(&ssi, 0, sizeof(ssi));
			ssi.user_alloc = sizeof(ss_proxy_t);
			ssi.handle_offset = offsetof(ss_proxy_t, ss);
			ssi.opaque_user_data_offset =
					offsetof(ss_proxy_t, conn);
			ssi.rx = ss_proxy_onward_rx;
			ssi.tx = ss_proxy_onward_tx;
			ssi.state = ss_proxy_onward_state;
		}

		if (lws_ss_deserialize_parse(&conn->parser,
				lws_get_context(wsi), conn->dsh, in, len,
				&conn->state, conn, &conn->ss, &ssi, 0)) {
			lwsl_err("%s: RAW_RX: deserialize_parse fail\n", __func__);
			return -1;
		}

		if (conn->state == LPCS_REPORTING_FAIL ||
		    conn->state == LPCS_REPORTING_OK)
			lws_callback_on_writable(conn->wsi);

		break;

	case LWS_CALLBACK_RAW_WRITEABLE:
		// lwsl_notice("LWS_CALLBACK_RAW_PROXY_SRV_WRITEABLE\n");

		/*
		 * We can transmit something back to the client from the dsh
		 * of stuff we received on its behalf from the ss
		 */

		if (!conn || !conn->wsi)
			break;

		n = 0;
		pay = 0;
		s[3] = 0;
		cp = (const uint8_t *)s;
		switch (conn->state) {
		case LPCS_REPORTING_FAIL:
			s[3] = 1;
			/* fallthru */
		case LPCS_REPORTING_OK:
			s[0] = LWSSS_SER_RXPRE_CREATE_RESULT;
			s[1] = 0;
			s[2] = 1;

			n = 4;

			/*
			 * If there's rideshare sequencing, it's added after the
			 * first 4 bytes or the create result, comma-separated
			 */

			rsp = conn->ss->policy;

			while (rsp) {
				if (n != 4 && n < (int)sizeof(s) - 2)
					s[n++] = ',';
				n += lws_snprintf(&s[n], sizeof(s) - n,
						"%s", rsp->streamtype);
				rsp = lws_ss_policy_lookup(wsi->context,
					rsp->rideshare_streamtype);
			}
			s[2] = n - 3;
			conn->state = LPCS_OPERATIONAL;
			lws_set_timeout(wsi, 0, 0);
			break;
		case LPCS_OPERATIONAL:
			if (lws_dsh_get_head(conn->dsh, KIND_SS_TO_P,
					     (void **)&p, &si))
				break;
			cp = p;

#if defined(LWS_WITH_DETAILED_LATENCY)
			if (cp[0] == LWSSS_SER_RXPRE_RX_PAYLOAD &&
			    wsi->context->detailed_latency_cb) {

				/*
				 * we're fulfilling rx that came in on ss
				 * by sending it back out to the client on
				 * the Unix Domain Socket
				 *
				 * +  7  u32  write will compute latency here...
				 * + 11  u32  ust we received from ss
				 *
				 * lws_write will report it and fill in
				 * LAT_DUR_PROXY_CLIENT_REQ_TO_WRITE
				 */

				us = lws_now_usecs();
				lws_ser_wu32be(&p[7], us -
						      lws_ser_ru64be(&p[11]));
				lws_ser_wu64be(&p[11], us);

				wsi->detlat.acc_size =
					wsi->detlat.req_size = si - 19;
				/* time proxy held it */
				wsi->detlat.latencies[
				            LAT_DUR_PROXY_RX_TO_ONWARD_TX] =
							lws_ser_ru32be(&p[7]);
			}
#endif

			pay = 1;
			n = (int)si;
			break;
		default:
			break;
		}
again:
		if (!n)
			break;

		n = lws_write(wsi, (uint8_t *)cp, n, LWS_WRITE_RAW);
		if (n < 0) {
			lwsl_info("%s: WRITEABLE: %d\n", __func__, n);

			goto hangup;
		}

		switch (conn->state) {
		case LPCS_REPORTING_FAIL:
			goto hangup;
		case LPCS_OPERATIONAL:
			if (pay)
				lws_dsh_free((void **)&p);
			if (!lws_dsh_get_head(conn->dsh, KIND_SS_TO_P,
					     (void **)&p, &si)) {
				if (!lws_send_pipe_choked(wsi)) {
					cp = p;
					pay = 1;
					n = (int)si;
					goto again;
				}
				lws_callback_on_writable(wsi);
			}
			break;
		default:
			break;
		}
		break;

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);

hangup:
	//lws_ss_destroy(&conn->ss);
	//conn->state = LPCS_DESTROYED;

	/* hang up on him */
	return -1;
}

static const struct lws_protocols protocols[] = {
	{
		"ssproxy-protocol",
		callback_ss_proxy,
		sizeof(struct raw_pss),
		2048, 2048, NULL, 0
	},
	{ NULL, NULL, 0, 0, 0, NULL, 0 }
};

/*
 * called from create_context()
 */

int
lws_ss_proxy_create(struct lws_context *context, const char *bind, int port)
{
	struct lws_context_creation_info info;

	memset(&info, 0, sizeof(info));

	info.vhost_name			= "ssproxy";
	info.options = LWS_SERVER_OPTION_ADOPT_APPLY_LISTEN_ACCEPT_CONFIG;
	info.port = port;
	if (!port) {
		if (!bind)
			bind = "@proxy.ss.lws";
		info.options |= LWS_SERVER_OPTION_UNIX_SOCK;
	}
	info.iface			= bind;
	info.unix_socket_perms		= "root:root";
	info.listen_accept_role		= "raw-skt";
	info.listen_accept_protocol	= "ssproxy-protocol";
	info.protocols			= protocols;

	if (!lws_create_vhost(context, &info)) {
		lwsl_err("%s: Failed to create ss proxy vhost\n", __func__);

		return 1;
	}

	return 0;
}
