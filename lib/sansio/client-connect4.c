/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2021 Andy Green <andy@warmcat.com>
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

struct lws *
lws_client_connect_4_established(struct lws *wsi, struct lws *wsi_piggyback,
				 ssize_t plen)
{
#if defined(LWS_CLIENT_HTTP_PROXYING)
#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
	struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];
#endif
#endif
	const char *cce = "";
#if (_LWS_ENABLED_LOGS & LLL_INFO)
	int rawish;
#endif
	int n;

	/*
	 * The client bind already chose the role from the method: an http
	 * role talks http on the connection, anything else is "rawish" and
	 * does its own thing once the transport is up
	 */
#if (_LWS_ENABLED_LOGS & LLL_INFO)
	rawish = !lwsi_role_http(wsi);
#endif

	if (wsi_piggyback)
		goto send_hs;

#if defined(LWS_CLIENT_HTTP_PROXYING)
#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2)
	/* we are connected to server, or proxy */

	/* http proxy */
	if (wsi->a.vhost->http.http_proxy_port) {
		const char *cpa;
		int sb;
		/*
		 * The CONNECT is composed into the first 256 bytes of the
		 * compose_buf... but pt_serv_buf_size is the user's choice and
		 * has no enforced minimum, so clip to what actually exists.
		 *
		 * Each append must be given the space that is actually left,
		 * not the whole region again: lws_snprintf() returns the size
		 * it was given when it truncated, so the constant 256 used for
		 * every append meant a long address could compose up to 517
		 * bytes into a region believed to be 256.
		 */
		size_t room = wsi->a.context->pt_serv_buf_size;

		if (room > 256)
			room = 256;

		cpa = lws_wsi_client_stash_item(wsi, CIS_ADDRESS,
						_WSI_TOKEN_CLIENT_PEER_ADDRESS);
		if (!cpa)
			goto failed;

		lwsl_wsi_info(wsi, "going via proxy");

		sb = lws_servbuf_claim(pt, pt->compose_buf, room, "proxy CONNECT");
		plen = lws_snprintf((char *)pt->compose_buf, room,
			"CONNECT %s:%u HTTP/1.1\x0d\x0a"
			"Host: %s:%u\x0d\x0a"
			"User-agent: lws\x0d\x0a", cpa, wsi->c_port,
						   cpa, wsi->c_port);

#if defined(LWS_WITH_HTTP_BASIC_AUTH)
		if ((size_t)plen < room &&
		    wsi->a.vhost->proxy_basic_auth_token[0])
			plen += lws_snprintf((char *)pt->compose_buf + plen,
					room - (size_t)plen,
					"Proxy-authorization: basic %s\x0d\x0a",
					wsi->a.vhost->proxy_basic_auth_token);
#endif

		if ((size_t)plen + 3 > room) {
			/*
			 * Truncated... plen is then one past a NUL, and
			 * appending the terminator would send the proxy a
			 * CONNECT with an embedded NUL in it.  Fail instead.
			 */
			cce = "proxy CONNECT too long";
			lwsl_wsi_err(wsi, "%s", cce);
			lws_servbuf_release(pt, sb);
			goto failed;
		}

		plen += lws_snprintf((char *)pt->compose_buf + plen,
					room - (size_t)plen, "\x0d\x0a");

		/* lwsl_hexdump_notice(pt->compose_buf, plen); */

		/*
		 * The stash / ah go on naming the origin, not the proxy: a
		 * relative redirect, a digest auth retry or any reconnect is
		 * to the origin, and connect2 takes the proxy's endpoint from
		 * the vhost each time it connects
		 */

		n = lws_io_tx_push(wsi, pt->compose_buf, (size_t)plen);
		lws_servbuf_release(pt, sb);
		if (n < 0) {
			lwsl_wsi_debug(wsi, "ERROR writing to proxy socket");
			cce = "proxy write failed";
			goto failed;
		}

		lws_set_timeout(wsi, PENDING_TIMEOUT_AWAITING_PROXY_RESPONSE,
				(int)wsi->a.context->timeout_secs);

		/* the reply is read from its start, by lws_client_tunnel_rx() */
		wsi->proxy_reply_status_ok = 0;
		wsi->proxy_reply_eoh = 0;

		lws_wsi_event(wsi, LWS_WSIEV_PROXY_CONNECT_SENT);

		return wsi;
	}
#endif
#endif

	/* coverity */
	if (!wsi->a.protocol)
		return NULL;

#if defined(LWS_WITH_SOCKS5)
	if (lwsi_state(wsi) != 	LRS_ESTABLISHED)
		switch (lws_socks5c_greet(wsi, &cce)) {
		case -1:
			goto failed;
		case 1:
			return wsi;
		default:
			break;
		}
#endif

send_hs:

#if defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2) || defined(LWS_ROLE_H3)
	if (wsi_piggyback &&
	    !lws_dll2_is_detached(&wsi->dll2_cli_txn_queue)) {
		/*
		 * We are pipelining on an already-established connection...
		 * we can skip tls establishment.
		 *
		 * Set these queued guys to a state where they won't actually
		 * send their headers until we decide later.
		 */

		lws_wsi_event(wsi, LWS_WSIEV_QUEUED);

		/*
		 * we can't send our headers directly, because they have to
		 * be sent when the parent is writeable.  The parent will check
		 * for anybody on his client transaction queue that is in
		 * LRS_H1C_ISSUE_HANDSHAKE2, and let them write.
		 *
		 * If we are trying to do this too early, before the network
		 * connection has written his own headers, then it will just
		 * wait in the queue until it's possible to send them.
		 */
		lws_callback_on_writable(wsi_piggyback);

		lwsl_wsi_info(wsi, "waiting to send hdrs (par state 0x%x)",
			      lwsi_state(wsi_piggyback));
	} else
#endif
	{
		lwsl_wsi_info(wsi, "%s %s client created own conn "
			  "(raw %d) vh %s st 0x%x",
			  wsi->role_ops->name, wsi->a.protocol->name, rawish,
			  wsi->a.vhost->name, lwsi_state(wsi));

		/*
		 * We are making our own connection and the socket is up:
		 * IO starts tls if it was asked for and brings the transport
		 * up, and the role starts its protocol from there
		 */
		switch (lws_client_transport_connected(wsi)) {
		case LWS_HPI_RET_HANDLED:
			break;
		case LWS_HPI_RET_PLEASE_CLOSE_ME:
			lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS,
					   "client transport connected");
			return NULL;
		default:
			/* closed on the way: freed, or living on in its close */
			return NULL;
		}
	}

	return wsi;

failed:
	lws_inform_client_conn_fail(wsi, (void *)cce, strlen(cce));

	lws_close_free_wsi(wsi, LWS_CLOSE_STATUS_NOSTATUS, "client_connect4");

	return NULL;
}

#if defined(LWS_WITH_CLIENT)
/*
 * Whether bytes that come after the reply that brought a tunnel up can be the
 * peer's.  Only a raw protocol over plaintext may have a peer that speaks
 * first (an smtp or ssh banner, relayed by the proxy straight after its
 * reply).  For the others our side speaks first, our ClientHello or our
 * request: bytes ahead of it can only be the proxy's, and kept, they would be
 * taken for the peer's, after a tls handshake that verified the real origin.
 */
static int
lws_client_tunnel_peer_may_speak_first(struct lws *wsi)
{
#if defined(LWS_WITH_TLS)
	if (wsi->use_ssl & LCCSCF_USE_SSL)
		return 0;
#endif

	return wsi->role_ops == &role_ops_raw_skt || lwsi_role_raw_proxy(wsi);
}

#if defined(LWS_CLIENT_HTTP_PROXYING) && \
    (defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2))
/*
 * The http proxy's reply to our CONNECT.  Its status line decides it, and
 * comes whole in the first read (the proxy writes its reply at once, and a
 * fragment shorter than the status line is not worth reassembling).  The
 * headers after it mean nothing to us (RFC 9110 9.3.6: not even a
 * Content-Length), but the tunnel only starts after the blank line that ends
 * them, which may be in a later read: how much of the CRLFCRLF has been seen
 * is kept in the wsi across reads.
 *
 * Returns -1 on failure with *pcce set, 0 when more of the reply is to come
 * (all of the read was taken), 1 when the tunnel is up (*used is where the
 * reply ended).
 */
static int
lws_client_proxy_reply(struct lws *wsi, const uint8_t *buf, size_t len,
		       const char **pcce, char *ebuf, size_t ebuf_len,
		       size_t *used)
{
	static const char eoh[] = "\x0d\x0a\x0d\x0a";
	unsigned int status = 0, m;
	size_t n = 0;

	if (!len) {
		*pcce = "proxy conn dead";

		return -1;
	}

	if (!wsi->proxy_reply_status_ok) {
		/* "HTTP/1.x NNN" then SP (the reason) or the CRLF */
		if (len < 13 || strncmp((const char *)buf, "HTTP/1.", 7) ||
		    (buf[7] != '0' && buf[7] != '1') || buf[8] != ' ' ||
		    (buf[12] != ' ' && buf[12] != '\x0d')) {
			*pcce = "http_proxy fail";

			return -1;
		}

		for (n = 9; n < 12; n++) {
			if (buf[n] < '0' || buf[n] > '9') {
				*pcce = "http_proxy fail";

				return -1;
			}
			status = (status * 10) + (unsigned int)(buf[n] - '0');
		}

		if (status != 200) {
			lws_snprintf(ebuf, ebuf_len, "http_proxy -> %u", status);
			*pcce = ebuf;

			return -1;
		}

		wsi->proxy_reply_status_ok = 1;
	}

	/* on to the blank line; the status line has no CR or LF before n */
	m = wsi->proxy_reply_eoh;
	while (n < len && m < 4) {
		if (buf[n] == (uint8_t)eoh[m])
			m++;
		else
			m = buf[n] == '\x0d';
		n++;
	}

	*used = n;
	if (m < 4) {
		wsi->proxy_reply_eoh = m & 3;

		return 0;
	}

	return 1;
}
#endif

/*
 * sansIO rx for a client's tunnel leg, for every client role: the proxy's
 * reply to the http CONNECT we sent.  Nothing in it is for the role or the
 * user: until the tunnel is up the bytes are the proxy's, and the connection
 * does not exist for the user yet.  When it comes up, IO carries on as for a
 * direct connection: tls first if that was asked for, else the transport is
 * up and the role hears so with its client_transport_up op, or the user with
 * the role's adoption callback (RAW_CONNECTED, say).  What followed the reply
 * in the read is left in *used for the role's own rx, when it can be the
 * peer's.
 */
lws_handling_result_t
lws_client_tunnel_rx(struct lws *wsi, const uint8_t *buf, size_t len,
		     size_t *used)
{
	struct lws_context_per_thread *pt = &wsi->a.context->pt[(int)wsi->tsi];
	const char *cce = "tunnel leg in unexpected state";
	int r = -1;
#if defined(LWS_CLIENT_HTTP_PROXYING) && \
    (defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2))
	char ebuf[24];
#endif

	*used = 0;

#if defined(LWS_CLIENT_HTTP_PROXYING) && \
    (defined(LWS_ROLE_H1) || defined(LWS_ROLE_H2))
	if (lwsi_transport(wsi) == LTS_WAITING_PROXY_REPLY)
		r = lws_client_proxy_reply(wsi, buf, len, &cce, ebuf,
					   sizeof(ebuf), used);
#endif

	switch (r) {
	case 0:
		/* more of the reply is to come */
		return LWS_HPI_RET_HANDLED;
	case 1:
		break;
	default:
		goto fail;
	}

	if (*used < len && !lws_client_tunnel_peer_may_speak_first(wsi)) {
		lwsl_wsi_err(wsi, "%d bytes after the tunnel came up, with our "
				  "side to speak next", (int)(len - *used));
		cce = "tunnel trailing bytes";
		goto fail;
	}

	/* the reply is ours, what follows it is not */
	lws_servbuf_trim(pt, buf + *used);

	lwsl_wsi_info(wsi, "tunnel up");

	/* clear his proxy connection timeout */
	lws_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);

	return lws_client_transport_connected(wsi);

fail:
	lwsl_wsi_info(wsi, "tunnel leg failed: %s", cce);
	lws_inform_client_conn_fail(wsi, (void *)cce, strlen(cce));

	return LWS_HPI_RET_PLEASE_CLOSE_ME;
}
#endif
