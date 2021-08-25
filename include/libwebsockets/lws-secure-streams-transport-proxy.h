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
 * These headers are related to providing user Secure Streams Serialization
 * transport implementations in user code.
 *
 * The default implementation uses wsi for proxy serving and connecting clients,
 * but it's also possible to provide user implementations of the operations
 * needed to serve on a different transport for proxy, and to connect out on
 * the different transport for client.
 *
 * You can provide your own lws_sss_ops_client_t and lws_sss_ops_proxy_t to
 * control how serialized data is transmitted and received, to use SS
 * serialization over, eg, UART instead.
 *
 * This allows situations where full SS proxy services can be offered to much
 * weker devices, without any networking stack or tls library being needed.
 */

/*
 * SSS Proxy Transport-related implementation apis
 */

struct lws_sss_proxy_conn;

/*
 * Operations that transports must offer... so ss proxy can serve to clients
 */

typedef struct lws_sss_ops_proxy {
	int (*init_server)(struct lws_context *context, const char *bind, int port);
	/**< Instantiate a proxy transport... bind/port are as shown for wsi
	 * transport, but may be overloaded to provide transport-specific init
	 */
	void (*req_write)(lws_sss_priv_t *priv);
	/**< Request a write to the client */
	int (*write)(lws_sss_priv_t *priv, uint8_t *buf, size_t len);
	/**< Write the requested data on the channel to the client */

	void (*onward_bind)(lws_sss_priv_t *priv, struct lws_ss_handle *h);
	/**< Called when the proxy creates an onward SS for a client channel */
#if defined(LWS_WITH_SYS_FAULT_INJECTION)
	const lws_fi_ctx_t * (*fault_context)(lws_sss_priv_t *priv);
	/**< Get the fault context relating to the proxy connection, if any */
#endif
	void (*client_up)(lws_sss_priv_t *priv);
	/**< Called when a client channel is acknowledged as up */
} lws_sss_ops_proxy_t;

/*
 * Helpers offered by lws to handle transport Proxy-side proxy link events
 */

/**
 * lws_ssproxy_transport_new_conn() - accept new client connection
 *
 * \param cx: the lws_context
 * \param fic: NULL, or the fault injection context to use
 * \param conn: the proxy connection to client instance object
 * \param sss_priv: the proxy connection private object to apply to conn
 *
 * Proxy transport should call this when it is accepting a new client connection
 * to create and initialize a new conn.  Eg wsi proxy transport calls it in
 * LWS_CALLBACK_RAW_ADOPT
 */
LWS_VISIBLE LWS_EXTERN lws_ss_state_return_t
lws_ssproxy_transport_new_conn(struct lws_context *cx,
#if defined(LWS_WITH_SYS_FAULT_INJECTION)
			       const lws_fi_ctx_t *fic,
#endif
			       struct lws_sss_proxy_conn **conn,
			       lws_sss_priv_t *sss_priv);
/**
 * lws_ssproxy_transport_close_conn() - close client channel / connection
 *
 * \param conn: the channel
 *
 * Closes a client channel and cleans up after it.  Eg the wsi proxy transport
 * calls this in LWS_CALLBACK_RAW_CLOSE
 */
LWS_VISIBLE LWS_EXTERN lws_ss_state_return_t
lws_ssproxy_transport_close_conn(struct lws_sss_proxy_conn *conn);

/**
 * lws_ssproxy_transport_rx() - handle rx that came from client channel
 *
 * \param conn: the channel
 * \param in: the incoming data
 * \param len: the number of bytes at in
 *
 * Deals with serialized SS data from a client.  Eg the wsi proxy transport
 * calls this in LWS_CALLBACK_RAW_RX.
 *
 * You must attend to DESTROY_ME and DISCONNECT_ME returns.  Instead of having
 * an explicit close op, the generic SS proxy helpers indicate they want to
 * assertively close the channel using their return code.
 */
LWS_VISIBLE LWS_EXTERN lws_ss_state_return_t
lws_ssproxy_transport_rx(struct lws_sss_proxy_conn *conn, void *in, size_t len);

/**
 * lws_ssproxy_transport_tx() - prepares serialized data to send to the client
 *
 * \param conn: the channel
 * \param fic: NULL, or the fault injection context to use
 *
 * Produces the next serialized SS data and writes it using the transport write
 * callback.  Eg the wsi proxy transport calls this in LWS_CALLBACK_RAW_WRITEABLE
 *
 * You must attend to DESTROY_ME and DISCONNECT_ME returns.  Instead of having
 * an explicit close op, the generic SS proxy helpers indicate they want to
 * assertively close the channel using their return code.
 */
LWS_VISIBLE LWS_EXTERN lws_ss_state_return_t
lws_ssproxy_transport_tx(struct lws_sss_proxy_conn *conn
#if defined(LWS_WITH_SYS_FAULT_INJECTION)
		, const lws_fi_ctx_t *fic
#endif
		);
