# SSPC client support

## liblws-sspc

SSPC client apis are built into libwebsockets as you would expect if built with
`LWS_WITH_SECURE_STREAMS_PROXY_API`.

However as part of the main libwebsockets build, they are also built into their
own tiny library, `liblws-sspc`, it's just the files in this directory, lws_dll2
and lws_dsh support.  This readme discusses how to use that.

The sub-library is to facilitate using SSPC client support on very small devices
that don't need the rest of lws, and have their own event loop support already.
That's interesting because such devices do not need to have tls, an IP stack or
any network, yet can use full Secure Streams capabilities (eg, h2, or ws over
tls) via an SS proxy.

`liblws-sspc` does not need a normal `struct lws_context` nor the lws event
loop or other apis, to maintain compatibility with the SS apis the user code
provides a simple, static stub lws_context.

You can find an example that links to `liblws-sspc` (not `libwebsockets` library)
at `minimal-examples/secure-streams/minimal-secure-streams-custom-client-transport`

## sspc custom client transport

See `include/libwebsockets/lws-secure-stream-client.h` for the library ABI.
Basically it exports a normal set of SS APIs (like `lws_ss_create()` etc) that
act the same as using SS directly.

That header also defines the ABI for adding a custom SSPC transport

```
typedef struct lws_sss_ops_client {
	int (*retry_connect)(struct lws_sspc_handle *h);
	/**< Attempt to create a new connection / channel to the proxy */
	void (*req_write)(lws_sss_priv_t *priv);
	/**< Request a write to the proxy on this channel */
	int (*write)(lws_sss_priv_t *priv, uint8_t *buf, size_t len);
	/**< Write the requested data on the channel to the proxy */
	void (*close)(lws_sss_priv_t *priv);
	/**< Close the channel to the proxy */
	void (*stream_up)(lws_sss_priv_t *priv);
	/**< Called when a new channel to the proxy is acknowledged as up */
} lws_sss_ops_client_t;

/**
 * lws_sspc_tag() - get the sspc log tag
 *
 * \param h: the sspc handle
 *
 * Returns the sspc log tag, to assist in logging traceability
 */
LWS_VISIBLE LWS_EXTERN const char *
lws_sspc_tag(struct lws_sspc_handle *h);

/**
 * lws_sspc_transport_connect_failed() - clean up after connect attempt fail
 *
 * \param h: the sspc handle
 *
 * Client transport should call this to handle connection attempt to proxy
 * failure.  Eg for wsi transport, it's called in LWS_CALLBACK_CLIENT_CONNECTION_ERROR
 */
LWS_VISIBLE LWS_EXTERN lws_ss_state_return_t
lws_sspc_transport_connect_failed(struct lws_sspc_handle *h);

/**
 * lws_sspc_transport_connected() - take care of successful connect to proxy
 *
 * \param h: the sspc handle
 *
 * Client transport should call this to handle connection attempt to proxy
 * success.  Eg for wsi transport, it's called in LWS_CALLBACK_RAW_CONNECTED
 */
LWS_VISIBLE LWS_EXTERN lws_ss_state_return_t
lws_sspc_transport_connected(struct lws_sspc_handle *h);

/**
 * lws_sspc_transport_closed() - handle closure of proxy connection
 *
 * \param h: the sspc handle
 *
 * Client transport should call this to handle connection to proxy closure.
 * Eg for wsi transport, it's called in LWS_CALLBACK_RAW_CLOSE
 */
LWS_VISIBLE LWS_EXTERN lws_ss_state_return_t
lws_sspc_transport_closed(struct lws_sspc_handle *h);

/**
 * lws_sspc_transport_rx_from_proxy() - handle rx from proxy
 *
 * \param h: the sspc handle
 * \param in: the incoming data
 * \param len: the number of bytes at in
 *
 * Client transport should call this to handle serialized data received from
 * the proxy.  Eg for wsi transport, it's called in LWS_CALLBACK_RAW_RX
 */
LWS_VISIBLE LWS_EXTERN lws_ss_state_return_t
lws_sspc_transport_rx_from_proxy(struct lws_sspc_handle *h,
				 const void *in, size_t len);

/**
 * lws_sspc_transport_tx() - handle tx to proxy
 *
 * \param h: the sspc handle
 * \param metadata_limit: largest metadata we can handle
 *
 * Client transport should call this to produce serialized data to send to the
 * proxy.  Eg for wsi transport, it's called in LWS_CALLBACK_RAW_WRITEABLE
 */
LWS_VISIBLE LWS_EXTERN lws_ss_state_return_t
lws_sspc_transport_tx(struct lws_sspc_handle *h, size_t metadata_limit);
```

You define these ops, which can also use the provided helpers to get generic
SS serialization and deserialization done.

## The stub `lws_context`



## liblws-sspc imports

There are just four imports needed by the library.  They are for things like
wiring up liblws-sspc logs to the system log apis.

|prototype|function|
|---|---|
|`lws_usec_t lws_now_usecs(void)`|get us-resolution monotonic time|
|`void __lws_logv(lws_log_cx_t *cx, lws_log_prepend_cx_t prep, void *obj, int filter, const char *_fun, const char *format, va_list ap)`|log emission|
|`void lws_sul_schedule(struct lws_context_standalone *ctx, int tsi, lws_sorted_usec_list_t *sul, sul_cb_t _cb, lws_usec_t _us)`|schedule sul callback|
|`void lws_sul_cancel(lws_sorted_usec_list_t *sul)`|Cancel scheduled callback|


