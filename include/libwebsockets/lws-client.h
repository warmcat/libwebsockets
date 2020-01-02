/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2019 Andy Green <andy@warmcat.com>
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

/*! \defgroup client Client related functions
 * ##Client releated functions
 * \ingroup lwsapi
 *
 * */
///@{

/** enum lws_client_connect_ssl_connection_flags - flags that may be used
 * with struct lws_client_connect_info ssl_connection member to control if
 * and how SSL checks apply to the client connection being created
 */

enum lws_client_connect_ssl_connection_flags {
	LCCSCF_USE_SSL 				= (1 << 0),
	LCCSCF_ALLOW_SELFSIGNED			= (1 << 1),
	LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK	= (1 << 2),
	LCCSCF_ALLOW_EXPIRED			= (1 << 3),
	LCCSCF_ALLOW_INSECURE			= (1 << 4),
	LCCSCF_H2_QUIRK_NGHTTP2_END_STREAM	= (1 << 5),
	LCCSCF_H2_QUIRK_OVERFLOWS_TXCR		= (1 << 6),
	LCCSCF_H2_AUTH_BEARER			= (1 << 7),
	LCCSCF_H2_HEXIFY_AUTH_TOKEN		= (1 << 8),
	LCCSCF_H2_MANUAL_RXFLOW			= (1 << 9),
	LCCSCF_HTTP_MULTIPART_MIME		= (1 << 10),
	LCCSCF_HTTP_X_WWW_FORM_URLENCODED	= (1 << 11),

	LCCSCF_PIPELINE				= (1 << 16),
		/**< Serialize / pipeline multiple client connections
		 * on a single connection where possible.
		 *
		 * HTTP/1.0: possible if Keep-Alive: yes sent by server
		 * HTTP/1.1: always possible... uses pipelining
		 * HTTP/2:   always possible... uses parallel streams
		 */
	LCCSCF_MUXABLE_STREAM			= (1 << 17),
};

/** struct lws_client_connect_info - parameters to connect with when using
 *				    lws_client_connect_via_info() */

struct lws_client_connect_info {
	struct lws_context *context;
	/**< lws context to create connection in */
	const char *address;
	/**< remote address to connect to */
	int port;
	/**< remote port to connect to */
	int ssl_connection;
	/**< 0, or a combination of LCCSCF_ flags */
	const char *path;
	/**< uri path */
	const char *host;
	/**< content of host header */
	const char *origin;
	/**< content of origin header */
	const char *protocol;
	/**< list of ws protocols we could accept */
	int ietf_version_or_minus_one;
	/**< deprecated: currently leave at 0 or -1 */
	void *userdata;
	/**< if non-NULL, use this as wsi user_data instead of malloc it */
	const void *client_exts;
	/**< UNUSED... provide in info.extensions at context creation time */
	const char *method;
	/**< if non-NULL, do this http method instead of ws[s] upgrade.
	 * use "GET" to be a simple http client connection.  "RAW" gets
	 * you a connected socket that lws itself will leave alone once
	 * connected. */
	struct lws *parent_wsi;
	/**< if another wsi is responsible for this connection, give it here.
	 * this is used to make sure if the parent closes so do any
	 * child connections first. */
	const char *uri_replace_from;
	/**< if non-NULL, when this string is found in URIs in
	 * text/html content-encoding, it's replaced with uri_replace_to */
	const char *uri_replace_to;
	/**< see uri_replace_from */
	struct lws_vhost *vhost;
	/**< vhost to bind to (used to determine related SSL_CTX) */
	struct lws **pwsi;
	/**< if not NULL, store the new wsi here early in the connection
	 * process.  Although we return the new wsi, the call to create the
	 * client connection does progress the connection somewhat and may
	 * meet an error that will result in the connection being scrubbed and
	 * NULL returned.  While the wsi exists though, he may process a
	 * callback like CLIENT_CONNECTION_ERROR with his wsi: this gives the
	 * user callback a way to identify which wsi it is that faced the error
	 * even before the new wsi is returned and even if ultimately no wsi
	 * is returned.
	 */
	const char *iface;
	/**< NULL to allow routing on any interface, or interface name or IP
	 * to bind the socket to */
	const char *local_protocol_name;
	/**< NULL: .protocol is used both to select the local protocol handler
	 *         to bind to and as the list of remote ws protocols we could
	 *         accept.
	 *   non-NULL: this protocol name is used to bind the connection to
	 *             the local protocol handler.  .protocol is used for the
	 *             list of remote ws protocols we could accept */
	const char *alpn;
	/**< NULL: allow lws default ALPN list, from vhost if present or from
	 *       list of roles built into lws
	 * non-NULL: require one from provided comma-separated list of alpn
	 *           tokens
	 */

	struct lws_sequencer *seq;
	/**< NULL, or an lws_seq_t that wants to be given messages about
	 * this wsi's lifecycle as it connects, errors or closes.
	 */

	void *opaque_user_data;
	/**< This data has no meaning to lws but is applied to the client wsi
	 *   and can be retrieved by user code with lws_get_opaque_user_data().
	 *   It's also provided with sequencer messages if the wsi is bound to
	 *   an lws_seq_t.
	 */

	const lws_retry_bo_t *retry_and_idle_policy;
	/**< optional retry and idle policy to apply to this connection.
	 *   Currently only the idle parts are applied to the connection.
	 */

	int		manual_initial_tx_credit;
	/**< if LCCSCF_H2_MANUAL_REFLOW is set, this becomes the initial tx
	 * credit for the stream.
	 */

	uint8_t		sys_tls_client_cert;
	/**< 0 means no client cert.  1+ means apply lws_system client cert 0+
	 * to the client connection.
	 */

	/* Add new things just above here ---^
	 * This is part of the ABI, don't needlessly break compatibility
	 *
	 * The below is to ensure later library versions with new
	 * members added above will see 0 (default) even if the app
	 * was not built against the newer headers.
	 */

	void *_unused[4]; /**< dummy */
};

/**
 * lws_client_connect_via_info() - Connect to another websocket server
 * \param ccinfo: pointer to lws_client_connect_info struct
 *
 *	This function creates a connection to a remote server using the
 *	information provided in ccinfo.
 */
LWS_VISIBLE LWS_EXTERN struct lws *
lws_client_connect_via_info(const struct lws_client_connect_info *ccinfo);

/**
 * lws_init_vhost_client_ssl() - also enable client SSL on an existing vhost
 *
 * \param info: client ssl related info
 * \param vhost: which vhost to initialize client ssl operations on
 *
 * You only need to call this if you plan on using SSL client connections on
 * the vhost.  For non-SSL client connections, it's not necessary to call this.
 *
 * The following members of info are used during the call
 *
 *	 - options must have LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT set,
 *	     otherwise the call does nothing
 *	 - provided_client_ssl_ctx must be NULL to get a generated client
 *	     ssl context, otherwise you can pass a prepared one in by setting it
 *	 - ssl_cipher_list may be NULL or set to the client valid cipher list
 *	 - ssl_ca_filepath may be NULL or client cert filepath
 *	 - ssl_cert_filepath may be NULL or client cert filepath
 *	 - ssl_private_key_filepath may be NULL or client cert private key
 *
 * You must create your vhost explicitly if you want to use this, so you have
 * a pointer to the vhost.  Create the context first with the option flag
 * LWS_SERVER_OPTION_EXPLICIT_VHOSTS and then call lws_create_vhost() with
 * the same info struct.
 */
LWS_VISIBLE LWS_EXTERN int
lws_init_vhost_client_ssl(const struct lws_context_creation_info *info,
			  struct lws_vhost *vhost);
/**
 * lws_http_client_read() - consume waiting received http client data
 *
 * \param wsi: client connection
 * \param buf: pointer to buffer pointer - fill with pointer to your buffer
 * \param len: pointer to chunk length - fill with max length of buffer
 *
 * This is called when the user code is notified client http data has arrived.
 * The user code may choose to delay calling it to consume the data, for example
 * waiting until an onward connection is writeable.
 *
 * For non-chunked connections, up to len bytes of buf are filled with the
 * received content.  len is set to the actual amount filled before return.
 *
 * For chunked connections, the linear buffer content contains the chunking
 * headers and it cannot be passed in one lump.  Instead, this function will
 * call back LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ with in pointing to the
 * chunk start and len set to the chunk length.  There will be as many calls
 * as there are chunks or partial chunks in the buffer.
 */
LWS_VISIBLE LWS_EXTERN int
lws_http_client_read(struct lws *wsi, char **buf, int *len);

/**
 * lws_http_client_http_response() - get last HTTP response code
 *
 * \param wsi: client connection
 *
 * Returns the last server response code, eg, 200 for client http connections.
 *
 * You should capture this during the LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP
 * callback, because after that the memory reserved for storing the related
 * headers is freed and this value is lost.
 */
LWS_VISIBLE LWS_EXTERN unsigned int
lws_http_client_http_response(struct lws *wsi);

/**
 * lws_tls_client_vhost_extra_cert_mem() - add more certs to vh client tls ctx
 *
 * \param vh: the vhost to give more client certs to
 * \param der: pointer to der format additional cert
 * \param der_len: size in bytes of der
 *
 * After the vhost is created with one cert for client verification, you
 * can add additional, eg, intermediate, certs to the client tls context
 * of the vhost, for use with validating the incoming server cert(s).
 */
LWS_VISIBLE LWS_EXTERN int
lws_tls_client_vhost_extra_cert_mem(struct lws_vhost *vh,
		const uint8_t *der, size_t der_len);

/**
 * lws_client_http_body_pending() - control if client connection needs to send body
 *
 * \param wsi: client connection
 * \param something_left_to_send: nonzero if need to send more body, 0 (default)
 * 				if nothing more to send
 *
 * If you will send payload data with your HTTP client connection, eg, for POST,
 * when you set the related http headers in
 * LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER callback you should also call
 * this API with something_left_to_send nonzero, and call
 * lws_callback_on_writable(wsi);
 *
 * After sending the headers, lws will call your callback with
 * LWS_CALLBACK_CLIENT_HTTP_WRITEABLE reason when writable.  You can send the
 * next part of the http body payload, calling lws_callback_on_writable(wsi);
 * if there is more to come, or lws_client_http_body_pending(wsi, 0); to
 * let lws know the last part is sent and the connection can move on.
 */
LWS_VISIBLE LWS_EXTERN void
lws_client_http_body_pending(struct lws *wsi, int something_left_to_send);

/**
 * lws_client_http_multipart() - issue appropriate multipart header or trailer
 *
 * \param wsi: client connection
 * \param name: multipart header name field, or NULL if end of multipart
 * \param filename: multipart header filename field, or NULL if none
 * \param content_type: multipart header content-type part, or NULL if none
 * \param p: pointer to position in buffer
 * \param end: end of buffer
 *
 * This issues a multipart mime boundary, or terminator if name = NULL.
 *
 * Returns 0 if OK or nonzero if couldn't fit in buffer
 */
LWS_VISIBLE LWS_EXTERN int
lws_client_http_multipart(struct lws *wsi, const char *name,
			  const char *filename, const char *content_type,
			  char **p, char *end);

/**
 * lws_http_basic_auth_gen() - helper to encode client basic auth string
 *
 * \param user: user name
 * \param pw: password
 * \param buf: where to store base64 result
 * \param len: max usable size of buf
 *
 * Encodes a username and password in Basic Auth format for use with the
 * Authorization header.  On return, buf is filled with something like
 * "Basic QWxhZGRpbjpPcGVuU2VzYW1l".
 */
LWS_VISIBLE LWS_EXTERN int
lws_http_basic_auth_gen(const char *user, const char *pw, char *buf, size_t len);

///@}
