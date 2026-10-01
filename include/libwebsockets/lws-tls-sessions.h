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

/*! \defgroup tls_sessions TLS Session Management

    APIs related to managing TLS Sessions
*/
//@{


#define LWS_SESSION_TAG_LEN 96

struct lws_tls_session_dump
{
	char			tag[LWS_SESSION_TAG_LEN];
	void			*blob;
        void			*opaque;
	size_t			blob_len;
};

typedef int (*lws_tls_sess_cb_t)(struct lws_context *cx,
				 struct lws_tls_session_dump *info);

/*
 * lws_tls_session_dump_save_flags() / lws_tls_session_dump_load_flags() flags
 */
enum {
	LWS_TLS_SESSION_DUMP_F_QUIC		= (1 << 0),
	/**< the session is the one made by, and offered to, quic connections
	 * to the host and port.  They are cached apart from tls over tcp's:
	 * the client sends 0-RTT data under the session it resumes, and a
	 * ticket from one transport carries the wrong alpn and transport
	 * parameters for the other */
};

/**
 * lws_tls_session_dump_save_flags() - serialize a tls session via a callback
 *
 * \param vh: the vhost whose client session cache to look in
 * \param host: the name of the host the session relates to
 * \param port: the port the session connects to on the host
 * \param flags: 0, or LWS_TLS_SESSION_DUMP_F_QUIC for the quic session
 * \param cb_save: the callback to perform the saving of the session blob
 * \param opq: an opaque pointer passed into the callback
 *
 * If a session matching the vhost/host/port and transport exists in the
 * vhost's session cache, serialize it via the provided callback.
 *
 * Only sessions of connections that fully validated the server are visible
 * here: those of connections with relaxed cert checks are kept apart in the
 * cache and never saved or loaded.
 *
 * \p opq is passed to the callback without being used by lws at all.
 *
 * Returns 0 if the session was found and the callback accepted it.
 */
LWS_VISIBLE LWS_EXTERN int
lws_tls_session_dump_save_flags(struct lws_vhost *vh, const char *host,
				uint16_t port, unsigned int flags,
				lws_tls_sess_cb_t cb_save, void *opq);

/**
 * lws_tls_session_dump_load_flags() - deserialize a tls session via a callback
 *
 * \param vh: the vhost whose client session cache to load into
 * \param host: the name of the host the session relates to
 * \param port: the port the session connects to on the host
 * \param flags: 0, or LWS_TLS_SESSION_DUMP_F_QUIC for a quic session
 * \param cb_load: the callback to retreive the session blob from
 * \param opq: an opaque pointer passed into the callback
 *
 * Try to preload a session described by the vhost / host / port and
 * transport into the client session cache, from the given callback.  It is
 * only offered to connections over that transport that fully validate the
 * server.  With LWS_TLS_SESSION_DUMP_F_QUIC, a client that opts into it sends
 * 0-RTT data under the loaded session, so it must only be given what
 * lws_tls_session_dump_save_flags() saved with the same flag.
 *
 * \p opq is passed to the callback without being used by lws at all.
 */
LWS_VISIBLE LWS_EXTERN int
lws_tls_session_dump_load_flags(struct lws_vhost *vh, const char *host,
				uint16_t port, unsigned int flags,
				lws_tls_sess_cb_t cb_load, void *opq);

/**
 * lws_tls_session_dump_save() - serialize a tls over tcp session
 *
 * As lws_tls_session_dump_save_flags() with flags 0
 */
LWS_VISIBLE LWS_EXTERN int
lws_tls_session_dump_save(struct lws_vhost *vh, const char *host, uint16_t port,
			  lws_tls_sess_cb_t cb_save, void *opq);

/**
 * lws_tls_session_dump_load() - deserialize a tls over tcp session
 *
 * As lws_tls_session_dump_load_flags() with flags 0
 */
LWS_VISIBLE LWS_EXTERN int
lws_tls_session_dump_load(struct lws_vhost *vh, const char *host, uint16_t port,
			  lws_tls_sess_cb_t cb_load, void *opq);

///@}
