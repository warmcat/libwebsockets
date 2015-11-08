#include "private-libwebsockets.h"
#include "core-util/CriticalSectionLock.h"

extern "C" void *mbed3_create_tcp_stream_socket(void)
{
	lws_conn_listener *srv = new lws_conn_listener;
	
	//lwsl_notice("%s: %p\r\n", __func__, (void *)srv);
	
	return (void *)srv;
}

/* this is called by compatible_close() */
extern "C" void mbed3_delete_tcp_stream_socket(void *sock)
{
	lws_conn *conn = (lws_conn *)sock;
	
	conn->ts->close();
	
	lwsl_notice("%s: wsi %p: conn %p\r\n", __func__, (void *)conn->wsi, sock);
	delete conn;
}

extern "C" void mbed3_tcp_stream_bind(void *sock, int port, struct libwebsocket *wsi)
{
	lws_conn_listener *srv = (lws_conn_listener *)sock;
	
	lwsl_info("%s\r\n", __func__);
	/* associate us with the listening wsi */
	((lws_conn *)srv)->set_wsi(wsi);

	mbed::util::FunctionPointer1<void, uint16_t> fp(srv, &lws_conn_listener::start);
	minar::Scheduler::postCallback(fp.bind(port));
}

extern "C" void mbed3_tcp_stream_accept(void *sock, struct libwebsocket *wsi)
{
	lws_conn *conn = (lws_conn *)sock;

	lwsl_info("%s\r\n", __func__);
	conn->set_wsi(wsi);
}

extern "C" LWS_VISIBLE int
lws_ssl_capable_read_no_ssl(struct libwebsocket_context *context,
			    struct libwebsocket *wsi, unsigned char *buf, int len)
{
	socket_error_t err;
	size_t _len = len;

	lwsl_debug("%s\r\n", __func__);
	
	(void)context;
	/* s/s_HACK/ts/g when mbed3 listen payload bug fixed */
	err = ((lws_conn *)wsi->sock)->s_HACK->recv((char *)buf, &_len);
	if (err == SOCKET_ERROR_NONE) {
		lwsl_info("%s: got %d bytes\n", __func__, _len);
		return _len;
	}
#if LWS_POSIX
	if (LWS_ERRNO == LWS_EAGAIN ||
	    LWS_ERRNO == LWS_EWOULDBLOCK ||
	    LWS_ERRNO == LWS_EINTR)
#else
	if (err == SOCKET_ERROR_WOULD_BLOCK)
#endif
		return LWS_SSL_CAPABLE_MORE_SERVICE;

	// !!! while listen payload mbed3 bug, don't error out if nothing */	
//	if (((lws_conn *)wsi->sock)->s_HACK != ((Socket *)((lws_conn *)wsi->sock)->ts))
//		return 0;

	lwsl_warn("error on reading from skt: %d\n", err);
	return LWS_SSL_CAPABLE_ERROR;
}

extern "C" LWS_VISIBLE int
lws_ssl_capable_write_no_ssl(struct libwebsocket *wsi, unsigned char *buf, int len)
{
	socket_error_t err;

	lwsl_debug("%s: wsi %p: write %d (from %p)\n", __func__, (void *)wsi, len, (void *)buf);
	
	err = ((lws_conn *)wsi->sock)->ts->send((char *)buf, len);
	if (err == SOCKET_ERROR_NONE)
		return len;

#if LWS_POSIX
	if (LWS_ERRNO == LWS_EAGAIN ||
	    LWS_ERRNO == LWS_EWOULDBLOCK ||
	    LWS_ERRNO == LWS_EINTR) {
		if (LWS_ERRNO == LWS_EWOULDBLOCK)
			lws_set_blocking_send(wsi);
#else
	if (err == SOCKET_ERROR_WOULD_BLOCK)
		return LWS_SSL_CAPABLE_MORE_SERVICE;
#endif

	lwsl_warn("%s: wsi %p: ERROR %d writing len %d to skt\n", __func__, (void *)wsi, err, len);
	return LWS_SSL_CAPABLE_ERROR;
}

/*
 * Set the listening socket to listen.
 */

void lws_conn_listener::start(const uint16_t port)
{
	socket_error_t err = srv.open(SOCKET_AF_INET4);

	if (srv.error_check(err))
		return;
	err = srv.bind("0.0.0.0", port);
	if (srv.error_check(err))
		return;
	err = srv.start_listening(TCPListener::IncomingHandler_t(this,
					&lws_conn_listener::onIncoming));
	srv.error_check(err);
}

int lws_conn::actual_onRX(Socket *s)
{
	struct libwebsocket_pollfd pollfd;

	pollfd.fd = this;
	pollfd.events = POLLIN;
	pollfd.revents = POLLIN;
	
	lwsl_debug("%s: lws %p\n", __func__, wsi);
	
	s_HACK = s;
	
	return libwebsocket_service_fd(wsi->protocol->owning_server, &pollfd);
}

/* 
 * this gets called from the OS when the TCPListener gets a connection that
 * needs accept()-ing.  LWS needs to run the associated flow.
 */

void lws_conn_listener::onIncoming(TCPListener *tl, void *impl)
{
	mbed::util::CriticalSectionLock lock;
	TCPStream *ts = srv.accept(impl);
	lws_conn *conn;

	if (!impl || !ts) {
		onError(tl, SOCKET_ERROR_NULL_PTR);
		return;
	}
	
	conn = new(lws_conn);
	if (!conn) {
		lwsl_err("OOM\n");
		return;
	}
	conn->ts = ts;

	/* 
	 * we use the listen socket wsi to get started, but a new wsi is
	 * created.  mbed3_tcp_stream_accept() is also called from
	 * here to bind the conn and new wsi together
	 */
	lws_server_socket_service(wsi->protocol->owning_server,
				  wsi, (struct pollfd *)conn);

	ts->setOnSent(Socket::SentHandler_t(conn, &lws_conn::onSent));
	ts->setOnReadable(TCPStream::ReadableHandler_t(conn, &lws_conn::onRX));
	ts->setOnError(TCPStream::ErrorHandler_t(conn, &lws_conn::onError));
	ts->setOnDisconnect(TCPStream::DisconnectHandler_t(conn,
			    &lws_conn::onDisconnect));
	/*
	 * mbed3 is messed up as of 2015-11-08, data packets may
	 * appear on the listening socket initially
	 */
	conn->actual_onRX((Socket *)tl);
	conn->actual_onRX((Socket *)conn->ts);

	lwsl_debug("%s: exit\n", __func__);
}

extern "C" LWS_VISIBLE struct libwebsocket *
wsi_from_fd(struct libwebsocket_context *context, lws_sockfd_type fd)
{
	lws_conn *conn = (lws_conn *)fd;
	(void)context;

	return conn->wsi;
}

extern "C" LWS_VISIBLE void
lws_plat_insert_socket_into_fds(struct libwebsocket_context *context,
						       struct libwebsocket *wsi)
{
	(void)wsi;
	lws_libev_io(context, wsi, LWS_EV_START | LWS_EV_READ);
	context->fds[context->fds_count++].revents = 0;
}

extern "C" LWS_VISIBLE void
lws_plat_delete_socket_from_fds(struct libwebsocket_context *context,
						struct libwebsocket *wsi, int m)
{
	(void)context;
	(void)wsi;
	(void)m;
}

void lws_conn::onRX(Socket *s)
{
	actual_onRX(s);
}

void lws_conn_listener::onDisconnect(TCPStream *s)
{
	lwsl_info("%s\r\n", __func__);
	(void)s;
	//if (s)
	//delete this;
}
void lws_conn::onSent(Socket *s, uint16_t len)
{
	struct libwebsocket_pollfd pollfd;

	(void)s;
	(void)len;

	pollfd.fd = this;
	pollfd.events = POLLOUT;
	pollfd.revents = POLLOUT;
	
	s_HACK = s;

	lwsl_debug("%s: wsi %p\r\n", __func__, (void *)wsi);
	
	libwebsocket_service_fd(wsi->protocol->owning_server, &pollfd);
}

void lws_conn_listener::onError(Socket *s, socket_error_t err)
{
	(void) s;
	lwsl_notice("Socket Error: %s (%d)\r\n", socket_strerror(err), err);
	if (ts)
		ts->close();
}

void lws_conn::onDisconnect(TCPStream *s)
{
	(void)s;
	libwebsocket_close_and_free_session(wsi->protocol->owning_server, wsi,
						LWS_CLOSE_STATUS_NOSTATUS);
}


void lws_conn::onError(Socket *s, socket_error_t err)
{
	(void) s;
	lwsl_notice("Socket Error: %s (%d)\r\n", socket_strerror(err), err);
	if (ts)
		ts->close();
}