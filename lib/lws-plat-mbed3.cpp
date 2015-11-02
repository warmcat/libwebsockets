#include "private-libwebsockets.h"

extern "C" void *mbed3_create_tcp_stream_socket(void)
{
	lws_conn_listener *srv = new lws_conn_listener;
	
	printf("%s: %p\r\n", __func__, (void *)srv);
	
	return (void *)srv;
}

extern "C" void mbed3_delete_tcp_stream_socket(void *sock)
{
	printf("%s: %p\r\n", __func__, sock);
	delete (lws_conn *)sock;
}

extern "C" void mbed3_tcp_stream_bind(void *sock, int port, struct libwebsocket *wsi)
{
	lws_conn_listener *srv = (lws_conn_listener *)sock;
	
	lwsl_notice("%s\r\n", __func__);
	/* associate us with the listening wsi */
	((lws_conn *)srv)->set_wsi(wsi);

	mbed::util::FunctionPointer1<void, uint16_t> fp(srv, &lws_conn_listener::start);
	minar::Scheduler::postCallback(fp.bind(port));
}

extern "C" void mbed3_tcp_stream_accept(void *sock, struct libwebsocket *wsi)
{
	lws_conn *conn = (lws_conn *)sock;

	lwsl_notice("%s\r\n", __func__);
	conn->set_wsi(wsi);
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

/* 
 * this gets called from the OS when the TCPListener gets a connection that
 * needs accept()-ing.  LWS needs to run the associated flow.
 */

void lws_conn_listener::onIncoming(TCPListener *tl, void *impl)
{
	lws_conn *conn;
	
	printf("%s\r\n", __func__);
	if (!impl) {
		onError(tl, SOCKET_ERROR_NULL_PTR);
		return;
	}
	
	conn = new(lws_conn);
	conn->ts = srv.accept(impl);
	
	conn->ts->setOnReadable(TCPStream::ReadableHandler_t(this,
						&lws_conn_listener::onRX));

	if (!conn->ts) {
		onError(tl, SOCKET_ERROR_BAD_ALLOC);
		return;
	}
	
	conn->ts->setOnError(TCPStream::ErrorHandler_t(this,
						       &lws_conn_listener::onError));
	conn->ts->setOnDisconnect(TCPStream::DisconnectHandler_t(this,
					&lws_conn_listener::onDisconnect));
	conn->ts->setOnSent(Socket::SentHandler_t(this, &lws_conn_listener::onSent));

	/* 
	 * we use the listen socket wsi to get started, but a new wsi is
	 * created.  mbed3_tcp_stream_accept() is also called from here to
	 * bind the ts and wsi together
	 */
	lws_server_socket_service(wsi->protocol->owning_server,
				  wsi, (struct pollfd *)conn);
}

void lws_conn_listener::onRX(Socket *s)
{
	socket_error_t err;
	static const char *rsp =
		"HTTP/1.1 200 OK\r\n"
		"\r\n"
		"Ahaha... hello\r\n";
	size_t size = BUFFER_SIZE - 1;
	int n;
	
	lwsl_notice("%s\r\n", __func__);
	
	err = s->recv(buffer, &size);
	n = s->error_check(err);
	if (!n) {
		buffer[size] = 0;
		printf("%d: %s", size, buffer);

		err = s->send(rsp, strlen(rsp));
//		if (err != SOCKET_ERROR_NONE)
//			onError(s, err);
	} else
		printf("%s: error %d\r\n", __func__, n);
}

void lws_conn_listener::onDisconnect(TCPStream *s)
{
	lwsl_notice("%s\r\n", __func__);
	(void)s;
	//if (s)
	//delete this;
}
void lws_conn_listener::onSent(Socket *s, uint16_t len)
{
	lwsl_notice("%s\r\n", __func__);
	(void)s;
	(void)len;
	ts->close();
}

void lws_conn_listener::onError(Socket *s, socket_error_t err)
{
	(void) s;
	lwsl_notice("Socket Error: %s (%d)\r\n", socket_strerror(err), err);
	if (ts)
		ts->close();
}
