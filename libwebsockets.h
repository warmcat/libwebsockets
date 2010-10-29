
enum libwebsocket_callback_reasons {
	LWS_CALLBACK_ESTABLISHED,
	LWS_CALLBACK_CLOSED,
	LWS_CALLBACK_SEND,
	LWS_CALLBACK_RECEIVE,
};

struct libwebsocket;

extern int libwebsocket_create_server(int port,
		  int (*callback)(struct libwebsocket *,
					   enum libwebsocket_callback_reasons));

extern int libwebsocket_write(struct libwebsocket *, void *buf, size_t len);
