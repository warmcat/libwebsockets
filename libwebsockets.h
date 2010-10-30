
enum libwebsocket_callback_reasons {
	LWS_CALLBACK_ESTABLISHED,
	LWS_CALLBACK_CLOSED,
	LWS_CALLBACK_SEND,
	LWS_CALLBACK_RECEIVE,
};

struct libwebsocket;

extern int libwebsocket_create_server(int port,
		  int (*callback)(struct libwebsocket *,
					   enum libwebsocket_callback_reasons, void *, size_t));

/*
 * IMPORTANT NOTICE!
 * 
 * The send buffer has to have LWS_SEND_BUFFER_PRE_PADDING bytes valid BEFORE
 * buf, and LWS_SEND_BUFFER_POST_PADDING bytes valid AFTER (buf + len).
 * 
 * This allows us to add protocol info before and after the data, and send as
 * one packet on the network without payload copying, for maximum efficiency.
 * 
 * So for example you need this kind of code to use libwebsocket_write with a
 * 128-byte payload 
 * 
 * char buf[LWS_SEND_BUFFER_PRE_PADDING + 128 + LWS_SEND_BUFFER_POST_PADDING];
 * 
 * // fill your part of the buffer... for example here it's all zeros
 * memset(&buf[LWS_SEND_BUFFER_PRE_PADDING], 0, 128);
 * 
 * libwebsocket_write(wsi, &buf[LWS_SEND_BUFFER_PRE_PADDING], 128);
 * 
 */

#define LWS_SEND_BUFFER_PRE_PADDING 12
#define LWS_SEND_BUFFER_POST_PADDING 1

extern int libwebsocket_write(struct libwebsocket *, unsigned char *buf, size_t len, int is_binary);
