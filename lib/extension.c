#include "private-libwebsockets.h"

#include "extension-deflate-stream.h"

struct libwebsocket_extension libwebsocket_internal_extensions[] = {
	{
		"deflate-stream",
		lws_extension_callback_deflate_stream,
		sizeof (struct lws_ext_deflate_stream_conn)
	},
	{ /* terminator */
		NULL, NULL, 0
	}
};
