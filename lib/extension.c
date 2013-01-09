#include "private-libwebsockets.h"

#include "extension-deflate-frame.h"
#include "extension-deflate-stream.h"
#include "extension-x-google-mux.h"

struct libwebsocket_extension libwebsocket_internal_extensions[] = {
#ifdef LWS_EXT_GOOGLE_MUX
	{
		"x-google-mux",
		lws_extension_callback_x_google_mux,
		sizeof (struct lws_ext_x_google_mux_conn)
	},
#endif
#ifdef LWS_EXT_DEFLATE_STREAM
	{
		"deflate-stream",
		lws_extension_callback_deflate_stream,
		sizeof (struct lws_ext_deflate_stream_conn)
	},
#else
	{
		"x-webkit-deflate-frame",
		lws_extension_callback_deflate_frame,
		sizeof (struct lws_ext_deflate_frame_conn)
	},
	{
		"deflate-frame",
		lws_extension_callback_deflate_frame,
		sizeof (struct lws_ext_deflate_frame_conn)
	},
#endif
	{ /* terminator */
		NULL, NULL, 0
	}
};
