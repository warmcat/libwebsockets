
#include <zlib.h>

#define DEFLATE_FRAME_COMPRESSION_LEVEL 1

struct lws_ext_deflate_frame_conn {
	z_stream zs_in;
	z_stream zs_out;
	int buf_in_length;
	int buf_out_length;
	int compressed_out;
	unsigned char *buf_in;
	unsigned char *buf_out;
};

extern int lws_extension_callback_deflate_frame(
		struct libwebsocket_context *context,
		struct libwebsocket_extension *ext,
		struct libwebsocket *wsi,
		enum libwebsocket_extension_callback_reasons reason,
		void *user, void *in, size_t len);
