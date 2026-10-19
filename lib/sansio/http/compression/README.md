HTTP compression
----------------

This directory contains generic compression transforms that can be applied to
specifically HTTP content streams, after the header, be it h1 or h2.

The compression transforms expose an "ops" type struct and a compressor name
as used by `content-encoding`... the ops struct definition can be found in
./private-lib-roles-http-compression.h.

Because the compression transform depends on being able to send on its output
before it can process new input, the transform adds a new kind of buflist
`wsi->buflist_comp` that represents pre-compression transform data
("input data" from the perspective of the compression transform) that was
delivered to be processed but couldn't be accepted.

Currently, zlib 'deflate' and brotli 'br' are supported on the server side.

On the server side, a text-ish response is compressed when the client accepts
it, unless the vhost has `LWS_SERVER_OPTION_NO_HTTP_STREAM_COMPRESSION`, or the
app called `lws_http_compression_opt_out()` for that one response before
composing its headers.  Responses that carry a secret next to anything the
client can influence must not be compressed (BREACH): they should use the
opt-out.
