# lws_jpeg stateful JPEG decoder

Lws includes a rewrite of picojpeg that performs stateful, line-at-a-time decoding.

The heap memory requirement is 2.1KB plus an internally-allocated either 8 or 16-line
pixel buffer, the width of the image, and with either Y (for grayscale jpeg) or RGB
bytes per pixel.  Eg for a 600px wide image

|Type|Heap requirement|
|---|---|
|Grayscale|6.5KB|
|RGB 4:4:4|16.4KB|
|RGB 4:2:2v|16.4KB|
|RGB 4:4:2h|31KB|
|RGB 4:4:0|31KB|

No other allocations occur during decode.


In particular the input JPEG data is stream parsed into the JPEG MCU buffer, so there
is no requirement for it all to be in memory at the same time, and there is no
framebuffer required, only a line of pixels is processed in isolation at a time.

The results in an extremely tight decoder suitable for microcontroller type
platforms that lack enough memory to hold a framebuffer, but can stream the
rendered data out over SPI or i2c to a display device that does have its own
(usually write-only) framebuffer memory.

## Creating and destroying the decoding context

The apis to create and destroy a decoding context are very simple...

```
LWS_VISIBLE LWS_EXTERN lws_jpeg_t *
lws_jpeg_new(void);

LWS_VISIBLE LWS_EXTERN void
lws_jpeg_free(lws_jpeg_t **jpeg);
```

## Performing the decoding

The only decoding API provides input PNG data which may or may not be partly or
wholly consumed, to produce a line of output pixels that can be found at `*ppix`.

```
LWS_VISIBLE LWS_EXTERN lws_stateful_ret_t
lws_jpeg_emit_next_line(lws_jpeg_t *jpeg, const uint8_t **ppix,
			const uint8_t **buf, size_t *size);
```
If input data is consumed, `*buf` and `*size` are adjusted accordingly.
This api returns a bitfield consisting of:

|Return value bit|Meaning|
|---|---|
|`LWS_SRET_OK` (0, no bits set)|Completed|
|`LWS_SRET_WANT_INPUT`|Decoder needs to be called again with more PNG input before it can produce a line of pixels|
|`LWS_SRET_WANT_OUTPUT`|Decoder has paused to emit a line of pixels, and can resume|
|`LWS_SRET_FATAL`|Decoder has encountered a fatal error, any return greater than `LWS_SRET_FATAL` indicates the type of error|
|`LWS_SRET_NO_FURTHER_IN`|Indicate no further new input will be used|
|`LWS_SRET_NO_FURTHER_OUT`|Indicate no further output is forthcoming|

To get early information about the dimensions and colourspace of the JPEG, you
can call this api initially with restricted chunk size (eg, 128 bytes) until 
`lws_jpeg_get_components()` returns nonzero.  You can continue where you left off
later when you want to receive the result pixels.

## Output format

To minimize the internal buffer, the provided line of pixels is either just a Y
grayscale byte per pixel if a grayscale JPEG, or 3 RGB bytes per pixel.  You can
query which by using `lws_jpeg_get_components()` to find out how many bytes per
pixel.

Although 4:4:4, 4:2:2 of both orientations, and 4:2:0 are handled differently
internally, they all present 3-byte RGB output of the full width at `*ppix`.

