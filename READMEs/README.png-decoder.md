# lws_upng stateful PNG decoder

Lws includes a rewrite of UPNG that performs stateful, line-at-a-time decoding.

The memory requirement is fixed at 40KB plus enough buffer for two output
lines of pixels.  In particular the input PNG data is stream parsed, so there
is no requirement for it all to be in memory at the same time, and there is
no framebuffer required either, so there is no requirement for all the output
to be in memory at the same time, either.

The results in an extremely tight decoder suitable for microcontroller type
platforms that lack enough memory to hold a framebuffer, but can stream the
rendered data out over SPI or i2c to a display device that does have its own
(usually write-only) framebuffer memory.

## Creating and destroying the decoding context

The apis to create and destroy a decoding context are very simple...

```
LWS_VISIBLE LWS_EXTERN lws_upng_t *
lws_upng_new(void);

LWS_VISIBLE LWS_EXTERN void
lws_upng_free(lws_upng_t **upng);
```

## Performing the decoding

The only decoding API provides input PNG data which may or may not be partly or
wholly consumed, to produce a line of output pixels that can be found at `*ppix`.

```
LWS_VISIBLE LWS_EXTERN lws_stateful_ret_t
lws_upng_emit_next_line(lws_upng_t *upng, const uint8_t **ppix,
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

To get early information about the dimensions and colourspace of the PNG, you
can call this api initially with the first 33 bytes (`*size` restricted to 33)
and adjust the true size -33 for further calls.  This will make it return with
`WANT_INPUT` after having processed the PNG header information but not produced
any pixel line information.

