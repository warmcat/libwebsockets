# lws_gif stateful GIF decoder

Lws includes a stateful, line-at-a-time decoder for the first frame of GIF.
Like the PNG and JPEG support it issues one row of output at a time into a
buffer shared by every live gif object, so there is no framebuffer and heap
use does not scale with anything about the image except its logical screen
width (one row).

Everything except the shared row buffer is bounded by the format itself:
the LZW code tables are bounded by the 12-bit code ceiling and the colour
tables by the 256-entry palette, so the same allocations serve any GIF up
to the format's 65535 x 65535 limit.  Nothing an attacker controls sizes
an allocation except the logical screen width.

## Memory requirements

Fixed allocations at `lws_gif_new()`:

|Allocation|Size|
|---|---|
|Decode context (parse state, both colour tables)|~1.6KB|

When decoding starts (the minimum code size byte parses), one further
allocation is made for the LZW tables, and the shared row pool is sized:

|Allocation|Size|Bounded by|
|---|---|---|
|LZW prefix + suffix tables|12KB|12-bit code ceiling|
|Shared row buffer (pool)|logical screen width, doubling from 256B|16-bit width field|

The row buffer is a single pool shared by every live gif object, on the
same discipline as the svg rasterization scratch: the row carries no state
between lines (or objects), so one allocation serves any number of
simultaneously-live images.  A page full of gifs costs one row buffer sized
for the widest, not one each.  The pool is refcounted on the live objects,
grows by doubling to the largest demand, and is freed with the last gif.
The row returned at `*ppix` is valid only until the next call on any gif
object.

The 12KB LZW table allocation is deferred until decoding actually starts,
so the metadata-first flow can size layout from the logical screen
descriptor (the first 13 bytes) before committing to it.  Unlike the row,
the table carries decode state between calls and cannot be shared.

## Semantics

Rows are issued in logical screen coordinates as single bytes indexing the
active colour table (the first image's local table if it had one, else the
global table).  Every screen row is issued exactly once: areas the image
rectangle does not cover are filled with the background index, parts of the
image rectangle outside the logical screen are clipped, and the screen rows
above and below the image rectangle come out as background rows.  The
transparent palette index, if the graphic control extension declared one,
is available from a getter; rows still carry the index and it is the
compositor's business to treat it as transparent.

Only the first image is decoded.  Further images, and any extensions
around them, are walked structurally to the trailer so completion is
still detected, but their pixel data is discarded.  Animated rendering
needs frame composition state and is a possible later phase.

### Interlaced images

Interlaced rows arrive in gif interlace order (rows 0, 8, 16..., then 4,
12..., then 2, 6, 10..., then 1, 3, 5...) with their true y at `*py`.
Linearizing them into strict top-down order requires a whole framebuffer,
which this decoder does not have.  The dlo integration instead re-decodes
its retained copy of the compressed asset once per sweep line, discarding
rows of other passes until the wanted one; that costs O(height)
re-decodes of the compressed data over a whole image, so it is only used
for interlaced images, which are rare in the wild.

## Performing the decode

The api follows the other image decoders:

```
LWS_VISIBLE LWS_EXTERN lws_gif_t *
lws_gif_new(void);

LWS_VISIBLE LWS_EXTERN void
lws_gif_free(lws_gif_t **gif);

LWS_VISIBLE LWS_EXTERN lws_stateful_ret_t
lws_gif_emit_next_line(lws_gif_t *gif, const uint8_t **ppix, int *py,
		       const uint8_t **buf, size_t *len, char hold_at_metadata);
```

Input is consumed from arbitrarily-sized chunks; if any was consumed,
`*buf` and `*len` are adjusted.  With `hold_at_metadata` set, consuming
stops once the logical screen descriptor has parsed, so dimensions for
layout are available before the decode allocations are made; continue
later by feeding the remaining input with the flag clear.  Returns are
`LWS_SRET_WANT_OUTPUT` with the row at `*ppix` and its y at `*py`,
`LWS_SRET_WANT_INPUT` when more input is needed to progress,
`LWS_SRET_OK` when the trailer was reached, or `LWS_SRET_FATAL` for
structurally invalid input (bad header, minimum code size outside 2..8,
codes referencing table entries that cannot exist yet, degenerate
dimensions, unknown block introducers).  Truncated input is not an error:
whatever complete rows decoded are issued and the state stays renderable.

`lws_gif_restart()` resets the parse, LZW and row state while keeping the
allocations, so retained input can be re-decoded (this is how the dlo
integration reaches individual rows of interlaced images).

Getters: `lws_gif_get_width()` / `lws_gif_get_height()` (logical screen),
`lws_gif_get_interlaced()`, `lws_gif_get_palette()` /
`lws_gif_get_palette_count()`, `lws_gif_get_transparent_index()`, and the
usual `lws_gif_get_bpp()` / `lws_gif_get_bitdepth()` /
`lws_gif_get_components()` / `lws_gif_get_pixelsize()` (8 / 8 / 1 / 8 for
palette indices).

## Integration with dlo and lhp

`LWS_WITH_GIF` (on by default) adds `LWSDLOSS_TYPE_GIF` alongside the PNG,
JPEG and SVG image dlos: `<img>` fetches of URLs ending `.gif` are decoded
streaming with the same metadata-first flow as the raster images, then
blitted line-at-a-time into the dlo line composition buffer with palette
expansion and transparency at set_px time.  Building with
`LWS_WITH_GIF=0` removes it and the `.gif` url handling cleanly.

Unlike the png and jpeg dlos, the gif dlo retains the asset payload in
one buffer (16MB ceiling) rather than consuming it from the flow buflist,
since interlaced gifs must be re-decodeable from the start; progressive
gifs free it again as soon as the frame completed.  This is the same
order of retention the svg dlo applies to its document.

The png/jpeg content-type fixups are not extended to gif, since the
retained-payload state lives past the decoder pointer those fixups swap.

## The test tool

`lws-api-test-gif` generates a corpus with an in-test GIF encoder, so
expected pixels are known by construction: one case per minimum code size
and alphabet, local vs global colour tables, transparency, interlace at
heights around the pass boundaries (with progressive/interlaced raster
equivalence and arrival-order checks), frame offsets and clipping against
the logical screen, background fill, forced dictionary clears, the KwKwK
code case, table saturation with deferred clears, sub-block framing at
the extremes, narrow images whose strings straddle many rows, multi-frame
documents where only the first frame renders, and byte-exact agreement
between one-shot and arbitrarily-chunked streaming decodes.  A hand-
computed golden vector covers the LZW core independently of the encoder,
and robustness sweeps cover every truncation and deterministic single-
byte mutations.

It can also decode a single file for eyeballing, in the same way as the
svg and lhp dlo tools, to a 24bpp top-down `.bmp`:

```
$ lws-api-test-gif --gif icon.gif [--out icon.bmp] [--bg 202020]
```

Transparent pixels and screen areas no frame row covered composite on to
the background colour; the exit status is nonzero if the file could not
be opened or parsed.  `--dump <dir>` writes the corpus as `.gif`/`.ppm`
pairs.  Running the tool with no `--gif` performs the corpus selftest.
