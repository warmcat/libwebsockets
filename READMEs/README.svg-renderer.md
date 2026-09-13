# lws_svg stateful SVG renderer

Lws includes a stateful, line-at-a-time renderer for the fill-only subset of
SVG.  Where the PNG and JPEG support decode a raster that already has a
fixed size, this parses the vector document into a small retained scene and
then computes each output line on demand by intersecting the geometry with
the scanline.  Like the raster decoders, there is no requirement for a
framebuffer, only one line's spans exist at a time; the whole rendered
output never has to be in memory.

Because the vector scene is retained, a rendered line can be produced in any
order and repeatedly, at any requested output scale.  Two differences from
the raster decoders follow from the format:

 - The whole document must have parsed before the first line can be
   rendered, since SVG geometry may be referenced before it is defined
   (`<defs>`, gradients).  So the input must be fully buffered or retained
   somewhere (via lws buflist, in the dlo integration) at least until the
   document completes; afterwards the source is no longer needed.
 - Memory is proportional to the document's geometry, not to a fixed
   decode buffer or to the output size.

All arithmetic is pure integer: coordinates, transforms and raster math in
saturating Q16.16 (range +/-32768, resolution 1/65536), and parse values,
angles and opacity in 1e-8 fixed point through the `lws_fx` operators.
There is no floating point anywhere in the renderer, no libm dependency,
no FPU requirement, and rendered output is bit-identical across platforms.
Saturation replaces overflow, so hostile transform stacks clip the geometry
instead of producing out-of-range values.

## Memory requirements

Fixed allocations at `lws_svg_new()`:

|Allocation|Size|
|---|---|
|Parse context (includes the 24-deep element style stack)|1272B|
|Attribute value accumulation buffer|256B, grows by doubling to the largest attribute|

During parsing, a transient working array holds the current shape's
geometry at 16B/point in user space, growing to the largest single shape
and reused for the rest of the document, and the attribute value buffer
grows to accommodate the largest attribute (typically a path `d` string),
capped at 64KB.

The retained scene lives in a single lwsac allocated in 4KB chunks:

|Retained item|Size|
|---|---|
|Per shape|56B|
|Per subpath|40B|
|Per flattened point|8B|

So a typical icon or chart SVG resolves to a few KB of retained scene.  For
hostile input, scene growth is capped at 2048 shapes, 1024 subpaths per
shape and 262,144 flattened points in total (2MB of point data, or an
absolute ceiling of around 6MB including per-subpath overhead when the
points are arranged as minimal subpaths); exceeding any cap is a FATAL
parse result, as is nesting deeper than 24 elements.

At render time, one scratch buffer of 16B per scanline crossing of the
largest shape is allocated on first use and reused for every line.  Spans
are delivered to a caller callback, so the renderer itself holds no output
buffer at all; the line buffer is the caller's (in the dlo integration, the
existing display line composition buffer).

## Supported subset

 - Shapes: `path` (all commands including endpoint arcs), `rect` (with
   rounded corners), `circle`, `ellipse`, `polygon`, `polyline`
 - Solid fills with `nonzero` and `evenodd` fill rules, `fill`,
   `fill-opacity`, `opacity` and `fill-rule`, inherited through `g`, also
   from `style=""` content
 - Minimal CSS from `<style>` blocks (plain or CDATA-wrapped): rules with
   one simple selector (element name, `.class`, `#id`, or a comma-separated
   list of them) over the same fill property set, applied with the css
   cascade priority presentation attribute < stylesheet < `style=""`, and
   with element < class < id specificity.  Comments and at-rules are
   skipped leniently; rules must appear before the elements they style
 - `transform` on groups and shapes: `matrix`, `translate`, `scale`,
   `rotate` (with optional centre), `skewX`, `skewY`, nested
 - `width`/`height` with CSS units, `viewBox`, and all
   `preserveAspectRatio` policies
 - CSS colours in hex, `rgb()`/`rgba()` and named forms; `none` and
   `transparent` paint nothing
 - xml comments, processing instructions, doctype, CDATA and entities in
   attribute values

Not rendered in this phase of the work: strokes, gradients and other paint
servers, text, masks, filters, patterns, `<use>`/`<symbol>` instancing.
Subtrees that are only containers for these (`<defs>`, `<text>`, gradients,
unknown elements) are parsed but suppressed; a fill referencing an
unsupported paint server (`url(#...)`) paints nothing.  `<style>` blocks
are parsed for the minimal css described above, but selectors beyond the
simple forms given are ignored.

## Creating and destroying the render context

The apis to create and destroy a context are very simple...

```
LWS_VISIBLE LWS_EXTERN lws_svg_t *
lws_svg_new(void);

LWS_VISIBLE LWS_EXTERN void
lws_svg_free(lws_svg_t **svg);
```

## Performing the parse

The document is fed to the stateful parser in arbitrarily-sized chunks; the
parse results are insensitive to the chunking.

```
LWS_VISIBLE LWS_EXTERN lws_stateful_ret_t
lws_svg_parse(lws_svg_t *svg, const uint8_t **buf, size_t *len,
	      char hold_at_metadata);
```

If input is consumed, `*buf` and `*len` are adjusted accordingly.  The
return consists of:

|Return value bit|Meaning|
|---|---|
|`LWS_SRET_OK` (0, no bits set)|The document completed (root element closed), the scene is ready; with `hold_at_metadata`, the root tag parsed and dimensions are available|
|`LWS_SRET_WANT_INPUT`|The input so far was consumed and more is needed to progress|
|`LWS_SRET_FATAL`|The document exceeded a resource cap or allocation failed|

With `hold_at_metadata` set, the parser stops at the end of the root `<svg>`
tag even if more input is available at `*buf`, so image dimensions for
layout are available before the whole document is retained, in the same
spirit as the raster decoders' header-only phase.  Continue the full parse
later by feeding the remaining input with the flag clear.

A document whose input ends without closing the root element is not an
error; whatever parsed is renderable (and renders nothing further once the
input ends).

Intrinsic dimensions for layout come from `lws_svg_get_width()` /
`lws_svg_get_height()`: the `width`/`height` attributes when in px,
otherwise the `viewBox` extents, otherwise the CSS default replaced element
size of 300x150.  They return 0 until the root tag has parsed.

## Rendering a line

```
LWS_VISIBLE LWS_EXTERN lws_stateful_ret_t
lws_svg_render_line(lws_svg_t *svg, const lws_svg_render_t *ri, int y,
		    lws_svg_span_cb_t cb, void *user);
```

`ri` gives the output raster size in px; the document's viewBox and
preserveAspectRatio policy map the user-space geometry into it.  Line `y`
is sampled at the pixel centres and the filled spans are delivered to `cb`
in ascending x, in document order, as half-open `[x0, x1)` pixel ranges
with the span's composed RGBA (alpha already includes opacity composition).

Coverage is binary at pixel centres in this phase; antialiased rendering
can be layered on top later by aggregating subsampled lines.  Lines may be
requested in any order and repeatedly; the only mutation of the context is
growth of the crossing scratch buffer.

## Integration with dlo and lhp

`LWS_WITH_SVG` (on by default) adds `LWSDLOSS_TYPE_SVG` alongside the PNG
and JPEG image dlos: `<img>` fetches of URLs ending `.svg` are parsed
streaming from the Secure Streams buflist with the same metadata-first
flow as the raster images, then rendered line-at-a-time into the dlo line
composition buffer at the box size the layout chose.  Building with
`LWS_WITH_SVG=0` removes it and the `.svg` url handling cleanly.

`lws-api-test-svg` generates a corpus of around 200 documents covering each
supported feature with analytic checks (exact span geometry, independent
pixel-centre oracles, streaming chunk equivalence, transform invariances
and robustness sweeps); `--dump <dir>` writes the corpus as `.svg`/`.pbm`
pairs for eyeballing.

It can also render a single file for eyeballing, in the same way as the
lhp dlo tool renders to a 24bpp top-down `.bmp`:

```
$ lws-api-test-svg --svg icon.svg [--out icon.bmp] [--scale 2] [--bg 202020]
```

The spans are composited in document order on to the background colour
line-at-a-time and written as the `.bmp`; the exit status is nonzero if
the file could not be opened or parsed.  Running the tool with no `--svg`
performs the corpus selftest.
