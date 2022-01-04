# lws_display_list

`lws_display_list` is a modernized 1970s-style Display List of graphic
primitives held in an `lws_dll2` list of Display List Objects (DLOs).
Provided DLO primitives are:

 - filled rectangle (with controllably-rounded corners)
 - PNG (1:1 and original orientation only, transparency supported)
 - utf-8 text areas (using kerned bitmap psfu Unicode fonts)

The aim of it is to process some other representation to describe the
logical scene completely using DLOs in memory, discard the earlier
representation and then rasterize the Display List a single line at a
time from top to bottom, so no backing framebuffer is required at all.
DLOs are destroyed as they go out of scope during rasterization.

Although the memory required does scale with scene complexity in
terms of number of DLOs, it hardly scales at all with output
resolution, allowing modern 32-bpp rendering on very constrained
devices, if a bit slowly.  Eg, text DLOs hold blocks of UTF-8 text,
so the number of DLOs only scales slowly for chunks of text too.

## DLO capabilities

DLOs are not as trivial as they sound

 - no floats required (uses `lws_fixed3232` where fractional needed)
 - 16-bit signed coordinate space with off-surface clipping handled
 - Internal 32-bpp RGBA colourspace (8-bit opacity)
 - correct Z-order opacity resolution
 - Supports arbitrary palette-ization (down to 1bpp) and error diffusion
 - DLO-private error diffusion for clean opaque overlaid objects
 - Kerned bitmap text using a variety of standardized unicode fonts

All DLOs in a Display List are consumed as they are rasterized,
individual DLOs are destroyed as soon as they go out of scope during
top - bottom rendering, freeing any related resources as soon as possible.

## DLO PNGs

DLOs may point to a compressed PNG, which is decompressed on the fly
and the decompression context destroyed as the rasterization goes
beyond its bounding box.  Using the lws stateful rewrite of upng, the
memory cost of 32-bpp PNG decode of any dimensions is 40K + 16 x width
bytes, including error diffusion line buffers.  Decoding of the
compressed PNG data is done statefully on demand as needed to fill an
output line, so no memory is needed to hold excess decode production.

Multiple PNG DLOs including PNG-over-PNG (with alpha mixing) are
allowed. PNGs only take heap memory while the current rasterization
line intersects them, so any number of PNGs that don't intersect
vertically do not cost any more peak memory allocation than decoding one,
since the decoding contexts and DLOs of the earlier ones have been
destroyed before the next one's decoding context is allocated.

## DLO text

Text DLOs are predicated around unicode utf-8 and psfu (unix terminal
bitmap font standard), a variety of liberally-licensed fonts up to
32px high are available.

Glyphs are kerned on-the-fly to simulate proportional fonts to make
best use of horizontal space and read easier.

Wrapping inside a bounding box is supported as is "run-on", where text
DLOs follow one another inline, used for example to use a bold font
in part of a text using a different DLO with a different font before
continuing with another DLO using the non-bold font cleanly.  DLOs
are marked as running-on or not.

Centering and right-justification is possible by summing run-ons on
the current line by walking the display list backwards until a non-
run-on DLO is seen, and adjusting the affected DLOs x position.

## Display List lifecycle

### Create empty display list

Create the display state (the dynamic counterpart of the const, static
`lws_display` definition) and the empty display list.

```
	lws_display_state_t lds;
	lws_displaylist_t dl;
```

Instantiate the `lws_display` and bind the display list to it
```
	lws_display_state_init(&lds, cx, 30000, 10000, lls, &disp.disp);

	lws_display_dl_init(&dl, &lds);



### Create DLOs into the list

Eg, create a png from `data` / `len`, return NULL if failed.

```
	if (!lws_display_dlo_png_new(&dl, &box, data, len)) {
```

Eg, create a white background rectange the size of the `lws_display`

```
               lws_dlo_rect_t *dr;
               lws_box_t box = { 0, 0, dl.ds->disp->ic.wh_px[0].whole,
                                       dl.ds->disp->ic.wh_px[1].whole };

               dr = lws_display_dlo_rect_new(&dl, &box, 0,
                               LWSDC_RGBA(255, 255, 255, 255));
               if (!dr)
                       return 1;
```

### Rendering into an lws_display

```
	lds->disp->blit(lds, (uint8_t *)&dl, &box);
```
