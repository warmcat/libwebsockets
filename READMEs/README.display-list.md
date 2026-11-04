# lws_display_list

`lws_display_list` is a modernized 1970s-style Display List of graphic
primitives held in an `lws_dll2` list of Display List Objects (DLOs).

Provided DLO primitives are:

 - filled rectangle (with individually controllable rounded corners)
 - PNG (1:1 and original orientation only, transparency supported)
 - JPEG (1:1 and original orientation only)
 - utf-8 text areas (using compressed, antialiased mcufonts)

The aim of it is to process some other representation to describe the
logical scene completely using DLOs in memory, discard the earlier
representation and then rasterize the Display List a single line at a
time from top to bottom, so no backing framebuffer is required at all.
DLOs are destroyed as they go out of scope during rasterization.

Although the memory required does scale with scene complexity in
terms of number of DLOs, it hardly scales at all with output
resolution, allowing modern 32-bpp rendering on very constrained
devices, if slowly.

## DLO capabilities

DLOs are quite capable

 - no floats (`lws_fx` integer fixed-point)
 - 16-bit signed coordinate space with off-surface clipping handled
 - Internal 32-bpp RGBA colourspace (8-bit opacity)
 - correct Z-order opacity resolution
 - Supports arbitrary paletteization (down to 1bpp) and error diffusion
 - DLO-private error diffusion for clean opaque overlaid objects
 - Antialised bitmap text using compressed fonts (eg 7 font sizes 10-
   32px in both regular and bold < ~170KB, with kerning)
 - Very lightweight stateful PNG and JPEG decode

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

## DLO JPEGs

DLOs can also represent JPEGs using a stream parsing rewite of picojpeg.
No framebuffer is required to hold the output, it produces one line of
pixels at a time.  JPEGs use either 8- or 16- line deep MCUs,
necessitating an 8 or 16 line RGB (or Y if grayscale) pixel buffer
during decode.

Heap requirements while a JPG is being rasterized is 2.5KB plus the
MCU buffer dependent on the chroma coding:

|Image type|Fixed alloc|MCU buffer|
|---|---|---|
|grayscale|2.5KB|image width x 8 bytes|
|YUV 4:4:4|2.5KB|image width x 24 bytes|
|YUV 4:4:2v|2.5KB|image width x 24 bytes|
|YUV 4:4:2h|2.5KB|image width x 48 bytes|
|YUV 4:4:0|2.5KB|image width x 48 bytes|

## DLO text

Text DLOs are predicated around unicode utf-8 and a stream parsing
rewrite of mcufont decoder.

mcufont includes a ttf renderer app which is ported into lws as well,
this allows production of antialised (16 alpha level) compressed
bitmaped fonts from any ttf font at a selected size and including
specified subsets of unicode code points.

Font glyphs are decompressed statefully as part of the DLO line
rasterization process, so there are no glyph buffers or caching.
The decompression is very fast and allows fitting over a dozen
font sizes and weights into 100KB.

Pairs of glyphs are kerned by the shape of their ink, from a small profile
of each glyph's edges the encoder puts in the font, so text is measured and
placed kerned without decoding any glyph pixels; see
`contrib/mcufont/README.md`.

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

## Round displays and band updates

`lws_surface_info_t` describes two things about a display that layout and
drawing can take advantage of

 - `.round`: only the circle inscribed in the surface can be seen, eg, a
   round LCD.  `lws_surface_visible_span()` gives the columns that can be
   seen on every line of a band of lines, so whatever is laid out between
   them can all be seen.

 - `.band`: the display's blit can be sent a band of whole lines on their
   own, opened with a blit of the band's box, more than one line high, then
   the lines one at a time, then a zero-height blit.  The lines are always
   the whole width of the display.  (This is not `.partial`, which the EPD
   drivers use to mean they can do a partial refresh.)

## Strip ui

`lws-dlo-ui.h` is a finished user interface for small displays: the caller
says what is in it, as data, and is told what the user picked, without
writing any html itself.  It is made of strips stacked down the display,
each clipped to itself

 - a title strip, saying where we are, eg, "Boot"

 - a list strip, of rows of an optional icon and a line of text, centred,
   that scrolls by dragging it on a touch display, or to keep the row the
   caller says is the focus in its middle.  Pressing a row tells the
   caller which it was.

```
	lws_dlo_ui_info_t i;

	memset(&i, 0, sizeof(i));
	i.cx = cx;
	i.lds = &lds;
	i.row = my_row_cb;	/* fills in row n: icon, text, state */
	i.pick = my_pick_cb;	/* row n was pressed */

	ui = lws_dlo_ui_create(&i);
	lws_dlo_ui_set_title(ui, "AP");
	lws_dlo_ui_set_list(ui, count, -1);
```

It makes the html for the whole display whenever something changes, lays it
out with lhp, and keeps the display list, so it can resolve touches against
it and render just the bands of the strips that changed, on a display that
says it is `.band`.  On a `.round` one, each strip's content, and each row
of the list, is kept to the columns of the circle that can be seen where it
is.  Everything the caller gives it is shown as text, never taken as markup.

It uses the display like any other update: it sets `lds->display_busy`, the
display's completion callback clears it, and should then call
`lws_dlo_ui_kick()` so anything that changed meanwhile is drawn.  Give it
touch events with `lws_dlo_ui_touch()`.  It only uses the faces built in,
so it can be shown before there is any network.

`minimal-examples-lowlevel/api-tests/api-test-dlo-ui` shows it on a pretend
round display, and the lhp embedded examples use it for their boot overlay.
