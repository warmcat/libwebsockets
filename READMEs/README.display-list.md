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

## Panning a page bigger than the display

A retained display list (`lws_display_render_state_t .retained`) can be
rendered again at another offset without laying it out again, eg, as a page is
dragged on a touch display.  `lws_display_render_pan(rs, dx, dy)` moves the
view by dx, dy, kept to what the page's content covers, and returns nonzero if
it moved; the caller then renders the display list again from the top of the
display.  `rs->pan_x`, `rs->pan_y` is the point of the page at the top left of
the display, so a touch at x, y on the display is at x + pan_x, y + pan_y on
the page, eg, for `lws_display_dl_hit_test()`.  Where the view shows beyond the
page, the lines start out white.

The layout drops content below the surface it is given, so for a page longer
than the display to be panned down to its end, set `rs->layout_h` to a height
to lay it out to before browsing it with `lws_lhp_ss_browse()`.  css viewport
units and the like still resolve against the display's height, unless
`rs->viewport_h` says else.

On a round display, a page the size of the display has things in its corners
that the circle doesn't show.  So there the view can also go beyond each edge
of the content, but only as far as it takes to bring a corner of it to the
first pixel of the circle that can be seen there, at 45 degrees from its
middle: 36px on a 240px circle.  A surface that is only the lower part of a
round display, eg, below a title strip, says so with `.round_top`, how far
down the display it starts: the circle is still the display's, and if the 45
degree point is above the surface, its top corners go to where the circle is
seen on its top line instead.

png and jpeg decoders only go forwards.  Images the raster has passed are
fetched again for the next render, from the document asset cache if there is
one, and an image the raster goes back up, eg, one partway down the display
when the view moves down, is started again, renewed from the cache if it's
there, else fetched again from where it came from.

`minimal-examples-lowlevel/api-tests/api-test-dlo-pan` shows and checks it.

## Strip ui

`lws-dlo-ui.h` is a finished user interface for small displays: the caller
says what is in it, as data, and is told what the user picked, without
writing any html itself.  It is made of strips stacked down the display,
each clipped to itself.  Its list page has

 - a title strip, saying where we are, eg, "Boot".  Pressing it calls the
   title callback, if there is one, eg, to go back or show another list.

 - a list strip, of rows of an optional icon and a line of text, centred,
   that scrolls by dragging it on a touch display, or to keep the row the
   caller says is the focus in its middle.  Pressing a row tells the
   caller which it was.

and its edit page, shown by `lws_dlo_ui_edit()` to type something in, eg, a
passphrase, has

 - the title strip, saying what is typed: pressing it abandons the edit

 - an edit strip, showing what was typed, or stars if it is masked, which
   can be dragged sideways to see all of it

 - a keyboard strip: the ui owns the keyboard, with lower and upper case and
   symbol layers.  It is bigger than a small display, and dragged around its
   strip to reach the keys.  Done gives what was typed to the done callback,
   which can accept it, or keep it being edited.

and its frame page, shown by `lws_dlo_ui_frame()`, has

 - the title strip, eg, saying which page of the application this is

 - the body, the rest of the display, which is the caller's: it lays its own
   content out on the surface `lws_dlo_ui_frame_body()` gives, eg, browsing a
   page with lhp onto it, and draws the whole display itself, getting the
   title strip's lines from `lws_dlo_ui_frame_line()`.  So on a display that
   can only take an update of all of it, eg, an EPD, the title strip and the
   page arrive together.

and its dialog page, shown by `lws_dlo_ui_dialog()`, has

 - the title strip, saying what the dialog is, eg, "Settings": pressing it,
   or ESC, tells the caller, eg, to close it

 - the panel, the rest of the display, showing html the caller writes, eg, a
   table of things and some fields to edit.  It is clipped to what can be
   seen of the display, and dragged to scroll it if it's taller.  Each
   `<a href="...">` in it can be pressed, or gone to and pressed with the
   buttons: the caller is told its href, which means whatever the caller
   wants, eg, "ap:3" or "edit:hostname".

So a settings dialog of the application's own is only its html, written again
whenever what it shows changes, and what to do with each href.  Editing a
field is the edit page, which comes back to the dialog when it ends: with
`LWS_DLO_UI_EDIT_KEEP`, however it ends, the done callback gets what was
typed, eg, to store a hostname whether or not Done was pressed.

```
static void
my_html(void *opaque, lws_dlo_ui_html_t *h)
{
	lws_html_w_printf(h, "<table><tr><td>Host</td><td>"
				  "<a href=\"edit:host\">");
	lws_html_w_text(h, hostname, (size_t)-1);	/* shown as text */
	lws_html_w_printf(h, "</a></td></tr></table>");
}

static void
my_action(void *opaque, const char *href)
{
	if (!strcmp(href, "edit:host"))
		lws_dlo_ui_edit(ui, "Hostname", 32, LWS_DLO_UI_EDIT_KEEP);
}

	/* eg, on a click of a "settings" button */
	lws_dlo_ui_dialog_t d;

	memset(&d, 0, sizeof(d));
	d.html = my_html;
	d.action = my_action;
	d.css = "td { padding-right: 8px }";	/* optional */

	lws_dlo_ui_set_title(ui, "Settings");
	lws_dlo_ui_dialog(ui, &d);
```

`lws_dlo_ui_dialog_changed()` has the html written again, eg, when a list in
it changes, keeping where it's scrolled to.  The dialog is closed by showing
another page, eg, `lws_dlo_ui_frame()` to go back to what the application was
showing.

Each strip only moves for drags that begin in it, and dragging never types
anything.

On every page, the title strip can show a capsule at its right end, with
small icons for how strong the wlan signal is and how charged the battery is,
`lws_dlo_ui_set_status()`.  They are boxes styled by the css, so they need no
images and are sized for the display; on a round display the capsule is at
the right end of what can be seen of the title's line.  It is only drawn
again when what it shows changes, eg, the battery's charge is shown in
quarters.  Pressing it is a button: with `.status_button = "settings"`, it
issues the interaction event `{"type":"button","src":"ui/settings",
"event":"click"}`, as a physical button called "settings" would, so either can
open the settings, through the same code.

While the frame is shown, the ui only draws the title strip by itself when
it changes, and only on a `.band` display.  On a `.bistable` one, eg, an EPD
that takes seconds to update, the change waits for the caller's next update;
otherwise the caller is told with the `frame_redraw` callback, to draw it all
again.

Without touch, the ui can be driven by buttons, or anything else that says
which way to go: `lws_dlo_ui_nav()` moves a cursor up and down the list,
around the keyboard, and between the links of a dialog, and presses what it is
on with ENTER; ESC goes back.
`lws_dlo_ui_interaction()` takes any interaction event, giving touches to
`lws_dlo_ui_touch()` and clicks of buttons named "up", "down", "left",
"right", "enter" and "esc" to `lws_dlo_ui_nav()`, so the caller can give it
everything, whatever the board has.  Typing on the keyboard needs the four
directions and enter: with fewer buttons than that, only touch can.

```
	lws_dlo_ui_info_t i;

	memset(&i, 0, sizeof(i));
	i.cx = cx;
	i.lds = &lds;
	i.row = my_row_cb;	/* fills in row n: icon, text, state */
	i.pick = my_pick_cb;	/* row n was pressed */
	i.title = my_title_cb;	/* optional: the title was pressed */
	i.done = my_done_cb;	/* what was typed, or NULL if abandoned */
	i.css = "#t { background-color: #800 }";	/* optional */

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

How it looks is css: a default theme, which the caller's css follows and can
override.  The ids and classes it can style, eg, `#t` for the title strip and
`#tt` for its text, `.k` for a key, are listed in `lws-dlo-ui.h`.  Where
things are and how big is set by the ui after that, from the display, so css
can't move them.

What is typed is cleared from the ui's memory when the edit ends, and from
the html it was shown in when that is made again.

It uses the display like any other update: it sets `lds->display_busy`, the
display's completion callback clears it, and should then call
`lws_dlo_ui_kick()` so anything that changed meanwhile is drawn.  Give it
interaction events with `lws_dlo_ui_interaction()`.  It only uses the faces
built in, so it can be shown before there is any network.  Laying it out again
only stops its own document, so a page being browsed into the frame's body
carries on fetching meanwhile.

`minimal-examples-lowlevel/api-tests/api-test-dlo-ui` shows it on a pretend
round display, and the lhp embedded examples use it for their boot overlay
and settings dialog.
