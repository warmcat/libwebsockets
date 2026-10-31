# origin

This is part of the MIT-licensed mcufont project which can be found here

https://github.com/mcufont/mcufont

That project is great but it's not actively maintained[1][2] and most work
on it was done back in 2013.

The decoder part was rewritten for lws as `./lib/misc/dlo/dlo-font-mcufont.c`.
This directory contains the ttf-> mcufont encoder, which is a C++
commandline tool for development.

[1] https://github.com/mcufont/mcufont/issues/11
[2] https://github.com/mcufont/mcufont/issues/26

## Building

Install `freetype-dev` or similar package on your build host.

Enable lws cmake option `-DLWS_WITH_MCUFONT_ENCODER=1` to get it built.

It produces an executable for your build host in `./bin/lws-mcufont-encoder`
or similar as part of the normal lws cmake build process then, and `make
install` installs it with lws's other executables, since a server using
`plugins/protocol_lws_mcufonts` runs it to make the pages devices ask for.

## Modifications vs upstream

1) The rledecoder is rewritten to decode statefully, emitting a rasterized
line at a time and only taking in more input when required to issue the
next pixel that is needed for the current line.  This implementation is
integrated into lws dlo stuff down ./lib/misc/dlo.

2) The mcufont decoder type headers are distributed as part of the lws
public headers, but are not imported with libwebsockets.h inclusion, you
should `#include <libwebsockets/mf_rlefont.h>` if you need them (you
normally won't need them, since the dlo stuff will bring it in for its
own usage).

3) Only the encoder part is brought into lws ./conftrib/mcufont; the
encoder can be built by selecting lws cmake option `-DLWS_WITH_MCUFONT_ENCODER=1`

4) The encoder part is modified to issue a single table blob file,
instead of the C typed structs and arrays requiring fonts to be
selected and managed only at build-time; it's at least possible to
download or otherwise manage fonts then after build-time.

The blob starts with a 64-byte header with a magic, versioning, flags and
a map of where the other regions can be found in the file... the overall
layout is like:

```
 [64-byte header]
  [font name string]
  [font short name string]
  [Dictionary Data area]
  [Dictionary Offset area]
  [Unicode range tables]
   [offset table for range]
   [data table for range]
```

File offsets are measured from the first byte of the blob / file.

Dictionary and glyph offset tables contain 16-bit offsets which apply to the first
byte of the Dictionary Data area and the Glyph data table respectively.

The header part is laid out like:

```
 0000  4D 43 55 46  4-byte magic "MCUF"
 0004  XX XX XX XX  4-byte MSB   Flags + Version
 0008  XX XX XX XX  4-byte MSB   file offset: 00-terminated string: `full_name`
 000C  XX XX XX XX  4-byte MSB   file offset: 00-terminated string: `short_name`
 0010  XX XX XX XX  4-byte MSB   file offset: Dictionary Data area (8b)
 0014  XX XX XX XX  4-byte MSB   count: extent of Dictionary Data area
 0018  XX XX XX XX  4-byte MSB   file offset: Dictionary Offsets (16b) into Data area
 001C  XX XX XX XX  4-byte MSB   count: rle dictionary
 0020  XX XX XX XX  4-byte MSB   count: ref dictionary + rle dictionary
 0024  XX XX XX XX  4-byte MSB   file offset: Char Range Tables
 0028  XX XX XX XX  4-byte MSB   count: Char Range Tables
 002C  XX XX XX XX  4-byte MSB   unicode fallback char
 0030  XX XX        2-byte MSB   `width`
 0032  XX XX        2-byte MSB   `height`
 0034  XX XX        2-byte MSB   `min_x_advance`
 0036  XX XX        2-byte MSB   `max_x_advance`
 0038  XX XX        2-byte MSB   signed  `baseline_x`
 003A  XX XX        2-byte MSB   `baseline_y`
 003C  XX XX        2-byte MSB   `line_height`
 003E  XX           1-byte       count of kerning bands the glyph height is cut into
 003F  XX           1-byte       kerning target gap, in clear columns
```

The version in the low byte of `Flags + Version` is 6; the lws decoder
refuses fonts with any other version.

Char range tables comprise for each range:

```
+0000  XX XX XX XX  4-byte MSB   unicode index start
+0004  XX XX XX XX  4-byte MSB   count of indexes covered
+0008  XX XX XX XX  4-byte MSB   file offset: start of 16-bit glyph offsets table
+000C  XX XX XX XX  4-byte MSB   file offset: start of data above offsets point into
```

Each glyph's string in the data starts with its advance width in one byte,
then its kerning profile, then the compressed runs of its pixels.

## Pages of a face

A face with glyphs for a lot of scripts makes a big mcufont, of which a
device usually needs only a page or two, and which takes a long time to
optimize: around 7 minutes for a 32px face with a few pages of Latin glyphs,
at 50 iterations.  So a face can also be cut into pages of 256 codepoints,
page n holding the glyphs for codepoints n * 256 to n * 256 + 255, each
page its own small mcufont.  A device fetches only the pages its text needs
(see `lws_fonts_register_manifest()`), and a server only has to make the
pages that are asked for (`plugins/protocol_lws_mcufonts`).

```
 $ lws-mcufont-encoder face_info Font.ttf
 {"name":"Font Regular","height":1200,"units_per_em":1000,"pages":"0000-0005,001e-0021"}
 $ lws-mcufont-encoder rlefont_page Font.ttf 32 0020 Font32-0020.mcufont 10
```

`face_info` is quick, it renders nothing, and is the same for every size: it
lists the pages the .ttf has any glyphs on as runs of hex page numbers, and
gives the face's height and units per em, from which its line height at a
size is `(height * size + units_per_em / 2) / units_per_em`, exactly as
`rlefont_page` makes it.  The pages are named for the face without a size,
as `face_info` names it.  `rlefont_page` makes the mcufont for
one page, optimized for the given number of iterations (default 10).  The
optimizer's gains flatten off quickly: 20 iterations give pages around 5%
bigger than 50 do, in less than half the time.

So the pages of a face fit together, they are all cut from the whole face:

 - `height`, `baseline_y` and `line_height` are the whole face's, the glyphs
   are only cropped horizontally for each page, so glyphs from different
   pages sit on the same baseline in the same box

 - the kerning target gap and the count of kerning bands are the whole
   face's too, so pairs kern the same whichever pages they are on

 - `width`, `baseline_x` and the advances may differ between pages, and
   the kerning profile columns are kerned relative to the `baseline_x` of
   the page each glyph came from

The device checks each page it fetches has the same height, baseline,
line height and kerning parameters as the first page of the face it got.

The first page in a face's list is its core page, whose fallback glyph
stands in for codepoints on pages the face doesn't have.

`fonts-manifest.cmake` here lays out a directory of whole .mcufont faces as
a server serving pages would, with every page a copy of the whole face, for
testing or for static serving of faces that only have a page or two.

## Kerning

Glyphs are kerned by the shapes of their ink, so layout can place them
without decoding any pixels.  The encoder cuts the glyph height into bands,
a row each up to 64 rows high, and for each band notes the leftmost and
rightmost columns with any ink.  A band with no ink between bands with ink,
like the gap in an `i`, takes the extent of the band above.

The profile in the glyph string is:

```
 XX                 first band with ink, or FF if the glyph has no ink (and
                    the profile is just this byte)
 XX                 last band with ink
 XX XX              leftmost and rightmost columns with ink in the first band
 then for each band after the first, up to the last:
 XX                 the change in the leftmost and rightmost columns from the
                    band above, as two signed nibbles (left in the top one)
   or
 88 XX XX           when either change is too big for a nibble: the leftmost
                    and rightmost columns themselves
```

For a pair of glyphs, the decoder finds the fewest clear columns between
their ink, comparing each band of the first glyph with the bands of the
second beside it and either side, so they can't meet at a corner either.
If that is more than the font's target gap, the second glyph is moved left
to close it up to the target, by at most a quarter of the narrower advance.
Glyphs are never moved apart, and a glyph with no ink, like a space, stops
kerning across it.  The encoder sets the target gap to the median of the
fewest clear columns between all the pairs of letters in the font, ie, the
font's own spacing, but at least one clear column: kerning never brings ink
together, even in small faces set so tight that some pairs touch.

The same kerning is used when measuring text for layout and when placing the
glyphs to render it, so text is drawn at the widths it was laid out with.

