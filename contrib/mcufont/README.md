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

Enable lws cmake option `-DLWS_WITH_MCUFONT_ENCODER=1` to get it built, but
since it is for development it is not packaged with the rest of lws by make
install.

It produces an executable for your build host in `./bin/lws-mcufont-encoder`
or similar as part of the normal lws cmake build process then.

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
 003E  00 00        2-byte       Reserved
```

Char range tables comprise for each range:

```
+0000  XX XX XX XX  4-byte MSB   unicode index start
+0004  XX XX XX XX  4-byte MSB   count of indexes covered
+0008  XX XX XX XX  4-byte MSB   file offset: start of 16-bit glyph offsets table
+000C  XX XX XX XX  4-byte MSB   file offset: start of data above offsets point into
```

