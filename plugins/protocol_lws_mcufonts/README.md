# lws-mcufonts

Serves fonts to devices using `lws_fonts_register_manifest()`, made from a
directory of .ttf (or .otf) files, at whatever size each device asks for.

Devices fetch `fonts.json` from the plugin's mount, which lists each face
(each .ttf) and the sizes it can be had at, and then
`<face>/<size>/<page>.mcufont` beside it for each page of 256 codepoints
their text needs, at the size their css wants.  See
[README.html-parser.md](../../READMEs/README.html-parser.md) for the device
side, and [contrib/mcufont](../../contrib/mcufont/README.md) for the pages.

Pages are made with the mcufont encoder only when a device first asks for
them at a size, so a .ttf with glyphs for many scripts costs disk only for
the pages, at the sizes, that devices actually use.  Until a page has been
made the plugin answers 404, and the device sets that text in its closest
built-in face meanwhile and asks again 20s later.  Pages listed in
`warm-pages` are made at startup at each of the `warm-sizes` instead, so the
pages nearly every device needs are there from the start.

What the plugin makes goes in an `lws_diskcache` directory that is trimmed to
a size limit, oldest first, so a size that was only used for a while ages out
again.  A trimmed page is just made again the next time it's asked for.

## Prerequisites

 - lws built with `-DLWS_WITH_PLUGINS=1 -DLWS_WITH_SPAWN=1
   -DLWS_WITH_DISKCACHE=1 -DLWS_WITH_STRUCT_JSON=1`, for a unix-type platform

 - the encoder, `lws-mcufont-encoder`, built with `-DLWS_WITH_MCUFONT_ENCODER=1`
   (it needs the freetype development package), and installed by
   `make install` beside lwsws, eg in `/usr/local/bin`

 - a directory of .ttf files, readable by lwsws once it has dropped
   privileges.  Only files whose names are letters, digits, `.`, `-` and `_`
   are used, since the name goes in the urls

 - a directory for the cache, which the plugin creates if needed

## How long pages take to make

Each page is made by running the encoder, which renders the whole face and
then optimizes the page's compression.  With the default 10 iterations, page
0000 of a Latin face (usually its biggest page) takes around 15s at 14px and
30s at 32px on a fast x86_64 machine, and longer again for bigger sizes.
`jobs` encoders run at once, and a device asking for a page that's still being
made just gets 404 again.

Before the faces can be listed, the plugin runs the encoder's `face_info` for
each .ttf, which is quick and the same for every size, and keeps what it said
in the cache, so later starts with the same .ttf files don't run it again.  `fonts.json` is 404 until
every face has been learned; devices retry it every 30s.

## Using with lwsws

Add a mount for the plugin to the vhost's mounts, here at `/mcufonts`, so
devices register `https://<your vhost>/mcufonts/fonts.json`:

```
	{
	  "mountpoint": "/mcufonts",
	  "origin": "callback://lws-mcufonts"
	}
```

and enable it on the vhost with its pvos:

```
	"ws-protocols": [{
	  "lws-mcufonts": {
	    "ttf-dir": "/usr/share/lws-mcufonts/ttf",
	    "cache-dir": "/var/cache/lws-mcufonts",
	    "cache-size-mb": "256",
	    "encoder": "/usr/local/bin/lws-mcufont-encoder",
	    "max-size": "100",
	    "warm-pages": "0000,0020",
	    "warm-sizes": "8,10,12,13,17,20,27",
	    "iterations": "10",
	    "jobs": "2"
	  },
	  "lws-mcufonts-stdwsi": {
	    "status": "ok"
	  }
	}]
```

`lws-mcufonts-stdwsi` is the plugin's protocol for the encoder's stdin, stdout
and stderr pipes, it needs no configuration.

pvo|Default|Meaning
---|---|---
ttf-dir|(required)|Directory of .ttf / .otf files to serve, each as a face
cache-dir|(required)|Directory for the pages and face information the plugin makes
encoder|(required)|Path to `lws-mcufont-encoder`
cache-size-mb|64|The cache is trimmed, oldest first, to this size in MiB
min-size|6|The smallest pixel size a page is made at (4 to 255)
max-size|100|The biggest pixel size a page is made at (min-size to 255): devices wanting bigger text get this size
warm-pages|(none)|Pages to make for every face at startup at each `warm-sizes`, as hex page runs like `0000-0001,0020`
warm-sizes|(none)|Sizes to make the `warm-pages` at, as decimal runs like `12-16,20`
iterations|10|Optimization iterations per page (0 to 1000): more makes pages a few percent smaller, for proportionally more time
jobs|2|How many encoders may run at once
job-timeout-s|600|An encoder still running after this is killed, and its page is tried again when it's next asked for

Each face is listed with the path `<ttf name without extension>`, eg
`FiraSansCondensed-Regular` for `FiraSansCondensed-Regular.ttf`, the name
freetype gives it, eg "Fira Sans Condensed Regular", which is what devices
match css `font-family`, weight and style against, the sizes `min-size` to
`max-size`, and the face's height and units per em, from which devices work
out its line height at each size.  Its page 0020 at 14px is then
`FiraSansCondensed-Regular/14/0020.mcufont`.

A device picks the size whose line height is closest to its css
`font-size`, as it does with its built-in faces, so the sizes asked for
follow the content devices show.  Since a face's line height is a bit more
than its size, that's a smaller size than the css one: for Fira Sans
Condensed (height 1200, 1000 units per em), css `font-size: 14px` asks for
12px, and css sizes 10, 12, 14, 16, 20, 24 and 32px ask for 8, 10, 12, 13,
17, 20 and 27px.  Give `warm-sizes` in those terms.  Each size of
each page is made once, the first time it's asked for, and then served from
the cache until it's trimmed: `max-size` bounds how big, and how slow to make,
a page can be, and `cache-size-mb` how much disk the sizes in use take.

The ttf dir is listed once, at startup: restart lwsws to pick up new or
changed .ttf files.  A changed .ttf (by size or mtime) has its pages made
afresh, the old ones are left for the cache trimming to remove.

## Limits

The plugin only lists what every device can take: a face whose name is longer
than 63 characters, whose path is longer than 63, whose page list is more
than 159 characters or 32 runs, or whose line height at `max-size` doesn't
fit in 16 bits, is left out with a warning.  Devices take at most 64 faces
(ie, .ttf files) and 16KiB of `fonts.json`, so faces after that, in order of
their paths, are left out with a warning too.

Only urls for the faces in `fonts.json`, at a size from `min-size` to
`max-size` written without leading zeros, and pages the face has, are
answered with anything other than 404, and only those can cause anything to
be made: the url is never used as a filename, cache objects are named by the
sha1 of the face, size and page.  At most 64 pages wait to be made at once,
beyond that requests for further pages are just 404 until the queue drains.

## Testing

`minimal-examples-lowlevel/api-tests/api-test-mcufonts-plugin` builds the
plugin in, and with the encoder from the same build, serves the Fira faces in
`contrib/mcufont/fonts` and fetches from it as a device would.
