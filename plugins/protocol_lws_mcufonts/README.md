# lws-mcufonts

Serves fonts to devices using `lws_fonts_register_manifest()`, made from a
directory of .ttf (or .otf) files, at the sizes you choose.

Devices fetch `fonts.json` from the plugin's mount, which lists each face
(each .ttf at each size), and then `<face>/<page>.mcufont` beside it for each
page of 256 codepoints their text needs.  See
[README.html-parser.md](../../READMEs/README.html-parser.md) for the device
side, and [contrib/mcufont](../../contrib/mcufont/README.md) for the pages.

Pages are made with the mcufont encoder only when a device first asks for
them, so a .ttf with glyphs for many scripts costs disk only for the pages
that devices actually use.  Until a page has been made the plugin answers
404, and the device sets that text in its closest built-in face meanwhile and
asks again 20s later.  Pages listed in `warm-pages` are made at startup
instead, so the pages nearly every device needs are there from the start.

What the plugin makes goes in an `lws_diskcache` directory that is trimmed to
a size limit, oldest first.  A trimmed page is just made again the next time
it's asked for.

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
30s at 32px on a fast x86_64 machine.
`jobs` encoders run at once, and a device asking for a page that's still being
made just gets 404 again.

Before the faces can be listed, the plugin runs the encoder's `face_info` for
each face, which is quick, and keeps what it said in the cache, so later
starts with the same .ttf files don't run it again.  `fonts.json` is 404 until
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
	    "sizes": "10,12,14,16,20,24,32",
	    "warm-pages": "0000,0020",
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
ttf-dir|(required)|Directory of .ttf / .otf files to serve, each at each size
cache-dir|(required)|Directory for the pages and face information the plugin makes
encoder|(required)|Path to `lws-mcufont-encoder`
cache-size-mb|64|The cache is trimmed, oldest first, to this size in MiB
sizes|14|Comma-separated pixel sizes to offer each face at (6 to 200, up to 16 sizes)
warm-pages|(none)|Pages to make for every face at startup, as hex page runs like `0000-0001,0020`
iterations|10|Optimization iterations per page (0 to 1000): more makes pages a few percent smaller, for proportionally more time
jobs|2|How many encoders may run at once
job-timeout-s|600|An encoder still running after this is killed, and its page is tried again when it's next asked for

Each face is listed with the path `<ttf name without extension><size>`, eg
`FiraSansCondensed-Regular14` for `FiraSansCondensed-Regular.ttf` at 14px, and
the name freetype gives it, eg "Fira Sans Condensed Regular 14", which is what
devices match css `font-family`, weight and style against.

The ttf dir is listed once, at startup: restart lwsws to pick up new or
changed .ttf files.  A changed .ttf (by size or mtime) has its pages made
afresh, the old ones are left for the cache trimming to remove.

## Limits

The plugin only lists what every device can take: a face whose name is longer
than 63 characters, whose path is longer than 63, or whose page list is more
than 159 characters or 32 runs is left out with a warning.  Devices take at
most 64 faces (ie, .ttf files times sizes) and 16KiB of `fonts.json`, so faces
after that, in order of their paths, are left out with a warning too.

Only urls for the faces and pages in `fonts.json` are answered with anything
other than 404, and only those can cause anything to be made: the url is
never used as a filename, cache objects are named by the sha1 of the face and
page.  At most 64 pages wait to be made at once, beyond that requests for
further pages are just 404 until the queue drains.

## Testing

`minimal-examples-lowlevel/api-tests/api-test-mcufonts-plugin` builds the
plugin in, and with the encoder from the same build, serves the Fira faces in
`contrib/mcufont/fonts` and fetches from it as a device would.
