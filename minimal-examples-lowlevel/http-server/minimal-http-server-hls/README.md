# lws minimal http server HLS

This example demonstrates how to use the `protocol_lws_hls` plugin to dynamically serve HTTP Live Streaming (HLS) content from static `.mp4` and `.mkv` files. It recursively scans the specified media directory, creates an HTML index, and chunks video files on the fly into HLS `.ts` segments.

## build

```
 $ cmake . && make
```

## usage

```
 $ ./lws-minimal-http-server-hls
[2026/07/08 12:00:00:0000] USER: LWS minimal http server HLS | visit http://localhost:7681
[2026/07/08 12:00:00:0000] USER: Media dir: /usr/local/share/libwebsockets-test-server/hls
```

Visit http://localhost:7681 for the media library listing.  The URL space is
flat and owned by the plugin at /: the listing, the player page and its
assets (player.html, player.js, hls.min.js, dir.js/css, favicon.ico) all sit
beside the HLS endpoints (/stream/, /init/, /segment/, /avstream/, /subsm/,
/subseg/, /preview/, /index/), with the raw media files under /media/ the
only separate mount.  The plugin serves the player assets itself from
www-dir, so the whole app is a single mount and every link is relative.

## Commandline Options

- `--media-dir <path>`: Override the default directory containing media files (default: installed `media/` path).
- `--port <port>`: Port to listen on (default 7681).
- `--trust-login-headers`: Trust `x-lws-login-*` headers forwarded by an lws proxy in front (see the plugin README).
- `--help`: Show built-in LWS options (e.g. `-d <log level>`).

## Subtitle and audio tracks

`/stream/<file>` is the playlist the player loads.  When the container has
text subtitle streams (or `.srt` / `.vtt` sidecar files named after it), or
more than one audio stream, it is a master playlist advertising them as
`#EXT-X-MEDIA` renditions; otherwise it is the plain muxed A/V media playlist.

With several audio streams the variant is video-only (`/avstream/<file>/v`)
and each audio stream gets its own audio-only playlist (`/avstream/<file>/aN`,
N being the stream index), cut on the same keyframe timeline as the video, so
the client can switch between them mid-stream.  The player page shows a
dropdown of the audio languages, defaulting to the first one matching the
browser's language preferences, and remembers the choice per file.  Audio
codecs the browser cannot play (AC3, EAC3, DTS, ...) are transcoded to AAC as
for the muxed case.

## lwsws configuration

If you want to use the HLS plugin with `lwsws` (the LWS JSON-configured web server) instead of this minimal C example, you can enable and configure the plugin and mounts via your `lejp` vhost configuration file:

```json
{
  "vhosts": [
    {
      "name": "localhost",
      "port": 7681,
      "ws-protocols": [
        {
          "lws-hls": {
            "status": "ok",
            "media-dir": "/path/to/your/media",
            "www-dir": "/usr/local/share/libwebsockets-test-server/hls/mount-origin"
          }
        }
      ],
      "mounts": [
        {
          "mountpoint": "/",
          "origin": "callback://lws-hls"
        }
      ]
    }
  ]
}
```

`www-dir` (default `<media-dir>/mount-origin`) is where the plugin serves
player.html and its assets from; mounting it at / like this makes the whole
app one flat mount, with everything referenced by relative paths only.

## Subdirectory lifecycle

Media that arrives in its own subdirectory is listed and playable with the
subdirectory in its name, and the delete button accepts it.  A
subdirectory whose last playable media is gone -- deleted through us or
removed outside us -- is itself removed, any remaining non-media contents
included, since there is nothing the viewer could play from it any more.
The check runs at startup, hourly, and after every deletion; the toplevel
media dir is never touched, and the `.index` / `.atrans` cache dirs are not
part of it.  Each removal is logged.

## Reverse proxying

The whole app is expected to work behind an lws reverse proxy (or any
proxy) that mounts it at an arbitrary point of a public server's URL space,
so every link the pages and playlists compose is relative to the page it
appears in: the private server never knows the public URL base, and must
never emit absolute paths.

With the plugin serving the assets itself, everything the pages reference
is a same-directory relative path, which is the default and needs no
configuration.  The `asset-prefix` pvo still exists for deployments that
serve the player page from their own static mount somewhere else: it is a
relative fragment prefixed onto the listing's links, and an absolute value
is refused at init.

Two things to know when proxying at a point of a public URL space:

 - link to the mount with a trailing slash (https://host/abcde/), since
   relative paths only stay inside the mount from the "directory" the
   browser believes the page is in;

 - the login helper script reference (`/lws-login-media/lws-login.js`)
   predates this and is still absolute: it is optional and silently
   skipped when it does not load, but if you need it behind a proxy, mount
   the lws-login media endpoint at the public side accordingly;

 - the PUBLIC vhost's CSP is what the browser ends up enforcing on the
   proxied pages, not the private one: hls.js plays through MSE, so the
   public side must allow `media-src 'self' blob:` (and connect-src 'self'
   for the fetches).  A public vhost enforcing lws's best-practice headers
   without that (its default CSP is `default-src 'none'`) blocks the
   video element's blob: source, which Firefox reports as "Media load
   rejected by URL safety check".  The CSP this example uses on its own
   vhost is a suitable one to set on the public side.
