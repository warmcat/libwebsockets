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

Visit http://localhost:7681 to view the generated media library.

## Commandline Options

- `--media-dir <path>`: Override the default directory containing media files (default: installed `media/` path).
- `--help`: Show built-in LWS options (e.g. `-d <log level>`).

## Subtitle and audio tracks

`/hls/stream/<file>` is the playlist the player loads.  When the container has
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
            "media-dir": "/path/to/your/media"
          }
        }
      ],
      "mounts": [
        {
          "mountpoint": "/media",
          "origin": "file:///usr/local/share/libwebsockets-test-server/hls/mount-origin",
          "default": "index.html"
        },
        {
          "mountpoint": "/media/hls",
          "origin": "callback://lws-hls"
        }
      ]
    }
  ]
}
```
