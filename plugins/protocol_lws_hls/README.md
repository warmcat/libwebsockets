# lws-hls plugin

This plugin implements an Apple HLS (HTTP Live Streaming) server using `libavformat`.
It dynamically builds an `.m3u8` playlist for media files within a specified directory,
and extracts/remuxes MPEG-TS segments on the fly without performing disk I/O.

## Minimal Example

A minimal example server is provided at `minimal-examples-lowlevel/http-server/minimal-http-server-hls`.
This standalone example demonstrates how to:

- Create an LWS vhost that explicitly loads `protocol_lws_hls`.
- Provide an overarching `media-dir` via the per-vhost options (PVO) mapping to expose local videos.
- Stream media files without transcoding.

To test the minimal server:

```bash
cd build/minimal-examples-lowlevel/http-server/minimal-http-server-hls
./lws-minimal-http-server-hls --media-dir /path/to/my/videos
```
Then visit `http://localhost:7681` to view the directory listing.

## lwsws configuration

If you are using the generic `lwsws` (lws web server) framework, you can configure the plugin on a vhost through your JSON configuration file (parsed by `lejp`). You must instantiate the protocol on the vhost, and also create two separate mounts in the URL space: one for static file serving of the player assets, and one using `callback://` to route incoming HTTP requests to the protocol plugin callback.

Example JSON snippet (e.g. inside `/etc/lwsws/conf.d/myvhost.json`):

```json
{
  "vhosts": [{
    "name": "localhost",
    "port": 7681,
    "ws-protocols": [{
      "lws-hls": {
        "status": "ok",
        "media-dir": "/var/lib/media"
      }
    }],
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
  }]
}
```

This attaches the `lws-hls` protocol to the vhost, maps the `/media` URL path to a standard file mount pointing to your player HTML assets, and creates a `/media/hls` callback mount bound to the `lws-hls` protocol callback. This ensures player files (like `player.html` and `dir.css`) are served statically, while dynamic playlist generator, thumbnail generator, and streaming requests are properly routed to the plugin.
