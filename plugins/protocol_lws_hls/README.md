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

This attaches the `lws-hls` protocol to the vhost, maps the `/media` URL path to a standard file mount pointing to your player HTML assets, and creates a `/media/hls` callback mount bound to the `lws-hls` protocol callback. This ensures player files (like `player.html`, `dir.js` and `dir.css`) are served statically, while dynamic playlist generator, thumbnail generator, and streaming requests are properly routed to the plugin.

## Deleting media

The directory listing shows a bin button on each item, and the player a
delete button, for a request the plugin decides is an app admin; the same
decision gates the `hls/delete/<name>` POST that does the deletion.  The
plugin takes it from, in order:

 - the `x-lws-login-state` an in-process `lws-login` bouncer gating the mount
   stamped on the request (nothing to configure: only an interceptor can stamp
   it)

 - `"trust-login-headers": "1"`: the same header as forwarded by an lws reverse
   proxy whose mount is gated by `lws-login` on the box in front of this one.
   The bouncer strips the browser's own copy, so it is trustworthy from that
   path; setting this asserts the vhost is not reachable any other way.  Off by
   default

 - `"jwt-jwk"`: the auth server's public JWK, to validate the `auth_session`
   cookie directly; the `"*"` wildcard grant or a `"service-name"` (default
   `hls`) grant at level 2 or more qualifies.  For a vhost with the bouncer
   neither in-process nor in front of it

The client side asks the bouncer at `.lws-login-status` whether to show the
buttons (the cookie is `HttpOnly`); the server enforces regardless.  When the
plugin runs with the `lws-hls-stub` privilege-separated child, the child does
the unlink; otherwise the plugin does it itself.

## Threading model

Everything that opens a media file with `libavformat` runs on a worker thread
owned by the vhost, never on the lws event loop.  Opening a large MKV, scanning
it to build a keyframe index when it has no cues, demuxing a segment, and
transcoding its audio all take from tens of milliseconds to minutes, and done
synchronously inside `LWS_CALLBACK_HTTP` they would stall every vhost on the
context for the duration.

The HTTP callback validates the URL and queues a task naming what is wanted
(init segment, playlist, media segment, subtitle playlist or segment,
thumbnail), and returns with the transaction pending.  The worker runs the
tasks FIFO, builds the response body into the task, and wakes the event loop
with `lws_cancel_service()`; the event loop then hands the body to the waiting
session and starts the HTTP response.  A session that closes while its task is
queued drops it; one that closes while its task is running sets a cancel flag
the demux and index scan loops poll, so the worker stops early rather than
finishing work nobody will collect.

## Keyframe index

Segment boundaries come from the video track's keyframe index: the container's
cues when it has them, otherwise a one-off scan of the whole file (cached per
vhost).  The scan does not trust the container's keyframe flags alone: for
HEVC and H.264 it also looks at the NAL unit types, because libavformat only
recovers missing flags from the bitstream for H.264, and a release MKV whose
muxer did not understand HEVC typically flags nothing but the first frame.
For matroska the scan also locates each keyframe's enclosing Cluster, which is
what the demuxer needs to seek to.  When keyframes had to be found in the
bitstream, segment seeks use `AVSEEK_FLAG_ANY`, so the demuxer does not sit
waiting for a flagged keyframe that never comes; libavformat logs "keyframes
not correctly marked" once per seek on such files.

Independently of that, the input walked for a single media segment is bounded
(`HLS_SEGMENT_MAX_SPAN_US`, `HLS_SEGMENT_MAX_PKTS`, `HLS_BUF_MAX` in
`hls-av.c`), so a keyframe index that turns out to describe the wrong
boundaries cannot make the worker transcode the whole file for one request.
