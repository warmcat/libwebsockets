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

## The listing

`hls/` lists the media files newest first, each with a thumbnail from
`hls/preview/<file>` (the frame at 10s) and a link into the player.  What
`dir.js` then does with it is per viewer, from the resume state `player.js`
keeps in the browser's localStorage: a file the viewer has started gets a
resume badge, its thumbnail is re-requested as `hls/preview/<file>/<secs>`
so it shows the frame they will resume at, and the items are reordered by
the later of the file's date and when the viewer last watched it, so what
they were watching recently sits at the top alongside what was recently
added.  Nothing about the viewer is stored on the server: the timed
thumbnails are cached per (file, seconds) like the default ones, the seconds
bucketed by the client to 5s so the cache is not asked for every second.

A timed thumbnail is only cut through the file's keyframe index (see below),
never by asking the demuxer to seek a large file without cues; a file that
has no index yet gets the default frame instead.

The listing keeps itself current.  The page carries a generation token of
what it lists (`data-gen` on its body), and `dir.js` subscribes to
`hls/events`, an SSE stream of the current token: when it is not the one
the page was built with, media arrived, finished arriving (see below) or
went, and the page reloads.  While anyone is subscribed, the media dir is
rewalked every 3s from `stat()` alone, and our own deletes make it look
at once; with nobody subscribed, nothing is walked.  The token covers each
listed file's name and whether it is still arriving, and for a settled file
its size and date, but not the size or date of a file still being written,
so a long copy does not reload the page every few seconds.  Polling rather
than a directory notifier, because media lives in subdirectories too and a
copy finishing is only the passing of time.  Behind a proxy, the stream
must not be buffered (the response says `x-accel-buffering: no`).

## Media that is not all there yet

Media usually arrives in the media dir by being copied there, and a film
takes minutes to copy over a network while the listing already sees it.
libavformat opens a partial file without complaint and describes a shorter
film, and the keyframe index, audio shadows and thumbnails built from that
would be persisted or cached as if it were the whole thing.  So before
anything is built from a file, `hls-media.c` decides whether it is all
there:

 - **still arriving**: it was written to in the last `HLS_MEDIA_SETTLE_SECS`
   (30s), ie a copy is in progress, whatever the container;

 - **incomplete**: its container's own framing says there is more than the
   file holds.  Matroska / webm declare the Segment size up front, and an
   mp4 is a run of top-level boxes, each declaring its size, which needs a
   `moov` (written last unless the file was made faststart).  This catches
   a copy that stalled or died, however long ago.  A matroska written live
   with an unknown Segment size says nothing either way.

The listing shows such files, with their state where the thumbnail would
be, but with no link to the player and no thumbnail; an admin still gets
the delete button, for a copy that died.  Dotfiles are never listed, which
is how rsync and others name a copy in progress.  Whatever asks, the worker
answers 503 for any playlist, segment or init segment of such a file and
does not cut its thumbnail, the indexer and the audio shadow transcoder
do not open it, and `hls/index/<file>` reports `"media":"arriving"` or
`"media":"incomplete"` without queueing anything, so the player says so and
waits, playing it once it is complete.  A failure because the file was not
all there is not remembered: the next ask after it completes builds it.

The keyframe index and the audio shadows are also recorded against the
file's size and mtime from before they were built, and discarded if the
file is not still that when they are done.

A subdirectory that something is being written into, under any name, is not
removed by the purge of subdirectories with nothing playable left in them.

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

Building a keyframe index is the one job that does not run on the worker.
The worker is FIFO, so a multi-minute scan of one large file there would
hold up every other file's playlist and segment requests behind it.  When a
task needs an index that is in neither memory nor `.index`, the worker parks
the task, queues the build on a second, indexer thread, and carries on with
the queue; when the build lands the parked tasks go back to the head of the
worker's queue and are answered from the cache.  A build that fails, or
finds nothing worth caching, is remembered for ten minutes so tasks for that
file are not parked behind it again but built inline as before.

## Keyframe index

Segment boundaries come from the video track's keyframe index: the container's
cues when it has them, otherwise a one-off scan of the whole file.  Either way
the file is read end to end once, which for a large MKV is minutes, so the
result is kept in memory per vhost and also written to
`<media-dir>/.index/<sha1 of the filename>.idx`, and loaded from there after
a restart.  The index records the media file's size and mtime; one that no
longer matches, whose media is gone, or that is older than its media (it was
made from something else, eg a replacement copied in with its size and date
preserved), is removed when seen, when the media
is deleted through the plugin, at protocol init, and by an hourly sweep, so
nothing accumulates in `.index`.  If `.index` cannot be created (media dir
not writable by the server), that is logged once per attempt and the index
stays in memory only.

`hls/index/<file>` reports whether the index exists as JSON
(`{"ready":..,"running":..,"failed":..,"progress":<percent of file read>}`)
and queues the build on the indexer thread if it does not.  The player asks
this before it gives hls.js the playlists and waits, showing the progress
over the video area, since hls.js gives a playlist load 10-20 seconds and
then abandons that rendition; on a large file that was the first attempt
"troubled" and the audio track missing on the second.

The scan does not trust the container's keyframe flags alone: for
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
