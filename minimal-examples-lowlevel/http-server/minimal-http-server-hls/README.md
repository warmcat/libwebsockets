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
