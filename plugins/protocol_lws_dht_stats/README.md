# protocol_lws_dht_stats

## Introduction

The `lws-dht-stats` plugin is a specialized HTTP and WebSocket plugin designed to provide real-time and historical telemetry of a Libwebsockets DHT (Distributed Hash Table) network node. Similar to the `lws-latency` plugin, it hosts a dynamic HTML/JS Web Dashboard visualizing network pulses, peer counts, and aggregate data drops natively over a live WebSocket stream.

The plugin manages the internal `lws_dht_ctx` sliding-window arrays and streams:
- **`stats_current`**: Live accumulative counters representing metrics like `ping`, `pong`, `find_node`, and peer volume spanning the current window.
- **`stats_history`**: A sequence of historical frames (typically 48 rotating buckets containing 30 minutes of data each) archiving historical network density over a long-term polling period.

## Usage and Integration

To enable this plugin, the binary must be compiled with DHT support using:
```bash
cmake .. -DLWS_WITH_DHT=1
```

Once compiled, you must include its protocol module `lws_dht_stats_protocols` into your `info.protocols` array, and mount the static `index.html` UI files using `LWSMPRO_FILE` so a web browser can open the visual dashboard and negotiate the WS stream.

```c
static const struct lws_http_mount mount_stats = {
	.mountpoint		= "/",
	.origin			= "plugins/dht_stats/assets", /* Installed to share/ usually */
	.def			= "index.html",
	.origin_protocol	= LWSMPRO_FILE,
	.mountpoint_len		= 1,
};
```

## Per-Vhost Options (PVOs)

The `lws-dht-stats` plugin does not consume any Per-Vhost Options (PVOs) of its
own.

However, as for any lws protocol plugin, the protocol still has to be named in
the vhost's pvo list for lws to bind and initialize it on that vhost.  With
lwsws, that is an empty `ws-protocols` entry:

```json
"ws-protocols": [{
    "lws-dht-stats": {
    }
}]
```

and programmatically, a `lws_protocol_vhost_options` naming `lws-dht-stats`
with `options` left NULL.  There are no sub-options to give in either case,
and the plugin initializes correctly either way.

It resolves the underlying DHT execution context afresh on every use, so that a
vhost destroyed at runtime (eg, by an lwsws config reload) can never be left
behind as a stale pointer:

1. It queries `lws_get_vhost_by_name(..., "dht")`, attaching to a `dht`
   designated vhost (which is the recommended lws architecture pattern for
   isolating the DHT UDP backend).
2. If the `"dht"` vhost does not exist, it falls back to the vhost this
   protocol is itself bound to.
