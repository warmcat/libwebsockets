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

The `lws-dht-stats` plugin is designed to operate seamlessly without requiring explicit Per-Vhost Options (PVOs).

It automatically intelligently detects the underlying DHT execution context using the following resolution methodology:
1. It queries `lws_get_vhost_by_name(..., "dht")` attempting to attach to a globally initialized `dht` designated vhost (which is the recommended LWS architecture pattern for isolating the DHT UDP backend).
2. If the `"dht"` vhost is not explicitly defined, it safely falls back to polling the context from the native vhost handling the active HTTP request.

As a result, no explicit `info.pvo` array fields string mappings are necessary to configure this plugin.
