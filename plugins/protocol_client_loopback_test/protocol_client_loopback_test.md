# client-loopback-test

## Introduction

The `client-loopback-test` is a plugin facilitating testing of WebSocket client functionality. It acts over HTTP to initiate a looped-back WebSocket client connection using `lws_client_connect_via_info` directly pointing to its own WebSocket protocol handler. The URL mount is typically set to `/c`, giving callers a way to make subsequent `ws://` or `wss://` URI loopback connection attempts.

## Restrictions on the destination

The destination in the URI is a *request*, not an instruction: an unauthenticated peer must not be able to make the server open connections to arbitrary hosts (SSRF).

 - the URI selects only `ws://` (no tls) or `wss://` (tls)
 - the port always comes from the vhost the plugin is mounted on, never from the URI
 - the host part must be a loopback name (`localhost`, `127.0.0.1`, `::1`), the vhost's own name, or listed in the `allow` PVO below

Anything else is refused with a 403.  Error pages do not quote the request back, since `lws_return_http_status()` emits its body as `text/html`.

## Per-Vhost Options (PVOs)

|PVO|Meaning|
|---|---|
|`allow`|Comma-separated list of additional destination addresses that may be named in the URI, eg, `"10.0.0.1,my-peer.example.com"`.  Optional; loopback and the vhost's own name are always allowed.|

```
	"client-loopback-test": {
	 "status": "ok",
	 "allow": "10.0.0.1"
	},
```
