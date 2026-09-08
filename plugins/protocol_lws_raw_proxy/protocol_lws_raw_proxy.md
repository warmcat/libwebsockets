# raw-proxy

## Introduction

The `raw-proxy` plugin behaves as an active raw-socket proxy capable of port-forwarding traffic from incoming connections directly to a specified onward destination socket natively throughout the libwebsockets event loop without bridging. It implements a non-blocking `LWS_CALLBACK_RAW_PROXY_...` flow to correctly buffer transmission arrays natively across the incoming and outgoing legs cleanly.

## Per-Vhost Options (PVOs)

This plugin requires one Per-Vhost Option (PVO) at instantiation to define the routing destination:

| PVO Name | Description |
|---|---|
| `onward` | **Required.** String encoding specifying the proxy loop destination. The required format is either `ipv4:IP_ADDR[:PORT]` or `ipv6:IP_ADDR`. |

## Behaviour when the onward connection fails

The onward connection is started as soon as the inbound connection is accepted,
and rx on the accepted side is flow-controlled off until it is up, so nothing
is read from the peer that could not yet be forwarded.

If the onward connection fails (host down, refused, DNS failure, TLS failure),
lws issues `LWS_CALLBACK_CLIENT_CONNECTION_ERROR` and, deliberately, no
`..._CLI_CLOSE`.  The plugin handles that callback by marking the onward side
closed and closing the accepted connection, so the accepted socket is not left
open with no timeout and the shared state (both rings and everything queued in
them) is freed.  The peer sees the proxy connection close.
