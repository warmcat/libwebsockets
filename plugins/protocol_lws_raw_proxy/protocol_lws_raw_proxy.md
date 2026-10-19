# raw-proxy

## Introduction

The `raw-proxy` plugin behaves as an active raw-socket proxy capable of port-forwarding traffic from incoming connections directly to a specified onward destination socket natively throughout the libwebsockets event loop without bridging. It implements a non-blocking `LWS_CALLBACK_RAW_PROXY_...` flow to correctly buffer transmission arrays natively across the incoming and outgoing legs cleanly.

## Per-Vhost Options (PVOs)

This plugin requires one Per-Vhost Option (PVO) at instantiation to define the routing destination, and takes one optional one:

| PVO Name | Description |
|---|---|
| `onward` | **Required.** String encoding specifying the proxy loop destination. The required format is either `ipv4:IP_ADDR[:PORT]` or `ipv6:IP_ADDR`. |
| `idle-timeout-secs` | Optional.  While both sides are up, close both once nothing has passed in either direction for this many seconds; anything passing either way restarts it.  Default `300`, `0` disables the idle timeout.  A value that is not a decimal integer fails the vhost's protocol init. |

## Idle timeout

By default a proxied connection idle in both directions for 300s is closed, so
a peer that vanishes without closing, or never sends anything, cannot hold an
fd and an onward connection indefinitely.  Protocols with long legitimately
quiet sessions, eg, interactive ssh, should either send keepalives more often
than that (ssh `ServerAliveInterval` / `ClientAliveInterval`), or have the
vhost set a larger `idle-timeout-secs`, or `0`.

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
