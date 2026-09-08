# Using WebTransport and QUIC Datagrams in libwebsockets

`libwebsockets` supports WebTransport (RFC 9297) and QUIC Datagrams (RFC 9221) natively over its HTTP/3 and QUIC transport layers. WebTransport is an API that provides low-latency, bidirectional, multiplexed, and secure client-server messaging.

## WebTransport vs. WebSocket

WebTransport offers several architectural advantages over WebSocket, particularly in high-performance or lossy networking environments:

| Feature | WebSocket (`ws`) | WebTransport (`wt`) |
| --- | --- | --- |
| **Transport Protocol** | TCP (HTTP/1.1 or HTTP/2) | UDP (QUIC via HTTP/3) |
| **Multiplexing** | Built-in for H2, none for H1. | Native QUIC streams (multiple independent streams without head-of-line blocking). |
| **Delivery Guarantees** | Reliable, strictly ordered. | Offers both reliable streams and unreliable **Datagrams**. |
| **Connection Setup** | Requires 1-3 RTTs (TCP + TLS + HTTP). | 0-RTT or 1-RTT (QUIC handshake). |
| **Security** | TLS 1.2 or 1.3 | Always TLS 1.3 (embedded in QUIC). |

Use **WebSocket** when you need maximum backward compatibility across older clients, infrastructure, and proxies.
Use **WebTransport** when you require low-latency media streaming, gaming, or parallel data transfers where head-of-line blocking is unacceptable.

## Architecture in `libwebsockets`

WebTransport in `libwebsockets` maps elegantly to the `wsi` (WebSocket Instance) abstraction. WebTransport requires an HTTP/3 virtual host.

### The Session `wsi`

A WebTransport connection starts with an HTTP/3 `CONNECT` request specifying the `:protocol: webtransport` pseudo-header. If accepted, `libwebsockets` transitions this `wsi` to the `wt` role (`&role_ops_wt`).

- **Datagrams**: The session `wsi` handles WebTransport Datagrams. Any payload written directly to the session `wsi` is encapsulated in a QUIC `DATAGRAM` frame, prefixed with the WebTransport Quarter Session ID.

### Child Streams

Within the WebTransport session, you can spawn multiple independent QUIC streams. 

- **Creation**: Call `lws_wt_create_stream(session_wsi, is_unidi)` to create a new child stream. `is_unidi` determines whether it is a unidirectional or bidirectional stream.
- **Handling**: Each child stream gets its own `wsi` running the `wt` role, and its own pss. It will trigger its own `LWS_CALLBACK_WT_BIND_PROTOCOL`, `LWS_CALLBACK_RECEIVE`, `LWS_CALLBACK_CLOSED` and `LWS_CALLBACK_WT_DROP_PROTOCOL` events. A stream the peer created is also announced with `LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED`.
- **Writing**: Data written to a child stream using `lws_write` is framed directly as a QUIC `STREAM` payload, avoiding multiplexing overhead.

### Protocol bind and unbind

`LWS_CALLBACK_WT_BIND_PROTOCOL` and `LWS_CALLBACK_WT_DROP_PROTOCOL` are the `wt` role's analogues of `LWS_CALLBACK_HTTP_BIND_PROTOCOL` / `LWS_CALLBACK_HTTP_DROP_PROTOCOL`.

They are only about the logical binding of the session or stream `wsi` to your protocol, and say nothing about the state of the connection or the stream: they are not `LWS_CALLBACK_ESTABLISHED` / `LWS_CALLBACK_CLOSED` under another name.

- the bind is where anything the protocol wants to allocate for the `wsi` should be created; it is also the only announcement a stream that you created yourself with `lws_wt_create_stream()` gets, since nobody adopted it
- the drop is where those allocations must be destroyed, and where anything pointing into the pss (eg, a `lws_dll2_t` list node living inside it) must be removed. The pss may be freed immediately afterwards, either because the `wsi` is closing or because it is being rebound
- a `wsi` that was bound while still in the `h3` role, and then transitioned into `wt` (the session `wsi` after the `CONNECT`, and any peer stream that had to be rebound), saw `LWS_CALLBACK_HTTP_BIND_PROTOCOL` for that original bind. A protocol that can be reached both ways should handle both drop reasons.

### Filtering the CONNECT

Before the server answers the `CONNECT` with a 200 and the stream leaves the
`h3` role, the protocol that was selected for the session receives
`LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION`, exactly as for a ws upgrade.  `in`
is the negotiated wt protocol name (or NULL).  The request headers are still
attached at that point, so the `:path` and any urlargs can be inspected with
`lws_hdr_copy()` / `lws_get_urlarg_by_name_safe()`.  Returning nonzero refuses
the session: the `CONNECT` is answered with a 403 and the stream is closed,
with no `LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED`.

This is the place to do things like `/wt?code=...` token checks, since the
browser WebTransport API does not let a page set request headers.

## Quick Start Example

### Server-side Initialization

Ensure your context and vhost are configured with HTTP/3 support and TLS:

```c
struct lws_context_creation_info info;
memset(&info, 0, sizeof info);

info.port = 443;
info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
info.alpn = "h3"; /* Required for WebTransport */
info.ssl_cert_filepath = "server.cert";
info.ssl_private_key_filepath = "server.key";
```

### Handling the `wt` Protocol

Implement the protocol callback. Distinguish between the session and its streams using `lws_wt_is_session(wsi)`:

```c
#include <libwebsockets/lws-webtransport.h>

static int
callback_webtransport(struct lws *wsi, enum lws_callback_reasons reason,
                      void *user, void *in, size_t len)
{
    switch (reason) {
        case LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED:
            if (lws_wt_is_session(wsi)) {
                /* New WebTransport session established.
                 * You can create streams here, or wait for the client to initiate them. */
                struct lws *stream_wsi = lws_wt_create_stream(wsi, 0 /* bidi */);
            } else {
                /* The peer created a child stream. */
            }
            break;

        case LWS_CALLBACK_WT_BIND_PROTOCOL:
            /* This session or stream wsi is now bound to us... create
             * anything the pss needs.  This is not about connection state. */
            break;

        case LWS_CALLBACK_WT_DROP_PROTOCOL:
            /* Unbound... destroy whatever the pss owns, and remove anything
             * that points into the pss, it may be freed straight after. */
            break;

        case LWS_CALLBACK_RECEIVE:
            if (lws_wt_is_session(wsi)) {
                /* Received a WebTransport Datagram */
            } else {
                /* Received data on a WebTransport Stream */
            }
            break;

        /* ... other callbacks ... */
    }
    return 0;
}
```

## Security and Browser Clients

Major web browsers (Chrome, Firefox, Safari) support the `WebTransport` JavaScript API. However, browsers strictly enforce TLS certificates for WebTransport. 

If you are developing locally with self-signed certificates, the browser will instantly reject the connection. You can bypass this during development in Chromium-based browsers using:

```bash
# Ignore certificate errors for local WebTransport development
google-chrome --ignore-certificate-errors --origin-to-force-quic-on=localhost:443
```

Alternatively, you can provide the SHA-256 hash of your self-signed certificate in the JavaScript `WebTransport` constructor's `serverCertificateHashes` option.
