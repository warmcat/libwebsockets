# QUIC 0-RTT / Early Data

libwebsockets supports QUIC 0-RTT (Early Data) to allow clients to send data before the TLS 1.3 handshake fully completes, reducing latency for resuming connections.

Because 0-RTT data is susceptible to replay attacks, the implementation uses an explicit opt-in model. Existing applications using QUIC or HTTP/3 will ignore 0-RTT by default and continue operating with the standard `LWS_CALLBACK_CLIENT_ESTABLISHED`.

## How it works

When a client connection initiates a handshake with a server it has previously connected to, it can attempt to send 0-RTT data using early TLS secrets.
- If the server accepts it, the client's 0-RTT data is processed immediately.
- If the server rejects it, the connection falls back to the standard 1-RTT handshake.

## Enabling 0-RTT

To enable 0-RTT capabilities on a connection, both the client and server must explicitly allow it using flags and options:

### Client

When creating a client connection, set the `LCCSCF_ALLOW_EARLY_DATA` flag in the `ssl_connection` member of your `struct lws_client_connect_info`:

```c
struct lws_client_connect_info i;
memset(&i, 0, sizeof(i));
// ...
i.ssl_connection = LCCSCF_USE_SSL | LCCSCF_ALLOW_EARLY_DATA;
// ...
lws_client_connect_via_info(&i);
```

### Server

When creating the server vhost, add the `LWS_SERVER_OPTION_ALLOW_EARLY_DATA` flag to the vhost `options`:

```c
struct lws_context_creation_info info;
memset(&info, 0, sizeof(info));
// ...
info.options |= LWS_SERVER_OPTION_ALLOW_EARLY_DATA;
// ...
lws_create_context(&info);
```

## Opting a Stream into 0-RTT

When early data is possible on a connection, the protocol callback will receive a new reason: `LWS_CALLBACK_CLIENT_ESTABLISHED_EARLY`.

To opt a specific stream into sending 0-RTT data, your callback **must return `1`** when handling this reason:

```c
static int
callback_example(struct lws *wsi, enum lws_callback_reasons reason,
                 void *user, void *in, size_t len)
{
    switch (reason) {
    case LWS_CALLBACK_CLIENT_ESTABLISHED_EARLY:
        /* We have an opportunity to send 0-RTT data.
         * Return 1 to opt-in and become writable immediately.
         * Return 0 (default) to ignore 0-RTT.
         */
        return 1;

    case LWS_CALLBACK_CLIENT_ESTABLISHED:
        /* The traditional handshake has completed. */
        break;

    // ...
    }
    return 0;
}
```

If you return `1`, the stream opts into 0-RTT, and LWS will immediately call `lws_callback_on_writable(wsi)` for that stream so you can send your early data payload. 

> [!NOTE]
> Opting into 0-RTT does not skip the normal `LWS_CALLBACK_CLIENT_ESTABLISHED`. You will still receive `LWS_CALLBACK_CLIENT_ESTABLISHED` when the QUIC handshake actually completes.

## Handling Rejection and Idempotency

### Client-side Rejection Status

Since 0-RTT can be rejected by the server (e.g. if the server lost its session ticket keys), the client needs to know if the early data it sent was actually accepted.
You can query the status of 0-RTT using the `lws_tls_0rtt_status(wsi)` API:

```c
enum lws_0rtt_status status = lws_tls_0rtt_status(wsi);

if (status == LWS_0RTT_STATUS_REJECTED) {
    /* 0-RTT was rejected by the server. Any early data sent must be re-sent. */
}
```

### Server-side Idempotency

Because 0-RTT data can be intercepted and replayed by attackers, servers MUST ensure that any actions taken based on 0-RTT data are strictly idempotent (e.g., HTTP GET requests without side effects).

Servers can check if incoming data was received during the 0-RTT phase by calling `lws_rx_is_early_data(wsi)`:

```c
if (lws_rx_is_early_data(wsi)) {
    /* Data was received via 0-RTT. Enforce idempotency!
     * Do not process state-changing requests like POST or DELETE here.
     */
}
```
