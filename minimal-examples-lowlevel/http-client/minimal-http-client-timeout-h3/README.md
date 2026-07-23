# lws-minimal-http-client-timeout-h3

This tests the HTTP/3 client reply timeout.

It runs as a single binary in two modes:

 - by default, as a client that issues a single `GET` over HTTP/3 against the
   blackhole server described below, and
 - with `-s`, as a "blackhole" QUIC/H3 server that completes the QUIC + TLS
   handshake but then deliberately never sends any H3 response.

The intended outcome is that the **client times out** waiting for the server's
reply and receives `LWS_CALLBACK_CLIENT_CONNECTION_ERROR` ("Timed out waiting
server reply") within the context timeout — rather than hanging on the live
QUIC connection indefinitely, which was the historical gap this example pins
down.

When run under ctest, the blackhole server is started with `-s` on a free port
as a background fixture, and the client is then run against it.  The client
returns `0` if it timed out as expected, and non-zero otherwise.

## Build

```bash
 $ cmake . && make
```

## Usage (manual)

In one terminal, start the blackhole server:

```bash
 $ ./lws-minimal-http-client-timeout-h3 -s -p 7681 -d 1039
```

In another, run the client against it:

```bash
 $ ./lws-minimal-http-client-timeout-h3 -p 7681 -d 1039
```

The client should report `Completed: OK (timed out as expected)` after the
short reply timeout configured via `info.timeout_secs`.
