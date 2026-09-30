# lws minimal webtransport client

Opens a WebTransport session over h3 to `localhost:7681`, opens a bidi stream
on it and sends one message, finishing the stream with it.  It then ends the
session by closing the session wsi, and exits when the session's
`LWS_CALLBACK_CLOSED` arrives.

It shows:

 - the session being announced with `LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP`,
   the h3 response to the extended `CONNECT`, not the ws
   `LWS_CALLBACK_CLIENT_ESTABLISHED`
 - a stream created with `lws_wt_create_stream()` and written from its
   `LWS_CALLBACK_CLIENT_WRITEABLE`, tolerating WRITEABLE coming again
 - ending the session from the client, which the server sees as its session
   and streams closing

See [README.webtransport.md](../../../READMEs/README.webtransport.md).

## build

```
 $ cmake . && make
```

## usage

Run it against `lws-minimal-webtransport-server`, started first in the
directory holding its `localhost-100y.cert` and `.key`.

Commandline option|Meaning
---|---
-d <loglevel>|Debug verbosity in decimal, eg, -d15

```
 $ ./lws-minimal-webtransport-client
[2026/09/30 12:38:06:7705] U: LWS minimal WebTransport client
[2026/09/30 12:38:06:8123] U: WebTransport session established
[2026/09/30 12:38:06:8124] U: Sent message on stream, ending the session
[2026/09/30 12:38:06:8124] U: WebTransport session closed
[2026/09/30 12:38:06:8166] U: Completed: OK
```

It exits with 1 if the connection failed or it was interrupted, otherwise 0.
