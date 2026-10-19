# lws-api-test-client-final-callback

Confirms every client connection gets one last callback on its own protocol,
and only one, when the context is destroyed under it:
`LWS_CALLBACK_CLIENT_CONNECTION_ERROR` if it never connected, else its CLOSED
(`LWS_CALLBACK_CLIENT_CLOSED` for ws, `LWS_CALLBACK_CLOSED_CLIENT_HTTP` for
http).  A protocol keeping a client's wsi pointer, eg, through `i.pwsi`,
learns from it that the wsi is gone, so it cannot touch the freed wsi later,
in its `LWS_CALLBACK_PROTOCOL_DESTROY` say.

In one context, a "silent" raw server takes connections and never answers,
and a ws server accepts ws connections.  The client protocol, which is not
its vhost's `protocols[0]`, starts these clients, and once they are all in
these states, the context is destroyed:

|client|state at the destroy|final callback|
|---|---|---|
|ws-unanswered|its ws upgrade sent to the silent server, waiting for the answer|CLIENT_CONNECTION_ERROR|
|http-unanswered|its GET sent to the silent server, waiting for the response|CLOSED_CLIENT_HTTP|
|tls-handshake|in its tls handshake with the silent server|CLIENT_CONNECTION_ERROR|
|ws-established|established with the ws server|CLIENT_CLOSED|
|unroutable|connecting to 192.0.2.1 (TEST-NET-1), or already refused where that has no route|CLIENT_CONNECTION_ERROR|

None of the clients may still be held by the client protocol at its
`LWS_CALLBACK_PROTOCOL_DESTROY`.  The first final callback during the destroy
also tries to connect again, as a naive retry would: lws must refuse it, since
a connection made there could keep the destroy's close loop going forever.

ctest runs it on the default event loop and again on libuv
(`api-test-client-final-callback-libuv`), which finishes the closes later,
from its own close callbacks.

## Switches

|Option|Meaning|
|---|---|
|--port-silent <port>|Port of the silent server (default 7681)|
|--port-ws <port>|Port of the ws server (default 7682)|
|--server <address>|Address the clients connect to (default localhost)|
|--uv|Run on a libuv event loop (an lws built-in option)|
|--help|Show the options|

## Run

```
$ ctest -R api-test-client-final-callback
```
