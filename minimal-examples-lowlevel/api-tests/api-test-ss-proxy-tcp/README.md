# lws-api-test-ss-proxy-tcp

Checks where an SS proxy listening on tcp (`lws_ss_proxy_create()` with a
port) listens.  The tcp link has no client authentication, anybody who can
connect to it can use the proxy's policy and the credentials it holds, so lws
listens on loopback unless told otherwise, and refuses a bind address that is
not loopback unless the context creation info sets
`.ss_proxy_tcp_allow_remote`.

Each case runs in a context of its own, on the same port:

|case|proxy created with|what must happen|
|---|---|---|
|default|the port, no bind|it listens on a loopback address (127.0.0.1, or ::1 without IPv4), and a client can connect to it there|
|refused|the port, the wildcard address (0.0.0.0, or :: without IPv4)|creating the proxy fails|
|allowed|as refused, with `.ss_proxy_tcp_allow_remote = 1`|it listens on the wildcard address|

The policy is built into the test.

## Switches

|switch|meaning|
|---|---|
|--port <port>|tcp port for the proxy to listen on (required)|
|--help|Show the switches|

## Build

Needs `LWS_WITH_SECURE_STREAMS_PROXY_API`, `LWS_WITH_CLIENT` and
`LWS_WITH_SERVER`, and a JSON policy build (not
`LWS_WITH_SECURE_STREAMS_STATIC_POLICY_ONLY`).  It is registered with ctest
as `api-test-ss-proxy-tcp`, with a free port from the ctest port allocator.

## Run

```
$ ctest -R api-test-ss-proxy-tcp
```

or run `lws-api-test-ss-proxy-tcp --port 7681` directly; it takes the usual
builtin switches, eg `-d1151` for more logging.
