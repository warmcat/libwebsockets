# lws-api-test-client-early-fail

A client connection that fails before its socket was ever in the fds table is
freed by the connect code itself rather than by the usual close.  The free
still resets the wsi, giving back its ah and taking it off the pt's timer
lists, so it must hold the context lock and then the pt lock, as the close
does (G-701).  Debug builds with `LWS_MAX_SMP` > 1 assert that, so before the
fix this test aborted there.

A fake nameserver on loopback, adopted into the event loop, answers every
question with NXDOMAIN.

|client|fails|expected|
|---|---|---|
|http GET to `no-such-host.invalid`|later, from the resolver's callback|`LWS_CALLBACK_CLIENT_CONNECTION_ERROR` mentioning NXDOMAIN|
|http GET to a unix socket path longer than `sun_path` (builds with unix sockets)|at once, inside `lws_client_connect_via_info()`|`lws_client_connect_via_info()` returns NULL, and no `LWS_CALLBACK_CLIENT_CONNECTION_ERROR`|

It also passes in builds without SMP, where it checks the clients fail
cleanly; run it under ASan to see nothing leaks or is used after free.

## Run

ctest gives the fake nameserver a free udp port in `LWS_ASYNCDNS_PORT`, the
port the resolver asks its nameservers on.

```
$ ctest -R api-test-client-early-fail
```

By hand, set `LWS_ASYNCDNS_PORT` to any free udp port:

```
$ LWS_ASYNCDNS_PORT=5353 ./bin/lws-api-test-client-early-fail
```
