# lws api test http pss lifecycle

Checks that `LWS_CALLBACK_HTTP_BIND_PROTOCOL` and
`LWS_CALLBACK_HTTP_DROP_PROTOCOL` bracket every per-transaction allocation
(pss) an http server protocol is given, over several transactions riding one
connection (G-556).

The server protocols allocate a resource in the pss at `LWS_CALLBACK_HTTP`
and free it at `LWS_CALLBACK_HTTP_DROP_PROTOCOL`, the way an app keeps an
`lws_spa`, an fd or an lwsac for the transaction.  That is only safe if BIND
reaches the protocol before any other callback carrying the pss, and DROP
follows every BIND exactly once before the pss is freed: at the end of a
keep-alive transaction, when another protocol is bound, or when the
connection closes.

Requests answered by the vhost's protocols[0] itself, eg a path in a file
mount with no such file, which falls through to protocols[0]'s
`LWS_CALLBACK_HTTP` as the form examples' `/form1` does, used to miss out on
the first transaction of an h1 connection and on every h2 stream: the pss
was never bound, so no DROP came for it and the resource leaked.  A protocol
bound by a callback mount always had its BIND / DROP pair, and still does.

Legs, each a series of alternating GET and POST requests from an lws client
in the same process, all riding one kept-warm connection:

 - h1 to a path in the file mount answered by protocols[0] (4 requests)
 - h1 to a callback mount bound to its own protocol (3 requests)
 - the same two over h2 (cleartext, prior knowledge), each request a stream

After the leg's connection has closed, the protocol under test must have seen
`LWS_CALLBACK_HTTP` for every request, each on a pss that had been bound and
was then dropped exactly once, with every resource freed, binds and drops
equal, and no callback on a pss that had not been bound.  Every request must
have ridden the same server connection.

The file mount serves the test's own directory, so ctest runs it from there.

```
$ ./lws-api-test-http-pss-lifecycle -p 7681 --h2-port 7682
```

Option|Meaning
---|---
-d <loglevel>|Debug verbosity in decimal, eg, -d1151
-p <port>|Port for the h1 server vhost (default 7681)
--h2-port <port>|Port for the h2 prior-knowledge server vhost (default 7682)
--server <addr>|Server address to connect to (default 127.0.0.1)
