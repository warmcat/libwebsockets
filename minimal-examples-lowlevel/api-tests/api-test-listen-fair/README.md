# lws-api-test-listen-fair

Checks that a listen socket with a backlog doesn't keep the event loop to
itself while it adopts the connections in it, when adopting each one is
costly: the connections already adopted must be served meanwhile.

On a slow cpu, adopting a tls connection is costly, since the server makes
the first step of its handshake as it adopts it.  On a riscv64 board with
mbedtls 2.28 that step took ~1.5s, so eight connections arriving together
held the loop for 12s while the first one's next handshake message waited
unread, until its deadline for the request (the vhost's
`timeout_secs_ah_idle`) ran out.

Here no tls is needed: the server's `LWS_CALLBACK_FILTER_NETWORK_CONNECTION`,
which lws calls for each connection it accepts, keeps the cpu busy for
250ms.  A raw client in the same process opens 12 connections at once and
sends a GET on each, to a vhost allowing 1s for each request, against 3s to
adopt them all.  Every GET must be answered.

```
$ ./lws-api-test-listen-fair --server localhost
```

Option|Meaning
---|---
`--server <host>`|Where the client connects to reach the server, default `localhost`
