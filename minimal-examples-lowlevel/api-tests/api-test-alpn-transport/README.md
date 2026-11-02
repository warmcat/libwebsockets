# lws api test alpn transport

h3 is only ever carried by quic, and h2 and http/1.1 only by tcp.  A connection
that negotiated an alpn on the transport that can't carry it would bind a role
that can never make progress there, so

 - an lws client leaves out of what it offers on tcp anything only quic can
   carry, and fails the connection if that leaves nothing

 - an lws server never selects on tcp anything only quic can carry, nor on
   quic anything only tcp can, whatever its vhost's alpn list and whatever the
   client offers

 - a tls connection that negotiated an alpn its transport can't carry anyway,
   eg, with a peer that is not lws, fails rather than becoming a role that can
   never make progress there

 - a client request whose alpn only quic can carry, eg, "h3" alone, is made on
   quic, also when it is redirected

One process runs four server vhosts, each on its own port with the alpn list
"h3,h2,http/1.1", so each listens on tcp and quic and advertises its quic, and
a client.  The servers answer each GET with the protocol it was served over.
Each step goes to a server the client has learned nothing about yet, so that
what it learned about another doesn't decide the transport.

|Step|Client alpn|Served over|
|---|---|---|
|h3 alone|`h3`|h3: made on quic, with no h3 known there|
|h3 alone, redirected to another server|`h3`|h3: the redirect was followed on quic|
|tcp, h3 offered|`h3,h2,http/1.1`|h2: on tcp, the client left h3 out|
|tcp, h3 offered anyway (fault `tls_alpn_unfiltered`)|`h3,http/1.1`|h1: the server did not select h3 on tcp|

The second step needs `LWS_WITH_SYS_FAULT_INJECTION`, and is left out without it.

## build

Needs `LWS_ROLE_H3`, `LWS_ROLE_H2`, client and server support.

## usage

|Option|Meaning|
|---|---|
|`--port0` .. `--port3 <port>`|The four servers' ports|
|`--cert <file>`|Server certificate|
|`--key <file>`|Server key|

ctest runs it with free ports and the api-test-ws-close localhost certificate.

```
$ ./bin/lws-api-test-alpn-transport --cert localhost-100y.cert --key localhost-100y.key
[2026/11/02 10:00:00:0000] U: LWS API selftest: alpn and the transport carrying it
[2026/11/02 10:00:00:0100] U: PASS: step 0: h3 alone: made on quic
[2026/11/02 10:00:00:0200] U: PASS: step 1: h3 alone, redirected: the redirect is followed on quic
[2026/11/02 10:00:00:0300] U: PASS: step 2: tcp, h3 offered: h3 left out on tcp
[2026/11/02 10:00:00:0400] U: PASS: step 3: tcp, h3 offered anyway: the server doesn't select it on tcp
[2026/11/02 10:00:00:0500] U: Completed: PASS (0 of 4 steps failed)
```
