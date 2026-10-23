# lws api test h3 stream reset

"Rapid reset" (CVE-2023-44487 class) on h3.  QUIC gives a peer more streams
only with a MAX_STREAMS (RFC 9000 4.6), but the server used to raise its limit
the moment a peer stream ended and hold the peer to that, not to what it had
advertised, so a peer resetting each request once it had been dispatched had
new ones dispatched for as long as it liked.

An h3 server and its clients run in this process.  The server's vhost allows 20
streams ended before they were answered per connection per 10s
(`mux_reset_limit`).

 - Client A sends 64 GETs, 8 at a time, on one connection.  The server starts
   each answer and never finishes it; A gives up on each stream as soon as the
   answer's headers arrive, which sends the server STOP_SENDING, and sends the
   next batch once the whole batch went.  The server must close each
   connection A uses with `H3_EXCESSIVE_LOAD`, after dispatching no more than
   36 requests on it.

 - Client B, which gives up on nothing, has 448 GETs answered, 8 at a time, on
   one connection: more streams than the server's initial limit of 400, so B
   must be given more by MAX_STREAMS, which the server now sends in batches as
   streams complete.

```
$ ./lws-api-test-h3-stream-reset -p 7681 --cert ../api-test-ws-close/localhost-100y.cert \
	--key ../api-test-ws-close/localhost-100y.key
```
