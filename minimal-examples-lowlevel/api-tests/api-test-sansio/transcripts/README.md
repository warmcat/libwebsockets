# lws sansIO transcripts

Each file here is one connection's life as data: the times, the bytes its
peer sent, the bytes lws wrote, what lws gave the application, and its
close.  `api-test-sansio` produces them by driving lws' protocol half with
no socket and no clock of its own (READMEs/README.sans-io-split.md, "Time"),
and checks, in every build that runs it, that what lws does now is still
what is recorded here.  They are also the specification a port of the
sansIO half is checked against: fed the same bytes at the same times, with
the same application, it must write the same bytes and deliver the same
payloads.

## Format

```
{
 "format": "lws-transcript/1",
 "case": "h1-ws-server",
 "side": "server",
 "t0_us": 1000000000,
 "t0_wall": 1767225600,
 "seed": 0,
 "steps": [
  {"t": 1000, "rx": "474554..."},
  {"t": 1000, "tx": "485454..."},
  ...
 ]
}
```

|member|meaning|
|---|---|
|`format`|`lws-transcript/1`.  A change to what follows is a new version|
|`case`|the connection's name, and the file's|
|`side`|`server`: the peer connected to lws.  `client`: lws connected to the peer|
|`t0_us`|the monotonic time, in microseconds, when the run starts: every step's `t` is after it|
|`t0_wall`|the wall time, seconds since 1970, at `t0_us`.  The wall time moves with the monotonic time|
|`seed`|0: nothing in the connection's bytes depends on lws' random.  Otherwise lws' random is the xoshiro256** stream seeded with it (`lws_fi_random_seed()`), see "Random" below|
|`steps`|what happened, in order|

Each step has `t`, microseconds since `t0_us`, and one of:

|kind|meaning|
|---|---|
|`rx`|the peer sent these bytes, and they are handed to lws at `t`|
|`tx`|lws wrote these bytes to the peer at `t`.  Bytes written in several writes at the same time are one step: how many writes it took is not part of the behaviour|
|`app_rx`|lws delivered this payload to the application: a response body, or a ws message's payload|
|`close`|lws released the connection's transport.  The value is empty|

Bytes are lowercase hex.  A replay hands lws each `rx` at its `t`, telling
it the time first, and runs anything that falls due at a `t` before what
happens then.  The `tx`, `app_rx` and `close` steps are what it must see,
in order, at their times.

## Random

A connection whose bytes depend on lws' random (a ws client's
`Sec-WebSocket-Key` and its frame masks) has a nonzero `seed`, and the
peer's side of it depends on those bytes too: the 101 response carries the
accept value of the key the client chose.  Such a transcript reproduces only
when the random is the seeded stream drawn in the same order, so:

 - `api-test-sansio` records and checks it only in a build with fault
   injection (`LWS_WITH_SYS_FAULT_INJECTION`), which can seed lws' random,
   and says so in other builds;
 - a port either draws the same bytes from the same stream in the same order
   (xoshiro256** seeded by splitmix64, each 64-bit result little-endian,
   the vector in `api-test-random-prng`), or its replay treats the drawn
   values as free, taking them from its own `tx` and checking what follows
   from them (the accept value, the masking) instead of the bytes.

The tls library's own random, inside its handshakes, is not lws' and is not
covered: no transcript here is under tls yet.

## The connections and their applications

A replay needs the same application on lws' side.  In each connection it
does only this:

|case|side|the application|
|---|---|---|
|`h1-ws-server`|server|one vhost with protocols `http` and `echo`.  `http`: answers any request 200, `text/plain`, content length 10, body `sansio ok\n`, then completes the transaction (the connection is kept).  `echo`: sends each ws message that came in one frame back, as text; it sends nothing for a fragmented one.  The peer does an h1 GET, then a ws upgrade to `echo` on the same connection, then sends the masked text frame `Hello` of RFC 6455 5.7|
|`h1-client-get`|client|connects to `sansio`, port 80, h1, `GET /x`, and pulls the response body as it comes|
|`ws-client`|client|connects to `sansio`, port 80, `GET /echo`, ws subprotocol `echo`; once established, sends one text message `Hello`, and takes the messages it receives|
|`ws-server-version-8`, `ws-server-no-version`, `ws-server-conn-no-upgrade`, `ws-server-no-subprotocol`|server|as `h1-ws-server`.  The peer asks for a ws upgrade saying `Sec-WebSocket-Version: 8`; or no version at all; or `Connection: up`, which is not the `upgrade` token; or only the subprotocol `chat`, which the vhost does not have.  lws answers the first with 426 and `sec-websocket-version: 13`, the others with 400, each with the usual status page, then shuts the connection down (a half-close, waiting for the peer's; no `close` step follows)|
|`ws-client-rsv1-no-ext`, `ws-client-rsv2`, `ws-client-huge-frame`|client|as `ws-client`, no extension offered.  After the 101, the peer sends a frame with RSV1, with RSV2, or whose length is 256MiB + 1: lws gives the app nothing of it and sends a close, status 1002 `rsv bits` for the RSV ones and 1009 `huge frame` for the length; the peer answers the close and lws releases the connection|
|`ws-client-pmd-rsv2`, `ws-client-pmd-rsv1-continuation`, `ws-client-pmd-rsv1-ping`|client|as `ws-client`, on a vhost offering `permessage-deflate` (no parameters), sending nothing once established, and the peer's 101 accepts `permessage-deflate`.  The peer then sends a frame with RSV2; or an uncompressed, unfinished text frame `He` (given to the app) and then a continuation with RSV1; or a ping with RSV1.  As above, lws fails the connection, with 1002 `rsv bits`|
|`h1-uri-dotdot-args`, `h1-uri-dot-args`, `h1-uri-plus`, `h1-uri-at-limit`|server|a third vhost, `sansio-uri`, whose only protocol, `http`, answers any request 200, `text/plain`, with the path lws decoded, a newline, then the args, and completes the transaction.  The context limits the request URI to 33 bytes and `User-Agent` to 16 (`token_limits`).  The peer asks for `/x/..?a=b` (path `/`, args `a=b`), `/x/.?a=b` (path `/x/`), `/a+b?c+d=e+f` (path `/a+b`, args `c d=e f`: `+` is only a space in the args) and a 33-byte path, which is served whole|
|`h1-uri-past-limit`, `h1-header-past-limit`|server|as above.  The peer asks for a 34-byte path, or sends a 17-byte `User-Agent`: rather than serving the request with the value cut short, lws answers 414, or 431, with the usual status page saying `Oversized request URI` or `Oversized headers`, and shuts the connection down|
|`h2-oversized-headers`|server|a fourth vhost, `sansio-h2`, taking h2 with prior knowledge, whose only protocol is the `http` of `sansio-uri`.  The peer sends the preface, an empty SETTINGS and the ack of the server's, then three GET / requests.  sid 1: `:authority` entered in the dynamic table, then a 3000 byte user-agent and a 2000 byte referer, not indexed, that the 4096 byte ah cannot hold, then `accept: x` entered in the dynamic table after it filled: answered 431 `Oversized headers`, the connection kept.  sid 3: `:authority` and `accept` from the dynamic table: `accept` could not be kept, so it is answered 431 too, rather than served as if the peer had not sent it.  sid 5: only `:authority` from the dynamic table, which was kept: served|
|`ws-server-huge-frame`|server|as `h1-ws-server`: after the upgrade, the peer sends a masked frame whose length is 256MiB + 1.  lws closes with status 1009, `huge frame`|
|`ws-server-pmd-rsv1-continuation`|server|as `h1-ws-server`, on a second vhost, `sansio-pmd`, with `permessage-deflate` (no parameters).  The peer asks for a ws upgrade to it offering `permessage-deflate`, which is accepted, then sends an unfinished text frame `He` and a continuation with RSV1: lws closes with status 1002, `rsv bits`, and once the peer answers the close, shuts the connection down|

## Recording

```
 $ ./bin/lws-api-test-sansio --record ../minimal-examples-lowlevel/api-tests/api-test-sansio/transcripts
```

from a build with fault injection, so the seeded connections are recorded
too.  ctest runs `lws-api-test-sansio --transcripts transcripts` in this
directory's parent, which fails if what lws does differs from what is here,
and says at which line.

A transcript is behaviour: a change to one is a change to what lws puts on
the wire, and the commit making it says why.  A new case adds a file here,
its row above, and its connection's application to the test.
