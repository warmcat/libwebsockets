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
|`app_rx`|lws delivered this payload to the application: a response body, or a ws message's payload.  How a message or a body was split into deliveries follows how much lws was handed at a time, and is not behaviour: what a replay must match is the concatenation of the `app_rx` steps of each ws message, and of each response body, and where each of those ends relative to the other steps|
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
when the random is the seeded stream drawn in the same order.  The stream
starts afresh from `seed` when the connection does, so what it draws does not
depend on the connections before it, or on which of them a build has.  So:

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
|`h1-client-cl-junk`, `h1-client-cl-twice`, `h1-client-te-list`|client|as `h1-client-get`.  The peer answers 200 with `Content-Length: 10abc`; with `Content-Length: 10` and a second `Content-Length: 5`; or with `Transfer-Encoding: chunked` and a second `Transfer-Encoding: gzip`, which makes the codings a list.  lws cannot know where such a body ends: it gives the app none of it, fails the connection and releases it|
|`h1-client-head-chunked`, `h1-client-head-cl`, `h1-client-304-cl`|client|as `h1-client-get`, asking with `HEAD` for the first two.  The peer answers 200 with `Transfer-Encoding: chunked`; 200 with `Content-Length: 10`; or, to the `GET`, 304 with `Content-Length: 10`.  None of these has a body (RFC 9112 6.3): lws completes the transaction at the end of the headers and gives the app nothing|
|`ws-client`|client|connects to `sansio`, port 80, `GET /echo`, ws subprotocol `echo`; once established, sends one text message `Hello`, and takes the messages it receives|
|`ws-server-version-8`, `ws-server-no-version`, `ws-server-conn-no-upgrade`, `ws-server-no-subprotocol`, `ws-server-not-get`|server|as `h1-ws-server`.  The peer asks for a ws upgrade saying `Sec-WebSocket-Version: 8`; or no version at all; or `Connection: up`, which is not the `upgrade` token; or only the subprotocol `chat`, which the vhost does not have; or, otherwise acceptably, with a POST, where an h1 upgrade must be a GET (RFC 6455 4.1).  lws answers the first with 426 and `sec-websocket-version: 13`, the others with 400, each with the usual status page, then shuts the connection down (a half-close, waiting for the peer's; no `close` step follows)|
|`ws-client-rsv1-no-ext`, `ws-client-rsv2`, `ws-client-huge-frame`|client|as `ws-client`, no extension offered.  After the 101, the peer sends a frame with RSV1, with RSV2, or whose length is 256MiB + 1: lws gives the app nothing of it and sends a close, status 1002 `rsv bits` for the RSV ones and 1009 `huge frame` for the length; the peer answers the close and lws releases the connection|
|`ws-client-ping-close`|client|as `ws-client`, sending nothing once established.  The peer sends a ping `p` and then a close with status 1000 in one read: lws sends the masked pong, then the masked answer to the close with the peer's 1000, and releases the connection|
|`ws-client-interim`|client|as `ws-client`.  The peer answers the upgrade with an interim `100 Continue`, then in the same read the 101: lws skips the interim response, goes on waiting, and is established by the 101|
|`ws-client-pmd-rsv2`, `ws-client-pmd-rsv1-continuation`, `ws-client-pmd-rsv1-ping`|client|as `ws-client`, on a vhost offering `permessage-deflate` (no parameters), sending nothing once established, and the peer's 101 accepts `permessage-deflate`.  The peer then sends a frame with RSV2; or an uncompressed, unfinished text frame `He` (given to the app) and then a continuation with RSV1; or a ping with RSV1.  As above, lws fails the connection, with 1002 `rsv bits`|
|`h1-uri-dotdot-args`, `h1-uri-dot-args`, `h1-uri-plus`, `h1-uri-at-limit`|server|a third vhost, `sansio-uri`, whose only protocol, `http`, answers any request 200, `text/plain`, with the path lws decoded, a newline, then the args, and completes the transaction.  The context limits the request URI to 33 bytes and `User-Agent` to 16 (`token_limits`).  The peer asks for `/x/..?a=b` (path `/`, args `a=b`), `/x/.?a=b` (path `/x/`), `/a+b?c+d=e+f` (path `/a+b`, args `c d=e f`: `+` is only a space in the args) and a 33-byte path, which is served whole|
|`h1-uri-past-limit`, `h1-header-past-limit`|server|as above.  The peer asks for a 34-byte path, or sends a 17-byte `User-Agent`: rather than serving the request with the value cut short, lws answers 414, or 431, with the usual status page saying `Oversized request URI` or `Oversized headers`, and shuts the connection down|
|`h1-reqline-http09`, `h1-reqline-no-method`, `h1-reqline-version-2`, `h1-reqline-version-junk`, `h1-reqline-version-long`|server|as above.  The peer sends a request line with no version, `GET /x` (HTTP/0.9); a head with no request line, only `Host: sansio-uri`; or asks for `/x` as `HTTP/2.0`, `HTTP/1.x` or `HTTP/1.10`.  A request line is method, target and `HTTP/` digit `.` digit: lws answers 400 with the usual status page, except 505 for the major version it does not speak, and shuts the connection down|
|`h1-reqline-unknown-method`, `h1-reqline-unknown-header-first`|server|as above.  The peer asks for `/x` with the method `FOO`, which lws does not implement: 501 (RFC 9110 9.1); or starts its head with `X-Foo: bar`, a header lws does not know, rather than a request line: 400.  Either way with the usual status page, and the connection is shut down|
|`h1-reqline-leading-empty`, `h1-reqline-leading-empty-many`|server|as above.  The peer sends two empty lines, then its request for `/x`: they are ignored (RFC 9112 2.2) and it is served; or nine: past eight, no request is coming, and lws answers 400 and shuts the connection down|
|`h1-reqline-version-1-2`|server|as above.  The peer asks for `/x` as `HTTP/1.2`: a later minor version is served as the highest lws speaks, and the response says `HTTP/1.1`|
|`h2-oversized-headers`|server|a fourth vhost, `sansio-h2`, taking h2 with prior knowledge, whose only protocol is the `http` of `sansio-uri`.  The peer sends the preface, an empty SETTINGS and the ack of the server's, then three GET / requests.  sid 1: `:authority` entered in the dynamic table, then a 3000 byte user-agent and a 2000 byte referer, not indexed, that the 4096 byte ah cannot hold, then `accept: x` entered in the dynamic table after it filled: answered 431 `Oversized headers`, the connection kept.  sid 3: `:authority` and `accept` from the dynamic table: `accept` could not be kept, so it is answered 431 too, rather than served as if the peer had not sent it.  sid 5: only `:authority` from the dynamic table, which was kept: served|
|`h1-404-keepalive`|server|a fifth vhost, `sansio-404`, whose 404 document is `/404.html`.  `/cb` is mounted on its only protocol, `http`; everything else is a file mount on a directory that does not exist, falling back to `http` for what it cannot open.  `http` answers whatever reaches it with `lws_return_http_status()` 404, then completes the transaction.  On one kept-alive connection the peer asks for `/x`: lws redirects it to the 404 document with a 302; then for `/404.html`, which is not there either: the 404 status page; then for `/cb/y`: redirected with a 302 again, as `/x` was|
|`ws-server-ping-close`, `ws-server-close-partial`|server|as `h1-ws-server`: after the upgrade, the peer sends, masked, in one read, a ping `p` and then a close with status 1000; or a text frame `Hello` and then the close, while the connection takes at most 4 bytes a write.  lws answers the ping with its pong before it answers the close, with the peer's own 1000; the echo of `Hello`, left partly unwritten, goes out whole before the answer to the close, rather than the connection being dropped.  After its answer lws reads nothing more, and shuts the connection down|
|`ws-server-huge-frame`|server|as `h1-ws-server`: after the upgrade, the peer sends a masked frame whose length is 256MiB + 1.  lws closes with status 1009, `huge frame`|
|`ws-server-pmd-rsv1-continuation`|server|as `h1-ws-server`, on a second vhost, `sansio-pmd`, with `permessage-deflate` (no parameters).  The peer asks for a ws upgrade to it offering `permessage-deflate`, which is accepted, then sends an unfinished text frame `He` and a continuation with RSV1: lws closes with status 1002, `rsv bits`, and once the peer answers the close, shuts the connection down|
|`h2-ws-peer-close`|server|a sixth vhost, `sansio-h2ws`, taking h2 with prior knowledge, with the ws protocols of `sansio`.  The peer sends the preface and SETTINGS, then an extended CONNECT (RFC 8441) for a ws stream on sid 1 speaking `echo`, which is accepted with 200; then one DATA frame holding, masked, a close with status 1000 and after it a ping `p`.  lws answers the close with the peer's own 1000 and END_STREAM, reads nothing after it, so the ping gets no pong, and resets the stream with NO_ERROR, since the peer has not ended its side: not REFUSED_STREAM, which is only for a refused upgrade|
|`h2-ws-close-crossed`|server|as `h2-ws-peer-close`, whose `echo` starts the close itself, going away (1001 `bye`), when it is sent the text `Close`.  The peer sends `Close` in one DATA frame, while lws' writes take nothing, so its close is still waiting to go when the peer's own close, status 1000, arrives in the next DATA frame, with END_STREAM: the connection goes on reading for its streams.  The closes have crossed: once writes go again, lws sends only the answer to the peer's, with the peer's own 1000 and END_STREAM, not its own close.  The peer has ended the stream, so it is not reset|
|`h1-post-no-length`|server|as `h1-uri-*`, on `sansio-uri`.  The peer sends, in one read, `POST /x?a=1` with neither `Content-Length` nor `Transfer-Encoding`, and behind its head `GET /y?b=2`.  The POST has no body (RFC 9112 6.3): lws answers it (path `/x`, args `a=1`), then serves the GET as the next request on the kept-alive connection, rather than taking it as the POST's body and reading until the close|
|`h1-connect-rejected-ua`|server|as `h1-reqline-*`, on `sansio-uri`, in a context that turns away a user agent containing `badbot` with `403 Go away`.  The peer sends a CONNECT for `example.com:443` saying it is `badbot/1`: it is refused like any other request of its, 403 with the status page, and the connection shut down, rather than handed to the fallback role first|
|`h1-post-zero-answered`|server|as `h1-404-keepalive`, on `sansio-404`, while the connection takes at most 4 bytes a write.  The peer sends `POST /cb/y` saying `Content-Length: 0`: `http` answers it from its headers, redirected to the 404 document with a 302, and completes the transaction, the answer still going.  The empty body's completion is not given to `http`, which answers from it, as no body's is once the transaction is complete: there is the one answer.  Then `GET /cb/y` on the kept-alive connection, redirected the same|
|`h1-body-done`|server|as `h1-uri-*`, on `sansio-uri`, whose app answers `/body-done` from the request body's first piece, 200 `text/plain` with content length 3 and the body `ok\n`, and completes the transaction then.  The peer sends `POST /body-done` with `Content-Length: 5`, then the body `abcde` in one piece: the answer goes, the body's completion is not given to the app after it completed, and `GET /x` on the kept-alive connection is answered as usual|
|`h1-answer-before-body`|server|as `h1-uri-*`, on `sansio-uri`, while the connection takes only 65 bytes of what is written.  The peer sends `POST /x` with `Content-Length: 5`, and no body yet.  The app's answer to it, path `/x`, goes as it does for a GET: its headers from the request, its body `/x\n` from the writeable, which comes before the request body has, and it completes the transaction.  Only the headers and the body's first byte go; the request body `abcde` arriving meanwhile is not read.  Once writes go again, the rest of the answer goes and the request body is read and discarded, and `GET /y` on the kept-alive connection is answered as usual|
|`h2c-upgrade`|server|as `h1-uri-*`, on `sansio-uri`, which takes h2 only by upgrade.  The peer sends `GET /x` asking to upgrade to `h2c`, with `HTTP2-Settings` saying `MAX_CONCURRENT_STREAMS` 100: lws answers 101.  Then the peer's preface and SETTINGS, and the ack of the server's: the server's SETTINGS is its first h2 frame, and the GET, which is stream 1, is answered on it through the app, path `/x`, ending the stream|
|`h2c-upgrade-with-body`|server|as `h2c-upgrade`, but a `POST /x` with `Content-Length: 3` and its body: a request with a body of its own is not upgraded, what follows its head would be read as h2.  lws answers 400 with the usual status page|
|`h1-connect-raw`|server|a vhost `sansio-raw` whose fallback (`listen_accept_role` `raw-skt`, `listen_accept_protocol` `raw-echo`) is a raw protocol, `raw-echo`, which answers a CONNECT's head as a tunnel would, `200 Connection established`, and echoes anything else.  The peer sends `CONNECT sansio-raw:443` with `Host: sansio-raw`: the connection becomes raw and `raw-echo` is given the head, its first rx, and answers it; then the peer sends `hello` through it, which comes back|
|`h1-client-digest-retry`|client|as `h1-client-get`, with the credentials `user` / `pass`.  The peer answers `401 Unauthorized` with a digest challenge (RFC 7616, realm `sansio`, qop `auth`), keeping the connection and with `Content-Length: 0`: the client asks for `/x` again on the same connection, with its `Authorization: Digest` response, and takes the answer to that, 200 with the body `ok`.  The response's cnonce is lws' random|
|`ws-client-digest-retry`|client|as `ws-client`, sending nothing once established, with the credentials `user` / `pass`: the peer answers the upgrade with the same `401` as `h1-client-digest-retry`, the client asks again on the same connection with its digest response, and the 101 to that establishes it|
|`h1-short-answer`|server|as `h1-uri-*`, on `sansio-uri`, whose app answers `/short` with a head giving `content-length: 10`, sends `abc` (nothing to a HEAD) and completes the transaction.  The peer sends `HEAD /short`: the answer is whole without a body, and the connection is kept alive.  Then `GET /short`: the answer is 7 bytes short of its length, and kept alive, the peer would read the next answer as the rest of it, so the connection is shut down|

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
