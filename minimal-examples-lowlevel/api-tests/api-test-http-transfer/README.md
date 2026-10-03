# lws api test http transfer

Exercises the http body transfer framings lws is expected to handle, in both
directions, with an lws server and an lws client in one process.

Request bodies (client to server) on h1: Content-Length in one write and in
many; Transfer-Encoding: chunked with chunks of assorted sizes, in one write, in
many, and with the framing split across writes; chunked with chunk extensions
and trailer fields; chunked on a GET followed by a pipelined request on the same
connection; a Content-Length POST with a GET pipelined behind it in the same
write, answered some time after its body completed, where the body must complete
exactly once and the GET wait parked for the answer, without keeping the event
loop busy, before it is served (direct and through the http proxy mount), and
the same with two GETs to a callback mount that names its protocol as its
origin, where the second must then be dispatched as itself, once, and to a
mount with a body limit, where the first, which has no body, must not take the
second as one; a GET whose one-shot answer is larger than the socket buffers,
from a raw client that does not read it for a while, with its next GET sent in
its own write meanwhile, where the server must not spin on its readable socket
while the answer waits to drain, and must answer the GET once it has; and the
refusals (an unsupported
Transfer-Encoding gets 501, Transfer-Encoding with Content-Length gets 400, a
chunked body over the mount limit drops the connection, a Content-Length over it
gets 413); and `Expect: 100-continue` on Content-Length and chunked bodies, with
an over-limit body refused instead of continued and an unknown expectation
answered 417.

Request bodies on h2 (cleartext, prior knowledge): Content-Length, no
Content-Length (END_STREAM delimited), and no body.

Response bodies (server to client): Content-Length, hand-framed chunked with
extensions and trailers, and unknown length (close-delimited on h1, END_STREAM
on h2), each across many writes.

On h3, a response write lws took whole must not report the stream as a partial
(`lws_partial_buffered()`) or choked (`lws_send_pipe_choked()`) just because
quic has yet to send it or have it acked: quic throttles its streams itself.

A file mount serves only what it has a mimetype for: a file whose extension
neither the mount's `extra_mimetypes` nor the server's own table knows is
refused with 415 over h1 and h2, rather than sent as `application/octet-stream`.

A 302 is followed on the same wsi, over h1 and from an h2 stream, but never
into the unix socket namespace: the server also listens on a unix socket
(abstract on linux) and redirects to it (`http://+<path>:80/...`), and the client
must refuse to follow that, since only the app may name a unix socket.

The server answers each request with `len=<n> sum=<x>` describing the decoded
payload it received, followed by n bytes of the same pattern, so the client can
check both directions byte-exactly.

```
$ ./lws-api-test-http-transfer -p 7681 --h2-port 7682
```

Option|Meaning
---|---
-d <loglevel>|Debug verbosity in decimal, eg, -d15
-p <port>|Port for the h1 server vhost (default 7681)
--h2-port <port>|Port for the h2 prior-knowledge server vhost (default 7682)
--case <n>|Run only case n
--serve-only|Only run the server vhosts, to poke at by hand
