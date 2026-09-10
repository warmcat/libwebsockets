# lws api test http transfer

Exercises the http body transfer framings lws is expected to handle, in both
directions, with an lws server and an lws client in one process.

Request bodies (client to server) on h1: Content-Length in one write and in
many; Transfer-Encoding: chunked with chunks of assorted sizes, in one write, in
many, and with the framing split across writes; chunked with chunk extensions
and trailer fields; chunked on a GET followed by a pipelined request on the same
connection; and the refusals (an unsupported
Transfer-Encoding gets 501, Transfer-Encoding with Content-Length gets 400, a
chunked body over the mount limit drops the connection, a Content-Length over it
gets 413).

Request bodies on h2 (cleartext, prior knowledge): Content-Length, no
Content-Length (END_STREAM delimited), and no body.

Response bodies (server to client): Content-Length, hand-framed chunked with
extensions and trailers, and unknown length (close-delimited on h1, END_STREAM
on h2), each across many writes.

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
