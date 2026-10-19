# lws api test http ah lifetime

A server request's header table (ah) comes from a small pool, and lws should
hold one only while the request needs it.  When that changes, these cases must
keep passing.  The server's ah idle timeout is 2s, much shorter than its other
timeouts, and each case waits for longer than that at the point where a
released and re-attached ah would arm it.

Case|Roles|What
---|---|---
`file-stall`|h1|A raw client GETs an 8MB file from a file mount and stops reading it for 4s, sending a pipelined GET in its own write meanwhile.  The file must still be going when it reads again, then arrive whole, then the answer to the GET.  With `LWS_WITH_ASYNC_QUEUE` the file is read by the async worker.
`pipeline-depth`|h1|64 GETs pipelined in one write, then one more in its own write, must all be answered on the kept connection.  80 GETs in one write must not all be answered: the server closes the connection after at least 64.
`slow-cl`|h1, h2, h3|A POST with a Content-Length whose body pauses for 3s after the request headers and again after its first piece: the Content-Type must be readable at `LWS_CALLBACK_HTTP` and the body must arrive whole.
`slow-stream`|h1, h2, h3|The same without a Content-Length: chunked on h1, ended by the stream on h2 and h3.
`late-spa`|h1, h2, h3|A multipart form POST whose server gives the request headers back at `LWS_CALLBACK_HTTP` and only creates its `lws_spa` at the first `LWS_CALLBACK_HTTP_BODY`: the spa must still parse the form as multipart, from the Content-Type the request was dispatched with.
`late-range`|h1, h2, h3|A GET with `Range: bytes=2-11` whose server gives the request headers back at `LWS_CALLBACK_HTTP` and only then calls `lws_serve_http_file()`: the answer must be a 206 of exactly those bytes (needs `LWS_WITH_RANGES`).
`late-coded`|h1, h2, h3|The same with `Accept-Encoding: deflate` and no Range: the text file must come deflated (needs `LWS_WITH_HTTP_STREAM_COMPRESSION`).
`body-rate`|h1, h2, h3|The server's request bodies must keep up with 1000 bytes/s after a 2s grace time.  Two POSTs at once, on one connection on h2 and h3: `/trickle` sends 10 bytes every 500ms and must be reset soon after the grace time without its body completing; `/steady` sends 16KB at 4KB/s with a 1.5s pause in the middle and must arrive whole.
`mux-cap`|h2, h3|The server lets one connection's streams waiting on the client hold 2 header tables at once.  Four POSTs on one connection hold their bodies back, and three GETs go on it too: only two POSTs may be dispatched, the others refused on their own, every GET must be answered, and when the bodies come the two POSTs must be answered.

The server and the clients are in one process.  The h3 cases need the
test certificate and key.

```
$ ./lws-api-test-http-ah-lifetime --case slow-cl --role h2 -p 7681
```

Option|Meaning
---|---
-d <loglevel>|Debug verbosity in decimal, eg, -d1151
-p <port>|Port for the server (default 7681)
--server <addr>|Server address to connect to (default 127.0.0.1)
--case <case>|`file-stall`, `pipeline-depth`, `slow-cl`, `slow-stream`, `late-spa`, `late-range`, `late-coded`, `body-rate` or `mux-cap`
--role <role>|`h1` (default), `h2` (prior knowledge) or `h3`; `file-stall` and `pipeline-depth` are h1 only, `mux-cap` h2 / h3 only
--cert <path>|Server certificate, for h3
--key <path>|Server private key, for h3
