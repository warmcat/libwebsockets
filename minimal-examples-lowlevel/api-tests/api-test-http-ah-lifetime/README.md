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
--case <case>|`file-stall`, `pipeline-depth`, `slow-cl`, `slow-stream` or `late-spa`
--role <role>|`h1` (default), `h2` (prior knowledge) or `h3`; the first two cases are h1 only
--cert <path>|Server certificate, for h3
--key <path>|Server private key, for h3
