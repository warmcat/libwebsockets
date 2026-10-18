# lws api test http bodyless

Answers that have no body must not send one, and must end where the peer
expects them to.  On a kept-alive h1 connection anything else desyncs it: the
peer reads the next answer from the stray bytes, or waits for an end that
never comes.  The server's handlers are written as an app writes them:

Path|Handler
---|---
`/body`|200 `text/plain` from `lws_add_http_common_headers()` with its Content-Length, then the body as `LWS_WRITE_HTTP_FINAL` from the writeable.
`/redir`|a headers-only 302 `text/html`, Content-Length 0, as the lws-login and auth-server redirects are.  With `LWS_WITH_HTTP_STREAM_COMPRESSION`, lws must not code it: a coded answer goes chunked on h1, and a headers-only one never sends the last-chunk.
`/nofinal`|like `/body`, but the body is written as `LWS_WRITE_HTTP` before the transaction is completed, relying on its Content-Length.  When lws coded it, the chunked framing is lws' own, and lws ends it at the completion.

A raw h1 client sends GET /redir, GET /body, GET /nofinal and GET /body on
one connection, each once the previous answer is whole, and parses the
answers byte-exactly: status, framing (Content-Length or chunked), the body,
and nothing after the answer before the next request goes.  Every request
says `accept-encoding: deflate`, so a build with stream compression codes the
bodies.

The server and the client are in one process.

```
$ ./lws-api-test-http-bodyless -p 7681
```

Option|Meaning
---|---
-d <loglevel>|Debug verbosity in decimal, eg, -d1151
-p <port>|Port for the server (default 7681)
--server <addr>|Server address to connect to (default 127.0.0.1)
