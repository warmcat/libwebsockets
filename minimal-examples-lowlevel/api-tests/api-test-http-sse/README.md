# lws-api-test-http-sse

An h1 SSE stream must live as long as its server and client want it to.

`lws_http_mark_sse()` gives the stream's header table up, since an SSE
transaction never parses another request.  The h1 rx policy, which is asked
on every service and not only for rx, used to hand it a new one in
`LRS_DOING_TRANSACTION`, and attaching one arms the ah idle timeout: every h1
SSE stream was closed `timeout_secs_ah_idle` (default 10s) after it was first
writeable.

The server vhost here sets a 1s `timeout_secs_ah_idle` and sends one event
when the stream opens and another 3s later.  The test passes when the client
gets both on the one connection, and the server notices the client hanging
up once it has them (which is what reading the stream in
`LRS_DOING_TRANSACTION` is for).

## Running

The test is registered with ctest as `api-test-http-sse`; it obtains a free
listen port at configure time and passes it via `-p`.

```
$ ctest -R api-test-http-sse
```
