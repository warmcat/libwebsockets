# lws api test h3 goaway retry

An h3 server closing a connection of its own accord, because it waited long
enough for the connection's first request (`timeout_secs_ah_idle`) or its next
one (`keepalive_timeout`), sends GOAWAY saying which requests it did not
process (RFC 9114 5.2), and then CONNECTION_CLOSE with H3_NO_ERROR.

A client request lost on its way, that the server never heard of, used to
fail with the connection.  Now a GET or HEAD the server did not answer goes
again, once, on a new connection, when the server's GOAWAY says it did not
process it, or, with no GOAWAY, when the server ended the connection without
error or forgot it (a Stateless Reset).  Nothing else is sent again.

An h3 server and its clients run in this process.  The server waits 1s for a
connection's first request, and as long for its next.  The `h3_req_lost`
fault loses a request's first try.

 - A: a GET's first try is lost.  The server sends GOAWAY 0 and closes the
   connection after 1s, and the GET is answered on a new connection.

 - B: a POST's first try is lost.  It is not idempotent, so it is not sent
   again: it fails with the connection, and the server never sees it.

 - C: a GET is answered, then a second GET on the same connection is lost.
   The server's GOAWAY 4 says it took the first stream only, and the second
   GET is answered on a new connection.

```
$ ./lws-api-test-h3-goaway-retry -p 7681 --cert ../api-test-ws-close/localhost-100y.cert \
	--key ../api-test-ws-close/localhost-100y.key
```

It needs `-DLWS_WITH_SYS_FAULT_INJECTION=1`.
