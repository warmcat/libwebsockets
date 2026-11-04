# lws api test h3 client no ah

An h3 client stream keeps the headers of its response in an ah, taken when
they arrive.  When there is none to be had, because the heap can't make one or
the pool is in use, only that stream fails: it is cancelled with
`H3_REQUEST_CANCELLED`, and its client sees it closed with no response,
`LWS_CALLBACK_CLOSED_CLIENT_HTTP`, which it may try again.
It used to close the whole connection with `QPACK_DECOMPRESSION_FAILED`, and
every other stream on it with it.

An h3 server and its client run in this process, the client's requests all on
one connection.  The `h3_rx_no_ah` fault finds no ah for a response's headers.

 - A: a GET is answered, bringing up the connection.

 - S, B: a GET whose answer the server holds back 500ms goes, and with it a
   GET whose response finds no ah.  B fails, and S is answered after it, on
   the same connection.

 - C: once both ended, a GET is answered on the same connection again.

```
$ ./lws-api-test-h3-client-no-ah -p 7681 --cert ../api-test-ws-close/localhost-100y.cert \
	--key ../api-test-ws-close/localhost-100y.key
```

It needs `-DLWS_WITH_SYS_FAULT_INJECTION=1`.
