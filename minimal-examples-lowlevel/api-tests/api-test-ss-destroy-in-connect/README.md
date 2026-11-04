# lws api test ss destroy in connect

A Secure Stream whose connection attempt fails inside `lws_ss_client_connect()`,
and whose state callback gives up on it then, returning `LWSSSSRET_DESTROY_ME`
for `UNREACHABLE`, is destroyed once, by whoever asked for the connection, when
`lws_ss_client_connect()` hands the `DESTROY_ME` back to it.

Over h3, the quic connection's tls session is made as its transport comes up,
which for a numeric address is inside the connect call.  The
`tls_client_bio_create` fault fails it, as running out of heap for it would,
and the wsi is closed there and then, before the stream heard of it.  That
close used to destroy the handle itself: the connect call went on with the
freed handle, and the caller destroyed it again.

Nothing is listening: the connection never gets as far as sending anything.

```
$ ./lws-api-test-ss-destroy-in-connect
```

It needs `-DLWS_WITH_SYS_FAULT_INJECTION=1`.
