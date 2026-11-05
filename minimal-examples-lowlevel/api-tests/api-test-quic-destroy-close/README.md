# lws api test quic destroy close

A quic connection still open when its context is destroyed tells the peer
with CONNECTION_CLOSE (RFC 9000 10.2).  A tcp connection's peer hears of it
from the kernel's FIN, but quic has no transport close: without it, the peer
holds the connection until it idles out, and may take a last packet of ours
that arrives from an address it sees changed (eg, a NAT rebinding) for a
migration, probing a path nobody is left to answer.

An h3 server runs on the main thread with its own context.  A client on
another thread, with a context of its own, GETs from it, and destroys its
context as soon as it has the answer, its connection still kept warm.  The
server, which would wait 10s for the connection's next request, must see the
connection go within 1s of the client's context being destroyed.

```
$ ./lws-api-test-quic-destroy-close -p 7681 --cert ../api-test-ws-close/localhost-100y.cert \
	--key ../api-test-ws-close/localhost-100y.key
```
