# lws api test http tls ah

A server http connection's header table (ah) comes from a small pool, and its
hold, `timeout_secs_ah_idle`, is the deadline for the request head.  A tls
connection must only take one when its handshake has completed: the handshake
needs none and is bounded by the tls accept timeout, `timeout_secs`.

The server's pool has exactly the room one https GET needs, counting the lws
client in the same process.  A raw connection connects to the tls server and
sends nothing.  Then an lws https client GETs `/`, over h1, or h2 chosen by
alpn: it must be answered well inside the 2s ah idle timeout, which it can't
be if the silent connection holds an ah.  The silent connection must then be
closed at the 4s tls accept timeout, not at the ah idle timeout.

On h2 the pool is the same size: the server's stream takes an ah, and its
network connection, whose headers are all decoded into its streams' ahs,
must not hold one too.

```
$ ./lws-api-test-http-tls-ah --cert localhost-100y.cert \
	--key localhost-100y.key -p 7681 --h2
```

Option|Meaning
---|---
-d <loglevel>|Debug verbosity in decimal, eg, -d1151
-p <port>|Port for the server (default 7681)
--server <addr>|Server address to connect to (default 127.0.0.1)
--cert <path>|Server certificate
--key <path>|Server private key
--h2|GET over h2, chosen by alpn, instead of h1
