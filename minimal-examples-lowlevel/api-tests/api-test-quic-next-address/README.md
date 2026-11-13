# lws-api-test-quic-next-address

A quic client is aimed at one of the addresses its peer's name resolves to.
If that address refuses it, with an ICMP port unreachable, before anything
ever came back from it, the peer is not there, and the client moves on to the
name's next address at once, on a fresh socket, the way a refused tcp connect
does.  Without that it would retransmit into nothing until its handshake timed
out or, on h3, until its grace gave up on quic for tcp.

Once anything has arrived from the address it is aimed at, the peer has
answered, and an ICMP error after that changes nothing: it is only what the
path, or an off-path attacker, says.

The h3 server in the process listens on one literal loopback address,
`--bind`, and the client asks for `localhost`, which resolves to both.  Which
of the two the client tries first is the platform's and the routing table's
choice, so ctest runs the test once with the server on each: in one of the
runs the client is refused first.  Either way the request must be served over
h3, with no fallback to tcp.

The client hears `LWS_CALLBACK_CONNECTING` for each address it tries, as a tcp
client does, so a second one is the move, and `lws_get_peer_simple()` and
`lws_get_peer_addresses()` then both say where to.  The move must come inside 400ms of the start, before the
client's first PTO (500ms) could have resent anything to the refusing
address, and be to the address the server listens on.  The run whose first
address is the server's has no move, and says so.

With `--reject-move`, the client's callback returns nonzero for the move,
which must close the connection instead: a run that moves must not be served,
one that doesn't must still be.  ctest runs each family both ways.

A host with no ipv6 loopback can't bind `::1`, and the `-v6` run is skipped
there.

```
$ ./lws-api-test-quic-next-address -p 7695 --bind ::1 --address localhost \
	--cert ../api-test-quic-smp/localhost-p256-100y.cert \
	--key ../api-test-quic-smp/localhost-p256-100y.key
```

Option|Meaning
---|---
-d <loglevel>|Debug verbosity in decimal, eg, -d15
-p <port>|The server's quic port (default 7695)
--bind <literal>|The server's only quic address (default ::1)
--address <name>|What the client asks for (default localhost)
--reject-move|The client refuses to move on to the next address
--cert <file>|The server's certificate
--key <file>|The server's key
--help|Show the options
