# lws-api-test-listen-any-port

A server vhost asking for any free port (`info.port` 0) on a dual-stack build
listens on both IPv4 and IPv6.  The first address family's bind chooses the
port, and the other family's bind must take the same port number, which
something else may already have in that family.  lws must then give that port
up and start again with another, rather than fail to create the vhost.

Two vhosts are given faults that make the second family's bind find the port
taken:

 - `listen_port_taken` once: starting again once with another port is enough;
 - `listen_port_taken_v6` every time: IPv6 has every port IPv4 chooses, as it
   had 8 in a row on Sai's macOS, so starting again with IPv4 choosing is
   never enough: IPv6 must choose.

Each must still come up, and a client of `127.0.0.1` and one of `::1` must
each get an http response on the port it ended up with.

A vhost that serves h3 too also listens on its port number in udp, which
something else, eg, a udp client socket, may already have.  With `--cert` and
`--key`, a third vhost offering h3 is given `listen_port_taken_quic` once,
making its QUIC listener's bind find the port taken.  It must start again on
another port, and h3 clients of `127.0.0.1` and `::1` must each be answered
over QUIC.  This case needs `LWS_ROLE_H3` and TLS.

Needs `LWS_WITH_SYS_FAULT_INJECTION`, and both `LWS_WITH_IPV4` and
`LWS_WITH_IPV6`.

```
$ ./bin/lws-api-test-listen-any-port --cert localhost-100y.cert \
	--key localhost-100y.key
```
