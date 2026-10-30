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

Needs `LWS_WITH_SYS_FAULT_INJECTION`, and both `LWS_WITH_IPV4` and
`LWS_WITH_IPV6`.

```
$ ./bin/lws-api-test-listen-any-port
```
