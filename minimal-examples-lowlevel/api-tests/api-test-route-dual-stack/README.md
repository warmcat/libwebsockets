# lws api test route dual stack

lws picks the route a destination would go out on from its routing table, and
drops a DNS result it has no way to use.  The most specific route the
destination is on wins; between default routes, one of the destination's own
family wins, then the better priority.

A v4 destination may go out through a v6 default route, as `::ffff:a.b.c.d`,
but only on a host whose egress is v6 alone: on a dual-stack host it must take
the v4 one, whatever order the routes came in and whatever their priorities.

A default route on a point-to-point link has no gateway, eg, wg-quick's
`::/0 dev wg0`, and is still a way out for its family.  A v6 network route,
eg, a split tunnel's `::/1 dev wg0`, doesn't take in v4 destinations, though
lws compares those as v4-mapped.  A route to a network
via a gateway, eg, `10.0.0.0/8 via 192.0.2.1`, is not a default route.

Once netlink has given the context the host's routes, for each case the test
replaces them in the context's table (`lws_routing_table_get()`) with the
case's routes, and asks for a udp socket to a destination:

Case|Destination|Socket
---|---|---
v6 default route first, both with the same priority|127.0.0.1|made
v6 default route first, with the better priority|127.0.0.1|made
v4 default route first, both with the same priority|127.0.0.1|made
v4 default via a gateway, v6 default with no gateway, v6 address|::1|made
v6 default with no gateway first, then a v4 default via a gateway|127.0.0.1|made
only a v4 default with no gateway, v6 address|::1|dropped
v6 split tunnel routes `::/1` and `8000::/1`, and a v4 default|127.0.0.1|made
only a network route via a gateway|127.0.0.1|dropped

Nothing is sent.  Linux only, since the context only judges destinations by
its routes when it has them from netlink.

```
$ ./lws-api-test-route-dual-stack
```

Option|Meaning
---|---
-d <loglevel>|Debug verbosity in decimal, eg, -d15
