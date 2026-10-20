# lws api test route dual stack

lws picks the route a destination would go out on from its routing table, and
drops a DNS result it has no way to use.  A v4 destination may go out through a
v6 gateway, as `::ffff:a.b.c.d`, but only on a host whose egress is v6 alone:
on a dual-stack host it must take the v4 gateway, whatever order the routes
came in and whatever their priorities.

Once netlink has given the context the host's routes, the test replaces them
in the context's table (`lws_routing_table_get()`) with a v6 and a v4 default
route, and asks for a udp socket to a v4 address, which must be made:

 - v6 default route first, both with the same priority
 - v6 default route first, with the better priority
 - v4 default route first, both with the same priority

Nothing is sent.  Linux only, since the context only judges destinations by
its routes when it has them from netlink.

```
$ ./lws-api-test-route-dual-stack
```

Option|Meaning
---|---
-d <loglevel>|Debug verbosity in decimal, eg, -d15
