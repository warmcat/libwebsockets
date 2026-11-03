# lws api test route tables

lws keeps one routing table, from the route messages the kernel sends it over
netlink, about the routes in all of the kernel's tables, each route marked with
the table it is in.  With policy routing, eg, `ip rule from <addr> lookup 107`,
another table can hold a copy of the main table's routes for an interface.

When the kernel deletes a route, only that route goes from lws' table: the one
in the same kernel table, to the same network with the same length, with the
same gateway or none, on the same interface, with the same priority.  When it
adds one, it takes the place of that same route if lws has it, and a route
replaced, eg, by `ip route replace`, takes the place of the one in the same
table to the same network with the same priority, whatever its gateway or
interface.  A route with another priority is another route.

So flushing and refilling table 107 leaves the main and local tables' routes
alone, along with the connections using them, and the local table's route to
the host's own address that says it still has it.

Once netlink has given the context the host's routes, for each case the test
empties the context's table, gives it the case's route messages the way the
kernel would send them, with `lws_netlink_inject()`, and after each one checks
which routes the table holds, and that routes which should be untouched still
have the same uidx, ie, are the same entries connections were tagged with.

Case|Checks
---|---
a policy table holding a copy of main's routes, flushed and refilled|main's and the local table's routes are kept through it, and can still be deleted
a policy table with an id over 255, flushed|the id comes from `RTA_TABLE`, not `RT_TABLE_COMPAT`; main's routes are kept
a shorter network on the same address, added and deleted|the longer network and the local route are kept
a network on the link and via a gateway|deleting the one on the link keeps the one via the gateway
a default route replaced|its gateway and then interface change; the route with another priority is kept
the same routes announced again, plain and replaced|they are kept as they were
a route's priority changed|the route with the new one is added, and the old one deleted

Nothing is sent.  Linux only, since netlink is where the routing table comes
from.

```
$ ./lws-api-test-route-tables
```

Option|Meaning
---|---
-d <loglevel>|Debug verbosity in decimal, eg, -d15
