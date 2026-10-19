# lws api test h2 ah refuse

An h2 request needs a header table (ah) from the server's pool while its
headers are decoded, and a POST keeps it until its body completes.  When the
pool is in use, the new stream must be refused on its own with RST_STREAM
`REFUSED_STREAM` (safe for the client to retry), and the connection and its
other streams must go on.  Trailers on a stream that already gave its ah back
must not need one from the pool again.

The server has room for two streams' ahs.  A raw h2 client (cleartext, prior
knowledge) in the same process holds two POSTs open with their bodies
unfinished, sends trailers for a third whose body completed already, and opens
another POST, which must be refused.  The refused stream's header block adds
entries to the hpack dynamic table, and a last request refers to them: the
server has to see their values, as a client retrying the refused request on
the connection would need.

`--case cap`: the streams of one connection waiting on the client may only
hold so many ahs at once (3 here), so one client cannot take the pool from
everybody else by opening many slow POSTs.  The pool has room for 8.
Connection A opens six POSTs whose bodies don't come: three must be refused
with `REFUSED_STREAM`.  Connection B then GETs and must be answered, and when
A's bodies end, its three kept streams are answered.  Without the cap, A's
streams and its own ah take 7 of the 8, B's connection the last, and B's GET
is refused.

```
$ ./lws-api-test-h2-ah-refuse -p 7681
$ ./lws-api-test-h2-ah-refuse --case cap -p 7681
```

Option|Meaning
---|---
-d <loglevel>|Debug verbosity in decimal, eg, -d1151
-p <port>|Port for the h2 prior-knowledge server (default 7681)
--server <addr>|Server address to connect to (default 127.0.0.1)
--case <case>|`pool` (default, the pool is full) or `cap` (one connection's share of it)
