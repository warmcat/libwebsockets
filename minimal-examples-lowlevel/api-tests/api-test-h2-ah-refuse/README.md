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

```
$ ./lws-api-test-h2-ah-refuse -p 7681
```

Option|Meaning
---|---
-d <loglevel>|Debug verbosity in decimal, eg, -d1151
-p <port>|Port for the h2 prior-knowledge server (default 7681)
--server <addr>|Server address to connect to (default 127.0.0.1)
