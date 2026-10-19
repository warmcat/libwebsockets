# lws-api-test-peer-stack

Checks the peer address stack api in `lws-network-helper.h`: lws keeps who a
connection's peer is as a stack, the transport's own peer at the bottom and a
claim about the real client (eg, a trusted front's PROXY v2 header) above it,
each entry tagged with how far it can be believed (`lws_peer_cred_t`:
hearsay, vouched, routable, crypto).

 - **formatter**: `lws_peer_entries_describe()` on entries made up in the
   test, in the log format and as one token, with IPv6 brackets, AF_UNIX, an
   address of no family lws can write, the cred and kind names, and buffers
   too small for the result.  With `LWS_PEER_DESC_BARE_SINGLE`, which is how
   lws's own logs describe the peer, a single entry is just its address,
   while a deeper stack is still described in full.

 - **effective**: `lws_peer_entries_effective()` on stacks made up in the
   test, including ones lws does not build yet: a hearsay entry above a
   vouched, routable or crypto one is never the effective entry; with
   nothing believable, the top entry is.

 - **tcp**: a raw client sends a GET to an http vhost.  The server sees one
   entry, the socket's peer, ROUTABLE and effective, which is what
   `lws_get_peer_simple()` gives, and what `lws_peer_describe()` gives with
   `LWS_PEER_DESC_BARE_SINGLE`, so logs show it as they always did; the
   client sees the server it connected to the same way.

 - **proxy-v2** (with `LWS_WITH_TLS_PASSTHROUGH`): the client sends a PROXY v2
   header first, to a vhost trusting loopback for one.  The client it names
   is on top, VOUCHED, over the front's own socket, ROUTABLE.  The claim is
   the effective entry and what `lws_get_peer_simple()` and
   `lws_get_peer_host_key()` give, and `lws_peer_raise()` for some other
   address raises nothing.  Logs describe both layers, with their creds.

 - **udp** (with `LWS_WITH_UDP`): a bound UDP socket's peer is the last
   datagram's source, HEARSAY, as a DATAGRAM entry: the socket has no peer of
   its own, so nothing (eg, the route checks) takes it for one.
   `lws_peer_raise()` raises it only for its own address (and port, when one
   is given), never lowers it, and after a datagram from another socket has
   replaced the entry, evidence about the old source raises nothing.  The
   receiver answers the first sender, a connected socket, which keeps its
   own peer, a SOCKET entry, when the answer arrives.  A raise covers only
   the datagram it was for: the sender raises its entry and sends again,
   and both the receiver's entry for that second datagram (same address and
   port as the first, which it raised) and the sender's for the next answer
   are HEARSAY again.

 - **redirect**: an http client asks for a path the server redirects to
   another on the same server, so `lws_client_reset()` dials again with the
   same wsi.  When it dials, its entry is HEARSAY, not the ROUTABLE its
   last connection proved, and ROUTABLE again once connected.

 - **access log** (with `LWS_WITH_ACCESS_LOG`): the servers write an access
   log.  The line for the tcp phase's GET starts with just the client's
   address, exactly what `lws_get_peer_simple()` gives, as access logs always
   did; the line for the proxy-v2 phase's starts with both layers as one
   field, `192.0.2.10:40000~v<127.0.0.1:<port>~r`.

## Commandline

| option | meaning |
|--------|---------|
| `--server ADDRESS` | where the tcp servers are reached, default `localhost` |
| `-p PORT` | loopback UDP port the receiver binds (from `lws_get_free_port()`) |
| `--access-log FILE` | the servers' access log, emptied first, checked at the end |

## Run

```
$ ctest -R api-test-peer-stack
```
