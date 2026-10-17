# lws api test h2 client peer

What an h2 client keeps of its own request, and what it takes from the peer,
when the peer's response is decoded into the same header table the request
was composed from.

 - A GET, and a HEAD, answered 307 to another path: the redirected request
   must go with the method it was made with.  The response decoded into the
   request's header table used to take over the last of its request items,
   so the request was followed with `:method: 307`.
 - A GET answered 307 by a response carrying a `:method` of its own: a
   response has no request pseudo-headers (RFC 9113 8.3.2), so the client
   must GOAWAY PROTOCOL_ERROR rather than follow it, which once took the
   response's `:method` for the redirect's.
 - A GET answered with DATA before any HEADERS: a response starts with its
   HEADERS (RFC 9113 8.1), so the client must GOAWAY PROTOCOL_ERROR, and the
   app must never see the DATA as body.
 - A GET answered 200 on a connection kept warm, which the fixture PINGs once
   the stream has gone: an idle connection is still live, and must ACK it,
   where it once dropped everything that came, unparsed.
 - A GET whose response HEADERS has no END_HEADERS, its CONTINUATION
   coming only after the request timed out and its stream closed: the rest of
   the block must still be decoded, for the connection's hpack table, and not
   fail the connection, as an unexpected CONTINUATION did.

The server is a raw socket in the same process speaking just enough h2 by
hand, so it can answer exactly as each case needs, and see exactly the
`:method` and `:path` of every request the client sent, on which of the
case's connections.  lws sends each field as a literal with a literal name
and no huffman coding, which is all the fixture decodes.

The test fails if any case does not end as expected inside the watchdog
period.

## build

```
 $ cmake . && make
```

## usage

|Option|Meaning|
|---|---|
|-p <port>|Port the fixture listens on, default 7681|
|--server <addr>|Address the client connects to, default 127.0.0.1|

```
 $ ./lws-api-test-h2-client-peer -p 7681
```
