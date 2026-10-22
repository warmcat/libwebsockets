# lws api test h2 stream reset

Streams of an h2 server connection being reset.  A raw h2 client (cleartext,
prior knowledge) in the same process writes the frames itself, so it controls
exactly what the server has read when.

The server resets a stream outside its frame parser when the stream closes,
eg, a GET whose HEADERS had no END_STREAM answered in full gets RST_STREAM
`NO_ERROR` at POLLOUT.  That must not disturb a frame the server is part way
through reading, for another stream or for the connection, nor be skipped
because the last frame the server read was one it ignored.

|case|what|
|---|---|
|`ping`|A PING is half sent when stream 1 is answered and reset; the rest goes after the RST_STREAM.  The PING must be answered with its payload|
|`hpack`|Half of stream 5's header block is sent when stream 3 is answered and reset; the second half, after the RST_STREAM, adds a user-agent to the hpack dynamic table.  Stream 5 must be served with it, and stream 7, which refers to the dynamic table entry, too|
|`ignored`|Stream 1's HEADERS is followed by a frame of an unknown type, which the server ignores.  When stream 1 is answered, its RST_STREAM must still be sent|
|`reset`|"Rapid reset" (CVE-2023-44487 class): the server allows 20 streams reset per connection per 10s (`mux_reset_limit`).  Connection A sends batches of 8 GETs whose answers are started but never finished, and once each batch has its response headers, resets it in the same write as the next batch.  The server must end A with GOAWAY `ENHANCE_YOUR_CALM` having dispatched no more than 36 of them; then connection B, which resets nothing, has 60 GETs answered|

```
$ ./lws-api-test-h2-stream-reset --case ping -p 7681
$ ./lws-api-test-h2-stream-reset --case hpack -p 7681
$ ./lws-api-test-h2-stream-reset --case ignored -p 7681
$ ./lws-api-test-h2-stream-reset --case reset -p 7681
```
