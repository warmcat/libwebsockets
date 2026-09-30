# lws api test http attack

Hostile requests against an lws server, over each http transport the build
has, checking lws still turns them away the way it should.  It replaces
`scripts/attack.sh`, and adds the other request shapes a server is expected
to be proof against.

lws is both ends, in one process, so a crash or a memory error in the server
(eg, under ASan) fails the test as surely as a wrong answer does.  Every
attack case is followed by a plain request on a new connection, which must
still be served.

## the server

 - `/f` is a file mount on `./docroot`.  `./secret.txt` sits beside the
   docroot, one level above it: no response may ever contain it.  A request
   the mount has no file for gets a 404.

 - every other path reaches an echo handler, which answers 200 with
   `echo:` and the path and urlargs as lws hands them to user code (after its
   percent-decoding and `../` normalization), and ` ua=` with any
   `User-Agent`.  So for each hostile path, the test sees what a user
   callback would have been given to act on.

The client side is raw for h1 and h2 (cleartext, prior knowledge), so it can
send bytes no well-behaved client would.  For h3 it is the lws client, which
can only send what that client composes: paths starting `//` are skipped
there, since it takes one of the `/` off.

## what is covered

On every transport:

|request|expected|
|---|---|
|the paths and urlargs of attack.sh, and its ~200 mass `.`, `/`, `?`, `%` variations|the normalized path and args exactly, or refused|
|directory traversal out of the file mount, plain, %-encoded, mixed, with `\`, `;`, double-encoding, overlong utf-8|never the secret: normalized into the echo handler, or 404|
|bad %-encoding, and CR, LF, NUL and DEL smuggled in by %-encoding in the path or args|refused|

Refused means a 403 on h1, a GOAWAY PROTOCOL_ERROR on h2 and the connection
closed on h3.

h1, raw:

|request|expected|
|---|---|
|noise: `not GET`, 80 bytes and 640KiB of random|nothing served|
|malformed, missing and relative uri, repeated method, 8000-byte uri|nothing served|
|a 2000-byte header name, a header line with no colon, whitespace before a colon, obs-fold|nothing served|
|an unknown header named as the start of a known one (`Accept-Lang:`)|served, and the header after it still seen|
|an h2 pseudo-header (`:method: POST`), a header name starting with `:`|nothing served|
|a header named as lws' urlargs slot (`Uri-Args:`) or starting as a method (`Put-Id:`)|served, as an unknown header, with no urlargs and the header after it still seen|
|a request followed by junk|the request served, the junk not|
|8 pipelined requests|all 9 served, in order|
|two different Content-Length, Content-Length with chunked, chunk size overflow, two Host|nothing served|
|NUL or a bare CR in a header value, 1000 headers|nothing served|
|40 urlargs|served|
|120 urlargs, more than the ah has header fragments for|414|
|a bare LF ending the request line, a header, or a chunked body's trailer|nothing served|
|headers never finished, or trickled in a byte at a time|dropped within the header timeout|

h2, raw frames:

|request|expected|
|---|---|
|bad preface|nothing served|
|CONTINUATION flood|GOAWAY ENHANCE_YOUR_CALM|
|PING, SETTINGS flood, rapid reset (1000 HEADERS + RST_STREAM)|served, or GOAWAY ENHANCE_YOUR_CALM|
|CONTINUATION on another stream, stream id going down, even stream id, WINDOW_UPDATE of 0, DATA on stream 0 or on an idle stream|GOAWAY PROTOCOL_ERROR|
|hpack index past both tables, huffman EOS|GOAWAY COMPRESSION_ERROR|
|hpack table size over the limit|clamped, served|
|frame over SETTINGS_MAX_FRAME_SIZE|GOAWAY FRAME_SIZE_ERROR|
|WINDOW_UPDATE past 2^31 - 1|GOAWAY FLOW_CONTROL_ERROR|
|a `get ` field smuggling a path, an uppercase field name|GOAWAY PROTOCOL_ERROR|
|CR LF in a value, no or two `:path`, pseudo-header after a regular one, `connection`, `transfer-encoding`, 1500 fields|nothing served|

Where the client sends more than the server reads before it gives up on it,
the server closes with that unread, the kernel resets the connection and what
the server still had to send, the GOAWAY included, is lost: there the
connection just ending with nothing served passes too.

h3, lws client: a `get ` field smuggling a path is refused.

## running it

```
$ ./lws-api-test-http-attack --transport h2 --h2-port 7682
```

Run it with the test directory as the cwd, it serves `./docroot`.

Option|Meaning
---|---
-d <loglevel>|Debug verbosity in decimal, eg, -d15
--transport h1\|h2\|h3|Only test this transport (default: all the build has)
-p <port>|Port for the h1 server vhost (default 7681)
--h2-port <port>|Port for the h2 prior-knowledge server vhost (default 7682)
--h3-port <port>|UDP port for the h3 server vhost (default 7683)
--server <address>|Address the clients connect to (default 127.0.0.1)
--only <text>|Only run the cases whose name contains text
