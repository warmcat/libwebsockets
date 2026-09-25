# lws api test http ranges

Checks that serving a file for a `Range:` request (RFC 7233) delivers exactly
the bytes asked for, in one process.

A file mount serves three generated files and the client side asks for them
back with every shape of range header, over h1 and h2 (prior knowledge, no
TLS).  Each response is checked as a whole: the status, the `Content-Type`,
the `Content-Range`, that the `Content-Length` promised is exactly the count
of body bytes that arrived, and that every payload byte is the byte the file
has at that offset.

The file content is a mixing function of the offset, so a part that is short,
doubled, misaligned, or seeked to the wrong place cannot pass by accident.

## what is covered

|request|expected response|
|---|---|
|no `Range:`|200, the whole file|
|`bytes=0-99`, `bytes=400-499`, `bytes=990-999`|206, that range|
|`bytes=-10`, `bytes=-2000`|206, the suffix, clamped to the file|
|`bytes=500-`, `bytes=0-`|206, to the end of the file|
|`bytes=0-0`, `bytes=999-999`|206, one byte|
|`bytes=900-100000`|206, clamped to the last byte|
|`bytes=0-9,5000-6000`|206, the one satisfiable range alone|
|`bytes=abc`, `bytes=`, `items=0-9`|200, an unusable `Range:` is ignored|
|`bytes=1000-`, `bytes=2000-3000`, `bytes=-0`, `bytes=500-400`|416|
|`bytes=0-999,0-999`|416, ranges that aggregate past the file|
|`bytes=0-99,200-299` and other multi-range forms|206 `multipart/byteranges`|
|a `Range:` longer than the parser's 128-byte buffer|200, ignored|
|`If-Range:` matching the etag / not matching|206 / 200|
|the same on an empty file|200 for no range, 416 for any range|

A `multipart/byteranges` body is parsed the way a client has to parse it: the
boundary comes from the `Content-Type` parameter, and the body must be the
delimiters, part headers and payloads RFC 2046 lays out, ending at the close
delimiter with nothing after it.

The files are a small one (1000 bytes, so a response fits one `lws_write()`),
a big one (200000 bytes, so every part spans many, putting the producer's
resumption and the h2 frame and tx credit clamps in play) and an empty one,
which has no satisfiable byte-range at all.

## build

Requires `LWS_WITH_RANGES`, `LWS_WITH_FILE_OPS`, and a server and client
build.  The h2 cases build only with `LWS_WITH_HTTP2`.

```
 $ cmake . && make
```

## usage

```
 $ ./lws-api-test-http-ranges -p 7681 --h2-port 7682 [--tmpdir dir] [--case n] [--serv-buf n] [-d 1039]
```

The generated files live in a scratch directory made under `--tmpdir`, the
current directory by default (ctest passes its build directory), and are
removed at exit.  `--case` runs one case alone.  The exit code is 0 only when
every case passed.

`--serv-buf` sets the pt serv_buf size, which is where the producer composes
the part header, the payload and the close delimiter, and so decides how much
of a part one write carries.  ctest registers the cases twice, once at the
default size and once (`api-test-http-ranges-small-buf`) at the floor of
`LWS_PRE + 1024`, where the framing is up against the end of the buffer on
every write.
