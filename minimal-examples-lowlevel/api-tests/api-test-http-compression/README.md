# lws api test http compression

Checks that http stream compression delivers files intact, in one process.

A file mount serves a generated multi-megabyte text file whose name is its
own sha256, eg `/3a7bd3e2...c1f0.txt`.  The client side then fetches it over
h1 and h2c (prior knowledge, no TLS), and h3 when lws has it and the test is
given a certificate, with each of these `accept-encoding` requests, decodes what comes back with zlib or brotli, and checks the
decoded length and sha256 against the name:

|request|expected response|
|---|---|
|no accept-encoding|identity|
|`gzip`|identity (lws does not offer gzip for plain files)|
|`deflate`|`content-encoding: deflate`, raw deflate|
|`br`|`content-encoding: br` (only when built with `LWS_WITH_HTTP_BROTLI`)|

Every response's caching and framing headers are checked as well:

|situation|`vary: accept-encoding`|framing|
|---|---|---|
|`.txt`, coded|yes|h1 `transfer-encoding: chunked`, h2 neither; no `content-length`|
|`.txt`, identity (no, unknown or refused coding)|yes|`content-length` (h2 may leave it out, the stream end frames it), no `transfer-encoding`|
|304 revalidating a `.txt` with its ETag|yes|neither|
|the same file as `.bin` (`application/octet-stream`, never compressed), and its 304|no|`content-length` / neither|
|`range: bytes=0-99` with `accept-encoding: deflate` (only `LWS_WITH_RANGES`), 206|no, a range is never coded|`content-length: 100`|
|a vhost with `LWS_SERVER_OPTION_NO_HTTP_STREAM_COMPRESSION`, and its 304|no|`content-length` / neither|

A callback mount, `/dyn`, answers with the same content as an app would, and
with `accept-encoding: deflate` on h1, h2 and h3:

|path|how the server answers|expected response|
|---|---|---|
|`/dyn/compose`|`lws_add_http_common_headers()` with the length, then the body from the writeable|`content-encoding: deflate`, `vary: accept-encoding`|
|`/dyn/compose-optout`|the same, after `lws_http_compression_opt_out()`|identity, `content-length`, no `vary`|
|`/dyn/file`|`lws_serve_http_file()`|`content-encoding: deflate`, `vary: accept-encoding`|
|`/dyn/file-optout`|the same, after `lws_http_compression_opt_out()`|identity, no `vary`|

The opted-out answers are what an app sends when a response carries a secret
next to something the client influences (BREACH).  The composed cases are
skipped for `--size 0`, an empty composed body has nothing to code.

The `vary` matters because a shared cache must not hand one client a coding
chosen for another; a 304 repeats it (RFC 9110 15.4.5).  A response whose
coding did not depend on `accept-encoding` must not say it does.  The range
cases are skipped for files shorter than the range, ie, `--size 0`.

The file is `text/plain` because lws only compresses text-ish mimetypes, and
its content is a pseudo-random hex stream interleaved with repeated words so
the compressors have real work without collapsing it.

## build

Requires `LWS_WITH_HTTP_STREAM_COMPRESSION`, a server and client build, and
`LWS_WITH_GENCRYPTO` for the digest.  It links zlib and, when lws has it,
brotlidec directly, since it decodes the same way the browser would.

```
 $ cmake . && make
```

## usage

```
 $ ./lws-api-test-http-compression -p 7681 --h2-port 7682 --nc-port 7683 --nc-h2-port 7684 [--h3-port 7685 --cert c --key k] [--size bytes] [--tmpdir dir] [-d 1039]
```

`-p` and `--h2-port` are the h1 and h2c listen ports of the vhosts that
compress, `--nc-port` and `--nc-h2-port` those of the vhosts with
`LWS_SERVER_OPTION_NO_HTTP_STREAM_COMPRESSION`.  `--h3-port`, `--cert` and
`--key` give the h3 cases a tls vhost that compresses; without `--cert` and
`--key` they are skipped.  `--size` defaults to 3 MiB.  The generated file lives in a scratch directory
made under `--tmpdir`, the current directory by default (ctest passes its
build directory), and is removed at exit.  The exit code is 0 only when every case passed.
