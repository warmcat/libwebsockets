# lws api test http compression

Checks that http stream compression delivers files intact, in one process.

A file mount serves a generated multi-megabyte text file whose name is its
own sha256, eg `/3a7bd3e2...c1f0.txt`.  The client side then fetches it over
h1 and h2c (prior knowledge, no TLS) with each of these `accept-encoding`
requests, decodes what comes back with zlib or brotli, and checks the
decoded length and sha256 against the name:

|request|expected response|
|---|---|
|no accept-encoding|identity|
|`gzip`|identity (lws does not offer gzip for plain files)|
|`deflate`|`content-encoding: deflate`, raw deflate|
|`br`|`content-encoding: br` (only when built with `LWS_WITH_HTTP_BROTLI`)|

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
 $ ./lws-api-test-http-compression -p 7681 --h2-port 7682 [--size bytes] [--tmpdir dir] [-d 1039]
```

`--size` defaults to 3 MiB.  The generated file lives in a scratch directory
made under `--tmpdir`, the current directory by default (ctest passes its
build directory), and is removed at exit.  The exit code is 0 only when every case passed.
