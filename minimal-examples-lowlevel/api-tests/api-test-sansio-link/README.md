# lws api test sansio-link

Only built when lws is configured with `-DLWS_WITH_SANSIO_LINK_TEST=1`.

That option links the sansIO half alone as `libwebsockets-sansio`: the
sources under `lib/sansio`, the substrate neither half owns and the
platform's injected clock, random source and file access, with the linker
told to report every unresolved symbol as an error.  It links only when
sansIO needs nothing of IO's but the `lws_io_ops_t` requests
(READMEs/README.sans-io-split.md, "The contract"), so the build is the
test.

This program links against that library, and nothing else of lws, and
runs a little of it: an http date rendered and parsed by the sansIO http
code, an address parsed and written by the substrate, and the clock.

## build

```
 $ cmake .. -DLWS_WITH_SANSIO_LINK_TEST=1 && make
```

## usage

```
 $ ./bin/lws-api-test-sansio-link
Completed: PASS
```
