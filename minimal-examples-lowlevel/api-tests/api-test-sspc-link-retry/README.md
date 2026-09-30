# lws-api-test-sspc-link-retry

An sspc stream is told `LWSSSCS_UPSTREAM_LINK_RETRY` each time its link to
the SS proxy fails, and user code may give up on the stream then by returning
`LWSSSSRET_DESTROY_ME`.  The link fails inside the transport, often
synchronously inside the connect attempt, so the handle has to stay usable
until the transport and the retry timer are done with it, and only then be
destroyed.

The test points the sspc link at a unix socket address nothing listens on,
so every link attempt fails, and checks

- giving up on the first failure, which on Linux arrives inside
  `lws_sspc_create()`: create fails cleanly, having issued `DESTROYING`
  once (or, where the failure arrives later, the stream is destroyed once)
- giving up on the second failure, which comes from the 1s retry timer: the
  stream is destroyed once
- in both cases, nothing is left scheduled against the destroyed stream

## Build

Needs `LWS_WITH_SECURE_STREAMS_PROXY_API`, `LWS_WITH_CLIENT` and
`LWS_WITH_UNIX_SOCK`.  It's registered with ctest as
`api-test-sspc-link-retry`.

## Run

```
$ ctest -R api-test-sspc-link-retry
```
