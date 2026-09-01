# lws-api-test-sspc-streamtype

Fences the serialized client (sspc) streamtype length cap
(`LWS_SS_SER_STREAMTYPE_MAX_LEN`, 31 chars).

The streamtype is serialized to the proxy inside a fixed-size frame and the
proxy-side parser only accepts streamtypes up to a fixed maximum length;
`lws_sspc_create()` refuses over-long streamtypes at creation time so no
frame is ever composed that claims more than was written into it.

The test needs no running proxy: the cap fires before any connection
attempt.  It asserts that

- a streamtype one char over the cap is refused at creation,
- a streamtype long enough to overrun the client-side tx composition
  scratch (60 chars) is refused at creation, and
- a boundary-length streamtype (exactly `LWS_SS_SER_STREAMTYPE_MAX_LEN`
  chars) is still accepted.

## Build

Enable `LWS_WITH_SECURE_STREAMS_PROXY_API` and `LWS_WITH_CLIENT`, then the
test builds and is registered with ctest as
`api-test-sspc-streamtype`.

## Run

```
$ ctest -R api-test-sspc-streamtype
```
