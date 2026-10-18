# lws-api-test-sspc-rx-metadata

The SS proxy tells an sspc client about rx metadata in METADATA frames.  A
value can arrive over several reads of the proxy link, and the link can go
down before all of it has come.  The client must only ever show user code a
complete value: until a new value has all arrived, `lws_sspc_get_metadata()`
keeps returning the previous complete value with that name.

The test is an sspc client, and it also plays the proxy, with a raw Unix
Domain Socket listener of its own (in the abstract namespace on Linux)
speaking the serialized SS protocol the way the proxy would.

|step|the proxy|`lws_sspc_get_metadata("md")` must give|
|---|---|---|
|1|creates the stream and sends `md` = `old`|`old`|
|2|sends the start of a METADATA frame with a new 64-byte value for `md`, stopping 5 bytes into the value|`old`|
|3|drops the link|`old`|
|4|on the link the sspc makes again, creates the stream and sends the whole new value|the new value|

## Build

Needs `LWS_WITH_SECURE_STREAMS_PROXY_API`, `LWS_WITH_CLIENT`,
`LWS_WITH_SERVER` and `LWS_WITH_UNIX_SOCK`.  It is registered with ctest as
`api-test-sspc-rx-metadata`.

## Run

```
$ ctest -R api-test-sspc-rx-metadata
```

or run `lws-api-test-sspc-rx-metadata` directly; it takes the usual builtin
switches, eg `-d1151` for more logging.
