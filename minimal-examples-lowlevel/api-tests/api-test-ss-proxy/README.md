# lws-api-test-ss-proxy

Exercises the proxy side of Secure Streams serialization, in one process.

The test is an SS proxy (`lws_ss_proxy_create()` on a Unix Domain Socket of
its own, in the abstract namespace on Linux), and it also makes raw client
connections to that socket, speaking the serialized SS protocol to the proxy
the way an sspc client process would.  Each connection is one "leg":

|leg|what the client does|what must happen|
|---|---|---|
|server|asks for `srv`, a server streamtype bound to an existing vhost|the proxy refuses to create it: a proxy client can only drive client streams|

The policy is built into the test.

## Build

Needs `LWS_WITH_SECURE_STREAMS_PROXY_API`, `LWS_WITH_CLIENT`,
`LWS_WITH_SERVER` and `LWS_WITH_UNIX_SOCK`, and a JSON policy build (not
`LWS_WITH_SECURE_STREAMS_STATIC_POLICY_ONLY`).  It is registered with ctest
as `api-test-ss-proxy`.

## Run

```
$ ctest -R api-test-ss-proxy
```

or run `lws-api-test-ss-proxy` directly; it takes the usual builtin
switches, eg `-d1151` for more logging.
