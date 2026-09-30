# lws-api-test-ss-proxy

Exercises the proxy side of Secure Streams serialization, in one process.

The test is an SS proxy (`lws_ss_proxy_create()` on a Unix Domain Socket of
its own, in the abstract namespace on Linux), and it also makes raw client
connections to that socket, speaking the serialized SS protocol to the proxy
the way an sspc client process would.  Each connection is one "leg":

|leg|what the client does|what must happen|
|---|---|---|
|server|asks for `srv`, a server streamtype bound to an existing vhost|the proxy refuses to create it (a proxy client can only drive client streams) and hangs up|
|create-fail-then-payload|asks for a streamtype that isn't in the policy, and sends payload after the failed result|the proxy hangs up after the result, without trying to queue the payload|
|sink-goes-first|asks for `sink`, fulfilled by a local sink registered in the process, and sends it 100 bytes; the sink destroys itself on rx, taking the proxied stream with it|the sink gets the payload, the proxy tells the client DESTROYING and does not touch the stream afterwards|

The clients run as the same user as the proxy, which by default may use it.
With `--refused`, the proxy is told only uid / gid 65534 may use it
(`.ss_proxy_perms = "65534:65534"`) and a single leg runs:

|leg|what the client does|what must happen|
|---|---|---|
|refused|connects and asks for `sink`|the proxy drops the connection without creating anything|

That needs the Linux abstract namespace socket, where the proxy checks each
client's credentials itself, and the test not running as root or as 65534;
otherwise it reports itself skipped.

The policy is built into the test.

## Switches

|switch|meaning|
|---|---|
|--refused|Run the leg where the proxy only allows another user|
|--help|Show the switches|

## Build

Needs `LWS_WITH_SECURE_STREAMS_PROXY_API`, `LWS_WITH_CLIENT`,
`LWS_WITH_SERVER` and `LWS_WITH_UNIX_SOCK`, and a JSON policy build (not
`LWS_WITH_SECURE_STREAMS_STATIC_POLICY_ONLY`).  It is registered with ctest
as `api-test-ss-proxy`, and with `--refused` as `api-test-ss-proxy-refused`.

## Run

```
$ ctest -R api-test-ss-proxy
```

or run `lws-api-test-ss-proxy` directly; it takes the usual builtin
switches, eg `-d1151` for more logging.
