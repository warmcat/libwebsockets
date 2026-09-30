# lws minimal secure streams testsfail

The application runs some bulk and failure path tests on Secure Streams,
checking that the right state sequence, timing and payload arrive for each.

Everything it talks to is local.  The ctest starts these fixtures:

Fixture|What it is
---|---
`tf_dns`|`lws-api-test-dns-server` serving `sstf.test.zone.in`: `hbin.sstf.test` resolves to the local fixtures, other names in the zone get NXDOMAIN, names outside it get REFUSED
`hbin`|`lws-minimal-http-server-httpbin`, plain h1
`hbin_tls`|the same with tls, using the `localhost` test cert
`hbin_b_self`|`lws-minimal-http-server-tls`, whose cert is not signed by anything the policy trusts

The test app is built only with `LWS_WITH_SYS_ASYNC_DNS`, and the ctest points
its resolver at the mock with the `LWS_ASYNCDNS_RESOLV_CONF` and
`LWS_ASYNCDNS_PORT` environment variables, so no external resolver or network
is involved.

The tests cover: plain success on h1, h1+tls and h2+tls; stream timeouts while
the server delays; NXDOMAIN reported as UNREACHABLE with the ack arg clear;
resolver REFUSED reported as UNREACHABLE with the ack arg set, after the dns
retry budget; exhausting the policy retries on NXDOMAIN taking at least as long
as the escalating backoff table, including for a raw stream, whose attempts
fail inside the connect call once the NXDOMAIN is cached and which we destroy
from `LWSSSCS_ALL_RETRIES_FAILED`; the same for an endpoint that is all
`${metadata}` nobody set, each attempt going `LWSSSCS_CONNECTING` then
`LWSSSCS_UNREACHABLE`; bulk payload; and tls failure by hostname mismatch and
by untrusted CA.

Every stream must see `LWSSSCS_CREATING` only once.  One bulk stream asks to
connect in `LWSSSCS_CREATING` and then returns `LWSSSSRET_DISCONNECT_ME` from
it: the connection it started must really be dropped and the stream connect
again by itself, still receiving the bulk payload that is sized by the
metadata it only set in `LWSSSCS_CREATING`.  In the proxied build (`-client`,
run by the `sspc-minimaltf` ctest) that disconnect drops the link to the
proxy, and the stream must recover on a new link.

## build

```
 $ cmake . && make
```

## usage

Commandline option|Meaning
---|---
-d <loglevel>|Debug verbosity in decimal, eg, -d15
-c <policy>|Policy file (the ctest passes the configured policy-local.json)
--amount <amount>| Set the amount of bulk data expected, eg, --amount 23456
