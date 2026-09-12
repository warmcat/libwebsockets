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
as the escalating backoff table; bulk payload; and tls failure by hostname
mismatch and by untrusted CA.

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
