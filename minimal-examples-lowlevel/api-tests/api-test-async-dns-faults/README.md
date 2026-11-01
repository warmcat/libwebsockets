# lws-api-test-async-dns-faults

How async dns copes with nameservers that misbehave.  Fake nameservers on
loopback, adopted into the event loop, answer each name in a different bad
way.

|name|the nameservers|expected|
|---|---|---|
|`ok.test`|the first listed never answers (Linux only, at 127.0.0.2), the second answers|found within 1.5s: with nothing known about either server, the question is raced to both|
|`servfail-aaaa.test`|A answered, SERVFAIL for AAAA|found within 1.5s, with the A address|
|`servfail-late-a.test`|SERVFAIL for AAAA, A answered 150ms later|found within 1.5s, with the A address|
|`drop-aaaa.test`|A answered, AAAA dropped|found with the A address when the AAAA retransmits run out, within 12s|
|`servfail.test`|SERVFAIL for both|fails within 3s, not as a timeout|
|`dead.test`, from an http client connection|never answered|`LWS_CALLBACK_CLIENT_CONNECTION_ERROR` saying the lookup timed out, within 12s|

Any other name is NXDOMAIN.

## Run

ctest gives the fake nameservers a free udp port in `LWS_ASYNCDNS_PORT`, the
port the resolver asks its nameservers on, and in `LWS_ASYNCDNS_RESOLV_CONF`
the resolv.conf the test writes listing them, so the platform's own
nameservers are never asked.

```
$ ctest -R api-test-async-dns-faults
```

By hand, set `LWS_ASYNCDNS_PORT` to any free udp port and
`LWS_ASYNCDNS_RESOLV_CONF` to a scratch file:

```
$ LWS_ASYNCDNS_PORT=5353 LWS_ASYNCDNS_RESOLV_CONF=/tmp/rc \
	./bin/lws-api-test-async-dns-faults
```
