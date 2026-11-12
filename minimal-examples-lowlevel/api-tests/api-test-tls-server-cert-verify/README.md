# lws-api-test-tls-server-cert-verify

With the mbedTLS backend, a tls client is given each cert of the server's
chain in `LWS_CALLBACK_PERFORM_SERVER_CERT_VERIFICATION` (the same callback as
`LWS_CALLBACK_OPENSSL_PERFORM_SERVER_CERT_VERIFICATION`), from the top of the
chain down to the server's own cert at depth 0:

|Argument|With mbedTLS|
|---|---|
|`user`|the cert, a `mbedtls_x509_crt *`|
|`in`|a `uint32_t *` to mbedtls' `MBEDTLS_X509_BADCERT_*` flags for the cert|
|`len`|the cert's depth in the chain|

The flags lws judges the connection on after the handshake are the ones the
callback leaves: it can clear them to accept a cert mbedtls refused, or set
some to refuse it.  Returning nonzero fails the handshake at once, whatever
`LCCSCF_ALLOW_SELFSIGNED`, `LCCSCF_ALLOW_EXPIRED` or `LCCSCF_ALLOW_INSECURE`
say, which is what pinning needs.

A server vhost `srv` presents the self-signed `localhost-100y.cert`.  Client
vhost `trusted` has that cert as its CA, `untrusted` only `unrelated-ca.crt`.
The pin is the SHA-256 of the SubjectPublicKeyInfo of `localhost-100y.cert`,
the cert's `pk_raw`.  Each case connects to `srv`, its callback acting on the
server's cert:

|Case|From|The callback, at depth 0|Connecting to `srv`|
|---|---|---|---|
|`observe`|`trusted`|does nothing|served|
|`pin-match`|`trusted`|returns 0, the pin matching|served|
|`pin-mismatch`|`trusted`|returns 1, the pin not matching|refused, the error saying the callback refused it|
|`pin-mismatch-insecure`|`trusted`, `LCCSCF_ALLOW_INSECURE`|returns 1, the pin not matching|refused all the same|
|`flag`|`trusted`|sets `MBEDTLS_X509_BADCERT_OTHER`, returns 0|refused|
|`untrusted`|`untrusted`|does nothing|refused: nothing it trusts signed the cert|
|`untrusted-pinned`|`untrusted`|clears the flags, the pin matching|served|

Every case also fails if the callback was not made for the server's cert,
since a pin would then be silently ignored: mbedTLS 3.6.0 does not make it on
TLS 1.3 connections.

## Running it

```
$ lws-api-test-tls-server-cert-verify -p 7681 --certs <this dir>
```

|Option|Meaning|
|---|---|
|`-p <port>`|Port of the server vhost (default 7681)|
|`-s <address>`|Address the clients connect to (default `localhost`)|
|`--certs <dir>`|Dir holding the certs and key (default `.`)|
