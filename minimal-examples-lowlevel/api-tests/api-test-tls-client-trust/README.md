# lws-api-test-tls-client-trust

A CA added to a client vhost after it was created, with
`lws_tls_client_vhost_extra_cert_mem()`, must be trusted by that vhost only.

The OpenSSL and OpenHiTLS backends share one client tls ctx between vhosts
created with the same client tls configuration, to save a copy of the OS
trust store per vhost, and the trust store belongs to the ctx.  Before G-392,
trust added to one vhost reached every vhost sharing its ctx, and every vhost
created like it later.  Now adding trust to a ctx another vhost shares is
refused, a ctx that was given trust is never shared afterwards, and
`.client_ssl_ctx_unshared` in the creation info gives a vhost a ctx of its own
to add trust to.  Secure Streams trust stores and JIT trust vhosts, which add
the rest of their certs after creation, are created that way.

A server vhost `srv` presents the self-signed `localhost-100y.cert`.  The
client vhosts trust only `unrelated-ca.crt`, with the OS trust store off, so
one reaches `srv` only if `localhost-100y.cert` was added to it.  They are
created in this order:

|vhost|created with|then|connecting to `srv`|
|---|---|---|---|
|`a`|`unrelated-ca.crt` in memory||refused|
|`b`|the same as `a`|given `localhost-100y.cert`: refused where it shares `a`'s ctx|not tried, it depends on the backend|
|`c`|the same, but `.client_ssl_ctx_unshared`|given `localhost-100y.cert`, which must work|served|
|`d`|the same as `a`||refused: it must not have joined `c`|
|`e`|`unrelated-ca.crt` by its path, which nobody else has|given `localhost-100y.cert`, which must work: it shares with nobody|served|
|`f`|the same as `e`||refused: it must not have joined `e`, whose trust is its own now|

The clients verify the server cert for real, with no relaxations.

## The OS trust store

With `--os-trust`, only `g` and `h` are made and run instead.  They have no CA
of their own and the OS trust store on.  The ctest runs it with
`SSL_CERT_FILE` naming `localhost-100y.cert`, so that the OpenSSL family's
default verify paths, which stand for the OS trust store, are all that lets
them reach `srv`.  It is run only on the OpenSSL family.

Loading the OS trust store is by far the most expensive part of making a
client tls ctx, and every tls vhost has one, though most never connect.  So
the OS trust is loaded into a ctx by its first client connection, not when
the ctx is made.

|vhost|created with|connecting to `srv`|
|---|---|---|
|`g`|no CA, the OS trust store on|served: its connection loads the OS trust first|
|`h`|the same as `g`, sharing its ctx|served|

## Running it

```
$ lws-api-test-tls-client-trust -p 7681 --certs <this dir>
```

|Option|Meaning|
|---|---|
|`-p <port>`|Port of the server vhost (default 7681)|
|`-s <address>`|Address the clients connect to (default `localhost`)|
|`--certs <dir>`|Dir holding the certs and key (default `.`)|
|`--os-trust`|Run the OS trust store cases `g` and `h` instead, see above|
