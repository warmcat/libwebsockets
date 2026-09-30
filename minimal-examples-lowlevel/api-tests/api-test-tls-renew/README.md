# lws-api-test-tls-renew

An lws client and an lws tls server in one process confirm a server vhost's
tls ctx made by `lws_tls_cert_updated()` is set up like the one it got when
it was created: the tls backends keep things like the alpn and the
client-cert policy on the ctx, not the vhost.

The server vhost is created with `LWS_SERVER_OPTION_IGNORE_MISSING_CERT` and
cert paths where nothing is, the way a vhost waiting for its first ACME cert
is, so it comes up with no ctx at all.  Then:

|case|expected|
|---|---|
|the cert "arrives": `lws_tls_cert_updated()` makes the vhost's first ctx|an h2 request to it is served over h2|
|the cert is renewed: `lws_tls_cert_updated()` makes a replacement ctx|an h2 request is again served over h2|

The cert is handed to `lws_tls_cert_updated()` in memory; the paths only
select the vhost.  It is not built with BearSSL, whose cert load only tries
the file when it is given a path.

## The PKI

|File|What|
|---|---|
|`ca.crt`|A throwaway CA, its key not kept, which the client trusts|
|`server.crt` / `.key`|Server cert for `short.example`, signed by `ca.crt`|

## Running it

```
$ lws-api-test-tls-renew -p 7681 --certs <this dir>
```

|Option|Meaning|
|---|---|
|`-p <port>`|Port of the tls server vhost (default 7681)|
|`-s <address>`|Address the client connects to (default `localhost`)|
|`--certs <dir>`|Dir holding the certs and key (default `.`)|
