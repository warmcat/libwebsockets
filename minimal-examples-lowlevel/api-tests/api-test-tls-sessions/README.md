# lws-api-test-tls-sessions

An lws client and an lws tls server in one process confirm how the client's
tls session cache names the sessions it keeps.

A session is cached under a tag made from the client vhost's name, the host
and the port, and a later connection resumes the session cached under its own
tag, skipping the server certificate check, since a resumed handshake carries
no certificate.  So the tag must identify the host exactly: a host name too
long for the tag must not be cached at all, rather than under a truncated tag
that another host sharing its beginning would find.

The server's cert, signed by `ca.crt`, which the client trusts, is valid for
`short.example` and for a 99-character name.  The client makes a fully
verified connection to each, by name, and then asks
`lws_tls_session_dump_save()` what is cached:

|connection to|expected|
|---|---|
|`short.example`|a session is cached for it, so the cache is in play|
|the 99-character name|no session is cached for it, and none for another name with the same first 91 characters either|

It is not built with mbedtls or schannel, which have no session dump.  With
gnutls, the server is held to TLS 1.2: a gnutls tls server issues no TLS 1.3
session tickets, so a TLS 1.3 client of it would have no session to cache.

## The PKI

|File|What|
|---|---|
|`ca.crt`|A throwaway CA, its key not kept|
|`server.crt` / `.key`|Server cert for `short.example` and the long name, signed by `ca.crt`|

## Running it

```
$ lws-api-test-tls-sessions -p 7681 --certs <this dir>
```

|Option|Meaning|
|---|---|
|`-p <port>`|Port of the tls server vhost (default 7681)|
|`-s <address>`|Address the client connects to (default `localhost`)|
|`--certs <dir>`|Dir holding the certs and key (default `.`)|
