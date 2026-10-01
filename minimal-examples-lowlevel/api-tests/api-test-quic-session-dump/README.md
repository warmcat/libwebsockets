# lws-api-test-quic-session-dump

An lws h3 server and lws quic clients in one process confirm that a quic
client's tls session can be kept outside the process, and resumed with 0-RTT
from there.

Quic sessions are cached apart from tls over tcp ones for the same host and
port: a client sends 0-RTT early data under whatever session it resumes, and
a ticket from one transport was issued for another alpn and carries the wrong
transport parameters for the other.  So `lws_tls_session_dump_save_flags()` and
`lws_tls_session_dump_load_flags()` take `LWS_TLS_SESSION_DUMP_F_QUIC` to
address the quic session, and without it only see the tls over tcp one.

Three client vhosts, each with its own session cache, connect over h3 to
`short.example`, fully verifying the server, and all willing to send 0-RTT:

|client|before connecting|expected|
|---|---|---|
|`cli1`|nothing cached|a full handshake.  Afterwards its session can be saved with `LWS_TLS_SESSION_DUMP_F_QUIC`, and nothing is found without it, or with an unknown flag|
|`cli2`|cli1's session loaded with `LWS_TLS_SESSION_DUMP_F_QUIC`|the session is resumed, and a server that takes 0-RTT receives the request as 0-RTT|
|`cli3`|cli1's session loaded without the flag, as a tcp session|the h3 connection does not use it: no 0-RTT is offered|

Only a gnutls quic server takes 0-RTT, and not before gnutls 3.8.4.  The
openssl-family ones (BoringSSL, AWS-LC, quictls, wolfSSL) never do, lws having
no replay protection for early data there.  Against those servers, cli2's
request must arrive in 1-RTT, whether or not the client tried 0-RTT first.

`cli2` and `cli3` need the session `cli1` saved, and are reported as skipped
if `cli1` fails.

It is not built with mbedtls or schannel, which have no session dump.

## The PKI

|File|What|
|---|---|
|`ca.crt`|A throwaway CA, its key not kept|
|`server.crt` / `.key`|Server cert for `short.example`, signed by `ca.crt`|

## Running it

```
$ lws-api-test-quic-session-dump -p 7681 --certs <this dir>
```

|Option|Meaning|
|---|---|
|`-p <port>`|UDP port of the h3 server vhost (default 7681)|
|`-s <address>`|Address the server binds and the clients connect to (default `localhost`)|
|`--certs <dir>`|Dir holding the certs and key (default `.`)|
