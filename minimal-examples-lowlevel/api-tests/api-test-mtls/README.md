# lws-api-test-mtls

Two lws server vhosts on one listener, each requiring a valid client
certificate from its own CA, and lws clients presenting different ones, in one
process: each vhost's policy has to hold on every transport it is served over,
h1 and h2 over tls, and h3 over quic, and a client cert one vhost's CA vouches
for must get nobody into the other.

The server vhosts have the build's default alpn, so beside their tcp listener
they open a quic one on the same port, as any tls vhost with h3 in its alpn
does.  `srv` trusts client certs signed by `ca.crt`, and takes any SNI name not
on the listener (`LWS_SERVER_OPTION_SNI_FALLBACK`).  `tenant.example.com`
trusts client certs signed by `tenant-ca.crt`, and has a server cert of its own
for that name.  Both answer a request with their name and the CN of the client
cert it was served under.

|client cert|names|expected|
|---|---|---|
|none|`srv`|refused|
|`self-signed.crt`, which `ca.crt` did not sign|`srv`|refused|
|`node2.crt`, signed by `tenant-ca.crt`|`srv`|refused|
|`node1.crt`, signed by `ca.crt`|`tenant.example.com`|refused|
|`node2.crt`|`tenant.example.com`|served by `tenant.example.com`, `cn=node2.example.com`|
|`node1.crt`|`srv`|served by `srv`, `cn=node1.example.com`|

`self-signed.crt` is self-signed under the CA's own name: a client presents
only a cert whose issuer is one the server said it trusts, and this one says
so, so it reaches the server, which has to find out that `ca.crt` did not sign
it.

The `node2` to `tenant.example.com` case is the one that shows the connection
was bound to the vhost its SNI chose, and that vhost's CA recorded as the one
that verified the client cert: had `srv`'s been recorded, as mbedtls before 3.2
did (C-670), `srv` serves him, or the tenant refuses him with a 421.

For each case the server has to have seen a connection of the case's
transport (a tcp accept, or a quic connection), so a refusal on the wrong
transport cannot pass, and the h3 client is not allowed to fall back to tcp.
A refused case is over when the server's connection for it has gone, and
nothing may have been served on it.

The clients naming `tenant.example.com` check the server cert is for that
name, since mbedtls clients send no SNI at all when they skip that check; the
others dial the server by address and skip it.

## The PKI

|File|What|
|---|---|
|`localhost-100y.cert` / `.key`|The usual self-signed test server cert, which `srv` presents|
|`ca.crt`|A throwaway client CA, its key not kept|
|`node1.crt` / `.key`|Client cert for CN `node1.example.com`, signed by `ca.crt`|
|`self-signed.crt` / `.key`|Self-signed client cert under the name of `ca.crt`|
|`tenant.crt` / `.key`|Self-signed server cert for `tenant.example.com`, which the tenant presents|
|`tenant-ca.crt`|A second throwaway client CA, its key not kept|
|`node2.crt` / `.key`|Client cert for CN `node2.example.com`, signed by `tenant-ca.crt`|

## Running it

```
$ lws-api-test-mtls --transport h3 -p 7681 --certs <this dir>
```

|Option|Meaning|
|---|---|
|`--transport h1\|h2\|h3`|The transport the clients use (required)|
|`-p <port>`|Port of the server vhosts, tcp and udp (default 7681)|
|`-s <address>`|Address the clients connect to (default `localhost`)|
|`--certs <dir>`|Dir holding the certs and keys (default `.`)|

ctest runs it once per transport the build has, each with a free port.
