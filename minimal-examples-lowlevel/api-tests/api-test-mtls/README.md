# lws-api-test-mtls

An lws server vhost that requires a valid client certificate, and lws clients
presenting different ones, in one process: the vhost's policy has to hold on
every transport it is served over, h1 and h2 over tls, and h3 over quic.

The server vhost has the build's default alpn, so beside its tcp listener it
opens a quic one on the same port, as any tls vhost with h3 in its alpn does.
It trusts client certs signed by `ca.crt`, and answers a request with the CN
of the client cert it was served under.

|client vhost|presents|expected|
|---|---|---|
|`none`|no client cert|refused|
|`self`|`self-signed.crt`, which `ca.crt` did not sign|refused|
|`node1`|`node1.crt`, which `ca.crt` signed|served, with `cn=node1.example.com`|

`self-signed.crt` is self-signed under the CA's own name: a client presents
only a cert whose issuer is one the server said it trusts, and this one says
so, so it reaches the server, which has to find out that `ca.crt` did not sign
it.

For each case the server has to have seen a connection of the case's
transport (a tcp accept, or a quic connection), so a refusal on the wrong
transport cannot pass, and the h3 client is not allowed to fall back to tcp.
A refused case is over when the server's connection for it has gone, and
nothing may have been served on it.

## The PKI

|File|What|
|---|---|
|`localhost-100y.cert` / `.key`|The usual self-signed test server cert, which the server presents|
|`ca.crt`|A throwaway client CA, its key not kept|
|`node1.crt` / `.key`|Client cert for CN `node1.example.com`, signed by `ca.crt`|
|`self-signed.crt` / `.key`|Self-signed client cert under the name of `ca.crt`|

## Running it

```
$ lws-api-test-mtls --transport h3 -p 7681 --certs <this dir>
```

|Option|Meaning|
|---|---|
|`--transport h1\|h2\|h3`|The transport the clients use (required)|
|`-p <port>`|Port of the server vhost, tcp and udp (default 7681)|
|`-s <address>`|Address the clients connect to (default `localhost`)|
|`--certs <dir>`|Dir holding the certs and keys (default `.`)|

ctest runs it once per transport the build has, each with a free port.
