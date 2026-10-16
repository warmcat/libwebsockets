# lws-api-test-cert-dist

End to end test of certificate distribution, between the `lws-cert-dist-server`
and `lws-cert-dist-client` plugins over mTLS.

Both plugins are composed into the test (`compose-cert-dist-*.c`, one per
translation unit since the two plugins' statics share names) and brought up on
two vhosts from a lejp-conf config, the same JSON lwsws reads, that the test
writes into a private work dir under `/tmp` along with the server's PKI tree:

 - vhost `cds` serves `lws-cert-dist-server` over TLS and requires a client
   cert signed by `ca.crt`
 - vhost `cdc` runs `lws-cert-dist-client`, with three `certs` entries and so
   three mTLS links to `cds`
 - vhost `node1-svc` is a tls server vhost whose cert and key are `node1`'s
   installed `fullchain.pem` and `privkey.pem`.  It doesn't listen, and comes
   up without them (`ignore-missing-cert`), since nothing is installed yet

Both plugins spawn their privileged stubs, which are the test executable run
again with `--lws-stub=`.  Their sockets go in the work dir, via the plugins'
`stub-dir` pvo, instead of the default `/var/run`, so the test needs no
privileges.

## The fake PKI

|File|What|
|---|---|
|`localhost-100y.cert` / `.key`|The usual self-signed test server cert. The server presents it, and the client trusts it by its `ca-filepath` pvo|
|`ca.crt`|A throwaway mTLS CA, its key not kept. The server trusts client certs it signed|
|`node1.crt` / `.key`|Client cert for CN `node1.example.com`, signed by `ca.crt`|
|`node2.crt` / `.key`|Client cert for CN `node2.example.com`, signed by `ca.crt`|

The cert and key distributed for `node1.example.com` are just pairs the test
has to hand: `localhost-100y`, then `node2` for the renewal, `localhost-100y`
again for the renewal whose install fails at first, and `node2` again for the
one made while the server's record of the cert it issued `node1` is wrong, and
`node1` with junk appended for the last one.  `example.com` has a cert of its
own beside them, the `node2` pair, which `node1` must never get.  They have to
be real pairs, since the server only sends a key that belongs to its cert.  The
test stores them the way the acme client does with the dnssec monitor:
timestamped leaf cert, key and fullchain files in `certs/production/crt` and
`key`, with `node1.example.com-latest*` symlinks moved onto each in turn and
the outgoing ones kept as `node1.example.com-previous*`.  The server is only
provisioned to hand them to `node1.example.com`, by holding the client cert it
issued it, `node1.crt`, as
`dist-client/distribution-client-node1.example.com.crt`.

## What is checked

 - `node1` gets the cert and key for its own name, `node1.example.com`, and not
   the domain's, installed as `fullchain.pem` and `privkey.pem` symlinks to
   timestamped siblings in a private dir, with the key not readable by anyone
   else
 - with `LWS_WITH_JOSE`, a renewal stopped where the links point to the new
   key and the old fullchain is not sent: `node1` keeps the pair it has
 - when the renewal completes, the new `-latest` pair (not the `-previous`
   one, nor a leaf-only cert) is pushed down the link that is already up and
   `node1` installs it
 - a renewal pushed while `node1`'s install dir is writable by its group is
   not installed, since the client's stub won't write a key into a dir others
   can plant files in, and `node1` keeps the pair it has.  Once the dir is
   private again, the client's retry, made about 10s later, installs it
   without anything changing on the server
 - while the server's record of the client cert it issued `node1` is a
   different cert, a renewal does not reach `node1`, although the cert it
   presents is signed by the CA and names `node1.example.com`
 - a further "renewal" whose fullchain is not plain PEM (it carries a double
   quote, which would end the string it travels in inside the request to the
   client's privileged stub, followed by a second `"subdomain"` naming a
   sibling install dir) is refused: `node1` keeps the pair it has and nothing
   appears under the other name
 - each time `node1` installs a new pair, the client hands `node1-svc` copies
   of it, and the vhost serves its cert.  The stub writes the files where the
   vhost may not be able to read them, eg, after lwsws dropped its
   privileges, so the copies are how the vhost gets the pair.  The test can
   read the files itself, so to tell the two apart, `node1`'s install dir is
   moved aside as soon as the new pair appears in it, and only put back once
   `node1-svc` serves the new cert: the vhost would only look at its files
   about 2s after they changed, and find them gone
 - `node2`, trusted for mTLS but not provisioned, gets nothing
 - `node3`, presenting a cert `ca.crt` did not sign, fails the handshake and
   gets nothing

## Running it

```
$ lws-api-test-cert-dist -p 7681 --certs <this dir>
```

|Option|Meaning|
|---|---|
|`-p <port>`|Port for the distribution server (default 7681)|
|`-s <address>`|Address the client uses for the server (default `localhost`)|
|`--certs <dir>`|Dir holding the test certs and keys (default `.`)|

ctest runs it with a free port and the build's local server address.
