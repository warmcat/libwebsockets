# lws-api-test-jit-trust

End to end test of the real JIT Trust flow (see `READMEs/README.jit-trust.md`),
locally, with no internet and without any `LCCSCF_ALLOW_SELFSIGNED` or similar
relaxation of the client's validation.

One process has a client vhost that trusts only the app's own test CA, three
tls server vhosts, and a `jit_trust_query()` system op answering from a small
trust blob that holds only the test root CA.  The blob is built at startup from
the root's DER and SKID, and the client vhost is given the app CA's DER, all
compiled into `main.c`.

## Steps

|Step|Server|Expected|
|---|---|---|
|untrusted|untrusted|Every attempt fails; each asks about the untrusted root, which the blob doesn't have|
|cold|trusted|The first attempt fails, JIT Trust asks about each of the four AKIDs in the chain, finds the root and makes a vhost trusting it; the retry completes on it|
|warm|trusted|The first attempt completes on the JIT Trust vhost, no queries|
|cached|trusted|After the JIT Trust vhost idles out, the first attempt completes on a vhost regenerated from the trust cache, asking only for the root|
|other port|app CA|Same address as trusted, another port: the first attempt completes on the client's own vhost, with no queries.  The trust cache entry for trusted is not for this server|
|rotated|trusted|Trusted now serves the app CA leaf (`lws_tls_cert_updated()`).  The first attempt is bound to the JIT Trust vhost by the cache and fails, which forgets the cache entry, so the retry completes on the client's own vhost|
|rotated, later|trusted|After the JIT Trust vhost idles out, the first attempt completes on the client's own vhost with no queries: no cache entry was left to regenerate it from|

The JIT Trust vhost is named from the SKIDs of the CAs it trusts, so the test
also checks it has the name made from the root's SKID alone.

## The test PKI

The chains have the shape of real ones: the leaf certs have no Subject Key Id,
like Let's Encrypt leaf certs, just an Authority Key Id naming their issuer.
The trusted server sends a leaf and three intermediates, the most JIT Trust
collects, which is the shape of warmcat.com's chain that JIT Trust was once
unable to sort.

|File|What|
|---|---|
|`trusted-chain.pem`|Leaf for `localhost`, `127.0.0.1` and `::1`, then intermediates 3, 2 and 1, each issued by the next.  Intermediate 1 was issued by the test root, whose DER and SKID are in `main.c`|
|`trusted-leaf.key`|The trusted leaf's key|
|`untrusted-leaf.pem`|Leaf of the same shape, issued directly by a root that is not in the trust blob|
|`untrusted-leaf.key`|The untrusted leaf's key|
|`app-leaf.pem`|Leaf of the same shape, issued directly by the app's own CA, whose DER is in `main.c`|
|`app-leaf.key`|The app CA leaf's key|

The CA keys are not kept.  The certs were made with openssl 3.5 like this, from
an `ext.cnf` holding the extension sections

```
[root]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = none

[inter]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always

[leaf]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost, IP:127.0.0.1, IP:::1
subjectKeyIdentifier = none
authorityKeyIdentifier = keyid:always
```

```
K="-newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes"
D="-not_before 20260101000000Z -not_after 21251231235959Z"

openssl req -x509 $K -keyout root.key -out root.pem -subj "/O=libwebsockets-test/CN=lws jit trust test root" -extensions root -config ext.cnf $D -sha256
openssl req -x509 $K -keyout uroot.key -out uroot.pem -subj "/O=libwebsockets-test/CN=lws jit trust untrusted root" -extensions root -config ext.cnf $D -sha256
openssl req -x509 $K -keyout aroot.key -out aroot.pem -subj "/O=libwebsockets-test/CN=lws jit trust test app root" -extensions root -config ext.cnf $D -sha256
ca=root; ser=0x1001
for i in 1 2 3; do
	openssl req $K -keyout inter$i.key -out inter$i.csr -subj "/O=libwebsockets-test/CN=lws jit trust test intermediate $i" -config ext.cnf
	openssl x509 -req -in inter$i.csr -CA $ca.pem -CAkey $ca.key -set_serial $ser -extfile ext.cnf -extensions inter $D -sha256 -out inter$i.pem
	ca=inter$i; ser=$((ser + 1))
done
openssl req $K -keyout trusted-leaf.key -out leaf.csr -subj "/O=libwebsockets-test/CN=localhost" -config ext.cnf
openssl x509 -req -in leaf.csr -CA inter3.pem -CAkey inter3.key -set_serial 0x2001 -extfile ext.cnf -extensions leaf $D -sha256 -out leaf.pem
openssl req $K -keyout untrusted-leaf.key -out uleaf.csr -subj "/O=libwebsockets-test/CN=localhost" -config ext.cnf
openssl x509 -req -in uleaf.csr -CA uroot.pem -CAkey uroot.key -set_serial 0x3001 -extfile ext.cnf -extensions leaf $D -sha256 -out untrusted-leaf.pem
openssl req $K -keyout app-leaf.key -out aleaf.csr -subj "/O=libwebsockets-test/CN=localhost" -config ext.cnf
openssl x509 -req -in aleaf.csr -CA aroot.pem -CAkey aroot.key -set_serial 0x4001 -extfile ext.cnf -extensions leaf $D -sha256 -out app-leaf.pem
cat leaf.pem inter3.pem inter2.pem inter1.pem > trusted-chain.pem
openssl x509 -in root.pem -outform der | xxd -i
openssl x509 -in root.pem -noout -ext subjectKeyIdentifier
openssl x509 -in aroot.pem -outform der | xxd -i
```

## Options

|Option|Meaning|
|---|---|
|`-p <port>`|Port for the trusted server (default 7681)|
|`--untrusted-port <port>`|Port for the untrusted server (default 7682)|
|`--appca-port <port>`|Port for the app CA server (default 7683)|
|`--server <address>`|Address to connect to (default `127.0.0.1`)|
