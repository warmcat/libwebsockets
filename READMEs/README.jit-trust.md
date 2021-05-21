# JIT trust

## Background

Most systems using openssl rely on a system trust bundle that openssl
was compiled to load at library init.  This is a bit expensive, since
it instantiates over 100 CA X.509 certs, but most modern Linux systems
don't really notice the expense, the advantage is client connections
have all the trusted root certs available in memory to perform
validation.

For mbedtls, it does not support cert bundle autoload out of the box
and for the kind of systems using mbedtls, for the kind of systems that
choose mbedtls, they don't want to permanently dedicate the heap needed
to hold over 100 CAs in memory all the time.

If the device only connects to endpoints that are signed by a specific
CA, you can just prepare the connection with the known trusted CA, that's
the approach the examples take.

However if you have a browser type application that could connect
anywhere, but you don't have heap spare to preload all the CAs, you need
something like "JIT trust".

## JIT trust overview

The basic approach is to connect to the server to retrieve its certificates,
then study the certificates to determine the identity of the missing
trusted cert we should be trying to validate with.

We attempt to get the trusted cert from some local or remote store, and
retry the connection having instnatiated the missing CA cert as trusted 
for that connection, if it is one that we do actually trust.

If the relationship was valid, the tls negotiation should then complete
successfully, and we can cache the CA cert and the host -> CA cert
pre-trust requirement so future connections can work first time.

## Subject Key Id and Authority Key Id

When a certificate is issued, it is signed by a parent certificate key
to prove it was issued by the owner of that parent's private key.  At
the same time, the certificate is marked with an "Authority Key ID"
(AKID) blob, that is usually hashed down from the parent certificate's
public key.

All of the certificates also publish their personal "Subject Key ID" or
SKID, so you can bind one certifcate's AKID to the certificate it
refers to by searching for one that has the same SKID.

Basically this AKID on a certificate is guiding the validator with
information about which certificate is next in the chain of trust
leading back to a trusted CA.  (Lying about it doesn't help an attacker,
because we're only using the AKID to get the CA certificate and then
try to do the full signature check using it, if it's not really
signed by the AKID cert it told, validation will just fail.)

## Converting the Mozilla trust bundle for JIT trust

Lws provides a bash script `./scripts/mozilla-trust-gen.sh` that can fetch the
latest Mozilla CA trust bundle for certs usable for tls validation, and convert
it to three different forms to allow maintaining the trust bundle in different
ways for different kinds of device to consume.

 - as a webroot directory, so you can server trusted DERs, with
   symlink indexes to the CA certs by SKID and issuer/serial

 - as an atomic binary blob, currently about 143KB, with structure
   at the start pointing to DER certs and indexes inside

 - a C-compiler friendly `uint8_t` array version of the blob,
   so it can be compiled into .rodata directly if necessary.

Currently there are 127 certs in the trust bundle, and the whole
blob is about 143KB uncompressed.

## Considerations about maintaining the trust blob

Mozilla update their trust bundle at intervals, and there have
been at least three cases where they have removed or distrusted CAs
from it, because they have issued dangerous certificates, (like
one for `*` that will validate anything at all).

The certs in the trust bundle expire, currently 10/127 will expire
within 3 years and 50/127 over the next 10 years.

So part of using the trust bundle is building in some way to update
what is trusted over the lifetime of the device, which may exceed
10 years.

Depending on the device, it may not be any problem to
keep the trust blob in the firmware, and update the firmware ongoing
every few months.  So you could build it into the firmware using
the C array include file.

Another device may have difficulty updating the firmware outside of
emergencies, it could keep the trust blob in a separate area and
update it separately.  Having it as a single blob makes it easy to
fetch and update.

Finally other devices, say in ESP32 class, may not have space or desire
to store the trust blob in the device at all, it could query a remote
server on demand to check for any trusted CA matching a given AKID and
retrieve and cache it in volatile ram.  This would use the webroot
produced by the script, via tls and a fixed CA cert outside this system.

## Format of the JIT trust blob

The trust blob layout is currently

```
00:  54 42 4c 42     Magic "TBLB"
04:  00 01           MSB-first trust blob layout version
06:  XX XX           MSB-first count of certificates
08:  XX XX XX XX     MSB-first trust blob generation unix time
0c:  XX XX XX XX     MSB-first offset from blob start of cert length table
10:  XX XX XX XX     MSB-first offset from blob start of SKID length table
14:  XX XX XX XX     MSB-first offset from blob start of SKID table
18:  XX XX XX XX     MSB-first total blob length

1c:  XX .. XX        DER certs (start at +0x1c)
  :  XX .. XX        DER cert length table (MSB-first 16-bit per cert)
  :  XX .. XX        SKID length table (8-bit per cert)
  :  XX .. XX        SKID table (variable per cert)
```

## Enabling JIT Trust

```
$ cmake .. -DLWS_WITH_TLS_JIT_TRUST=1
```

## Processing of x509 AKID and SKIDs

With mbedtls, we use a callback offered by the library to study each
x509 cert sent by the server in turn.  We parse out the SKID and AKID
on each one and stash them (up to 4 deep).

After the validation fails, lws has collected all the AKID and SKIDs
that were in certs sent by the server.  Since these may be sent in any
order, may be malicious, and may even contain the (untrusted) root CA,
they are sorted into a trust path using the AKID and SKID relationships
to end up with the identity of the needed CA cert in the first entry's
AKID.

There's also a case where the root cert was wrongly sent by the server
that we need to use the first entry's SKID, to get our own trusted
copy of the same root cert, if we do trust it.

We query an `lws_system_ops` handler which does whatever the policy is
to query for a trusted CA and get the DER, if found, it is cached so
it will be preloaded next time.

## APIs related to JIT Trust 

Systems that support JIT trust define an `lws_system_ops` callback
that does whatever the system needs to do for attempting to acquire
a trusted cert with a specified SKID or issuer/serial.

```
int (*jit_trust_query)(struct lws_context *cx, const uint8_t *skid, size_t skid_len, void *got_opaque);
```

The ops handler doesn't have to find the trusted cert immediately
before returning, it is OK starting the process and later if successful
calling a helper `lws_tls_jit_trust_got_cert_cb()` with the `got_opaque`
from the query.  This will cache the CA cert so it's available at the
next connection retry for preloading.

An implementation suitable for `ops->jit_trust_query` using trust blob lookup
in .rodata will be provided.


## Modifications needed for mbedtls

A patch is provided in `../contrib/mbedtls-akid-skid.patch` that currently has to
be applied to mbedtls to add the necessary apis for AKID and SKID querying.

