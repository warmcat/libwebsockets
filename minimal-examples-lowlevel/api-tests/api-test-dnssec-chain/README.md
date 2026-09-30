# lws api test dnssec-chain

Confirms the async-dns DNSSEC validator authenticates the signer's keys down a
chain of DS records from the trust anchor, before it believes anything they
signed.

The test mints ECDSA keys for a private hierarchy (`.`, `tld.`, `zone.tld.`,
plus a `bad.tld.` whose DS signature is spoiled and a `rogue.tld.` whose
DNSKEY RRset is signed by a key its DS doesn't vouch for), serves it signed
from a fake nameserver on a loopback UDP socket, and makes its own root KSK
the only trust anchor with `lws_async_dns_dnssec_set_root_anchors()`.

The context's DNSSEC mode is left OFF, and each query asks with
`LWS_ADNS_WANT_DNSSEC`, the way the DHT DNSSEC plugin looks up a domain's DS.

It checks that

 - a DS answer from the parent zone, an A answer and the zone's own DNSKEY
   RRset (keys of mixed lengths, so the canonical RRset order matters) validate
 - the DS asked for again is served from the cache and is still reported
   `LWS_ADNS_DNSSEC_VALID`
 - answers from `bad.tld.` and `rogue.tld.` are refused
 - a name whose signed CNAME points at a signed name validates with the
   target's address, and the target is asked about on its own although the
   CNAME answer brought its records along, like a recursive resolver's does
 - a name whose CNAME is unsigned is refused, although the name it points at
   would validate
 - a validated address answer's cache entry holds only the A RRset, not the
   RRSIG that came with it
 - with the context mode set to `LWS_ADNS_DNSSEC_REQUIRE` by
   `lws_async_dns_dnssec_set_mode()`, a lookup that doesn't ask with
   `LWS_ADNS_WANT_DNSSEC` is validated anyway, also after the nameservers were
   reloaded
 - each zone's keys were only fetched once for all of that
 - after the trust anchor is replaced by one that matches no root key, the
   chain is walked again from the root and nothing validates, not even what
   was cached as validated under the old anchor
 - the context can be destroyed while a query is parked on a chain walk that
   is still in flight (the nameserver never answers the root's DNSKEY), which
   is meaningful when run under ASan

Nothing leaves the machine.  It needs `LWS_WITH_SYS_ASYNC_DNS_DNSSEC`, and
isn't built on Windows, where the fake nameserver's BSD socket isn't available.

## build

```
 $ cmake . && make
```

## usage

```
 $ ./lws-api-test-dnssec-chain
[2026/09/26 18:00:00:0000] U: LWS API selftest: DNSSEC chain of trust
[2026/09/26 18:00:00:0100] U: step 0 (zone.tld type 43): validated as expected
...
[2026/09/26 18:00:00:0400] U: Completed: PASS
```
