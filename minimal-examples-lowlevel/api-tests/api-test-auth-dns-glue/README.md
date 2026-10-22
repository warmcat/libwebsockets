# lws-api-test-auth-dns-glue

Fence for security-audit finding G-288: a zone the authoritative-DNS plugin
(`protocol-lws-auth-dns`) serves may be DHT-published, ie shaped by an
attacker, so looking names up in it must not cost a walk of the whole zone
for each NS RR of a cut (referral glue), or for each label of a qname (the
NSEC3 closest encloser search).

The test builds the plugin in, counting the owner name compares its zone
lookups make, and installs a zone with a 100-NS-RR cut, A and AAAA glue for
every name server, and 4000 more A RRsets, the way the plugin installs zones.

| step | what is done | expected |
|------|--------------|----------|
| 1 | the zone is installed | every RRset is in the zone's owner index |
| 2 | a referral for `foo.big.glue.example A` is made, with room for all of it | 100 NS RRs, 200 glue RRs and the OPT, for at most 32 compares per NS RR (the unindexed walk made one per NS RR per RRset, ~420k) |
| 3 | names, in any case, with and without a trailing dot, are looked up | present ones found, absent ones not, for at most 32 compares each |

It needs no network and takes well under a second.

## Commandline

The test takes no options beyond the usual lws ones.
