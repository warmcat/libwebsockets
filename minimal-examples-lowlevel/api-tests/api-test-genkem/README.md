# lws api test genkem

Selftests for the generic Key Encapsulation Mechanism apis, `lws_genkem_*`,
which do ML-KEM (FIPS 203) the same way whatever the TLS backend.  Where the
TLS library has ML-KEM (eg, OpenSSL 3.5+) it is used, otherwise lws uses its
own implementation; the test logs which one each parameter set used.

For each of ML-KEM-512, ML-KEM-768 and ML-KEM-1024 it checks

 - known answers made by OpenSSL 3.5's ML-KEM (`kat-vectors.h`): the keypair
   made from a fixed seed, decapsulating a fixed ciphertext to its shared
   secret, and the FIPS 203 implicit rejection shared secret for a copy of
   that ciphertext with one bit flipped,

 - restoring the keypair from its seed, from its DK, and from its DK with
   its EK, and encapsulating with only the EK,

 - round trips between random keypairs and a peer that only has the EK,

 - that the FIPS 203 input checks refuse an EK with an out of range
   coefficient and a DK whose embedded hash of its EK is wrong, and that
   wrong lengths, a DK given with someone else's EK, and api misuse are
   refused.

## build

Needs `-DLWS_WITH_GENCRYPTO=1`.

```
 $ cmake . && make
```

## usage

Commandline option|Meaning
---|---
-d <loglevel>|Debug verbosity in decimal, eg, -d15

```
 $ ./lws-api-test-genkem
[2026/11/09 12:00:00:0000] USER: LWS genkem apis tests
[2026/11/09 12:00:00:0000] USER: test_kat: ML-KEM-512 using lws's ML-KEM
...
[2026/11/09 12:00:00:0000] USER: Completed: PASS
```
