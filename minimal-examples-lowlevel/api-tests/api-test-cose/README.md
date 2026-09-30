# lws api test cose

Selftests for the COSE key, validation and signing apis

 - `keys.c`: COSE key import, export and generation, plus

   - export through output buffers of every size from 1 to 80 bytes must
     give the same CBOR as a one-shot export

   - key set imports are all or nothing: one that fails (or is refused by
     the per-key callback) leaves the keys already in the set untouched,
     and a key whose kid is already in the set is refused
 - `sign.c`: COSE_Sign1, COSE_Sign, COSE_Mac and COSE_Mac0 validation
   against the cose-wg example objects, plus

   - signer / recipient unprotected buckets carrying arrays (an RFC9360
     x5chain-like label 33, one or two items, small or larger than any
     protected bucket) must still validate, since the end of an item of a
     nested array is not the end of the bucket

   - COSE_Sign1, COSE_Mac0 and two-signer COSE_Sign signing of a payload
     much bigger than the output buffer, passed in chunks bigger and smaller
     than it, must validate and carry exactly the payload that was signed

   - EdDSA COSE_Sign1 signing and validation, where the TLS backend has EdDSA

## build

```
 $ cmake . && make
```

## usage

Commandline option|Meaning
---|---
-d <loglevel>|Debug verbosity in decimal, eg, -d15
--help|Show this help information

```
 $ ./lws-api-test-cose
[2026/09/30 15:38:30:7412] U: LWS COSE api tests
...
[2026/09/30 15:38:30:8063] U: Completed: PASS
```
