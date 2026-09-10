# lws api test gencrypto

Demonstrates how to use and performs selftests for Generic Crypto,
which works the same whatever the tls backend is.

## RSA-PSS coverage

`lws-genrsa.c` contains an RSA-PSS section covering the JWS `PS256`, `PS384`
and `PS512` algs, which runs on every tls backend.  For each alg it

 - signs and verifies a round trip with the generic RSA apis in
   `LGRSAM_PKCS1_OAEP_PSS` mode (PSS salts randomly, so a signature we make
   cannot be compared against a fixed vector),

 - verifies a fixed RFC 8017 RSASSA-PSS signature made outside lws over the
   same key and message, so a backend that agrees with itself while doing the
   wrong thing (PKCS#1 v1.5 in place of PSS, or PSS with the wrong MGF1 hash
   or salt length) is still caught, and

 - checks that a PKCS#1 v1.5 signature over the same hash is *rejected* by
   the PSS verify.

## mbedtls cipher list mapping

On the mbedtls backend only, `lws-mbedtls-cipherlist.c` creates vhosts with
cipher lists in the OpenSSL, IANA and mbedtls spellings and confirms lws maps
them to mbedtls ciphersuite ids; a list entry naming no suite this mbedtls
has, or a list of nothing but OpenSSL cipher class selectors, must fail the
vhost rather than silently leave the mbedtls default suite list in force.

## build

```
 $ cmake . && make
```

## usage

Commandline option|Meaning
---|---
-d <loglevel>|Debug verbosity in decimal, eg, -d15

```
 $ ./lws-api-test-gencrypto
[2018/12/05 08:30:27:1342] USER: LWS gencrypto apis tests
[2018/12/05 08:30:27:1343] NOTICE: Creating Vhost 'default' (serving disabled), 1 protocols, IPv6 off
[2018/12/05 08:30:27:1343] NOTICE: created client ssl context for default
[2018/12/05 08:30:27:1344] NOTICE: test_genaes: selftest OK
[2018/12/05 08:30:27:1344] USER: Completed: PASS
```

