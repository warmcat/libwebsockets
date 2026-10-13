# lws minimal example for JWE

Demonstrates how to encrypt and decrypt using JWE and JWK, providing a
commandline tool for creating encrypted JWE and decoding them.

## build

```
 $ cmake . && make
```

## usage

Stdin is either the plaintext (if encrypting) or JWE (if decrypting).

Stdout is either the JWE (if encrypting) or plaintext (if decrypting).

You must pass a private or public key JWK file in the -k option if encrypting,
and must pass a private key JWK file in the -k option if decrypting.  To be
clear, for asymmetric keys the public part of the key is required to encrypt,
and the private part required to decrypt.

For convenience, a pair of public and private keys are provided,
`key-rsa-4096.private` and `key-rsa-4096.pub`, these were produced with just

```
 $ lws-crypto-jwk -t RSA -b 4096 --public key-rsa-4096.pub >key-rsa-4096.private
```

Similar keys for EC modes may be produced with

```
 $ lws-crypto-jwk -t EC -v P-256 --public key-ecdh-p-256.pub >key-ecdh-p-256.private
```

and for AES ("octet") symmetric keys

```
 $ lws-crypto-jwk -t OCT -b 128 >key-aes-128.private
```

JWEs produced with openssl and mbedtls backends are completely interchangeable.

## Supported algorithms

Key management ("alg", the first part of `-e`)|Content encryption ("enc", the second part of `-e`)
---|---
`RSA-OAEP`, `RSA-OAEP-256`|`A128CBC-HS256`, `A192CBC-HS384`, `A256CBC-HS512`, `A128GCM`, `A192GCM`, `A256GCM`
`A128KW`, `A192KW`, `A256KW`|`A128CBC-HS256`, `A192CBC-HS384`, `A256CBC-HS512`
`ECDH-ES`, `ECDH-ES+A128KW`, `ECDH-ES+A192KW`, `ECDH-ES+A256KW`|`A128CBC-HS256`, `A192CBC-HS384`, `A256CBC-HS512`

`RSA1_5` (RSAES-PKCS1-v1_5) is deliberately not supported, for encryption or
decryption: its padding is open to Bleichenbacher-style padding oracle attacks
(see RFC 8725 section 3.2), so lws rejects JWEs using it.  Use `RSA-OAEP`
instead.

The GnuTLS backend has no RSA-OAEP support yet, so with GnuTLS use the AES
key wrap or ECDH-ES algorithms.

Commandline option|Meaning
---|---
-d <loglevel>|Debug verbosity in decimal, eg, -d15
-e "<cek cipher alg> <payload enc alg>"|Encrypt (default is decrypt), eg, -e "RSA-OAEP A128CBC-HS256".  For decrypt, the cipher information comes from the input JWE.
-k <jwk file>|JWK file to encrypt or decrypt with
-c|Format the JWE as a linebroken C string
-f|Output flattened representation (instead of compact by default)

```
 $ echo -n "plaintext0123456" | ./lws-crypto-jwe -k key-rsa-4096.private -e "RSA-OAEP A128CBC-HS256"
[2026/10/13 07:47:09:6152] U: LWS JWE example tool
...
eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhDQkMtSFMyNTYifQ.kbogOhYbiZSqnP2dTy7FHvPJjXXd2sMqgQoTI-DtQ35_SyQN_xeQ5UfZKUTi3yBot1CL0R7QjOqm0FQMNctZQ3fTwHY3BGRoBOLhDHOUh89C-Qvq41_qfnwm213o9nZDxoKmZZVKkzyPMrU01465iLoD1C6ioBrGE9wraAm3SorcQzSxItkUKc72CYVBvG0QvDZCqEHW5necnhZ9tun7zEV9qJVGcJRXsw98ePj0gcVLhOMFSxGjy5h_wgmUgnJgkSFvPmKtre-50NLpeJ3GirBiEm3-HwwunH3Xtz__H8BqupEQ5u8O7HB5INnBhBa_DrL6GaETKrzK5KqBt1AL_ixjqX0vhdXP4pVzqq72f7CvHxCUjjU_YIiigxxUoydfdQWyKSTRpvwaeOyhRvVQLQVhCvlbjbHwFVYWLuAJm-2LHriee07FjPKx6i8kki9Im_mVomds4cAPzCSCCqNk4yXoEAWSO7AuKD_aj7c6WBB_onMxBkWIlbmT6JfF4HwgSGKNsJX1JbQD25O88_BmUrySzsPvjTLBkvr9fZaIdz-cbCtncUBas_BMm_XQnQtvgflZCmODHs8La6TYyYI1P5OvQJWhOz4rKYv6C5kTDKyCykP23ypI1fSy1L5h2DI4KqgVSEehyowem37tVlYFaSG7C6a-dEkuchk-6opDr0Y.zk69KHfR4HzUPCOF5U-BsA.DEpiyYyrUtMkiSgYCE4dRF9WOkgGGFgD09tI-C9SXaQ.bXmfsx53igPgtvW4eUe9lA
```

Notice the logging is on stderr, and the output alone on stdout.

You can also pipe the output of the encrypt action directly into the decrypt
action, eg

```
 $ echo -n "plaintext0123456" | \
   ./lws-crypto-jwe -k key-rsa-4096.pub -e "RSA-OAEP A128CBC-HS256" | \
   ./lws-crypto-jwe -k key-rsa-4096.private
```

prints the plaintext on stdout.
