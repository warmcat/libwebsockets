# Lws Crypto Apis

## Overview

![lws crypto overview](/doc-assets/lws-crypto-overview.svg)

Lws provides a "generic" crypto layer on top of both OpenSSL and
compatible tls library, and mbedtls.  Using this layer, your code
can work without any changes on both types of tls library crypto
backends... it's as simple as rebuilding lws with `-DLWS_WITH_MBEDTLS=0`
or `=1` at cmake.

The generic layer can be used directly (as in, eg, the sshd plugin),
or via another layer on top, which processes JOSE JSON objects using
JWS (JSON Web Signatures), JWK (JSON Web Keys), and JWE (JSON Web
Encryption).

## Using the generic layer

All the necessary includes are part of `libwebsockets.h`.

|api|cmake|header|Functionality|
|---|---|---|---|
|genhash|`LWS_WITH_GENHASH`|[./include/libwebsockets/lws-genhash.h](https://libwebsockets.org/git/libwebsockets/tree/include/libwebsockets/lws-genhash.h)|Provides SHA1 + SHA2 hashes and hmac|
|genrsa|`LWS_WITH_GENRSA`|[./include/libwebsockets/lws-genrsa.h](https://libwebsockets.org/git/libwebsockets/tree/include/libwebsockets/lws-genrsa.h)|Provides RSA encryption, decryption, signing, verification, key generation and creation|
|genaes|`LWS_WITH_GENAES`|[./include/libwebsockets/lws-genaes.h](https://libwebsockets.org/git/libwebsockets/tree/include/libwebsockets/lws-genaes.h)|Provides AES in all common variants for encryption and decryption|
|genec|`LWS_WITH_GENEC`|[./include/libwebsockets/lws-genec.h](https://libwebsockets.org/git/libwebsockets/tree/include/libwebsockets/lws-genec.h)|Provides Elliptic Curve for encryption, decryption, signing, verification, key generation and creation|


Unit tests for these apis, which serve as usage examples, can be found in [./minimal-examples/api-tests/api-test-gencrypto](https://libwebsockets.org/git/libwebsockets/tree/minimal-examples/api-tests/api-test-gencrypto)

### Keys in the generic layer

The necessary types and defines are brought in by `libwebsockets.h`.

Keys are represented only by an array of `struct lws_jwk_elements`... the
length of the array is defined by the cipher... it's one of

|key elements count|definition|
|---|---|
|`LWS_COUNT_OCT_KEY_ELEMENTS`|1|
|`LWS_COUNT_RSA_KEY_ELEMENTS`|8|
|`LWS_COUNT_EC_KEY_ELEMENTS`|4|
|`LWS_COUNT_AES_KEY_ELEMENTS`|1|

`struct lws_jwk_elements` is a simple pointer / length combination used to
store arbitrary octets that make up the key element's binary representation.

## Using the JOSE layer

All the necessary includes are part of `libwebsockets.h`.

|api|cmake|header|Functionality|
|---|---|---|---|
|JOSE|`LWS_WITH_JWS`|[./include/libwebsockets/jose.h](https://libwebsockets.org/git/libwebsockets/tree/include/libwebsockets/lws-jose.h)|Provides signature and verifcation services for RFC7515 JOSE JSON|
|JWS|`LWS_WITH_JWS`|[./include/libwebsockets/jws.h](https://libwebsockets.org/git/libwebsockets/tree/include/libwebsockets/lws-jws.h)|Provides signature and verifcation services for RFC7515 JWS JSON|
|JWK|`LWS_WITH_JWS`|[./include/libwebsockets/jwk.h](https://libwebsockets.org/git/libwebsockets/tree/include/libwebsockets/lws-jwk.h)|Provides signature and verifcation services for RFC7517 JWK JSON, both "keys" arrays and singletons|

Unit tests for these apis, which serve as usage examples, can be found in [./minimal-examples/api-tests/api-test-jose](https://libwebsockets.org/git/libwebsockets/tree/minimal-examples/api-tests/api-test-jose)

### Keys in the JOSE layer

Keys in the JOSE layer use a `struct lws_jwk`, this contains two arrays of
`struct lws_jwk_elements` sized for the worst case (currently RSA).  One
array contains the key elements as described for the generic case, and the
other contains various key metadata taken from JWK JSON.

|metadata index|function|
|---|---|
|`JWK_META_KTY`|Key type, eg, "EC"|
|`JWK_META_KID`|Arbitrary ID string|
|`JWK_META_USE`|What the public key may be used to validate, "enc" or "sig"|
|`JWK_META_KEY_OPS`|Which operations the key is authorized for, eg, "encrypt"|
|`JWK_META_X5C`|Optional X.509 cert version of the key|
|`JWK_META_ALG`|Optional overall crypto algorithm the key is intended for use with|

