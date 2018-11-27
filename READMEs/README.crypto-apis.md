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

Unit tests for these apis, which serve as usage examples, can be found in [./minimal-examples/api-tests/api-test-gencrypto](https://libwebsockets.org/git/libwebsockets/tree/minimal-examples/api-tests/api-test-gencrypto)

## Using the JOSE layer

All the necessary includes are part of `libwebsockets.h`.

|api|cmake|header|Functionality|
|---|---|---|---|
|JOSE|`LWS_WITH_JWS`|[./include/libwebsockets/jose.h](https://libwebsockets.org/git/libwebsockets/tree/include/libwebsockets/lws-jose.h)|Provides signature and verifcation services for RFC7515 JOSE JSON|
|JWS|`LWS_WITH_JWS`|[./include/libwebsockets/jws.h](https://libwebsockets.org/git/libwebsockets/tree/include/libwebsockets/lws-jws.h)|Provides signature and verifcation services for RFC7515 JWS JSON|
|JWK|`LWS_WITH_JWS`|[./include/libwebsockets/jwk.h](https://libwebsockets.org/git/libwebsockets/tree/include/libwebsockets/lws-jwk.h)|Provides signature and verifcation services for RFC7517 JWK JSON, both "keys" arrays and singletons|

Unit tests for these apis, which serve as usage examples, can be found in [./minimal-examples/api-tests/api-test-jose](https://libwebsockets.org/git/libwebsockets/tree/minimal-examples/api-tests/api-test-jose)

