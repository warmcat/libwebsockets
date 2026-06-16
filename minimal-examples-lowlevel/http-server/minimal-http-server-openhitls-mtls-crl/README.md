# lws minimal http server hitls mtls crl

## build

```
 $ cmake . && make
```

## usage

```
 $ ./lws-minimal-http-server-hitls-mtls-crl --port 7780
```

## Description

This test demonstrates TLS1.2 mutual authentication with certificate chain and CRL (Certificate Revocation List) using OpenHITLS.

## Test stages

- **Stage 0**: Normal certificate - expect connection success and app data transfer (1024 bytes)
- **Stage 1**: Expired server cert - expect connection success (client skips peer verification)
- **Stage 2**: Revoked server cert - expect connection success (client skips peer verification)

The test includes an echo server that:
1. Receives application data from client
2. Echoes the data back to client
3. Verifies 1024 bytes sent and received successfully

## Requirements

- LWS_WITH_SERVER
- LWS_WITH_CLIENT
- LWS_WITH_TLS
- LWS_WITH_OPENHITLS

## Certificates

The test uses the default test certificates from the parent directory:
- libwebsockets-test-server.pem
- libwebsockets-test-server.key.pem

Run from the parent http-server directory or copy certificates to current directory.

## mTLS Configuration

Server requires valid client certificate:
```c
info.options |= LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT;
info.ssl_ca_filepath = "libwebsockets-test-server.pem";
```
