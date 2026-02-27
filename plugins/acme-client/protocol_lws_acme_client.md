# lws-acme-client

## Introduction

The `lws-acme-client` protocol plugin implements an ACME client designed for interacting with Certificate Authorities (like Let's Encrypt). It supports both `tls-sni-01` (and `02`) as well as `http-01` challenges natively, meaning it handles obtaining new certificates and renewing them via automated provisioning workflows natively in `libwebsockets` without the need for external tools like `certbot`.

## Per-Vhost Options (PVOs)

This plugin handles the following Per-Vhost Options (PVOs) mapped exactly to aspects of the certificate being requested or the ACME process itself:

| PVO Name | Description |
|---|---|
| `country` | CSR Subject: 2-letter Country code. |
| `state` | CSR Subject: State or Province name. |
| `locality` | CSR Subject: Locality or geographic name. |
| `organization` | CSR Subject: Organization name. |
| `common-name` | CSR Subject: The primary domain being certified (e.g. `example.com`). **Required** to start acquisition. |
| `subject-alt-name` | CSR Subject Alt Names (SAN): Additional domains to certify on the same request. |
| `email` | Registration email for ACME account (used for expiry notifications by the CA). |
| `directory-url` | The initial ACME CA directory URL (e.g., Let's Encrypt staging or production URL). |
| `auth-path` | Absolute path where the ACME client authentication key (JWK) should be saved or loaded from. |
| `cert-path` | Path where the successfully derived certificate should be stored. |
| `key-path` | Path where the private key associated with the certificate should be stored. |
