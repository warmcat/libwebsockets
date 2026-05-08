# lws-cert-dist-server

This is the server-side protocol plugin for the certificate distribution system. It securely distributes TLS certificates (fullchain and private key) to authorized clients based on Mutual TLS (mTLS) authentication.

## Features

- Distributes certificates directly to verified clients over a secure WebSocket connection.
- Relies on Mutual TLS (mTLS) to authenticate clients. The Common Name (CN) of the client certificate is used to identify the subdomain.
- Actively watches the local Public Key Infrastructure (PKI) directory (if `LWS_WITH_DIR` is enabled) and automatically pushes updated certificates to connected clients when changes occur on disk.

## Configuration PVOs (Per-VHost Options)

| Name | Meaning | Default |
|---|---|---|
| `pki-root` | The root directory where domain certificates are stored. | `/var/dnssec/domains/` |

## Usage

When a client connects, the plugin extracts the Common Name (CN) from the client's TLS certificate to identify the requesting subdomain. It then validates that a distribution client certificate exists on the server for that subdomain at `pki-root/<domain>/dist-client/distribution-client-<subdomain>.crt`.
If authorized, it reads the `fullchain.pem` and `privkey.pem` for the domain, encodes them in a JSON payload, and sends them to the client. If file system watching is enabled (`LWS_WITH_DIR`), the server automatically triggers updates to connected clients whenever the respective `fullchain.pem` or `privkey.pem` files are modified.
