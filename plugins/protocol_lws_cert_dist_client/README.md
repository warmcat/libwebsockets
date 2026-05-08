# lws-cert-dist-client

This is the client-side protocol plugin for the certificate distribution system. It allows unprivileged client processes to securely request and update their TLS certificates (fullchain and private key) from a central `lws-cert-dist-server`.

## Features

- Securely fetches and updates TLS certificates for specified subdomains.
- Spawns a privileged stub process (`--lws-stub=distribution-client`) when running as root to manage local file system writes and UDS communication.
- Implements a UDS (Unix Domain Socket) IPC mechanism (`lws-cert-dist-stub`) for secure communication between the unprivileged process and the privileged stub.
- Atomic symlink updates when new certificates are received.

## Configuration PVOs (Per-VHost Options)

| Name | Meaning | Default |
|---|---|---|
| `base-dir` | The base directory where certificates will be stored. | `/etc/lwsws-pki` |
| `server-url` | The WebSocket URL of the central distribution server. | `wss://distribution-server.local` |
| `subdomains` | A list of subdomains to request certificates for. | N/A |

## Usage

When enabled, the plugin checks if it is running as root and if subdomains are configured. If so, it spawns a privileged stub process to handle file system operations and sets up a UDS server. Unprivileged clients connect to this UDS server, which forwards JSON payloads containing the `subdomain`, `fullchain`, and `privkey` received from the central distribution server.
