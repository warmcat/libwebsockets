# lws-cert-dist-client

This is the client-side protocol plugin for the certificate distribution system. It allows unprivileged client processes to securely request and update their TLS certificates (fullchain and private key) from a central `lws-cert-dist-server`.

## Features

- Securely fetches and updates TLS certificates from the distribution server.
- Establishes discrete mTLS WebSocket links for each configured client certificate; the certificate itself identifies the domain it is managing.
- Spawns a privileged stub process (`--lws-stub=distribution-client`) when running as root to manage local file system writes and UDS communication.
- Implements a UDS (Unix Domain Socket) IPC mechanism (`lws-cert-dist-stub`) for secure communication between the unprivileged process and the privileged stub.
- Atomic symlink updates when new certificates are received.

## Configuration PVOs (Per-VHost Options)

| Name | Meaning | Default |
|---|---|---|
| `base-dir` | The base directory where certificates will be stored. | `/etc/lwsws-pki` |
| `server-url` | The WebSocket URL of the central distribution server. | `wss://distribution-server.local` |
| `ca-filepath` | Optional. Path to the CA certificate used to verify the distribution server's certificate. Needed if the server uses a self-signed or private CA. | N/A |
| `certs` | A list of mTLS client certificates and keys to connect to the server. The client establishes a connection for each entry. The server deduces the domain being managed from the certificate presented. | N/A |

## Usage

When enabled, the plugin checks if it is running as root and if certs are configured. If so, it spawns a privileged stub process to handle file system operations and sets up a UDS server. Unprivileged clients connect to this UDS server, which forwards JSON payloads received from the central distribution server.

### Example `lwsws` Configuration

Below is an example of how to configure this plugin in an `lwsws` JSON config file (e.g., `/etc/lwsws/conf.d/cert-dist`):

```json
{
  "vhosts": [{
    "name": "cert-dist-client-vhost",
    "ws-protocols": [{
      "lws-cert-dist-client": {
        "status": "ok",
        "base-dir": "/etc/lwsws-pki",
        "server-url": "wss://distribution-server.local",
        "ca-filepath": "/etc/lwsws-pki/dist-server-ca.crt",
        "certs": [{
          "example-com": {
            "cert": "/etc/lwsws-pki/example.com/mtls-client.crt",
            "key": "/etc/lwsws-pki/example.com/mtls-client.key"
          }
        }, {
          "test-org": {
            "cert": "/etc/lwsws-pki/test.org/mtls-client.crt",
            "key": "/etc/lwsws-pki/test.org/mtls-client.key"
          }
        }]
      }
    }]
  }]
}
```
