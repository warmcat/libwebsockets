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

When a client connects, the plugin extracts the Common Name (CN) from the client's TLS certificate to identify the requesting subdomain.  The CN must be a plain hostname (`[A-Za-z0-9.-]`, no leading or trailing `.` or `-`, no `..`); anything else is rejected at `ESTABLISHED` with a policy violation close.  The domain is the CN with its leftmost label removed (or the CN itself if it has one dot or fewer).

### Authorisation

mTLS says only that *some* certificate the vhost's CA chain accepts was presented; on its own that must not be enough to hand out a domain's private key.  So the privileged stub additionally requires that this server was explicitly provisioned to distribute `<domain>` to `<subdomain>`, by the presence of

```
<pki-root>/domains/<domain>/dist-client/distribution-client-<subdomain>.crt
```

as a regular file.  If it is not there the request is refused and the stub connection is dropped: the check fails closed.  Provisioning a distribution client therefore means placing its issued certificate at that path as well as issuing it.

If authorized, it reads the newest `.crt` and `.key` under `<pki-root>/domains/<domain>/certs/production/`, encodes them in a JSON payload, and sends them to the client.  A client may send `{"hash":"<sha1-hex>"}` first (bounded to 40 hex digits, anything else is ignored); if it matches the hash of the current cert, an empty payload is returned instead.  If file system watching is enabled (`LWS_WITH_DIR`), the server automatically triggers updates to connected clients whenever the respective files are modified.

### Privileged stub

The unprivileged vhost spawns a stub child named `certdistsrv-<vhost>`, which is the only part that reads the PKI root.  The prefix is deliberately distinct from every other plugin's stub name: a stub child claims its work by prefix match, and claiming another plugin's child consumes the stdin secret meant for it.
