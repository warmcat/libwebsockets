# lws-cert-dist-server

This is the server-side protocol plugin for the certificate distribution system. It securely distributes TLS certificates (fullchain and private key) to authorized clients based on Mutual TLS (mTLS) authentication.

## Features

- Distributes certificates directly to verified clients over a secure WebSocket connection.
- Relies on Mutual TLS (mTLS) to authenticate clients. The Common Name (CN) of the client certificate is used to identify the subdomain.
- Watches the cert and key dirs of each provisioned domain (if `LWS_WITH_DIR` is enabled) and pushes renewed certificates to the connected clients for that domain when they change on disk.

## Configuration PVOs (Per-VHost Options)

| Name | Meaning | Default |
|---|---|---|
| `pki-root` | The root directory where domain certificates are stored, in `<pki-root>/domains/` | `/var/dnssec` |
| `stub-dir` | The directory the privileged stub's UDS socket is created in.  It must be one only the stub's user can create entries in. | `/var/run` |

## Usage

When a client connects, the plugin extracts the Common Name (CN) from the client's TLS certificate to identify the requesting subdomain.  The CN must be a plain hostname (`[A-Za-z0-9.-]`, no leading or trailing `.` or `-`, no `..`); anything else is rejected at `ESTABLISHED` with a policy violation close.  The domain is the CN with its leftmost label removed (or the CN itself if it has one dot or fewer).

### Authorisation

mTLS says only that *some* certificate the vhost's CA chain accepts was presented; on its own that must not be enough to hand out a domain's private key.  So the privileged stub additionally requires that this server was explicitly provisioned to distribute `<domain>` to `<subdomain>`, by the presence of

```
<pki-root>/domains/<domain>/dist-client/distribution-client-<subdomain>.crt
```

as a regular file.  If it is not there the request is refused: the check fails closed.  Provisioning a distribution client therefore means placing its issued certificate at that path as well as issuing it.

A refusal, like a domain whose cert or key is not there yet, is answered with an empty pair (the same reply as an unchanged cert, which the client installs nothing for) and the stub connection stays up.  The parent sends its requests to the stub one after another on that connection and reconnects with backoff if it drops, so a refusal that dropped it would stall every request queued behind, and an authenticated but unprovisioned peer could keep that up indefinitely.  Only a request that cannot have come from the parent, with a bad secret or names that would not have passed its validation, drops the connection.

If authorized, it sends the client the cert chain and key the acme client keeps current for the domain, which it renews by moving a symlink onto each new file:

```
<pki-root>/domains/<domain>/certs/production/crt/<domain>-latest-fullchain.crt
<pki-root>/domains/<domain>/certs/production/key/<domain>-latest.key
```

If the domain has no cert of its own, its wildcard cert is used, which the acme client files under the name `_.<domain>`.  The dirs also hold the timestamped files the links point to, leaf-only certs and the outgoing pair linked as `-previous`; none of those is ever sent.  The pair is only sent if the key belongs to the cert (with `LWS_WITH_JOSE`), since for a moment during a renewal the links can point to the new key and the old cert; the change that completes the renewal sends it then.  A client may send `{"hash":"<sha1-hex>"}` first (bounded to 40 hex digits, anything else is ignored); if it matches the hash of the current cert, an empty payload is returned instead.

### Renewals

With `LWS_WITH_DIR`, at vhost init the server starts watching the `crt/` and `key/` dirs of every domain under `<pki-root>/domains/` that has a `dist-client/` dir, and when a `.crt` or `.key` appears or changes in them, it sends the current cert and key to every client connected for that domain.  Changes are allowed 500ms to settle first, so a renewal written as a new cert and a new key goes out as one update.

The watches are made at vhost init because under lwsws that is before privileges are dropped; they keep working afterwards.  A domain provisioned after that is only watched from the next reload; until then its clients get the current cert whenever they reconnect.

### Privileged stub

The unprivileged vhost spawns a stub child named `certdistsrv-<vhost>`, which is the only part that reads the PKI root.  It listens on `<stub-dir>/lws-cert-dist-server-stub-<vhost>.sock`, a path the parent passes it on its commandline.  The prefix is deliberately distinct from every other plugin's stub name: a stub child claims its work by prefix match, and claiming another plugin's child consumes the stdin secret meant for it.
