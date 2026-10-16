# lws-cert-dist-client

This is the client-side protocol plugin for the certificate distribution system. It allows unprivileged client processes to securely request and update their TLS certificates (fullchain and private key) from a central `lws-cert-dist-server`.

## Features

- Securely fetches and updates TLS certificates from the distribution server.
- Establishes discrete mTLS WebSocket links for each configured client certificate; the certificate itself identifies the domain it is managing.
- Spawns a privileged stub process (`--lws-stub=certdistcli-<vhost>`) when running as root, to write the certs and keys.  Given a `stub-user`, the stub runs as that user, not root.
- Hands the vhosts serving an installed pair copies of it, since they can't read what the stub wrote.
- Implements a UDS (Unix Domain Socket) IPC mechanism (`lws-cert-dist-stub`) for secure communication between the unprivileged process and the privileged stub.
- Atomic symlink updates when new certificates are received.

## Configuration PVOs (Per-VHost Options)

| Name | Meaning | Default |
|---|---|---|
| `base-dir` | The base directory where certificates will be stored. | `/etc/lwsws-pki` |
| `server-url` | The WebSocket URL of the central distribution server. | `wss://distribution-server.local` |
| `ca-filepath` | Optional. Path to the CA certificate used to verify the distribution server's certificate. Needed if the server uses a self-signed or private CA. | N/A |
| `certs` | A list of mTLS client certificates and keys to connect to the server. The client establishes a connection for each entry. The server deduces the domain being managed from the certificate presented. | N/A |
| `stub-dir` | The directory the privileged stub's UDS socket is created in.  It must be one only root can create entries in. | `/var/run` |
| `stub-user` | `user` or `user:group`, by name or number, that the stub runs as once it is listening, instead of root.  It should be a user of its own, that lwsws's unprivileged user isn't and whose group it isn't in, eg, `lwsws-priv`: it owns `base-dir` and the keys in it.  Without a group, the user's own. | the stub stays root |

## Usage

When enabled with certs configured, the plugin spawns a privileged stub process (named `certdistcli-<vhost>`) to handle file system operations, listening on `<stub-dir>/lws-cert-dist-stub-<vhost>.sock`. The unprivileged side connects to it and forwards the JSON payloads received from the central distribution server.

The link to the server stays up, and the server pushes renewed certs down it as they appear; each one is installed as it arrives.

When the link drops, it is reconnected with a short backoff (up to 5s).  On each connect the client first sends the SHA-1 of the `fullchain.pem` it has installed, and the server sends its current cert only if that differs, so a client that was offline during a renewal catches up as soon as it is back.

### How the vhosts get the new cert

The stub writes the cert and key where lwsws's unprivileged process can't
read them.  So once the stub says a new pair is installed, the client hands
the vhosts that serve it copies of the pair from memory, with
`lws_tls_cert_updated()`: a vhost whose `host-ssl-cert` and `host-ssl-key` are
exactly `<base-dir>/<name>/fullchain.pem` and `<base-dir>/<name>/privkey.pem`.
It loads the new pair at once, and serves it then, or after its
`host-ssl-cert-grace-secs` if it has one.  At startup, before it drops its
privileges, lwsws loads the vhost's cert from the files as usual.

### Who the stub runs as

The stub is spawned as root, so it can make its socket where lwsws's
unprivileged process can connect to it, and then becomes its `stub-user`
before it serves anything.  All it does is write the certs and keys it is
sent into `base-dir`, so it needs no more than to own that.  A user of its own
keeps the keys out of reach of a compromised lwsws process.  If it can't
become the user, eg, the user doesn't exist, the stub fails and nothing is
installed.

Without a `stub-user` the stub stays root, as it always did, and says so in a
notice at startup.

#### Moving an existing install off root

The stub only writes into directories its own user owns and that nobody else
can write to, and `base-dir` must be one it can create those in.  Before a
`stub-user` is given, all of that belongs to root, so it has to be handed over
once, with lwsws stopped.  With `base-dir` `/var/lwsws-pki` and the stub user
`lwsws-priv`:

```
# systemctl stop lwsws
# useradd --system --no-create-home --shell /usr/sbin/nologin lwsws-priv
# chown -R lwsws-priv:lwsws-priv /var/lwsws-pki
# chmod 0700 /var/lwsws-pki /var/lwsws-pki/*/
```

Then add `"stub-user": "lwsws-priv"` to the plugin's pvos and start lwsws
again.  If the mTLS client certs and keys the `certs` entries name are kept
in `base-dir`, they go to `lwsws-priv` too, which is fine: lwsws loads them
when it starts, while it is still root.

Nothing else changes: the files are named and laid out as before, the vhosts
load them at startup while lwsws is still root, and the stub logs
`running as 'lwsws-priv'` when it starts.  If a directory was missed, the
install is refused with `'<dir>' is not a private directory we own: it must be
a directory owned by uid <n>...`, the cert stays what it was, and the client
retries with backoff.

### When an install fails

The stub answers every install with its outcome.  If it could not install a cert (for example, the install dir is not a private one it owns, or a write failed), or the server sent something that cannot be installed, the client logs why at `err` level, says it is still serving the previous cert, and drops the link.  The reconnect sends the hash of the cert still installed, so the server sends the new one again.

Whatever failed may well fail again, so these refetches back off further each time: about 10s, 30s, 1m, 5m, 15m, then hourly, with 20% jitter.  The delay is logged at `notice`.  A successful install resets it.

### What is installed where

Each `certs` entry is installed under `<base-dir>/<name>/`, where `name` is the entry's own key in the config (`example-com` and `test-org` below), *not* a name chosen by the distribution server.  The server's `subdomain` in the reply is only logged if it disagrees; a compromised distribution server can therefore replace the cert and key of the domain a given link was established for, and of no other.

Entry names must be plain names (`[A-Za-z0-9._-]`, no leading `.` or `-`, no `..`); an entry with an unusable name is skipped at init.  The stub enforces the same rule again before it touches the filesystem, refuses to write into a `<base-dir>/<name>` directory it does not own or that is group- or world-writable, and creates the timestamped cert and key files with `O_EXCL | O_NOFOLLOW` before swapping the `fullchain.pem` / `privkey.pem` symlinks over them atomically.

A `fullchain` or `privkey` larger than 256KB, or containing anything a PEM never does (a double quote, a backslash, a control character other than a line end, or a byte outside ASCII), is refused and the connection to the distribution server is dropped.  The bodies are JSON-escaped on their way to the stub regardless, and the stub refuses a request in which any member appears twice, so a body cannot smuggle in a second `subdomain` and have itself installed under a different name.

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
        "certs": {
          "example-com": {
            "cert": "/etc/lwsws-pki/example.com/mtls-client.crt",
            "key": "/etc/lwsws-pki/example.com/mtls-client.key"
          },
          "test-org": {
            "cert": "/etc/lwsws-pki/test.org/mtls-client.crt",
            "key": "/etc/lwsws-pki/test.org/mtls-client.key"
          }
        }
      }
    }]
  }]
}
```
