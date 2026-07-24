# lws-smtp-client

This is a protocol plugin providing a simple SMTP client API. It allows other components and plugins to asynchronously queue and send emails via a local or remote SMTP server.

## Features

- Non-blocking, event-loop integrated SMTP client.
- Provides a C API (`lws_smtp_client_ops_t`) exposed via the protocol's user pointer, allowing other plugins/C code to trigger emails dynamically.
- Implements an SMTP transaction state machine (`HELO`/`EHLO`, `MAIL FROM`, `RCPT TO`, `DATA`, body, `QUIT`).
- Optional transport security: plaintext (default), implicit TLS (SMTPS, `:465`), or STARTTLS (`:587`).

## Usage via C API

You can lookup the protocol and access its operations to send emails from within libwebsockets:

```c
const struct lws_protocols *pp = lws_vhost_name_to_protocol(vh, "lws-smtp-client");
if (pp) {
	lws_smtp_client_ops_t *ops = (lws_smtp_client_ops_t *)pp->user;

	lws_smtp_email_t email;
	email.from = "sender@example.com";
	email.to = "receiver@example.com";
	email.subject = "Test Email";
	email.body = "This is a test email sent via lws-smtp-client.";

	ops->send_email(cx, vh, &email);
}
```

The plugin internally queues the email and asynchronously negotiates the SMTP transaction. By default, it connects to an SMTP relay at `127.0.0.1:25` over plaintext.

## Configuration (PVOs)

The connection target and transport security are set with Per-Vhost Options on the `lws-smtp-client` protocol. All are optional.

| PVO Name | Description | Default |
| --- | --- | --- |
| `smtp-host` | The upstream MTA host to connect to. | `127.0.0.1` |
| `smtp-port` | The upstream MTA TCP port. | `25` |
| `smtp-tls` | Transport security mode: `none` (plaintext), `implicit` (TLS from connect, SMTPS), or `starttls` (plaintext connect then RFC 3207 STARTTLS upgrade). | `none` |

### Transport security modes

- **`none`** (default): the connection is plaintext end to end. This is the right choice for a local relay (e.g. postfix/exim) on `127.0.0.1:25` that accepts mail from localhost without authentication. No credentials are exchanged in the clear beyond the local loopback.
- **`implicit`**: TLS is negotiated immediately on connect (SMTPS). Use with port `465` against a submission service that expects implicit TLS.
- **`starttls`**: the connection starts plaintext; after the server greeting the plugin issues `EHLO`, waits for the server to advertise its capabilities, issues `STARTTLS`, and upgrades the existing connection to TLS via `lws_tls_client_upgrade()` before sending any mail content. Use with port `587` against an RFC 3207 submission service. Requires a TLS-enabled lws build (`LWS_WITH_TLS`); configuring `starttls` against a build without TLS fails loudly at protocol init.

In both TLS modes the server certificate is validated against the trusted CA store of the vhost's client SSL context; only the hostname check is relaxed (`LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK`), so the relay's issuing CA must be trusted. Self-signed or otherwise untrusted certificates are rejected.

## Limitations

- **No SMTP AUTH.** The state machine does not perform `AUTH PLAIN`/`AUTH LOGIN`. A submission relay that requires authentication (typical of public `:587` MSAs) will reject the `MAIL FROM`. Use a local relay that accepts unauthenticated submission from the loopback, or relay through a host that does. AUTH support may be added in a later phase.
- **No STARTTLS capability gating.** When `smtp-tls=starttls` is set the plugin always issues `STARTTLS`; it does not fall back to plaintext if the server fails to advertise the capability.
