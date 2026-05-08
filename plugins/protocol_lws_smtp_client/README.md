# lws-smtp-client

This is a protocol plugin providing a simple SMTP client API. It allows other components and plugins to asynchronously queue and send emails via a local or remote SMTP server.

## Features

- Non-blocking, event-loop integrated SMTP client.
- Provides a C API (`lws_smtp_client_ops_t`) exposed via the protocol's user pointer, allowing other plugins/C code to trigger emails dynamically.
- Implements a basic SMTP state machine (Connecting, Greeting, Helo, Mail From, Rcpt To, Data, Body, Quit).

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

The plugin internally queues the email and asynchronously negotiates the SMTP transaction. By default, it connects to an SMTP server at `127.0.0.1:25`.
