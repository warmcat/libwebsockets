# SMTP client

lws can send mail: queue it, and lws delivers it to an SMTP relay in the
background and tells you how each mail went.  The relay is usually the local
MTA (postfix, exim...) on `127.0.0.1:25`, which is the default, but it can be
anywhere, with implicit tls or STARTTLS.

Build with `-DLWS_WITH_EMAIL=1`.  It needs a build with client support; the
auth server, and so `LWS_WITH_DISTRO_RECOMMENDED`, turns it on.

It comes in two layers:

|layer|header|source|what it is|
|---|---|---|---|
|`lws_smtpc`|`lws-smtp-client.h`|`lib/system/smtp/`|the mail queue, the connection to the relay, retries and backoff, the outcome of each mail|
|the session|`lws-smtp.h`|`lib/sansio/smtp/`|the SMTP client protocol, sansIO: reply bytes in, command and message bytes out|

Most code wants only `lws_smtpc`.

## Sending mail

Every vhost has an SMTP client of its own, made the first time it is asked
for:

```c
static void
mail_done(void *opaque, const lws_smtp_email_t *email,
	  const lws_smtpc_result_t *res)
{
	if (res->outcome != LWS_SMTPC_DELIVERED)
		lwsl_warn("mail to %s failed: %d %s\n", email->to,
			  res->code, res->text);
}

...
	lws_smtp_email_t e;

	memset(&e, 0, sizeof(e));
	e.from		= "noreply@example.com";
	e.to		= "someone@example.net";
	e.subject	= "Hello";
	e.body		= "Hello,\nThis is a test.\n";

	if (lws_smtpc_queue(lws_smtpc_vhost(vh), &e, mail_done, NULL))
		/* refused: not a mail we can send, or the queue is full */;
```

Everything the mail points to is copied, so it can be on the stack.
`lws_smtpc_queue()` never calls back from inside itself; if it returns 0,
the callback is called exactly once later, with one of

|outcome|meaning|
|---|---|
|`LWS_SMTPC_DELIVERED`|the relay accepted the mail|
|`LWS_SMTPC_REFUSED`|the relay refused it with a 5xx|
|`LWS_SMTPC_GAVE_UP`|it was tried `max_tries` times without being done with|
|`LWS_SMTPC_ABANDONED`|the client, or its vhost, was destroyed before it was done with|

`res->code` and `res->text` are the relay's last reply about that mail
(0 and a short reason when there was none, eg, "connection lost").

To reach a different relay, or with different limits, make your own client
with `lws_smtpc_create()`, and destroy it with `lws_smtpc_destroy()`.  A
client's callbacks may queue more mail, and may destroy a client you made.

## The vhost's own client, and lwsws

The vhost's own client is configured by per-vhost options on the
`lws-smtp-client` protocol, which every vhost has when `LWS_WITH_EMAIL` is
built.  In lwsws JSON:

```json
"ws-protocols": [{
	"lws-smtp-client": {
		"status": "ok",
		"smtp-host": "127.0.0.1",
		"smtp-port": "25",
		"smtp-tls": "none"
	}
}]
```

|pvo|meaning|default|
|---|---|---|
|`smtp-host`|the relay to connect to|`127.0.0.1`|
|`smtp-port`|its port|25|
|`smtp-tls`|`none`, `implicit` (tls from the start) or `starttls`|`none`|
|`smtp-tls-host`|the name the relay's certificate is checked against|`smtp-host`|
|`smtp-tls-skip-hostname-check`|`1` to not check the certificate's name at all|`0`|
|`smtp-helo`|our name for EHLO|`localhost`|

With tls, the relay's certificate must be one the vhost's client tls
context trusts, and must be for the relay: the name it is checked against is
`smtp-tls-host` if given, else `smtp-host` itself, which may be an address
literal if the certificate carries it as an IP SAN.  A relay reached by an
address its certificate does not carry, typically a local one, needs either
`smtp-tls-host` naming what the certificate is for, or
`smtp-tls-skip-hostname-check`, which leaves the certificate checked against
the trusted CAs but not for its name: any certificate they issued is then
accepted, so it is only for a relay on a path nothing else can get onto.

These were the options of the smtp client plugin this replaces, which the
vhost's own client now reads; a config that used the plugin works unchanged,
except that the plugin and the first library version skipped the name check
whenever `smtp-tls-host` was not given.  A config with `smtp-tls` on and no
`smtp-tls-host` now has the certificate checked against `smtp-host`, and
needs `smtp-tls-skip-hostname-check` to get the old behaviour.

## How mail is delivered

 - Mails are queued in memory (up to `max_queue`, default 128) and sent in
   order, one at a time, on one connection to the relay that stays up while
   there are mails to send.  Nothing is persisted: mail still queued when the
   process ends is lost.

 - Each reply from the relay is waited for for at most
   `reply_timeout_secs` (default 60).

 - A 5xx refusing a mail is final for that mail; the next one goes on the
   same connection.

 - A 4xx, a session the relay refuses (eg, a 554 greeting), or a connection
   that ends before the mail at the head of the queue is done with, is a try
   at that mail.  At `max_tries` (default 5) it is given up; until then it is
   tried again on a later connection.

 - Connections are made with backoff (100ms, 1s, 5s, 15s, then every 30s,
   with 20% jitter), which only resets once a mail is done with, so a relay
   that is down, or keeps failing sessions, is not hammered.

 - Failing to connect at all is not a try: the mails wait for the relay.

 - With STARTTLS, a relay that does not offer it, or refuses it, gets no mail
   at all, and anything it sends between agreeing to STARTTLS and the tls
   starting fails the connection (it would be plaintext injected ahead of
   the tls).

## What is sent

Each mail has one sender and one recipient, plain `local@domain` addresses
(no quoted local parts, address literals or UTF-8 addresses).
`lws_smtp_email_check()` says if a mail is acceptable; `lws_smtpc_queue()`
refuses one that is not, so nothing a caller puts in a mail can inject
commands or headers.

The message is `text/plain; charset=UTF-8` with `Date:`, `From:`, `To:`,
`Subject:` and `Message-ID:` headers.  `lws_smtpc_queue()` adds the date and
a random message id at the sender's domain when the mail has none.  A subject
that is not plain ASCII, or is long, is sent as folded RFC 2047
encoded-words.  Body line ends are sent as CRLF whatever they were, lines
starting with `.` are dot-stuffed, and a body with 8-bit bytes is declared
`8bit`, with `BODY=8BITMIME` when the relay offers it.  A body line may be at
most 998 bytes once sent.

## Not done

 - SMTP AUTH: relay through a local MTA that accepts mail from loopback, or
   through one that trusts you some other way.
 - More than one recipient per mail, attachments and HTML.
 - A body with 8-bit bytes going to a relay that does not offer 8BITMIME is
   sent as 8bit anyway, not re-encoded.
 - Pipelining: each command waits for its reply.

## The sansIO session

`lws_smtp_session_t` is the client side of one SMTP session with no
transport under it and no clock, for code that has its own byte stream to a
server (or for a port of it).  The caller:

 1. calls `lws_smtp_session_init()` when its transport is up
 2. hands it what the server sends with `lws_smtp_session_rx()`, which says
    what to do next: send (`lws_smtp_session_tx()` fills a buffer from where
    it got to), start tls (then `lws_smtp_session_tls_up()`), give it a mail
    or end the session (`lws_smtp_session_mail()`), or close
 3. times the replies itself

`lws_smtpc` is exactly that, over an lws raw client connection.

## Tests

`minimal-examples-lowlevel/api-tests/api-test-smtp-client` tests the session
alone, byte for byte, then `lws_smtpc` end to end against a fake relay in the
same process: plaintext, implicit tls, STARTTLS, refusals, deferrals,
timeouts, and destroying clients and vhosts with mail queued.
