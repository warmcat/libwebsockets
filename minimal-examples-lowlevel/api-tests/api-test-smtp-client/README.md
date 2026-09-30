# lws api test smtp client

Tests the SMTP client (READMEs/README.smtp-client.md) in two halves.

First the sansIO session (`lws-smtp.h`) alone, with no transport: canned
server replies go in, whole and a byte at a time, and what the session sends
is compared with what it must send byte for byte... the commands, and the
message with its headers, encoded-word subjects, CRLF line ends and
dot-stuffing.  Malformed, refused, unexpected and injected replies are fed to
it too.

Then `lws_smtpc` end to end, against a fake relay run as raw listeners in the
same process:

|case|what|
|---|---|
|0|three mails on one plaintext connection, arriving exactly as they should|
|1|a mail refused with a 5xx, then one delivered after a RSET|
|2|a mail deferred with a 4xx, delivered on the next connection|
|3|a mail deferred every time, given up at max_tries|
|4|a relay that never answers, timed out|
|5|the client destroyed with mails queued|
|6|the client destroyed from a mail's callback|
|7|what the queue refuses: a bad mail, and one past max_queue|
|8|implicit tls|
|9|STARTTLS, then the session over tls|
|10|STARTTLS required, and not offered|
|11|the vhost's own client, configured by pvos|
|12|the vhost destroyed under a client with mails queued|

For STARTTLS the fake relay, once it has said 220, relays the connection's
bytes to a tls listener of its own, so the client's tls upgrade happens on a
real connection.  Without tls in the build, cases 8 to 10 are replaced by one
that checks a tls client is refused.

## ctest

ctest runs it with four free ports picked for the fake relay.

## build

```
 $ cmake .. -DLWS_WITH_EMAIL=1 -DLWS_WITH_MINIMAL_EXAMPLES=1 && make
```

## usage

|option|meaning|
|---|---|
|-p <port>|the fake relay's plaintext port (7700)|
|--tls-port <port>|its implicit tls port (7701)|
|--tlsb-port <port>|the tls port a STARTTLS is relayed to (7702)|
|--silent-port <port>|the port where it never says anything (7703)|
|--case <n>|run only end to end case n (the sansIO tests always run)|

```
 $ ./bin/lws-api-test-smtp-client
[2026/09/30 10:19:57:6621] U: sansIO session: 0 failures
...
[2026/09/30 10:20:00:1563] U: --- case 12: vhost destroyed under a client: PASS ---
[2026/09/30 10:20:00:2157] U: Completed: PASS (0 failures)
```
