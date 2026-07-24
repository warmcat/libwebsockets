# lws api test smtp client

Demonstrates how to send email through your local MTA

## build

Requires lws was built with the abstract SMTP protocol (`-DLWS_WITH_ABSTRACT=1` and the abstract smtp protocol source present). This example targets the older abstract SMTP sequencer API and is not built by current trees, where the abstract SMTP protocol has been removed in favour of the `lws-smtp-client` protocol plugin (see `plugins/protocol_lws_smtp_client/`).

```
 $ cmake . && make
```

## usage

Commandline option|Meaning
---|---
-d <loglevel>|Debug verbosity in decimal, eg, -d15
-r <recipient@whatever.com>|Send the test email to this email address


```
 $ ./lws-api-test-smtp_client -r andy@warmcat.com
[2019/04/17 05:12:06:5293] USER: LWS API selftest: SMTP client
[2019/04/17 05:12:06:5635] NOTICE: LGSSMTP_IDLE: connecting to 127.0.0.1:25
[2019/04/17 05:12:06:6238] NOTICE: email_sent_or_failed: sent OK
[2019/04/17 05:12:06:6394] USER: Completed: PASS

```

