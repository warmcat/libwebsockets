# lws api test smtp client

Performs unit tests on the lws SMTP client abstract protocol
implementation.

The first test "sends mail to a server" (actually is prompted by
test vectors that look like a server) and the second test
confirm it can handle rejection by the "server" cleanly.

## build

Requires lws was built with the abstract layer (`-DLWS_WITH_ABSTRACT=1` and the abstract smtp protocol source present). This test drives the abstract SMTP protocol via the unit-test transport; it is not built by current trees, where the abstract SMTP protocol has been removed in favour of the `lws-smtp-client` protocol plugin (see `plugins/protocol_lws_smtp_client/`).

```
 $ cmake . && make
```

## usage

Commandline option|Meaning
---|---
-d <loglevel>|Debug verbosity in decimal, eg, -d15
-r <recipient@whatever.com>|Send the test email to this email address


```
 $ ./lws-api-test-smtp_client
[2019/06/28 21:56:41:0711] USER: LWS API selftest: SMTP client unit tests
[2019/06/28 21:56:41:1114] NOTICE: test_sequencer_cb: test-seq: created
[2019/06/28 21:56:41:1259] NOTICE: unit_test_sequencer_cb: unit-test-seq: created
[2019/06/28 21:56:41:1272] NOTICE: lws_atcut_client_conn: smtp: test 'sending': start
[2019/06/28 21:56:41:1441] NOTICE: unit_test_sequencer_cb: unit-test-seq: created
[2019/06/28 21:56:41:1442] NOTICE: lws_atcut_client_conn: smtp: test 'rejected': start
[2019/06/28 21:56:41:1453] NOTICE: lws_smtp_client_abs_rx: bad response from server: 500 (state 4) 500 Service Unavailable
[2019/06/28 21:56:41:1467] USER: test_sequencer_cb: sequence completed OK
[2019/06/28 21:56:41:1474] USER: main: 2 tests 0 fail
[2019/06/28 21:56:41:1476] USER:   test 0: PASS
[2019/06/28 21:56:41:1478] USER:   test 1: PASS
[2019/06/28 21:56:41:1480] USER: Completed: PASS
```

