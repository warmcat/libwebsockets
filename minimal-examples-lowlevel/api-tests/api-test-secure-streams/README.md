# lws api test Secure Streams

Performs some tests against httpbin.org server
to check Secure Streams client performance

 - a GET, that must be ACKed with a response of at least 100 bytes
 - a GET of a 403, that must be NACKed
 - a 4096-byte POST, with its length given by `lws_ss_request_tx_len()`
 - the same POST with no length given (`lws_ss_request_tx()`), which goes
   chunked over h1

The POSTs must have sent their whole body before the response ACKs them.
The ctest runs these against a local httpbin with `-c policy-local.json`.

## build

```
 $ cmake . && make
```

## usage

Commandline option|Meaning
---|---
-d <loglevel>|Debug verbosity in decimal, eg, -d15
-c <path>|Policy JSON file to use instead of the built-in one

```
 $ ./lws-api-test-secure-streams
```

