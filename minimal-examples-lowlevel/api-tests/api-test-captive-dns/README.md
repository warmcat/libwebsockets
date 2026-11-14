# lws api test captive dns

Checks the captive portal's dns, `lws_captive_dns_start()`, which answers
every name with one address, eg, a device's own address while it is an AP to
be set up from a browser.

`lws_captive_dns_answer()` is given queries made by the test:

 - an A query, or ANY, is answered with the address, with a TTL of 0, and
   with recursion desired only if it was asked for

 - other types, eg, AAAA and HTTPS, and classes other than IN, are answered
   with no records; with an IPv6 address, it's AAAA that is answered

 - an EDNS OPT record after the question is accepted, and not echoed

 - a name of 255 is answered, but not one of 256, a label of 64, a compressed
   name, or a query cut short anywhere

 - responses, and anything but a single question, aren't answered, and an
   opcode other than QUERY is "not implemented"

 - for 200,000 random datagrams, no answer is more than 16 bytes longer than
   what came, or longer than the room given for it

Then it is started on 127.0.0.1 and `--port`, and asked over UDP for an A
record by a client in the same process, and again after it is stopped and
started on the same port at once.

## Options

|Option|Meaning|
|---|---|
|--port <port>|UDP port to answer dns queries on, default 5353|
|--help|Show this help information|

## build

```
 $ cmake .. -DLWS_WITH_SYS_CAPTIVE_DNS=1 -DLWS_WITH_MINIMAL_EXAMPLES=1 && make
```

## usage

```
 $ ./bin/lws-api-test-captive-dns
[2026/11/14 10:00:00:0000] U: LWS API Test - captive dns
...
[2026/11/14 10:00:00:5000] U: Completed: PASS
```
