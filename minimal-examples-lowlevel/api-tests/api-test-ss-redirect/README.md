# lws api test ss redirect

A Secure Streams client whose policy allows redirects (`allow_redirects`), and
that sends identity in its headers (here the device serial, as `x-dsn:` from
`http_dsn_header`), follows a redirect only on the authority its policy named.
The headers would go again to wherever the redirect took it, so a `Location`
naming another authority must be refused, however it is spelled:

 - a relative path, an absolute URI naming our authority, and a network-path
   reference (`//host:port/path`) naming our authority are followed
 - an absolute URI, or a network-path reference, naming another host is
   refused: `//host/path` is not a path, it names another authority as much
   as `http://host/path` does

A small raw socket server in the same process answers `/start/<phase>` with
that phase's redirect, and anything else with a 200, noting what it was asked
for.  Each phase is a stream of its own, with no retries.  The other host is
another name for the same server (`127.0.0.1` when the policy says
`localhost`), so a redirect to it that was followed would reach the server,
and be seen.

```
$ ./lws-api-test-ss-redirect -p 7681
```

Option|Meaning
---|---
-d <loglevel>|Debug verbosity in decimal, eg, -d15
-p <port>|Port for the test server (default 7681)
--server <address>|Address the client connects to (default localhost)
--help|Show the options
