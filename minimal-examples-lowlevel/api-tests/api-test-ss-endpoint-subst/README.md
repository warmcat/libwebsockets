# lws api test ss endpoint subst

A Secure Streams policy endpoint can take `${metadata}`, so where a stream
connects to can be chosen at runtime.  A metadata value that came from outside
the process (an SS proxy client set it, or it was captured from a server's
response header) may fill in where in the network the stream goes, but not
take it out of the network: if it went into the endpoint, a resulting
`file://` url, or a host that is a `+` unix domain socket address, is refused,
unless the policy wrote the `file://` or `+` literally, before the first `${`.
And if the policy wrote any of the endpoint itself, ie, it is not just one
`${name}`, an outside value with url delimiters in it is refused, so it can't
take over the scheme, host or port and push the policy's part into the path.
Values the app set itself with `lws_ss_set_metadata()` are not restricted.

A raw socket server in the same process listens on tcp and on a unix domain
socket, answering any request with a 200 and noting it.  The response carries
an `x-ep:` header, that the streamtypes capture into the metadata their
endpoint uses.  Each phase is a stream of its own, with no retries.  Phases
with a captured value connect once with a value the app set, capture the
server's value, and connect again with that:

 - endpoint `${ep}` with a captured `file://` url, a `+` socket inside a url,
   the same with the socket in `[]`, and a bare `+` socket: all refused,
   without connecting or opening anything
 - endpoint `${ep}` with a captured ordinary url to our tcp server: connects
 - endpoint `+${sock}` with a captured socket name: connects to our unix
   domain socket server, since the policy wrote the `+`
 - endpoint `${ep}` with a `file://` url the app set: the file is read as rx
 - endpoint `${ep}` with a bare `+` socket the app set: connects to our unix
   domain socket server
 - endpoint `${h}.invalid` with a captured url, `host:port/`, `host:port?`,
   `host:port#` or `x@host:port/`: all refused, without connecting.  The first
   attempt of each, with a url the app set, connects
 - endpoint `http://${h}:${p}/x` with a captured `host:port/x?`: refused, and
   with a captured plain host name: connects (skipped if the test server
   address is an IPv6 literal, which has `:` in it)

The test file and the unix domain socket are created in the current
directory, named with the process id, and removed afterwards.

```
$ ./lws-api-test-ss-endpoint-subst
```

Option|Meaning
---|---
-d <loglevel>|Debug verbosity in decimal, eg, -d15
--server <address>|Address of the tcp test server (default localhost)
--help|Show the options
