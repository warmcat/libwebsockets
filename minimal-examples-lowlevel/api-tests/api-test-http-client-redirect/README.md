# lws api test http client redirect

How the lws http client follows redirects, and the parts of RFC 9110 / 9112
that decide what it sends where afterwards.

 - A `Location` is resolved against the request it answers (RFC 3986 5.2): a
   relative path is merged with the request's path, dot segments are removed,
   a query alone keeps the path, a fragment is dropped, and
   `//host:port/path` names another authority rather than being a path.  A
   relative reference keeps the request's `Host:`.
 - The method it is followed with (RFC 9110 15.4): a 301 or 302 turns only a
   POST into a GET, a 303 turns anything but a HEAD into a GET, and 307 / 308
   keep the method.  A request that stays a POST or a PUT sends its body
   again; one turned into a GET sends none.
 - Locations that are refused rather than guessed at: two of them, one with
   userinfo, a port outside 1 - 65535, a scheme that is not http(s), and
   bytes that are not a URI reference.
 - A response saying `Connection: close` (RFC 9112 9.6) leaves its connection
   for no further request, even one that asked to pipeline on it; without it,
   the next request rides the same connection.
 - A request body is timed per piece: an upload that keeps moving completes,
   however much longer than the context's timeout (2s here) it takes.
 - A digest auth challenge that closes its connection is answered on a new
   one, to the same authority, so the request's `Host:` is kept (when lws has
   digest auth and a tls library, whose hashes it uses).
 - `lws_client_redirect_info()` tells the redirect callback where a redirect
   goes, and whether credentials set for the request may go there: only over
   https, to the request's host or a subdomain of it (another port is the
   same host; a host merely ending the same way, or an address, is not).  It
   tells the handshake header callback of a request a redirect made where it
   is going, and nothing for one that was not redirected.
 - lws itself refuses a redirect that would take the digest auth credentials
   it holds for the request elsewhere.

The server is a raw socket in the same process speaking http by hand, so it
can send exactly these redirects, and see exactly the request line, `Host:`
and body the client sent, and on which of the case's connections.  Each case
checks the last request the server saw, and how many it saw.

```
$ ./lws-api-test-http-client-redirect -p 7730
```

Option|Meaning
---|---
-d <loglevel>|Debug verbosity in decimal, eg, -d15
-p <port>|The server's port (default 7730)
