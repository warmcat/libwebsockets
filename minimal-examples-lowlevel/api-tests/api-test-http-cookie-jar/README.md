# lws-api-test-http-cookie-jar

End to end test of the client cookie jar (`info->http_nsc_filepath` with
`LCCSCF_CACHE_COOKIES` on the client connection), with a server vhost in the
same context that sets a batch of cookies on `/set` and echoes back the
`Cookie:` header each later request arrived with.  The client always connects
to 127.0.0.1 but names a different host each time, so the jar sees requests to
`a.example.com`, `b.example.com`, `example.com` and `other.example`.

It checks the RFC 6265 scoping the jar applies to what a server sets:

 - a `Domain=` that does not domain-match the request host is ignored
 - a `Domain=` that does, with or without a leading dot and in any case,
   sends the cookie to that domain and its subdomains
 - a single-label `Domain=` (a TLD) is ignored
 - a cookie with no `Domain=` is host-only and is not sent to sibling hosts
 - a cookie name that is not an RFC 6265 token (eg, containing `*`) is ignored
 - a `Secure` cookie is not accepted over plaintext
 - a cookie with no `Path=` gets the default-path of the request that set it,
   and a `Path=` scopes the cookie to that path and below

and that a cookie set with an empty value (`name=`) is sent back as `name=`,
without stopping the other cookies at its level from being sent.

It also checks what the jar does with the cookies it stored (issue #3688):

 - a `Path=/` cookie is sent to every path on its host, and a `Path=/api/`
   one to the paths under `/api/` but not to `/api` itself, even when an empty
   result was cached for that path before the cookie was set
 - `Max-Age` sets the expiry and wins over `Expires`, in both directions
 - `Max-Age=0`, or a negative `Max-Age`, deletes the cookie
 - a `Max-Age` or `Expires` that does not parse is ignored, not the cookie
 - a cookie with `Max-Age=2` stops being sent once it runs out (the test waits
   2.5s for it)
 - a single-label host (`myhost`) gets its host-only cookies back, including
   one set with `Domain=myhost`, and `localhost` does not get them
 - so does an IPv6 literal host (`[::1]`), which has no dot either, and
   `[::2]` does not get them

Needs `LWS_WITH_CACHE_NSCOOKIEJAR` (Linux), client and server support.

|option|meaning|
|---|---|
|-p <port>|Port for the server vhost (default 7700)|
|--jar <path>|Cookie jar file, emptied at start and removed at the end (default ./cookie-jar-test.txt)|
|--l1-max-items <n>|Limit the jar's heap L1 to n items (default no limit): with fewer than a request's cookies, sending them keeps refilling L1 from the jar while the lookup result is walked|

ctest runs it twice, the second time with `--l1-max-items 2`.

Run via ctest from a build with `-DLWS_WITH_MINIMAL_EXAMPLES=1`.
