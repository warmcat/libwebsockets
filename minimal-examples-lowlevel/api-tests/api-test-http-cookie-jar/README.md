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

Needs `LWS_WITH_CACHE_NSCOOKIEJAR` (Linux), client and server support.

|option|meaning|
|---|---|
|-p <port>|Port for the server vhost (default 7700)|
|--jar <path>|Cookie jar file, emptied at start and removed at the end (default ./cookie-jar-test.txt)|

Run via ctest from a build with `-DLWS_WITH_MINIMAL_EXAMPLES=1`.
