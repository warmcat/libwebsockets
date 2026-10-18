# lws-api-test-http-origin

Unit selftest for `lws_http_origin_check()`, the check a ws upgrade or a POST
that is authorized by an ambient credential (a session cookie) uses to refuse
requests a page of another site caused.  It is shared by the plugins that need
it (`protocol_deaddrop`, `protocol_lws_auth_server`'s admin ws,
`protocol_lws_dht_dnssec_monitor`'s UI ws).

A server vhost and a client run in the same process; the client sends each
case's `Host:` and `Origin:` header(s) and the server decides the case.  It
fences that the Origin must be `https://<Host>` (or `http://<Host>`, since the
test server is not itself TLS) compared whole and case-insensitively, so other
hosts, sibling hosts, lookalike suffixes, other ports, schemes, paths and
`null` are refused; that the allow list matches whole origins; and that no
Origin is accepted unless `LWS_HOC_REQUIRE_ORIGIN`, while an Origin that is
too long or repeated is refused rather than taken for "no Origin".

ctest passes `--server ${LWS_CTEST_SERVER_RESOLVE}`, the address the client
connects to; it defaults to `localhost`.

Run via ctest from a build with `-DLWS_WITH_MINIMAL_EXAMPLES=1`.
