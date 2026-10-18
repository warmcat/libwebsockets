# lws-api-test-http-cookie

Unit selftest for `lws_http_cookie_compose()`, the fail-closed Set-Cookie
composer used by the SSO plugins (`protocol_lws_login`,
`protocol_lws_oauth2_client`, `protocol_lws_auth_server`) instead of raw
`lws_snprintf`.

It covers the mint and host-only shapes, the F-048 worst-case *clearing*
cookie (63-byte cookie name + 127-byte `cookie-domain` + Expires + Max-Age=0)
including the auth-server plugin's `AUTH_SERVER_CLEAR_COOKIE_SZ` sizing, the
NULL-buffer measuring mode, fail-closed truncation refusal (one byte short
composes nothing), and refusal of NULL name / value arguments.

`getters.c` covers the request side, `lws_http_cookie_get()`,
`lws_http_cookie_get_nth()` and the JWT cookie readers built on them
(`lws_jwt_get_http_cookie_validate_jwt()`, `lws_jwt_auth_create()`), against
real request headers: a server vhost and a client in the same process, the
client sending each case's `Cookie:` header(s) and the server resolving the
case's lookup.  It fences that exactly the name asked for is resolved: a
`__Host-` or `__Secure-` cookie is only found under its full prefixed name,
and a bare-named cookie, which a sibling host could have planted, never
stands in for it, including a validly signed JWT planted that way.  And it
fences that a name only matches at the start of a cookie-pair: a `name=`
inside another cookie's value (`a=x name=FORGED`) is not a cookie of that
name, for the plain getters and the JWT readers alike.  It also fences the
JWT `purpose` (G-171): a token is only accepted where its signed `"pur"`
claim is exactly the purpose asked for, a token with a purpose is refused
where none is asked for, and signing refuses a purpose that could end its
JSON string or an `extra_json` carrying a `"pur"` of its own.  And it fences
the same contract for session tokens (G-188): `lws_jwt_auth_create_via_info()`
accepts a token only when its top-level `"iss"`, `"aud"` and `"pur"` are each
present once and exactly what was asked for (a duplicated, nested, non-string
or longer `"pur"` is refused, as is an empty requirement),
`lws_jwt_auth_create()` refuses any token with a purpose, a live token with
the right purpose is found behind one with the wrong purpose, and
`lws_jwt_auth_update()` keeps the purpose the object was created with.  It needs
`LWS_WITH_SERVER` and `LWS_WITH_CLIENT`, and `LWS_WITH_JOSE` for the JWT
cases.

ctest passes `--server ${LWS_CTEST_SERVER_RESOLVE}`, the address the client
connects to; it defaults to `localhost`.

Run via ctest from a build with `-DLWS_WITH_MINIMAL_EXAMPLES=1`.
