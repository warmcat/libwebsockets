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

Run via ctest from a build with `-DLWS_WITH_MINIMAL_EXAMPLES=1`.
