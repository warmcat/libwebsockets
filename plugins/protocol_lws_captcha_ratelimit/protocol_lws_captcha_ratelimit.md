# lws-captcha-ratelimit

## Introduction

The `lws-captcha-ratelimit` plugin provides a simple button-based captcha integration as an interceptor. It displays a button a fixed time after the page loads and delays another fixed time after the user clicks it. Successfully passing the captcha generates a signed JSON Web Token (JWT) tracking their authenticated ratelimiting session, mitigating immediate automated bot spam to endpoints mounted with this interceptor.

## Per-Vhost Options (PVOs)

This plugin is configured entirely by Per-Vhost Options (PVOs):

| PVO Name | Description |
|---|---|
| `jwt-jwk` | **Required.** A JSON Web Key string used to establish signing rules for the generated session tokens. Remember to escape quotes inside the JSON string if specifying directly. |
| `jwt-issuer` | Name to record as the JWT issuer. |
| `jwt-audience` | Audience restriction string embedded in the JWT. |
| `jwt-alg` | The JWT signing/validation cryptographic algorithm (e.g. `"HS256"`). |
| `jwt-expiry` | Expected validity duration for the session token in seconds. |
| `cookie-name` | Custom name emitted for tracking the browser cookie containing the session token. |
| `asset-dir` | Path to the directory where static web assets shown for captcha portals (HTML/CSS) live. |
| `pre-delay-ms` | Time in milliseconds to delay before the captcha interaction button appears to the user. |
| `post-delay-ms` | Time in milliseconds to delay processing after the user has submitted the captcha. |
## Stacking with `lws-login`

When `captcha_ratelimit` works in sequence with authentication interceptors like `lws-login`, unauthenticated public guests must endure the captcha delays prior to attempting log-in operations or browsing unauthenticated domains. If a user is already fundamentally logged into your application ecosystem, repeatedly forcing a captcha check hinders experience.

The `captcha_ratelimit` handles this natively, when `lws-login` is enabled on the same vhost.  When the challenge is submitted, it asks `lws-login` (`LWS_LOGIN_CALLBACK_SESSION_LIVE`) whether the request carries a live session holding the grant for the service the mount names.  If it does, the pass cookie is issued at once, skipping the `pre-delay-ms` and `post-delay-ms` delays; otherwise the delays apply as usual.  So `captcha_ratelimit` needs no copy of `lws-login`'s keys in its own options.

Only a real session skips the delays.  On a vhost or mount where `lws-login` has `unauth-allow` set, anonymous visitors are let through by `lws-login` itself, but they are not logged in, so they still wait out the captcha: rate limiting anonymous visitors to public pages is what the captcha is there for.

To spare logged-in users even seeing the challenge, the client-side `captcha.js`, using its injected `lws_interceptor_path`, queries `lws-login`'s `/.lws-login-status` endpoint and, if it reports a session with the grant, submits the challenge immediately.  The server makes its own decision as above, so this is only a convenience: a client claiming to be logged in gains nothing.
