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

The `captcha_ratelimit` handles this natively. Using its injected JavaScript context (`lws_interceptor_path`), the client-side `captcha.js` script queries the upstream `lws-login`'s `/.lws-login-status` JSON endpoint directly. If the upstream interceptor confirms the session is already authenticated, the JavaScript immediately bypasses the captcha interaction (`post-delay-ms` and `pre-delay-ms` penalties) by dynamically appending a `?bypass=1` URI argument to the captcha submission, saving configurations such as explicitly mapping `lws-login` cryptographic secrets redundantly in the `captcha_ratelimit` vhost options.
