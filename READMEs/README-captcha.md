# lws_captcha_ratelimit plugin

This plugin provides a simple interceptor mechanism based on a time delay (rate limit). It is designed to be used with the LWS `interceptor_path` mount option.

## Functionality

When a user accesses a protected mount, LWS checks for a valid JWT cookie. If the cookie is missing or invalid, the request is diverted to the `interceptor_path`. This plugin, when mounted at `interceptor_path`, serves a simple HTML page with a button.

Both before, and after when the user clicks the button, the plugin enforces a configurable wait. After the wait, it issues a signed JWT cookie valid for a configured duration (default 10 minutes) and redirects the user back to the original URL.

The challenge page itself comes with a short-lived "visit" cookie, which the
wait before the button is measured from.  It is signed with the same key,
issuer, audience and subject (the peer IP) as the pass cookie, so the two are
told apart by a signed purpose claim (`"pur"`, see `README.jwt.md`), not by
their cookie names, which the client chooses: a visit token presented under
the pass cookie's name does not pass the gate.  Pass cookies minted before the
purpose claim existed carry none, so after upgrading, visitors holding one are
challenged once more.

## Configuration

### 1. Enable the Plugin

Ensure `protocol_lws_captcha_ratelimit` is enabled in your build.

### 2. Configure Vhost PVOs

The plugin is configured via per-vhost options (PVOs) under the protocol name `lws_captcha_ratelimit`.

| Option | Description | Default |
|---|---|---|
| `jwt-issuer` | The issuer claim (`iss`) for the JWT. | "lws" |
| `jwt-audience` | The audience claim (`aud`) for the JWT. | "lws" |
| `jwt-alg` | The signing algorithm. | "HS256" |
| `jwt-expiry` | Validity duration of the JWT in seconds. | 600 (10 mins) |
| `cookie-name` | The name of the cookie to set/check. | "lws_captcha_ratelimit" |
| `jwt-jwk` | **Required.** Path to a file containing the JWK (JSON Web Key) or the JWK JSON itself. | - |
| `asset-dir` | Path to interceptor assets (CSS, JS, images). Use `file://` prefix for local paths. | - |
| `pre-delay-ms` | Delay before "Continue" button appears. | 5000 |
| `post-delay-ms` | Delay after "Continue" button is pressed. | 3000 |
| `status` | Status message to display. | "ok" |
| `stats-logging` | Whether to emit once-a-minute status logging | 0 |

## Stacking with `lws-login`

When `captcha_ratelimit` works in sequence with authentication interceptors like `lws-login`, unauthenticated public guests must endure the captcha delays prior to attempting log-in operations or browsing unauthenticated domains. If a user is already fundamentally logged into your application ecosystem, repeatedly forcing a captcha check hinders experience.

The `captcha_ratelimit` handles this natively, when `lws-login` is enabled on the same vhost.  When the challenge is submitted, it asks `lws-login` (`LWS_LOGIN_CALLBACK_SESSION_LIVE`) whether the request carries a live session holding the grant for the service the mount names.  If it does, the pass cookie is issued at once, skipping the `pre-delay-ms` and `post-delay-ms` delays; otherwise the delays apply as usual.  So `captcha_ratelimit` needs no copy of `lws-login`'s keys in its own options.

Only a real session skips the delays.  On a vhost or mount where `lws-login` has `unauth-allow` set, anonymous visitors are let through by `lws-login` itself, but they are not logged in, so they still wait out the captcha: rate limiting anonymous visitors to public pages is what the captcha is there for.

To spare logged-in users even seeing the challenge, the client-side `captcha.js`, using its injected `lws_interceptor_path`, queries `lws-login`'s `/.lws-login-status` endpoint and, if it reports a session with the grant, submits the challenge immediately.  The server makes its own decision as above, so this is only a convenience: a client claiming to be logged in gains nothing.

**JWK Generation:**

The JWK can be produced by `lws-crypto-jwk -t OCT`.

**Example JWK (`captcha-key.jwk`):**
```json
{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}
```

### 3. Configure Mounts

In your JSON configuration (e.g., `vhosts`), configure the protected mount with `interceptor-path` pointing to the mount handled by this plugin.

**Example `localhost` vhost config:**

```json
{
    "vhosts": [{
        "name": "localhost",
        "port": "7681",
        "ws-protocols": [{
            "lws_captcha_ratelimit": {
                "status": "ok",
                "jwt-jwk": "{\"k\":\"626UazEjGLhz1Kzrdi427lg0Z4cAamGNlz7O1rgFwECsjQBmmcgBYaj-LIK-vJp67gDUnUlq0GL44Br2_kox6VlX8iS24vVaDqrTNuCW-sEM06yJn2BJXDCn-ng3WsliA02U7CLu7UFOPr7kL6kXRGLSKkg0m5LaeyNO7q0vHEZyCLGEdyYCYjzYXhw8gny4qzlYCMsFvt6VoWnOEGeR4AS1J0s8KjCEb30RoQpRIipPdvjWSgVJKHRbOwXg-eE7R1YSUkgOD6ogyEzoDpNxTS2o0CNy0hNykZDYPzca01Smo3BAs3faSFqurtYRxEBhMk1yqkk3GI_jJma19KIfVrQN6vS5IQRyOyonRpH9uwCGm_I-NTquic4SRaBsjPxZ8bmTvtkQ1SgvySWNiMZ2St_F99K4VCXM1ZfUUK2B7aZ3cf4o4ZFh0J46Do8HNfuxvG_OT9B55r3dZ5tvfgbZwURBTWNmnUtDJPfWxswe6eYghU-jYscCdEyxzVWBUc_ujA_DOcFGKLycMOvLXo41Ho4TLHyX65u4ypAciER_QDkx8EGRPQvreByNEp2DLftEiZ02ImTduCpcWehcDBJ_1d3an0x1k4DRWbpk8T1BuanH1o77QUAqGKyW2rTo_IMO0ZE-0JqC_vOKlh46i9Wp9xi73zysDKkqex6MkyqAflE\",\"kty\":\"oct\"}",
                "jwt-issuer":           "lws-test",
                "jwt-audience":         "lws-test",
                "jwt-alg":              "HS256",
                "jwt-expiry":           600,
                "cookie-name":          "lws_captcha_jws",
                "asset-dir":            "file://_lws_ddir_/libwebsockets-test-server/captcha-ratelimit/captcha-assets",
                "pre-delay-ms":         5000,
                "post-delay-ms":        3000
            }
        }],
        "mounts": [{
            "mountpoint": "/",
            "origin": "/var/www/html",
            "default": "index.html",
            "interceptor-path": "/captcha"
        }, {
            "mountpoint": "/captcha",
            "origin": "callback://lws_captcha_ratelimit",
            "protocol": "lws_captcha_ratelimit"
        }]
    }]
}
```

Note that you should not use the provided example jwt-jwk in production.
You can regenerate one with `lws-crypto-jwk -t OCT` and copy it into place in the config.

In this example:
1.  Requests to `/` (and subpaths) are checked for a valid JWT.
2.  If invalid, they are diverted to `/captcha`.
3.  `/captcha` is handled by the `lws_captcha_ratelimit` protocol.
4.  The plugin serves the interceptor UI.
5.  Upon success, a cookie is set, and the user is redirected back to `/`.

Note that the interceptor UI references its assets (css, js and images) on the
interceptor mount itself, via the `lws_interceptor_path` injected into
`interceptor-config.js`.  The page is served at the originally requested,
protected URL; relative asset URIs would resolve against that URL and get the
HTML captcha page back instead of the asset.
