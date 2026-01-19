# lws_captcha_ratelimit plugin

This plugin provides a simple interceptor mechanism based on a time delay (rate limit). It is designed to be used with the LWS `interceptor_path` mount option.

## Functionality

When a user accesses a protected mount, LWS checks for a valid JWT cookie. If the cookie is missing or invalid, the request is diverted to the `interceptor_path`. This plugin, when mounted at `interceptor_path`, serves a simple HTML page with a button.

Both before, and after when the user clicks the button, the plugin enforces a configurable wait. After the wait, it issues a signed JWT cookie valid for a configured duration (default 10 minutes) and redirects the user back to the original URL.

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
