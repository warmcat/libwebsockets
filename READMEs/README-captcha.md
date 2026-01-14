# lws_captcha_ratelimit plugin

This plugin provides a simple captcha mechanism based on a time delay (rate limit). It is designed to be used with the LWS `captcha_path` mount option.

## Functionality

When a user accesses a protected mount, LWS checks for a valid JWT cookie. If the cookie is missing or invalid, the request is diverted to the `captcha_path`. This plugin, when mounted at `captcha_path`, serves a simple HTML page with a button.

When the user clicks the button, the plugin enforces a 5-second wait. After the wait, it issues a signed JWT cookie valid for a configured duration (default 10 minutes) and redirects the user back to the original URL.

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
| `jwt-jwk` | **Required.** Path to a file containing the JWK (JSON Web Key) used for signing/verifying. | - |

**Example JWK (`captcha-key.jwk`):**
```json
{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}
```

### 3. Configure Mounts

In your JSON configuration (e.g., `vhosts`), configure the protected mount with `captcha-path` pointing to the mount handled by this plugin.

**Example `localhost` vhost config:**

```json
{
    "vhosts": [{
        "name": "localhost",
        "port": "7681",
        "ws-protocols": [{
            "lws_captcha_ratelimit": {
                "jwt-jwk": "/path/to/captcha-key.jwk",
                "jwt-expiry": "600"
            }
        }],
        "mounts": [{
            "mountpoint": "/",
            "origin": "/var/www/html",
            "default": "index.html",
            "captcha-path": "/captcha"
        }, {
            "mountpoint": "/captcha",
            "origin": "callback://lws_captcha_ratelimit",
            "protocol": "lws_captcha_ratelimit"
        }]
    }]
}
```

In this example:
1.  Requests to `/` (and subpaths) are checked for a valid JWT.
2.  If invalid, they are diverted to `/captcha`.
3.  `/captcha` is handled by the `lws_captcha_ratelimit` protocol.
4.  The plugin serves the captcha UI.
5.  Upon success, a cookie is set, and the user is redirected back to `/`.
