# lws-login / JWT Auth Bouncer

## Introduction

The `lws-login` plugin is a mount-based interceptor handler that securely guards pages by explicitly requiring a verified JSON Web Token (JWT) session.

Instead of maintaining its own database, it acts as a lightweight, proactive **bouncer**, completely reliant on the core `lws_jwt_auth` helper API. Unauthenticated requests—or requests with a valid JWT but lacking the required `grants` privileges—are swiftly intercepted and redirected via HTTP 302 to a central Auth Server portal matching the configured PVOs. Once a user procures a valid session cookie from the Auth Server, the bouncer transparently allows traffic to pass through to the underlying application mount.

Furthermore, `lws-login` natively maintains an `lws_sorted_usec_list` (SUL) expiration timer tracking the exact token `exp` boundary. Even if a WebSocket successfully upgrades over the protected mount, the connection will be gracefully terminated the exact moment the active authorization token naturally expires!

## Per-Vhost Options (PVOs)

This plugin handles several PVO options to control the redirection routing and the properties of the required JWT session cookie:

| PVO Name | Description |
|---|---|
| `auth-server-url` | **Required.** The base URI of the central auth server portal to redirect unauthenticated users to (e.g. `https://auth.warmcat.com/login`). |
| `jwt-jwk` | **Required.** A JSON Web Key string used to establish signing criteria for verifying the token signature. Must match the public key the central server uses to sign tokens. |

**Where does the JWK come from?**
The central `auth-server` plugin automatically generates an Elliptic Curve (EC P-256) keypair upon its first startup and saves it to its configured `jwk_path` (e.g., `/var/db/lws-auth.jwk`). To configure the `jwt-jwk` PVO for this bouncer mount, you simply take the contents of that generated file.

Because the JWT validator only strictly requires the public key components to verify the signature, you can either:
1. Provide the exact literal JSON string from the Auth Server's generated JWK file.
2. Read the literal string dynamically into the PVO when configuring your mount from your application.

*(Note: While passing the full keypair including the private key into the bouncer works, it is best practice to strip the private component `d` from the JSON if the bouncer is operating on an entirely different physical server).*

| `cookie-name` | Custom name emitted for tracking the browser cookie containing the session token. Defaults to `"auth_session"`. |
| `service-name` | The explicitly required grant category strictly checked against the JWT privileges array. Defaults to `"default-service"`. |
| `min-grant-level` | The strict integer threshold allowing passage for the given service name within the token. Defaults to `1`. |

## Redirection Behavior

If a visiting client lacks the required `cookie-name` or their validated token does not meet the `<service-name>:<min-grant-level>` threshold, the plugin calculates the `redirect_uri` based on the exact path they were attempting to reach.

It intercepts the connection and issues a standard `HTTP 302 Found` bouncing them dynamically to:
`%auth-server-url%?service_name=%service-name%&redirect_uri=%url_encoded_path%`

The central Auth Server portal is expected to natively intercept these parameters, inform the user they are authenticating for `%service-name%`, and return them safely to `%url_encoded_path%` upon success!
