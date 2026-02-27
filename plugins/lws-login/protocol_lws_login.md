# lws-login

## Introduction

The `lws-login` plugin is a mount-based interceptor handler that securely guards pages behind SQLite3-based credentials. Unauthenticated requests are intercepted and served the login portal pages in the configured asset directory. A completed login will sign an authentication validation cookie (JWT) which guarantees future visits transparent HTTP access without login prompts. 

## Per-Vhost Options (PVOs)

This plugin handles several PVO options to control SQLite3 access logic and the properties of the resulting JWT session cookie generated:

| PVO Name | Description |
|---|---|
| `db-path` | **Required.** An absolute file path pointing to the SQLite3 database file holding user credentials schema. |
| `asset-dir` | Directory path containing static web assets shown for login portals (e.g. `index.html`.) Set to `.` by default. Prefix with `file://` if desired. |
| `jwt-issuer` | Name to define inside the JWT issuer flag. Defaults to `"lws"`. |
| `jwt-audience` | Audience restriction string embedded in the JWT. Defaults to `"lws"`. |
| `jwt-alg` | The JWT signing/validation algorithmic string. Defaults to `"HS256"`. |
| `jwt-expiry` | Expected validity duration for the session token in seconds. Defaults to `3600`. |
| `cookie-name` | Custom name emitted for tracking the browser cookie containing the session token. Defaults to `"lws_login_jwt"`. |
| `jwt-jwk` | **Required.** A JSON Web Key string used to establish signing criteria for the generated tokens. |
