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

You can produce a suitable JWK using the `lws-crypto-jwk` tool: `./bin/lws-crypto-jwk -t EC -v P-521`.  You'll need to escape the quotes in the key JWK if embedding it in JSON conf.

## SQLite3 Database Setup

The `lws-login` plugin expects a SQLite3 database containing a `users` table with `username` and `password` columns. The plugin will attempt to create this table automatically if it doesn't exist, but you must manually insert your users.

To initialize the schema and insert an example user (e.g., username `admin`, password `password123`), use the `sqlite3` command-line tool on your configured `db-path` (for example, `/var/lib/lwsws/login.sqlite`):

```bash
# Open the SQLite3 shell for your database payload
sqlite3 /var/lib/lwsws/login.sqlite
```

Then, run the following SQL commands:

```sql
CREATE TABLE IF NOT EXISTS users (
    username VARCHAR(32) PRIMARY KEY,
    password VARCHAR(64)
);

INSERT INTO users (username, password) VALUES ('admin', 'password123');
.exit
```

After creating the file, ensure that the system user running `lwsws` (e.g., `apache` or `nobody`) has read and write permissions to both the `login.sqlite` file and its parent directory.