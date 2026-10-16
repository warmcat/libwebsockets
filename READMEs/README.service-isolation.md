# Moving a TLS service onto its own box behind an lwsws front

This is how to take a service that is a vhost on your main lwsws, eg, an
`lws-auth-server` at `auth.example.com`, and run it on a separate box, while
your one public address still points at the main lwsws (the "front").

 - The front passes the service's connections through **undecrypted**: TLS
   (and QUIC) terminate on the service box, which alone holds the private
   key.
 - The front tells the service box who each client really is, with a PROXY
   v2 header, so its rate limits, bans and logs see real client addresses.
 - The service box gets its cert and key from the cert distribution server,
   kept current through ACME renewals.
 - The `lws-login` bouncers on the front's other vhosts learn the auth
   server's records from its feed, not its database.

Both lwsws need `LWS_WITH_TLS_PASSTHROUGH` (`LWS_WITH_DISTRO_RECOMMENDED`
includes it).  The service box needs h3 in its build if you want QUIC.

In the snippets, `<front-lan>` and `<svc-lan>` are the two boxes' LAN
addresses.

## 1. The service box's cert, by cert distribution

On the front's dnssec monitor:

 - make sure ACME issues a cert for the service name itself.  The
   distribution server sends a client the cert filed under its own name
   (`domains/example.com/certs/production/crt/auth.example.com-latest-*`),
   or else the domain's wildcard, never another name in the domain;
 - in its UI, create the distribution client for `auth` in example.com.  You
   get `distribution-client-auth.example.com.crt` and `.key`, CN
   `auth.example.com`.  Copy both to the service box, and also
   `pki/distribution-ca.crt`.  Leave the `.crt` in place on the front: the
   server compares the client cert presented with it, byte for byte, so
   don't regenerate it afterwards.

On the service box:

```json
"lws-cert-dist-client": {
	"status":	"ok",
	"base-dir":	"/etc/lwsws-pki",
	"server-url":	"wss://<front-lan>:<dist port>",
	"ca-filepath":	"/etc/lwsws-pki/distribution-ca.crt",
	"stub-user":	"lwsws-priv",
	"certs": { "auth": {
		"cert":	"/etc/lwsws-pki/mtls/distribution-client-auth.example.com.crt",
		"key":	"/etc/lwsws-pki/mtls/distribution-client-auth.example.com.key"
	} }
}
```

**Check:** it logs `cert for 'auth' installed`, and
`/etc/lwsws-pki/auth/fullchain.pem` and `privkey.pem` appear.  Give the
client's stub a user of its own with `"stub-user"`, eg, `lwsws-priv`, so it
doesn't stay root: `base-dir` must be owned by that user (root, without one)
and 0700, or the stub refuses to write a key there, and logs why.  See the
plugin's README for moving an existing install off root.  A failed install
is logged with its reason and retried with backoff; a client that was offline
catches up when it reconnects.

## 2. The service vhost on the service box

As it was on the front, except:

```json
"host-ssl-cert":		"/etc/lwsws-pki/auth/fullchain.pem",
"host-ssl-key":			"/etc/lwsws-pki/auth/privkey.pem",
"host-ssl-cert-grace-secs":	"900",
"proxy-v2-trusted":		"<front-lan>",
```

 - `host-ssl-cert-grace-secs`, as on the front, if the cert is published
   for DANE: a renewal arrives at once, before the new TLSA record has
   replaced cached copies of the old one.
 - `proxy-v2-trusted` makes every connection from the front, tcp or udp,
   start with a PROXY v2 header, whose client then becomes the peer address.
   A connection from the front without one is dropped, and nobody else's is
   ever read for one.
 - keep h3 in its `alpn`: QUIC is passed through too.

For an `lws-auth-server`, add to its pvos:

```json
"feed-secret":		"/etc/lwsws/auth-feed.secret",
"trusted-proxies":	"<see step 5>"
```

and enable the feed alongside it:

```json
"lws-auth-feed": { "status": "ok" }
```

The secret file holds 32 to 128 random printable characters, and is as
sensitive as the database: the feed carries every account's uid and grants.

**Mail:** the auth server sends through `127.0.0.1:25` by default.  Run a
relay on the service box, or point its vhost's `lws-smtp-client`
`smtp-host` at the front's MTA.

## 3. Moving the data

 - Stop the service on the front first: logins and the audit log write to
   the database, and anything written after the copy is lost.
 - Copy the database (`db_path`) and the signing key (`jwk_path` and its
   `.pub`), root-only.

**Test before cutting over** from a third machine, which is not in
`proxy-v2-trusted` and so is served without a header:

```
curl --resolve auth.example.com:443:<svc-lan> https://auth.example.com/
```

Check the cert and the page.  Testing from the front fails: its address is
trusted, so a connection without a header is dropped.

## 4. The front

Replace the service's vhost with:

```json
{
	"name":				"auth.example.com",
	"port":				"443",
	"tls-passthrough":		"<svc-lan>:443",
	"tls-passthrough-proxy-v2":	"1"
}
```

 - Give the target numerically: that also turns on QUIC passthrough.
 - The vhosts that terminate tls on the port must be made before it, so the
   listener is theirs.
 - Let the front reach the service box on tcp and udp 443.
 - DNS does not change, nor, with the same cert, does the TLSA record.

Every `lws-login` on the front:

 - drop `db-path` (it only warns now);
 - add `"auth-feed-secret"`, the same secret as the auth server's
   `feed-secret`;
 - drop `jwt-jwk` to take the key from the feed, or keep it pinned with only
   the public `.pub`.

## 5. Which address the auth server trusts for `X-Forwarded-For`

`lws-login`'s renewal side channel, and `lws-oauth2-client`'s `/api/token`,
reach `auth.example.com` at your public address, ie, back into the front's
own passthrough.  So they arrive at the auth server with a PROXY header
naming the front itself, typically its public address, since that is what
the kernel uses to reach itself.  They send the browser's address as
`X-Forwarded-For`, which the auth server believes only from
`trusted-proxies`: put that address there, so a run of bad renewals strikes
the browser, not your front.  Read it off what the auth server logs as the
peer of an `/api/sso_exchange`, or of the feed subscriber.

Don't shortcut the name to `<svc-lan>` in `/etc/hosts` on the front: those
connections would then come from the trusted LAN address with no PROXY
header, and be dropped.

## 6. After the cutover

 - the service logs real client addresses, not the front's;
 - `lws-login` logs `auth feed snapshot: N accounts, ...`, and after a
   password reset on the auth server, the old session's next request on the
   front logs `session epoch revoked` within a second or so;
 - a login, and a silent renewal, work;
 - an h3 visit works, and the front logs `quic from ... passed through`.

**Rollback** is putting the old vhost back on the front, with the old
`db-path`/`jwt-jwk`; anything the service box wrote to its copy of the
database meanwhile is lost.

## Limits

 - QUIC passthrough follows a client that moves (eg, a NAT rebinding) by the
   connection IDs the server shows in its long headers, which is all an lws
   server uses.
 - The PROXY header adds up to 52 bytes to each datagram between the front
   and the service box.
 - The front reads the SNI only from QUIC v1 Initials; a v2 one goes to the
   front's own QUIC.

See also `README.lwsws.md` (passthrough and PROXY v2 config), the
`lws-cert-dist-client` / `-server`, `lws-auth-server` and `lws-login` plugin
READMEs.
