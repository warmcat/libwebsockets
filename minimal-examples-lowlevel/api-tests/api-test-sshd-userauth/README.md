# lws-api-test-sshd-userauth

Fences the F-056 security fixes in the sshd plugin's USERAUTH handling,
the G-284 / G-285 fixes in its pre-auth transport parser, and G-286: the
services run only on the transport the key exchange sets up.

Both the public key blob and the signature blob sent with a
`SSH_MSG_USERAUTH_REQUEST` are walked with attacker-chosen inner lengths;
the walks must be bounded against, and exactly consume, the outer blob, or
the RSA verify is handed pointers past the blob allocations (pre-auth
remote heap OOB read).

An sshd vhost (with runtime-generated ops) and a raw client run in one
process.  The client does a real `curve25519-sha256@libssh.org` key
exchange with the plugin's own primitives, checks the server's ed25519
signature over the exchange hash, and drives the USERAUTH states over
`chacha20-poly1305@openssh.com`:

1. with ops that accept any blob structure (a consumer without the demo's
   whole-blob byte-compare fence), a pubkey blob with a huge inner length,
   and one with an mpint length one byte too large, must each be rejected
   with `USERAUTH_FAILURE`,
2. the genuine authorized pubkey blob (so `is_pubkey_authorized` passes)
   with signature blobs that are malformed in three ways (huge inner algo
   name length; signature length one past the end of the blob; trailing
   junk so the blob is not exactly consumed) must likewise be rejected
   with `USERAUTH_FAILURE`,
3. a genuinely signed request (signed with a runtime-generated keypair
   over the plaintext the server reconstructs, which starts with the
   session id from the key exchange) must still authenticate, open a
   session channel, and have
   a 1-byte `exec` command refused with `CHANNEL_FAILURE` without reading
   past the command allocation looking for an `"scp "` prefix.  Before the
   channel is opened, two more genuinely signed requests are sent after
   the success: they are silently ignored (RFC4252 5.1), and must not leak
   their signature allocations (G-303, LSan reports them otherwise).

Three further scenarios, each on a fresh connection, fence the pre-auth
transport parser:

4. a second `KEXINIT` while the first key exchange is in progress: the
   server must close the connection, rather than orphan its copy of the
   first one (RFC4253 7.1); that a single `KEXINIT` is accepted is shown by
   the scenarios that complete a key exchange,
5. a `DISCONNECT` with a 1000-byte description and language tag `"en"`,
   followed by an `IGNORE` in the same write: the `disconnect_reason` op
   must be called exactly once with both strings intact, and the server
   must close the connection without acting on the packet that follows,
6. after the key exchange, a `SERVICE_REQUEST` for an empty service name
   must be accepted (an empty string completes, rather than swallowing the
   following bytes), then a `DISCONNECT` with empty description and
   language tag must reach the op once and close the connection.

And three more fence G-286, each of which must close the connection
without any reply:

7. a `SERVICE_REQUEST` for `ssh-userauth` before any key exchange,
8. a `USERAUTH_REQUEST` before any key exchange (it used to be judged in
   plaintext, its signature made over an all-zero session id),
9. after the key exchange, a `USERAUTH_REQUEST` following an accepted
   `SERVICE_REQUEST` for a service other than `ssh-userauth`.

The test exits 0 if all the expectations held.

## Build

Requires lws built with `LWS_WITH_TLS` and `LWS_WITH_GENCRYPTO` (not
mbedTLS), client and server support.

```
cmake .. -DLWS_WITH_MINIMAL_EXAMPLES=1 && make && ctest -R sshd-userauth
```

## Usage

Commandline option|Meaning
---|---
`-p <port>`|Port to run the server-side vhost on (chosen uniquely by ctest)
`-d <level>`|Debug verbosity in decimal, eg, `-d1039`
