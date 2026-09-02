# lws-api-test-sshd-userauth

Fences the F-056 security fixes in the sshd plugin's USERAUTH handling.

Both the public key blob and the signature blob sent with a
`SSH_MSG_USERAUTH_REQUEST` are walked with attacker-chosen inner lengths;
the walks must be bounded against, and exactly consume, the outer blob, or
the RSA verify is handed pointers past the blob allocations (pre-auth
remote heap OOB read).

An sshd vhost (with runtime-generated ops) and a raw client run in one
process.  The client skips KEX and drives the USERAUTH states directly on
the plaintext transport:

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
   over the plaintext the server reconstructs, with the all-zero pre-KEX
   session id) must still authenticate, open a session channel, and have
   a 1-byte `exec` command refused with `CHANNEL_FAILURE` without reading
   past the command allocation looking for an `"scp "` prefix.

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
