# CI matrix and platform splits

## Sai configuration semantics

Sai (`.sai.json`) is the CI.  The rules for a config's `platforms`:

 - no `platforms` → all default platforms;
 - a list without `none` is **added** to the defaults;
 - `not X` removes X;
 - `none, X` → only X.

Some platforms build but never run ctest (scan-build / clang, coverity,
fuzz, quic-interop).  Sai substitutes only `${prep}`, `${cmake}` and
`${cpack}` into fixed per-platform steps, so a config that needs ctest on
a platform with no ctest step carries build + ctest inside its `cmake`
string (the `coverage` config does this).

Before assuming CI exercised a feature, check that its option is on in a
config that actually runs ctest.  Many options are on in no ctest config,
and several are never turned off in any.  `distro_recommended` is the only
ctest config covering a long list of options (MQTT, HTTP proxy, ranges,
SOCKS5, compression, ...).  When adding a Sai dimension, verify it locally
with `-DLWS_WITH_MINIMAL_EXAMPLES=1` **and** ctest: examples have broken
the link on a new dimension that built fine without them.

## Windows

 - **Wrap every POSIX io length** (`read`, `write`, `send`, `recv`,
   `sendto`...) in `LWS_POSIX_LENGTH_CAST()`.  A bare `size_t` (including
   `sizeof(buf) - n`) compiles everywhere except MSVC, where C4267 is an
   error.  Local gcc never shows it, so it must be a habit at write time.
 - A Windows ctest "timeout" with no failure text is usually an assert or
   crash, not a hang (historically a Debug CRT modal dialog; now routed to
   stderr).  The Sai log of a timed-out test is cut at an arbitrary point,
   so its tail says nothing about where it stopped.
 - Exit code 3 is `abort()` (a Debug CRT assert).  Exit code 252 is
   `lws_spawn_piped_kill_child_process()` killing a child: expected at
   teardown.
 - `lws_spawn` on Windows reads the child pipe itself and delivers data in
   the `RAW_RX_FILE` callback's `in`/`len`; on unix the callback reads the
   fd itself.  Callbacks must handle both.
 - The MSVC builders can have vcpkg MSBuild integration linking every
   installed library into `try_compile`, so feature probes for one TLS
   backend can come back "found" in a build of another.  Gate probes to
   the backend they belong to.  Static mbedtls on Windows needs `ws2_32`
   and `bcrypt` on its library list, or every probe fails to link and the
   build silently loses ALPN / SNI.
 - Mingw cross builds (`contrib/cross-w64.cmake`) are useful for syntax
   checking Windows-only files, but they see errors MSVC doesn't
   (int-vs-HANDLE) and miss ones it does (vcpkg probes).  Compile single
   objects from `build.make` rather than expecting a full link.
 - Schannel: `DecryptMessage()` returns `SEC_I_RENEGOTIATE` for any TLS 1.3
   post-handshake message (NewSessionTicket, KeyUpdate), which must be fed
   back through Initialize/AcceptSecurityContext.  `CERT_CHAIN_POLICY_SSL`
   takes ignore bits from `SSL_EXTRA_CERT_CHAIN_POLICY_PARA::fdwChecks` as
   well as `dwFlags`.  Schannel needs `lws_set_blocking_send()` or
   Windows fakes POLLOUT every turn.  Before blaming the TLS client path
   for a schannel-only failure, check whether the test is even built on
   the OpenSSL Windows dimension (it runs with HTTP3 off).

## macOS

 - **poll() is kqueue-backed and differs from Linux.**  An fd whose events
   ask for neither POLLIN nor POLLOUT reports nothing, not even POLLHUP.
   EOF on a read reports POLLIN|POLLHUP every time, even when the pipe is
   drained.  Mac-only spins and hangs are often this.  See
   [debug-recipes.md](debug-recipes.md) for an LD_PRELOAD shim that gives
   Linux these semantics.
 - **Received peer address family is the platform's choice.**  For an
   AF_INET6 socket bound to a v4-mapped address, macOS reports an IPv4
   peer as plain `sockaddr_in`; Linux uses the v4-mapped form.  And macOS
   refuses `sendto()` of an AF_INET sockaddr on an AF_INET6 socket
   (EINVAL); Linux accepts it.  Normalise a received address to the family
   of the socket you will answer on.  `AF_INET6` is 30 on Darwin, 10 on
   Linux: "af 30" in a log is a mac.
 - Darwin kqueue fds refuse O_NONBLOCK; adopting them needs
   `LWS_ADOPT_FLAG_NO_NONBLOCK`.
 - Linux loopback buffering hides bugs where a close with unread rx loses
   tx (the kernel aborts the connection and drops unsent data).  macOS
   shows them.  Clamp the receiver's `SO_RCVBUF` in tests to see them on
   Linux.

## libc printf

 - glibc prints an invalid conversion like `%"` literally; Apple libc and
   MSVC drop it.  A test failing only on mac and Windows in integer-only
   code: grep for a bare `%` in strings used as formats.
 - glibc prints `(null)` for a NULL `%s`; QNX libc faults, and other
   platforms may too.  Guard with the tree's inline `x ? x : "(null)"`
   idiom.
 - The context-less default log level must include `LLL_USER`; a Sai log
   with only `N:` lines and no `U:` banner means user output was lost.

## Release builds and log levels

Log calls compile out per level.  A variable only read by an
`lwsl_info()` must have its declaration, updates and the log call wrapped
in `#if (_LWS_ENABLED_LOGS & LLL_INFO)` (or the matching bit).  Do not add
`(void)var;`.  Local gcc may not warn where the Sai builders' compilers
do, so check a Release tree as well as a debug one.

## TLS backend splits

Sai builds many TLS backends and versions.  A failure on "the same N of M
platforms" of one backend's dimension is usually a version split.

 - **mbedtls**: some Sai platforms have 2.x (no TLS 1.3 at all), others
   3.6, plus a 4.x dimension.  Gate TLS 1.3 code on
   `MBEDTLS_SSL_PROTO_TLS1_3`.  mbedtls 4 has no `mbedtls_pk_setup()`, no
   `rsa_gen_key`/`ecp_gen_key`, and no rng args on `pk_parse_key` or
   `x509write_crt_der`; follow `lws_x509_mbedtls_gen_key()`.  mbedtls 4's
   RSA private op is roughly 4x slower than 3.6, so bursts of accepts
   against RSA-4096 keys can exceed TLS timeouts on small boards.  A
   QUIC-capable mbedtls needs the lws-patched tree; lws cmake refuses QUIC
   on stock mbedtls.
 - **GCM via `lws_genaes`**: mbedtls and schannel treat the *first* GCM
   call as the AAD pass regardless of `out`; openssl, gnutls, bearssl and
   openHiTLS key off `out == NULL`.  Every GCM caller must make an
   explicit AAD pass first (`in` NULL, len 0, `out` NULL if there is no
   AAD) and process the payload from the second call.  "Works on
   openssl/gnutls, fails on mbedtls/schannel" with GCM is this.
 - **GnuTLS**: versions before 3.8.4 crash a QUIC server that accepts
   0-RTT (upstream bug), so lws doesn't accept server 0-RTT there.  GnuTLS
   clients send 0-RTT on any resumed TLS 1.3 ticket.  Ubuntu 24.04 boards
   have 3.8.3.  Check the board's gnutls version first for gnutls-only
   QUIC / 0-RTT failures.  GnuTLS verifies the peer only in
   `lws_tls_client_confirm_peer_cert()`, after the handshake.
 - **openHiTLS and bearssl** need a non-NULL context for
   `lws_x509_create_cert()` (EAL init / entropy); openssl and mbedtls
   accept NULL.  Only openssl emits SKI/AKI in generated certs.
 - The openssl-family QUIC-API backends (aws-lc, boringssl, libressl,
   wolfssl) and openHiTLS behave differently from GnuTLS in fd ownership
   at TLS close; never assume the fd a TLS object was created with is
   still the wsi's socket.

## FreeRTOS / ESP32

Several callers on `LWS_PLAT_FREERTOS` pass a bare stack `struct lws_a`
cast to `struct lws *` for callbacks with no connection (protocol init,
broadcasts, cert load).  Anything past `wsi->a`, including `wsi->io`,
is off the end of it.  Internal protocol callbacks must switch on reason
before touching the wsi beyond `wsi->a`.  These crashes are only seen on
Sai hardware: suspect this when an esp32 crash follows "init
<vhost>.<protocol>" or a cancel.
