# Build and ctest traps

## The build tree is not what you think

 - **`<build>/include/libwebsockets/` is a copy made at configure time**:
   new header fields never reach it.  Hand-compiling a test with only
   `-I <build>/include` fails on them; put `-I include` first.
 - **Stale in-source `include/lws_config.h`.**  An in-source `cmake .`
   leaves `CMakeCache.txt` in the source root and generates
   `include/lws_config.h` there.  `-I<src>/include` comes before
   `-I<build>/include`, so every out-of-tree build then compiles against
   that stale config.  Symptom: a tree behaves as if it had different
   options from its own `lws_config.h` (missing fault injection, TLS code
   compiled with TLS off, ...).  Check for it first when a build fails
   inexplicably.  It comes back while the root `CMakeCache.txt` exists.
 - **`LWS_WITH_ASAN` turns on UBSan with trap-on-error**, so UB shows as a
   bare SIGTRAP with no report (and there is no gdb here).  To see the
   report, configure a tree with ASan off and
   `-DCMAKE_C_FLAGS="-fsanitize=undefined -fno-sanitize-recover=all"`, plus
   `-fsanitize=undefined` in `CMAKE_EXE_LINKER_FLAGS` and
   `CMAKE_SHARED_LINKER_FLAGS`.
 - **The root filesystem (/tmp) is small:** gcc fails with "Cannot create
   temporary file" when it fills.  `TMPDIR=<build tree>/tmp` for make and
   ctest avoids it.  Never run two makes in one build tree at once
   (`ranlib: malformed archive`).
 - **Run a full `make` before ctest.**  `libwebsockets-test-server`, the
   fixture for the http-client-post / multi-post tests, links the static
   library; the minimal examples link the shared one.  After a library
   change, `make websockets websockets_shared` leaves the fixture running
   old code.  `ldd bin/<x>` when results make no sense.
 - **Negative tests need the shared library rebuilt too.**  Most ctest
   binaries link `websockets_shared`.  For a before/after check of a fix,
   rebuild `websockets websockets_shared` (or the whole tree) for both
   halves, or the "unfixed" run silently uses the fixed library and the
   test looks valid when it proves nothing.
 - **Default Linux builds use GnuTLS, not OpenSSL.**  `LWS_WITH_HTTP3`
   defaults on and forces `LWS_WITH_GNUTLS`.  Use `-DLWS_WITH_HTTP3=0` for
   OpenSSL.  When a TLS test behaves unexpectedly, check `LWS_WITH_GNUTLS`
   in `CMakeCache.txt` first.
 - **Extensions are off by default** (`LWS_WITHOUT_EXTENSIONS=ON`).
   Permessage-deflate code is not even compiled unless you configure
   `-DLWS_WITHOUT_EXTENSIONS=0`.
 - **`LWS_WITH_DISTRO_RECOMMENDED=1` cannot be combined with turning an
   implied option off** (eg, `-DLWS_ROLE_DBUS=0` where dbus headers are
   missing): `CMakeLists-implied-options.txt` sets them as plain variables
   after the cache.  Spell the option list out instead, in a fresh tree.
 - **`LWS_WITH_SYS_DHCP_CLIENT` gates the system state** at
   `LWS_SYSTATE_DHCP` until an interface has a lease: with it on, client
   tests sit forever before OPERATIONAL.  Never put it in a ctest config.
 - **The auth-server plugin needs `LWS_WITH_STRUCT_JSON=1`.**  After any cmake re-run, rebuild the
   plugins too: lwsws drops stale ones with "build hash mismatch" (info
   level only) and the lwsws-oauth seed then fails "schema did not appear".
   To see per-vhost protocol init in lwsws, add `LLLF_LOG_SPEW_OFF`
   (1<<19) to `-d`.  Without
   it the lwsws-oauth tests still configure but the plugin is silently
   missing.
 - **NO_LOGS builds clean with plugins, lwsws, DHT, SS and h3** since
   G-142 / G-273 (75d5c5d22..02fce2bb9), also with LOG_SHIP and the
   log_ingest plugin (a008020ea); the webrtc mixer and rtc_camera
   were not checked (gstreamer / opus headers missing here).  A local
   used only by a log goes inside the log call or under
   `#if (_LWS_ENABLED_LOGS & LLL_x)` at that log's level, not a (void)
   cast.  `-DDISABLE_WERROR=ON` with `make -k` collects every warning in
   one pass.
 - **`LWS_WITH_DHT=1` with JOSE off fails `api-test-plugins`** until G-178
   is fixed: the dht_object_store plugin needs JOSE and fails to dlopen.
 - **minimal-crypto-dnssec does not build with PLUGINS_BUILTIN** (PLUGINS
   off) until G-205 is fixed; `make -k` builds the rest.
 - **The dht-dnssec plugin, lws-crypto-dnssec and their api-tests do not
   build with `LWS_IPV6=OFF`** until G-159 is fixed; only the DHT core
   can be checked in an IPv4-only tree.
 - **Client-only builds need `-DLWS_WITHOUT_SERVER=1`.**
   `-DLWS_WITH_SERVER=0` is silently overridden; check `lws_config.h`
   has no `LWS_WITH_SERVER` before trusting a "client-only" result.
 - **ASan suites with plugins or libuv fail on leaks that are not lws's**
   (lwsws-uv-*, api-test-plugins, hs_evlib_foreign_uv, dht, hls...): system libraries pulled in by a plugin (eg, the HLS plugin's
   ffmpeg / samba) leak in their constructors at dlopen; the stacks show
   `<unknown module>` because the plugin is unloaded before the report.
   Use `LSAN_OPTIONS=suppressions=<file>` with `leak:_dl_init` and
   `leak:_dlerror_run` (the dht tests also leak through
   `_dl_catch_error`), which hide only allocations made by the dynamic
   loader and library constructors.
   A context loads every `libprotocol_*.so` in the build tree's `lib/`, so
   a test that passed before a full `make` can fail this way after it;
   "dir_cb: ... was not loaded" lines from stale plugins are harmless.
 - A fetched mbedtls clone is 57MB; deleting its `tests/`, `docs/`,
   `visualc/` and `.git` leaves 20MB and it still builds with testing
   and programs off.
 - The root fs is small (8.8GB, shared with other sessions): keep fetched TLS library sources in your
   scratchpad and their build output under the checkout (BearSSL:
   `make BUILD=<dir under checkout>`; mbedtls can use its source
   `include/` directly, no install).  Use BearSSL git master: the 0.6
   release headers fail lws -Werror.
 - **bearssl can be built and ctested here** from upstream BearSSL
   source (plain `make`), with its inc/ and build/ outside the lws tree
   (CMake rejects interface include dirs inside it):
   `-DLWS_WITH_BEARSSL=1 -DLWS_BEARSSL_INCLUDE_DIRS=... -DLWS_BEARSSL_LIBRARIES=.../libbearssl.so`
   and `LD_LIBRARY_PATH` for ctest (B80: 284/284).
 - **mbedtls 3.6.x can be built here** the same way: clone upstream at a
   tag outside the lws tree (not under ~/projects either; use your
   scratchpad), `git submodule update --init` (its framework is
   required), build shared with `-DMBEDTLS_FATAL_WARNINGS=OFF` (this gcc
   trips -Warray-bounds in common.h), install to a prefix (lib64/), then
   `-DLWS_WITH_MBEDTLS=1 -DLWS_WITH_HTTP3=0 -DLWS_MBEDTLS_INCLUDE_DIRS=<p>/include`
   `"-DLWS_MBEDTLS_LIBRARIES=<p>/lib64/libmbedtls.so;<p>/lib64/libmbedx509.so;<p>/lib64/libmbedcrypto.so"`
   and `LD_LIBRARY_PATH` for ctest (B82).
 - **Data races in examples or lib can be shown red/green with clang
   `-fsanitize=thread`** (gcc has no libtsan here): build only
   `websockets_shared` with SSL off.  The rtc_camera plugin's
   `webcam-media.h` includes `<opus/opus.h>` unconditionally, so a
   PLUGINS + V4L2 + TRANSCODE build fails without opus headers.
 - **The webrtc mixer can be syntax-checked without GStreamer**: stub gst
   and `opus/opus.h` (OpusDecoder / OpusEncoder typedefs) headers plus a
   copy of the build's include dir with `LWS_WITH_DTLS` and
   `LWS_WITH_ALSA` defined in lws_config.h covers everything but
   mixer-media.c (`-fsyntax-only` with the build's warning flags).  Its
   pure helpers are tested by api-test-webrtc-mixer-signal / -depkt; the
   rest needs Sai.  clang -Werror fails layout-speaker.c until G-375.
 - Use `cmake .. --fresh` so a reused tree aligns with your options.  Stale
   example makefiles survive a reconfigure otherwise.

## Running ctest

 - **Watch for stale fixtures.**  The fixture scripts
   (`scripts/ctest-background*.sh`) keep each fixture's pid and log under
   its own build tree's `Testing/fixtures/`.  But a killed or interrupted
   run leaves its fixtures (servers, `proxy-fixture.py`, valgrind
   instances) alive and holding ports, so the next run's fixture dies of
   `EADDRINUSE` or, worse, tests pass against the old server.  `ki_*`
   failures, `EADDRINUSE` or "unexpectedly dead" mean: find leftovers and
   kill them by PID, then reproduce alone.  Running two trees' ctest at
   once also doubles the memory load (see
   [working-in-the-tree.md](working-in-the-tree.md)).
 - **Load-only failures are real bugs.**  Sai runs every test under
   `ctest -j8`.  To reproduce, run CPU burners (`while :; do :; done`
   loops, killed by PID afterwards) and loop the single test binary 30 to
   40 times with logs on disk.  Full-suite reruns rarely hit it.
 - **Single-stack builds** (`-DLWS_IPV4=OFF` / `-DLWS_IPV6=OFF`) make
   `LWS_CTEST_SERVER_RESOLVE` the literal `::1` / `127.0.0.1` instead of
   `localhost`.  The local test certs therefore carry
   `subjectAltName = DNS:localhost, IP:127.0.0.1, IP:::1`.
   `localhost-100y.cert` exists in many copies (minimal examples, base64
   DER in policy JSONs, arrays in `minimal-http-server-tls-mem.c`); if it
   is ever re-signed, keep the key and update every copy identically.
   Tests should take `LWS_CTEST_SERVER_RESOLVE` rather than hardcode
   `127.0.0.1`.
 - **Path length matters.**  Tests with goldens or caches can fail only
   on deep checkout paths (`LHP_URL_LEN` silently drops assets; the cache
   blob path buffer is 256 bytes).  For "fails on their machine, passes
   here", try a deep path first.

## Writing tests and examples

 - **`lws_service(cx, ms)` ignores `ms`.**  A loop like
   `while (now - start < N) lws_service(cx, 100);` only re-checks the
   clock when something unrelated wakes the loop.  Bound waits with a sul
   whose callback calls `lws_cancel_service(cx)`; a flag set in the
   callback alone is not seen until the next wake.  See `service_until()`
   in `api-test-lws_stub`.
 - **Don't count `lws_service()` returns to detect a spinning loop.**
   Before 279c65470 (G-348) the service wait was truncated to whole ms,
   so the last <1ms before every timer was spent in `poll(0)` turns,
   hundreds per timer (26815 vs 2569 turns measured for the same case).
   Since then waits round up (`lws_us_to_ms_ceil()`) and a timer costs
   1-2 turns (api-test-sul-wait), but turn counts still vary with load.
   Count only turns that took >= 1ms ("wakes"); that gave a stable 101
   unfixed vs 11 fixed in api-test-tls-passthrough.
   That catches a loop that wakes periodically, not a hot spin (all its
   turns are < 1ms): to catch a spin, add up the duration of the turns
   shorter than 1ms instead (489ms spinning vs 0-2ms idle over 500ms in
   api-test-proxy-v2-peer-limits).
 - **`LWS_WITH_SECURE_STREAMS_AUTH_SIGV4=1` breaks the sspc ctests** when
   `~/.aws/credentials` is missing: the proxy example returns -1 at
   OPERATIONAL, so all 12 sspc tests fail with ECONNREFUSED or time out.
 - Fuzz harnesses can link `lib/libwebsockets.a` and `extern`-declare
   private functions (eg `lws_ss_policy_set()`).  For readable UBSan
   reports, compile just the suspect .c files without
   `-fsanitize-undefined-trap-on-error` and link them ahead of the archive.
 - **Raw UDP test peers bound with `LWS_CAUDP_BIND` and port 0 can share a
   port** (SO_REUSEADDR, G-302): use `LWS_CAUDP_BIND | LWS_CAUDP_RANDOM_PORT`
   (G-626).
 - **The dnssec-monitor plugin needs `-DLWS_WITH_SPAWN=1
   -DLWS_WITH_SYS_WHOIS=1`**, or it silently isn't built.
 - **`LWS_WITH_SS_RIDESHARE` is never defined by CMake**, so the SS h1
   multipart send path (ss-h1.c) is compiled out of every build.
 - **api-test-h3-stream-reset's FAIL reason is swallowed by the spew
   limiter** at default level: run it with `-d 1027`.
 - **The `http-client-post-form*` ctests post an empty form** (no `--form`),
   so they don't exercise `lws_http_mp_sm`: api-test-http-client-multipart
   does.  The example only takes `--form=name=value`; with a space the value
   is taken as the URL.
 - **EADDRINUSE on a fixed api-test port is likely the configure-time port
   counter wrapping** (G-644): `lws_get_free_port()` hands out ports from a
   per-user counter in /tmp (15000-30000, ~355 per configure), so trees
   configured ~42 configures apart share ports.  Reconfigure, or don't run
   two such trees' ctests at once.
 - **Running minimal examples by hand:** they have no port switch (7681 is
   fixed) and with no arguments print help and exit, so pass eg `-d 7`.
   Evlib plugins are only searched in LWS_INSTALL_LIBDIR, so run libuv
   examples from a build tree configured with `-DLWS_WITH_EVLIB_PLUGINS=0`.
   A stalled-reader test against a slow producer takes a long time to see
   the stall: loopback send buffers autotune up to ~4MB.
 - **Linux loopback lets a test send from any 127/8 address**, so tests can
   use many source hosts (eg 127.0.0.2).  macOS lacks them: skip there.
 - **api-test-auth-dns-zonedir's clock starts before the context is
   created** and a phase allows only 2s for replies, so a slow zone-dir
   read at init fails it under load (G-509): start the reply window when
   the queries are sent.
 - **`lws_cmdline_option()` prefix-matches**: a switch that is a prefix of
   another (`-i` vs `-ip`) silently collides.  Builtins in
   `lws_cmdline_option_handle_builtin()` therefore also fire on longer
   arguments (`--event` selects libev), and the builtin `-h` prints help
   and exits before an example sees its own `-h` (G-622).
 - **qir (WebTransport interop shim) runs end to end on loopback**: use
   `--www` / `--downloads`, run the server where localhost-100y.cert/.key
   are, set TESTCASE and PORT; client REQUESTS=`https://localhost:PORT/<ep>/<file>`
   (for -send: client TESTCASE=transfer with a bare-endpoint REQUESTS, server
   REQUESTS_SERVER=`<ep>/<file>`).  Background servers with `exec` inside a
   subshell, or killing the subshell leaves the server holding the port.
 - **Tests that count PROTOCOL_INIT need
   `LWS_SERVER_OPTION_VH_INSTANTIATE_ALL_PROTOCOLS`** in plugins builds
   (G-572), or a vhost only inits protocols it has pvos for.
 - **A test compiling protocol plugins in statically, in a
   `LWS_WITH_PLUGINS` build, must set
   `LWS_SERVER_OPTION_VH_INSTANTIATE_ALL_PROTOCOLS` on its vhost** (or
   give pvos): otherwise PROTOCOL_INIT never runs for them and plugins
   needing their per-vhost struct refuse every connection.
 - **SS scratch programs hang at COLLECTING_STDIN** unless run with
   `< /dev/null`.
 - **fuzz-lhp's callback is a stub, so dlo layout is not fuzzed.**  A
   layout harness needs a context in `ctx->user1` plus registered fonts,
   or `lws_font_choose()` dereferences a NULL context.  Working recipe (A81,
   found G-667 in minutes): a context with `lws_font_register()`,
   `lhp_displaylist_layout` as the callback, `ctx->user1 = cx`, `base_url`
   NULL so nothing is fetched; for assets, build `lws-api-test-lhp-dlo`'s
   main.c against the static lib and run it on `file://` pages.  Grep its
   output with `grep -a` (it writes a bmp to stdout).
 - **`-DLWS_WITH_OTA=1` trees:** the `LWS_OTA_PUBLIC_JWK_FILE` content is
   pasted raw into a C string (quotes must be escaped), and every context
   reaching OPERATIONAL tries to create an "ota" stream.  Run the full
   suite in a non-OTA tree, and only api-test-ota in an OTA tree.
 - **`-DLWS_WITH_WEBRTC=1` trees fail `make` on rtc_camera** here (no
   opus headers): use `make -k`.  api-test-srtp only builds with WEBRTC.
 - To check a zone-parser change for regressions, sign zones with the
   `rsa-*.jwk` api-test keys and a fixed `sign_validity_start_time`: the
   output is identical on every run, so before/after can be diffed.
 - **gcc -O3 RELEASE trees catch `maybe-uninitialized` in api-tests that
   DEBUG and ASan trees don't** (G-517): build new tests in a release tree
   too, or at least `gcc -O3 -Wall -Wextra -Werror -c` the test's main.c.
 - **lhp-dlo golden cases run with `OUTPUT_QUIET ERROR_QUIET`**: debug
   prints never reach ctest output.  Run `bin/lws-api-test-lhp-dlo` on the
   case html (or its `<case>.dlo-<name>.html` copy in the build dir).
 - **minimal-crypto-dnssec's signzone waits for DHT IP consensus from the
   public bootstrap node**, so it hangs offline: call
   `lws_auth_dns_sign_zone()` directly in tests and harnesses.
 - **api-test-x509-jwk-privkey-pem fails under ASan in openssl trees**
   (BIGNUM leak) until G-405 is fixed; default trees here use gnutls.
 - **An h3 client only offers a connection for reuse / pipelining when its
   Host is its address**: a test wanting pipelined h3 requests to join
   must set `i.host = i.address`.
 - **api-test-iface-bind only builds with `LWS_WITH_SYS_FAULT_INJECTION=1`.**
 - **api-test-async-dns only builds with `LWS_WITH_AUTHORITATIVE_DNS=1`**:
   a default ASan tree silently has no async-dns ctest.
 - **api-test-vhost-listener-scope by hand needs `--cert` / `--key`** (the
   api-test-ws-close certs): without them it exits 0 having tested
   nothing.
 - `openssl mac -macopt hexkey:<k> -macopt size:8 SIPHASH` gives
   SipHash-2-4 reference values for checking lws's copy.
 - **api-test-proxy-v2-peer-limits needs `LWS_WITH_TLS_PASSTHROUGH`**:
   without it every connection is dropped, which looks like a broken tree.
 - **Red-testing proxied clients:** api-test-client-proxy-redirect's
   proxy-fixture.py resolves with the platform libc, so an inet_aton-form
   host like `2130706433` really reaches the local origin through it.
 - **Hostile h3 sequences without fault injection:** on an h3 client
   stream, `lws_write(..., LWS_WRITE_BINARY)` goes out raw with no DATA
   framing (`rops_write_role_protocol_h3()`), so a test can frame the
   stream itself (see the h3 case in api-test-http-attack).
 - **QPACK dynamic table references in an h3 test:** lws' own encoder never
   inserts entries.  The `h3_qpack_enc_big_entry` client fault puts one 4KiB
   cookie at absolute index 0 in the server's table; a later request on the
   same connection (`LCCSCF_PIPELINE`, Host = address) calls
   `lws_qpack_set_wsi_base_and_ric(wsi, 0, 1)` in APPEND_HANDSHAKE_HEADER
   and adds post-base references (api-test-h3-header-amplification).  A
   reference in the connection's first request can beat the insert there:
   the server then fails the connection as a blocked stream.
 - **Several h3 server vhosts in one context share a "listener" for SNI**
   when made with `CONTEXT_PORT_NO_LISTEN_SERVER` plus
   `lws_create_adopt_udp()`, even on different udp ports
   (`lws_vhost_shares_listener()` compares the -2 listen ports).  An SNI
   name matching no vhost is then refused (alert 112) instead of falling
   back to the only vhost; ctest dials `localhost`, so it fails there but
   passes by hand with `127.0.0.1` (no SNI).  Name a vhost `localhost`, or
   send the vhost's own name as the Host.
 - **h3 does not work in `-DLWS_WITH_HTTP2=0` builds** (seen at 28e9e89af):
   the h3 client fails responses with "HS: :status missing", so the h3
   parts of api-test-oversized-headers and others fail there.
 - **In-process SS proxy tests:** a mux proxy can run on a link transport
   of your own under `lws_transport_mux_proxy_ops`
   (api-test-ss-proxy-mux; deliver client->proxy bytes from a sul, never
   re-entrantly from `proxy_write`).  A fake proxy for sspc is a raw UDS
   vhost; the context reads `info.ss_proxy_bind` at connect time, so a
   random name can be written there after `lws_create_context()`
   (api-test-sspc-rx-metadata).
 - **STANDALONE sspc builds redefine `lws_free`** but not
   `lws_free_set_NULL()`; use `lws_free(x); x = NULL;` in sspc files.
 - api-test-lws_dsh takes no `-d` and the spew limiter hides its later
   lines: judge it by exit code.
 - **Struct layout on 32-bit without `-m32`:** gcc here rejects `-m32`, but
   `clang --target=i386-linux-gnu -S -emit-llvm` gives a quick
   `sizeof` / `offsetof` check.  A test transport that fills its documented
   headroom with a pattern catches callers passing buffers without it,
   even on 64-bit where padding hides it (api-test-ss-proxy-mux).
 - **"Snapshot at dispatch" red/green:** api-test-http-ah-lifetime's late-*
   cases have the server call `lws_http_headers_detach()` at
   LWS_CALLBACK_HTTP, on h1/h2/h3.
 - `LWS_WITH_RANGES` defaults off: range work needs `-DLWS_WITH_RANGES=1`
   and its code the guard.  `-DLWS_WITH_FILE_OPS=0` fails to configure
   unless `-DLWS_WITHOUT_TESTAPPS=1` is also given.
 - **A vhost created after `lws_create_context()` gets PROTOCOL_INIT only
   once the loop runs**: a test calling a plugin's ops straight after
   `lws_create_vhost()` must service until `lws_protocol_vh_priv_get()`
   is non-NULL.  `lws_context_info_defaults()` sets EXPLICIT_VHOSTS, so
   there is no "default" vhost: create your own.
 - **Red-testing an opaque-ownership fix:** free the opaque right after the
   cancel, so a missed cancel shows as an ASan use-after-free at vhost
   destroy.
 - **Red half for a plugin-folding test needing new header constants:**
   keep the new header and restore only the `.c` from HEAD, or select
   with `#if defined(<new macro>)` in the test (api-test-hls-queue).
 - **http-client-multi-post-pipe sends 8 concurrent POSTs on one h2
   connection** and the lws client does not retry REFUSED_STREAM: any
   per-connection stream refusal policy below 8 fails it.
 - **cgi stdin edge cases:** add a row to `cases[]` in
   api-test-http-cgi-stdin; its cgi.sh reads stdin to EOF, so a stdin
   that is never ended shows as a timeout (quick red/green).
 - **To delay a backend's accept in-process**, own the listen socket,
   `accept()` it late from a sul, then `lws_adopt_socket_vhost()` it
   (api-test-proxy-hdr --ws-delay).
 - The lws h2 client follows a HEAD's 302 unless
   `LCCSCF_HTTP_NO_FOLLOW_REDIRECT` is set.
 - **SNI comes from `i.host`, not `i.address`**, so `i.host` sets both
   SNI and `:authority`; a name matching no vhost (and no SNI fallback)
   fails the handshake with a TLS alert.  To send a real Host header next
   to `:authority` on h2/h3, add it with
   `lws_add_http_header_by_token(WSI_TOKEN_HOST, ...)` in
   `LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER` (api-test-h3-authority).
 - A TLS or h3 client given a literal IP as its host sends no SNI: a
   simple way to make SNI and Host / `:authority` differ in a test.
 - **Host: rebinds in api-test-sansio:** its vhosts are NO_LISTEN
   (`listen_port` -1), so `lws_select_vhost()` matches them by name and a
   connection adopted on one with `Host: <other>` really is rebound.
 - **api-test-sansio covers hpack** but `ctest -R 'h2|h3|http'` does not
   select it: run it whenever hpack.c changes.  Its transcripts can only
   be re-recorded (`--record`) from a `-DLWS_WITH_SYS_FAULT_INJECTION=1`
   tree: record into a scratch dir and copy back only the changed files
   after `cmp`.  Its clock jumps delay validity timers (sul insertion is
   relative to now): use an explicit `at()` at ping+0.5s, then at
   hangup+1s (cases 51, 53).
 - **QUIC key updates and injection:** `LWS_SERVER_OPTION_QUIC_EARLY_KEY_UPDATE`
   on both ends gives several key updates per connection (nothing else in
   ctest exercises them), and a udp relay that learns the server's SCID
   from its long headers can inject into a live h3 connection (see
   api-test-quic-forged).
 - **DHT external-address votes on loopback:** every node shares source
   key 127.0.0.1, so they are one witness and the quorum is 1.  Test vote
   logic with several hosts through the dht-extvote module directly
   (api-test-dht-extvote).
 - **A DHT nodes list carries at most 9 IPv4 entries** in lws format
   (`mp->nodes` is 256 bytes; longer lists are dropped).  The pending
   request table consumes the tid on the first reply, so tests needing
   more need several queried endpoints, not several datagrams.
 - **Getting a raw test socket into A's search:** have it ping A first (A
   adds pinging nodes to its routing table).  A's pong carries ip / v
   fields after the tid, so match the tid alone.  Per-introducer search
   caps treat a private introducer as its exact endpoint, so loopback
   peers count separately.
 - **The dht-dnssec plugin creates its DHT after the context is up**, not
   in `lws_create_context()`: a test building the plugin in waits in a
   sul until `vhd->dht` is set (see api-test-dht-dnssec-put).
 - **To make a DHT node create many sequencers** in a test, send to
   127.0.0.2 and up on one never-listened port (api-test-dht-seq-reentry).
   Only free or idle slots are taken: beyond 64 in use, sends are REFUSED.
   A send to a host that already has a sequencer is still queued when the
   table is full, so a REFUSED test must use hosts with none yet.
   `lws_dht_insert_node()` adds nodes as dubious: `lws_dht_get_nodes()`
   skips them, `lws_dht_foreach_node()` visits them, and 64 random IDs
   leave only ~16 in the table (only the eager first bucket split).
 - **Red-test in a detached worktree** at the previous commit with the new
   test copied in: an ASan red without disturbing the shared tree.
 - **Many raw UDP sockets in one test context** need
   `info.fd_limit_per_thread = 0`; bind port 0 and read the port back with
   `getsockname()` (api-test-dht-search-livelock).
 - **DHT BEP42 cannot be tested on loopback:** private addresses are
   always `bep42_ok` (`maybe_new_node()`, `lws_dht_ads_is_private()`).
 - **Make deadlines produce FAIL, not TIMEOUT.**  A test's failure path
   should be explicit: a deadline that sets failure and cancels service,
   not reliance on the ctest TIMEOUT.  Note a context destroy at the
   deadline fires the same close callbacks a real detection would, so
   don't count closes after the deadline.
 - **Bound the latency of close tests.**  A close that never reaches the
   wire can still "pass" when an unrelated timeout closes the connection
   later.  Require the peer to see the close within a bound.
 - **Servers set `info.fd_limit_per_thread = 0`** after
   `lws_context_info_defaults()`.  The defaults select a small, searched
   fd table sized for a client; when it is nearly full lws takes POLLIN
   off every listener until an fd frees, which looks like a ~5s stall
   per case.  A client that wants the small table uses
   `LWS_FD_LIMIT_PER_THREAD_MIN + n`, never bare arithmetic.  If a case
   stalls for ~5s, `strace -e poll` the process: listen fds with
   `events=0` is this.
 - **Prefix test-local macros** with something specific to the test
   (`ATK_`, `HCM_`...), never bare names like `ECHO`, `NONE`, `L`, and not
   `LWS_` (the library's namespace).  `libwebsockets.h` can pull in
   `uv.h` → `termios.h`, `windows.h` and others; compile with
   `-include termios.h` to check.
 - **Tolerate unrequested WRITEABLE.**  Especially on h3 streams, a
   WRITEABLE can arrive without being asked for.  Track "done" yourself;
   never infer completion from a WRITEABLE.
 - **`api-test-lws-login-bff` needs `LWS_WITH_PLUGINS_BUILTIN=1`**; it is
   silently not built in PLUGINS=1 trees.
 - **api-test-lwsws-oauth uses fixed ports 18011 / 18012**, so two trees
   cannot run it at once, and `lwsws-oauth-limits` has a 60s ctest
   TIMEOUT: a case waiting for a fresh TOTP step (30s) must run outside
   ctest (`ctest -R 'st_lwsws_oauth|sd_lwsws_oauth'`, then the binary with
   the arguments from `ctest -N -V`, then `ki_lwsws_oauth`).
 - **api-test-lwsws-oauth strike accounting:** a scenario can read its
   host's strikes from `/api/status` "strikes" via a trusted xff address,
   and loopback itself is never host-struck, so per-account effects are
   testable from loopback without host noise.  For red/green of a plugin
   change, `make` and ctest the fixture plus the one test (eg,
   `ctest -R 'lwsws_oauth|lwsws-oauth-limits'`): the fixture loads the
   rebuilt plugin.
 - **api-test-lwsws-oauth's sqlite db persists across ctest runs**; only
   a configure removes it (`file(REMOVE)` at configure time).  A test that
   causes bans must use a fresh client address each run (the existing
   scenarios use random 198.18/15 and 2001:db8 addresses).
 - **Checking for leftover children without reaping them:**
   `waitid(P_ALL, 0, &si, WEXITED | WNOHANG | WNOWAIT)`: ECHILD means
   none, `si_pid != 0` a zombie, 0 with `si_pid == 0` one still running
   (api-test-http-cgi-abandon).
 - **A server returning -1 at LWS_CALLBACK_HTTP** is reported promptly to
   an h1 client ("server closed before responding"), but an h2/h3 client
   stream gets no callback until its deadline (G-135).  Tests expecting
   "no answer" need a short deadline of their own.
 - **The lws h1 client drops a HEAD response's body**, so it cannot detect
   a server sending one; use a raw client (`LCCSCF_USE_SSL`, alpn
   `http/1.1`) for byte-exact h1 tests (lwsws-uv-captcha-head).
 - Keep scratch files under `--tmpdir` (ctest passes the binary dir),
   not `/tmp`, and create them owner-only.
 - **Measure lhp amplification against a baseline.**  A page's custom
   properties on `*` are costly by themselves (40 stanzas of 200
   properties over 120 nested divs: ~12s under ASan with no calc() at
   all), so compare with and without the construct before filing.
 - **lhp stores selector names normalised, with spaces inside parentheses
   removed**, so a descendant combinator inside `:is()` is lost in a test
   selector; use `~`, `>` or `+` there.
 - `lws_dir(..., lws_dir_rm_rf_cb)` empties a directory but leaves it;
   `rmdir()` it afterwards.
 - `memmem()` is GNU-only: don't use it in examples.
 - `lws_cmdline_option()` is a prefix match: a new option must not start
   with an existing option's name.
 - Every literal `%` in a string used as a printf format must be `%%`;
   declare corpus / document builders with `LWS_FORMAT(n)` so the compiler
   checks them.

 - `setsockopt bind to device 127.0.0.1 error (19)` in a test log is
   harmless: Linux builds default `LWS_WITH_BINDTODEVICE` on, and
   `lws_socket_bind()` hands a numeric iface to `SO_BINDTODEVICE`, which
   fails without privilege (G-225).

 - api-test-http-compression is the only test covering h3 stream
   compression with large bodies: the compressor drain under h3 credit
   pressure (G-233) only showed with a 3MB body, not 1MB or less.

## Debug logging in ctest

The default log spew handling keeps only the last 10 lines, so at
`-d1039` a busy fixture loses the middle of what you are debugging.  It
also swallows lines from a burst at default log levels (35 of 64 lines
in 20ms were lost in one test), so pass `--log-spew-tail 20000` whenever
a log is evidence that something was or was not emitted.

 - A test that captures log lines in an emit callback as evidence should
   pass `LLLF_LOG_SPEW_OFF`: the spew limiter tripped at default levels
   with only ~64 error lines (api-test-auth-dns-names).
 - Apps using `lws_cmdline_option_handle_builtin()` (lwsws, examples)
   take `--log-spew-tail <lines>`.  api-test-lws_struct-json does not
   honour it: run it with `-d 3` to see why it failed.
 - For ctest fixtures:
   `LWS_CTEST_BG_DEBUG="-d1039 --log-spew-tail 20000" ctest -R ...`;
   the log lands in `<build>/Testing/fixtures/`.  The default level for
   fixtures is `-d1039`, which also makes lwsws install its crash handler,
   so a fixture segfault leaves a backtrace in that log.
 - Logs containing binary bytes need `grep -a`.
 - QUIC info logs during a transfer are mostly dropped by the log spew
   rate limiter, so grepping `-d 1039` output cannot prove a fault
   injection fired mid-transfer; rely on the test's red half.  Transport
   parameter values do show.
 - The log spew limiter can also swallow `lwsl_user` lines at `-d 1039`;
   read test verdicts from a default-level run.
 - An lws ws client masks its payload in place: a buffer reused across
   `lws_write()` calls must be refilled before each write, or the next
   frame is garbage (a TEXT one then fails UTF-8 at the server).
 - A TLS listen vhost whose listen-accept protocol is raw sees
   `RAW_ADOPT` / `RAW_CLOSE` on that protocol with no client connected
   (two at startup, seen by B39 in api-test-raw-proxy): tests counting a
   server's connections must filter by vhost.
 - No 32-bit runtime on the aarch64 dev host; to check 32-bit arithmetic
   compile with `clang --target=i386-linux-gnu -fsyntax-only` plus
   `-D__uint128_t="unsigned long long"` (the host asm headers otherwise
   fail on it), and static-assert `sizeof(size_t) == 4`.
 - api-test-sshd-userauth compiles the ssh-base plugin sources in
   statically: for a red run, recompile just that test with its plugin
   include path pointed at a HEAD copy of plugins/ssh-base, no library
   rebuild needed.
 - Since G-286 the client in api-test-sshd-userauth does a complete
   curve25519 + chacha20-poly1305 key exchange: a new pre-auth scenario
   must start from that exchange, or expect to be closed if it sends
   anything but transport messages first.
 - A raw UDP wsi receives at most the protocol's `rx_buffer_size`; a
   longer datagram is silently truncated.  Sends are one datagram, never
   split (G-279, see READMEs/README.udp.md).
 - lwsws-oauth-limits and lwsws-oauth-login-h3 occasionally time out at
   -j6 under ASan and pass on rerun (seen by several agents 2026-10-19):
   rerun the group alone before treating it as a regression.
 - `unshare -rn` with a veth pair works unprivileged on the dev host, so
   a scratch program can provoke real netlink route events (eg `ip addr
   del`) without root (V34, route checks for G-316).  CI hosts may not
   allow user namespaces, so don't make a ctest depend on it.
 - A build tree's `include/` holds header copies made at cmake time:
   when compiling against a different checkout or worktree, put that
   tree's source `include/` first on the include path.
 - With no event lib configured `LWS_WITH_EVENT_LIBS` is undefined, so
   `LWS_EVLIB` and the evlib option bits are ignored (poll loop).  To
   exercise built-in evlib selection, configure an event lib with
   `-DLWS_WITH_EVLIB_PLUGINS=OFF`.
 - Privilege drop (G-324): a uid/gid that can't be dropped to now fails
   context creation, or `_exit(1)` from a deferred `lws_finalize_startup()`;
   `ctx_privdrop_finalize` fault injection and api-test-privdrop test it
   without root.
 - Any minimal example runs on libuv with `--uv` when `LD_LIBRARY_PATH`
   includes the build tree's `lib/` (where the evlib plugin is built): a
   quick way to fault-inject the evlib-plugin paths.
 - Raw-socket wsi skip the close shutdown (close.c, role_ops_raw_skt): an
   lws raw client that sets SO_LINGER 0 and returns -1 sends a
   deterministic RST, an easy way to test a server seeing a peer reset.
 - Never delete untracked directories in the source tree during cleanup
   unless you created them: they may be the maintainer's.
 - The lws h3 client keeps an idle connection warm for at least 1s and
   joins later requests to the same endpoint on that vhost onto it:
   tests counting server connections need a client vhost per client and
   a fresh context per part (B57, api-test-peer-stack-quic).
 - With `LWS_WITH_SECURE_STREAMS_AUTH_SIGV4` on, minimal-secure-streams-
   proxy exits if `~/.aws/credentials` is missing and ~10 sspc ctests
   time out; point `HOME` at a dir with a dummy credentials file.
 - api-test-ws-close measures wall time spent in sub-ms turns rather than
   counting turns (e8e10bab3); the busy turns before timers it worked
   around were fixed in 279c65470 (G-348).
 - Cleanup that kills processes by pattern must match only your own
   build tree's paths: a broad match killed another agent's test fixture.
 - Log-capture tests need `LLLF_LOG_SPEW_OFF` in `lws_set_log_level()`:
   every level trips the spew limiter (64 lines in 20ms), which drops
   lines silently (api-test-log-redact).
 - The lws h2 encoder never indexes headers: to exercise the HPACK
   dynamic-table path, write raw bytes in APPEND_HANDSHAKE_HEADER (0x40
   literal, then 0x80|62 on the next request with LCCSCF_PIPELINE).
 - A test NAT / relay should pass back only datagrams from the expected
   source, or a server answering the wrong address still looks green
   (how the G-199 P5 flood red showed in api-test-tls-passthrough).
 - `LWS_IO_OPS_ABI_VERSION` must be bumped whenever `lws_io_ops_t` gains a
   member (it is 3 since c9ef2a268).
 - A NO_LOGS build with `_DEBUG` still compiles `#if defined(_DEBUG)`
   blocks but compiles out `lwsl_header()` etc: a buffer used only by a
   log under such a block goes unused.  Guard by the log level,
   `#if (_LWS_ENABLED_LOGS & LLL_x)`, not by `_DEBUG`.
 - In an in-process QUIC test, the client's own TLS handshake slot comes
   back before the server sees its first Handshake packet: a handshake-
   limit refusal can't be shown in-process; use the sessions limit.
 - `LWS_CALLBACK_WSI_DESTROY` can't match an accepted TCP wsi by fd (the
   fd is already closed then): record the wsi at the `WSI_CREATE` after
   `FILTER_NETWORK_CONNECTION`.
 - EMFILE tests: lws frees fds on its own early on, letting a "starved"
   accept succeed: captive portal detection's TLS client takes a tls slot
   (set `LWS_SERVER_OPTION_CPD_BYPASS`), and the async-DNS nameserver
   reload on the first service pass closes its socket when it can't read
   resolv.conf (set `LWS_ASYNCDNS_WATCH_MS` high).  Service once first
   (api-test-quic-accept-gate emfile).
 - Test logs written to the eMMC build disk can block the process for
   seconds under load (seen as a 3.5-6s stall in api-test-ws-close
   proxied runs; clean with logs on tmpfs): suspect this before blaming
   the library for a sporadic multi-second stall.
