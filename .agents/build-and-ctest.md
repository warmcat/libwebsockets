# Build and ctest traps

## The build tree is not what you think

 - **Stale in-source `include/lws_config.h`.**  An in-source `cmake .`
   leaves `CMakeCache.txt` in the source root and generates
   `include/lws_config.h` there.  `-I<src>/include` comes before
   `-I<build>/include`, so every out-of-tree build then compiles against
   that stale config.  Symptom: a tree behaves as if it had different
   options from its own `lws_config.h` (missing fault injection, TLS code
   compiled with TLS off, ...).  Check for it first when a build fails
   inexplicably.  It comes back while the root `CMakeCache.txt` exists.
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
 - **The auth-server plugin needs `LWS_WITH_STRUCT_JSON=1`.**  Without
   it the lwsws-oauth tests still configure but the plugin is silently
   missing.
 - **NO_LOGS with lwsws or the DHT does not build on gcc 14** until G-142
   is fixed (pre-existing unused-variable warnings).  To check changed
   code in such a build, add `-Wno-error=unused-but-set-variable
   -Wno-error=unused-variable` and grep the warnings for your files.
   In such a tree `api-test-lws_dsh` also fails to link (undefined
   `lws_dsh_describe`).
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
   The service wait is truncated to whole ms, so the last <1ms before
   every timer is spent in `poll(0)` turns: hundreds per timer, varying
   with machine speed (26815 vs 2569 turns measured for the same case).
   Count only turns that took >= 1ms ("wakes"); that gave a stable 101
   unfixed vs 11 fixed in api-test-tls-passthrough.
 - **Hostile h3 sequences without fault injection:** on an h3 client
   stream, `lws_write(..., LWS_WRITE_BINARY)` goes out raw with no DATA
   framing (`rops_write_role_protocol_h3()`), so a test can frame the
   stream itself (see the h3 case in api-test-http-attack).
 - A TLS or h3 client given a literal IP as its host sends no SNI: a
   simple way to make SNI and Host / `:authority` differ in a test.
 - **api-test-sansio covers hpack** but `ctest -R 'h2|h3|http'` does not
   select it: run it whenever hpack.c changes.  Its transcripts can only
   be re-recorded (`--record`) from a fault-injection build.
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
   (`mp->nodes` is 256 bytes; longer lists are dropped): tests needing
   more must send several replies.
 - **The dht-dnssec plugin creates its DHT after the context is up**, not
   in `lws_create_context()`: a test building the plugin in waits in a
   sul until `vhd->dht` is set (see api-test-dht-dnssec-put).
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

## Debug logging in ctest

The default log spew handling keeps only the last 10 lines, so at
`-d1039` a busy fixture loses the middle of what you are debugging.  It
also swallows lines from a burst at default log levels (35 of 64 lines
in 20ms were lost in one test), so pass `--log-spew-tail 20000` whenever
a log is evidence that something was or was not emitted.

 - Apps using `lws_cmdline_option_handle_builtin()` (lwsws, examples)
   take `--log-spew-tail <lines>`.
 - For ctest fixtures:
   `LWS_CTEST_BG_DEBUG="-d1039 --log-spew-tail 20000" ctest -R ...`;
   the log lands in `<build>/Testing/fixtures/`.  The default level for
   fixtures is `-d1039`, which also makes lwsws install its crash handler,
   so a fixture segfault leaves a backtrace in that log.
 - Logs containing binary bytes need `grep -a`.
