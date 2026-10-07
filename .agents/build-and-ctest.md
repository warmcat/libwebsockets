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
 - Keep scratch files under `--tmpdir` (ctest passes the binary dir),
   not `/tmp`, and create them owner-only.
 - `memmem()` is GNU-only: don't use it in examples.
 - `lws_cmdline_option()` is a prefix match: a new option must not start
   with an existing option's name.
 - Every literal `%` in a string used as a printf format must be `%%`;
   declare corpus / document builders with `LWS_FORMAT(n)` so the compiler
   checks them.

## Debug logging in ctest

The default log spew handling keeps only the last 10 lines, so at
`-d1039` a busy fixture loses the middle of what you are debugging.

 - Apps using `lws_cmdline_option_handle_builtin()` (lwsws, examples)
   take `--log-spew-tail <lines>`.
 - For ctest fixtures:
   `LWS_CTEST_BG_DEBUG="-d1039 --log-spew-tail 20000" ctest -R ...`;
   the log lands in `<build>/Testing/fixtures/`.  The default level for
   fixtures is `-d1039`, which also makes lwsws install its crash handler,
   so a fixture segfault leaves a backtrace in that log.
 - Logs containing binary bytes need `grep -a`.
