# Debug recipes

Ways to force or observe behaviour that local runs normally hide.  Prefer
these, plus reading, over brute-force looping.

## Network conditions without root

 - `unshare -rn` gives a private network namespace with no root.  Bring
   `lo` up, then use netem on it (give the full path, `/sbin/tc`, since it
   may not be on PATH there):

   ```
   unshare -rn sh -c 'ip link set lo up; /sbin/tc qdisc add dev lo root netem delay 750ms rate 10mbit limit 25; ...'
   ```

   This reproduces QUIC interop delay / bandwidth / loss cases.  It cannot
   simulate NAT rebinding.  Some kernels have neither `netem` nor `prio`:
   `tc` says "Specified qdisc kind is unknown".  `nft` may still work in
   the namespace.
 - **Force h3 → h2 fallback**: loopback QUIC always wins otherwise.  In
   the namespace, drop UDP to the server's port with nft:

   ```
   unshare -rn sh -c 'ip link set lo up; nft add table inet t;
     nft add chain inet t out "{ type filter hook output priority 0; }";
     nft add rule inet t out udp dport 7681 drop; exec ./the-test ...'
   ```

   With netem and prio, a `prio` qdisc with netem `loss 100%` on one band
   and u32 filters `match ip protocol 17 0xff` steering to it does the
   same.  In a test, put the `udp_tx_loss` fault on one client connection's
   `lws_client_connect_info.fic`, as api-test-ws-close's fallback legs do.
 - **Close-path data loss**: clamp the receiver's `SO_RCVBUF` (or small
   `tcp_rmem` / `tcp_wmem` in a namespace) to make Linux behave like
   macOS, then check the receiver got every byte.
 - **A real send error on demand**: send twice in one pass on a
   `connect()`ed UDP socket to a loopback port nothing listens on.  On
   Linux the first datagram's icmp port unreachable is back before the
   second `sendto()`, which fails with `ECONNREFUSED`; no fault injection
   needed.  Bind the port again afterwards to let the peer "come back".
 - Bisecting by throughput / long RTT works well in a detached
   `git worktree` outside the shared tree.  Cross good / bad server and
   client builds to find which side regressed.

## Fault injection

`LWS_WITH_SYS_FAULT_INJECTION` (see `READMEs/README.fault-injection.md`)
forces rare paths, eg `--fault-injection "wsi/udp_tx_loss(30%)"` for
grace expiries, PTOs and lost frames.  At context level that loses every
wsi's UDP, async DNS's too, which can stop a test before it starts: put it
on the one connection instead where you can.  Watch a suspected spin by sampling
the process's utime (`/proc/PID/stat` field 14) at intervals, and get
its stack with `gdb -batch -p PID`.

Fault injection state is per object: each wsi inheriting a pattern gets
its own counter, so a pattern cannot fail "only the first socket" when
the code under test replaces the socket.

To spot a spin from inside a test, measure cpu time (`getrusage()`), not
`lws_service()` returns: the poll loop rounds the wait down to whole
milliseconds and returns many times polling with timeout 0 through the
last fraction of a millisecond before each timer is due.  With an event
library, `gdb -batch -p PID -ex 'break lws_handle_POLLOUT_event'
-ex continue -ex bt -ex 'p/x wsi->wsistate' -ex 'p *wsi->a.protocol'`
names the wsi a spinning `epoll_pwait()` is reporting.

## Forcing synchronous completion

To hit a path that is normally async (eg the first TLS client handshake
step completing in the call), temporarily patch the backend to sleep
and retry inside the call.  Looping the test rarely reproduces it.
Revert and check `git diff` afterwards.

To force a version-gated branch (eg the GnuTLS < 3.8.4 0-RTT refusal)
on a newer library, bump the version gate temporarily in a scratch
worktree.

## LD_PRELOAD shims

 - **Darwin poll semantics on Linux**: wrap `poll()` via
   `dlsym(RTLD_NEXT)`.  Before the real call, give each fd with no
   POLLIN / POLLOUT / POLLPRI in events `fd = ~fd`; afterwards restore it
   with `revents = 0`.  Any other fd with POLLHUP in revents and POLLIN in
   events gets POLLIN ORed in.  Reproduces mac-only spins (it found a cgi
   stderr pipe being read for 0 bytes every pass).
 - **Windows FIN semantics on Linux**: in a scratch copy of the tree, make
   the unix `LWS_POLLHUP` in `include/libwebsockets.h` plain `(POLLHUP)`, as
   on Windows.  Then wrap `poll()`: add POLLRDHUP to the events of every
   SOCK_STREAM fd, and afterwards turn a POLLRDHUP into POLLHUP (plus POLLIN
   if POLLIN was asked, as `windows-service.c` does), and add POLLHUP to any
   POLLERR.  This reproduced api-test-h2-client-queue's w11-only "no
   GOAWAY" failure exactly.  Making a FIN POLLHUP | POLLERR on an unchanged
   tree instead also reproduces it, but can't tell a FIN from a reset.
 - **NULL `%s` finder**: wrap `vsnprintf` / `vfprintf` / `vsprintf` /
   `__vsnprintf_chk` and their variadic wrappers, walk the format with
   `va_copy`, and log the format plus `backtrace_symbols_fd` whenever a
   `%s` argument is NULL.  Run the full ctest under it and symbolize the
   hits.  It only sees log levels the tests emit.  Rerun after large log
   or tag changes, or when an esp32 / QNX crash smells like printf.

## Tracing and coverage

 - `LWS_WITH_STATE_TRACE` / `LWS_WITH_STATE_CHECK` trace and check wsi
   state transitions; `scripts/state-row-coverage.sh` reports which table
   rows tests fire.  See `READMEs/README.wsi-state-machines.md`.
 - `LWS_WITH_GCOV=1` + `make coverage` after ctest
   (`READMEs/README.coverage.md`).  Counters accumulate until the `.gcda`
   files are deleted.
 - `scripts/sans-io-check.sh` and `scripts/sans-io-link-check.sh` find
   leaks across the sansIO / IO boundary.  The link check scans every
   `.o`: delete stale objects after file moves.
 - api-test-sansio transcripts are the spec the sans-IO port is checked
   against.  Transcript times only move forwards: add new cases at the
   end with later times.  Record them from a fault-injection build.
 - No `perf`?  `valgrind --tool=callgrind` works for profiling, and
   gdb-attach sampling for where a parse spends its time.

## Hand-testing pieces

 - **lhp / DLO layout**: `lws-api-test-lhp-dlo file://$PWD/x.html --bmp
   out.bmp -d 1031` renders a local page and dumps the DLO tree.  The
   golden cases and vectors under the api-test are ctests.
 - **Stubs**: stubs bind under `/var/run`; test by hand with `unshare -rm`
   plus a tmpfs mounted on `/var/run`, secret and payload on stdin, JSON on
   the UDS.
 - **Plugin UI pages**: serve `assets/` with a local http server, open
   them in a browser, and drive the page's render functions from the JS
   console with synthetic data.
 - `lws-minimal-http-server` needs at least one argument or it prints help
   and exits; it takes `--port`, not `-p`.
