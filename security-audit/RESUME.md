# Resume point (updated 2026-09-08, second session after the quota reset)

Second session: all six interrupted units were completed and committed (dht-misc C-257..C-260, webrtc-mixer
C-263..C-266, net-misc C-267..C-270, plat-unix C-272..C-279, plugin-demos C-282..C-288, core-net-misc
C-289..C-291), plus C-292/C-280/C-305 (proxy body back-pressure, accept4, evlib close result), auth-server JS
C-293..C-296, openssl-quic-dtls C-298/C-299, event-libs C-302..C-304, include-inline C-306/C-307.
In flight at the time of writing: fixers for plugin-webrtc DTLS caller (C-300/C-301), the two JS asset units,
mbedtls-x509-ssl (closes C-110); auditors for gnutls, bearssl, openhitls-conn/gen, plat-freertos-optee,
plat-windows. Still unaudited after those: mbedtls-conn, mbedtls-gen, schannel, dlo, drivers, media.
Open policy items for the maintainer: C-297 (built-in CSP connect-src ws:/wss:), C-262 (dht-dnssec 0770 dirs).
RE-AUDIT flags left deliberately: plugin-hls and plugin-dht-monitor (maintainer commits landed there),
ss-serialized-client and core-net-adopt-vhost (flag script matched broadly; verify by `audit.py diff`).

# Historical resume point (written 2026-09-08, end of the first session)

HEAD at write time: see `git log -1`. All completed units are committed one finding per commit
and stamped in state.json (`python3 security-audit/audit.py report`).

## Fixer agents that were still running when the session closed

Each had a file allowlist; their partial edits (if any) are the uncommitted, tracked files in
`git status --short | grep -v '^??'`. On restart, for each unit below: read the candidates file,
`git diff` the listed files, and relaunch a verifier/fixer (Opus) with the partial diff as input
(the same recovery used after the VM resize), then review, commit per finding, write
findings/C-NNN.md (next id: `python3 security-audit/audit.py new-id`), `audit.py done UNIT`.

| unit | candidates file | files being edited |
|---|---|---|
| plugin-webrtc-mixer | candidates/plugin-webrtc-mixer.md (11) | plugins/protocol_lws_webrtc_mixer/* |
| plugin-net-misc | candidates/plugin-net-misc.md (13) | plugins/protocol_lws_raw_proxy, smtp_client, extip, openmetrics_export, captcha_ratelimit |
| core-net-misc | candidates/core-net-misc.md (15; C-214 and its confirmation now fixed, 14 left) | partial edits saved to security-audit/partial/core-net-misc-partial.patch (do NOT apply blindly: stub.c has since changed for C-214; use for ideas) |
| plugin-dht-misc | candidates/plugin-dht-misc.md (12) | plugins/protocol_lws_dht_object_store, dht_stats, dht_store |
| plat-unix | candidates/plat-unix.md (16) | lib/plat/unix/unix-sockets.c has a small partial edit (candidate 1 started); maybe lib/core-net/sockets.c |
| plugin-demos | candidates/plugin-demos.md (13) | plugins/protocol_lws_mirror, post_demo, lws_status, latency, raw_test, fulltext_demo, client_loopback_test, urlarg, dumb_increment; maybe test-apps/test-server.c |

If a unit's files show no diff, the agent had not started editing: just relaunch the fixer.

## Units not yet audited

openssl-quic-dtls, mbedtls-x509-ssl, mbedtls-conn, mbedtls-gen, openhitls-conn/gen, bearssl, gnutls,
schannel, include-inline, event-libs, plat-windows, plat-freertos-optee, dlo, drivers, media,
plugin-auth-server-js, plugin-webrtc-js (wait for the mixer fixer first), plugin-web-misc-js.
`python3 security-audit/audit.py next -n 8` lists them with RE-AUDIT flags; flags caused only by
our own fix commits are cleared with `audit.py done UNIT --refresh`.

## Open library follow-ups recorded this session

Later on 2026-09-08 the maintainer decided on C-214, C-245, C-252, C-256 (all now fixed and committed:
0df6407cf, 70f7d4d35, fa1996620, 0ae36de68) and confirmed C-207 stays as is. The remaining open items
are the earlier design decisions listed with status open in findings-C.md.

(historical text follows)

C-214 (stub raw-only retire / cancel API; core-net-misc fixer was addressing it), C-245 (auth-dns
$ORIGIN normalisation), C-252 (context destroy should empty pt sul lists), C-256 (wt role bind/unbind
reasons alias ESTABLISHED; parse-quic adoption before stream type known).
Deployment-affecting: C-207 (cert-dist per-subdomain authorisation now enforced).

## Update (second session, later): TLS backends and platforms done
Committed since the previous note: openhitls C-322..C-324 (C-325 open), plat-windows/freertos/optee C-326..C-335
(C-336 open: mingw lws_filefd_type), gnutls C-337..C-342 (headline: gnutls client never verified the server
hostname, C-337), bearssl C-319..C-321, mbedtls-x509-ssl C-312..C-318 (C-110 closed), dlo C-346..C-349, http
C-345. In flight at the time of writing: schannel fixer, mbedtls-conn/gen fixer, the C-343 (EC key match
across backends + test expectation) / C-344 (QUIC client never verifies the server cert, cross-backend) fixer,
and the drivers/media auditor. After those, every unit in units.txt has had a first pass except the
lib/plat/freertos/esp32/** subdir (outside the unit glob) and the RE-AUDIT-flagged units where Andy's own
commits landed (plugin-hls, plugin-dht-monitor).
Open items for Andy: C-297 (built-in CSP connect-src), C-262 (dht-dnssec 0770 dirs), C-318 (cross-vhost CA
mismatch on rebind), C-325 (openhitls jit-trust), C-336 (mingw typedef), C-349 (lhp-ss dangling lhp).
Not built here, need a real target/toolchain before release: webrtc-mixer (C-263..C-266, no GStreamer),
openssl-quic.c (C-299, no BoringSSL), windows-spawn.c (C-328, mingw typedef), freertos/optee (C-331..C-334).

## Final state of the 2026-09-08 sessions
Every unit in units.txt has had a first pass. Findings C-001..C-366; 336 fixed-committed, 27 open (design /
maintainer decisions / follow-ups needing hardware or a toolchain). build-audit and build-agy build clean at HEAD.
Stale ctest fixtures and self-matching `pgrep -f ctest` agent poll loops were killed; future agent briefs must
run ctest in the foreground under `timeout` and never poll pgrep for their own command text.
Next steps when resuming: (1) decide the open policy items (C-297 CSP connect-src, C-318 cross-vhost CA on rebind,
C-262, C-363 cipher-name mapping); (2) build on real targets what could not be built here (webrtc-mixer
C-263..266 GStreamer, openssl-quic.c C-299 BoringSSL, windows-spawn.c C-328 mingw typedef C-336, mbedtls-quic.c
C-358 patched mbedtls, freertos/optee C-331..334, schannel C-350..352 MSVC); (3) second-pass re-audits of
plugin-hls and plugin-dht-monitor where the maintainer's own commits landed; (4) lib/plat/freertos/esp32/** which
is outside every unit glob; (5) add PS256/384/512 round-trip coverage to api-test-gencrypto (C-363).

## Pass 2 (2026-09-10): attacker-first units, second reading

Method: `PROMPT-audit-pass2.md`. Auditors got the pass-1 candidates and findings for
their unit, the last ten days of fix commits, and a brief to find one usable remote
vuln, not hygiene; each reported a convergence verdict. Candidates in
`candidates/<unit>-pass2.md`.

Units re-read: http-parsers, http-header-cookie, h1, http-server, h2-core, h2-hpack,
ws-ops, ws-server-client, quic-parse, mqtt-core, tls-common, openssl-x509,
openssl-server-client, async-dns, async-dns-parse, jws, jwe, jwk, cose-key,
cose-sign-validate, lejp, lecp, http-client, cgi.

Result: C-367..C-459, 93 findings, 85 fixed (one commit each, except C-429/C-430 and
C-453/C-454 which share a commit because the hunks are fused), 8 open decisions. Convergence: quic-parse
converged; hpack, h2 framing, ws arithmetic, lejp memory safety, cose memory safety,
openssl-x509 memory safety converged; NOT converged: h2 stream lifetime (C-378),
http-server (found a critical two passes missed, C-419), http-parsers (one-fragment
URI invariant and ah reentrancy, fixed in C-452..C-454, C-459 open), ws state
exits, mqtt resource accounting, async-dns (result layout, DNSSEC state), jose.c/lejp
seam, cose/lecp seam, TLS policy (which vhost serves / verifies), cgi ownership.

The http-parsers / http-header-cookie pass-2 candidates were fixed last (C-452..C-458:
'&'/';' path split of the method URI, ah-detach reentrancy and lock imbalance, zap
early return, known-header prefix match, zap walk bound, cookie write-pass bound).
C-459 (lws_header_table_attach() has the same reentrancy shape) is open.

Open decisions: C-459 (attach reentrancy contract), C-378 (h2 DATA END_STREAM never sets swsi->h2.END_STREAM, trailers
should decode into a discard sink, transfer-encoding not refused in h2 requests),
C-424 (SNI no-match served by first vhost on port), C-425 (lejp '#' comment
extension / REJECT_UNKNOWN tolerance / api-test-lejp golden buf), C-426 (test
follow-ups: x509 api-test under non-UTC TZ, ECDH-ES apu/apv round trip), C-436
(adopt.c resolver socket unconnected on Apple), C-450 (defensive consumer bound for
APPEND_HANDSHAKE_HEADER), C-451 (cgi_list to lws_dll2_t).

Behaviour changes to know about: C-406 puts a TLS 1.2 floor on OpenSSL server and
client ctxs (ssl_options_clear / ssl_client_options_clear lower it); C-422 makes the
ah excessive-hold watchdog live, restricted to connections still in LRS_HEADERS;
C-397 caps COSE signatures per object at 16; C-372 caps unacked QoS2 rx at 256;
C-432 makes DNS queries actually time out; C-438 bounds pmd drain work per service
call.

Environment note: build-audit has LWS_WITH_SYS_DHCP_CLIENT=ON and this VM has no DHCP
lease, so every client-side ctest there stalls at IFACE_COLDPLUG -> DHCP (reproduced
on the 9537cc3b3 baseline, not a regression). Validate client changes in build-agy
(DHCP client off): its full http/h2 set is 60/60 at a4bc7b9c2.

## Decisions round (2026-09-10 afternoon)

Andy's answers on the design items were implemented and committed:
C-297 CSP connect-src 'self' only; C-378 h2 stream state (DATA END_STREAM latched,
transfer-encoding refused, trailers decoded into a discard sink, plus the server.c
stashed-body guard); C-424 SNI no-match refused on shared ports with
LWS_SERVER_OPTION_SNI_FALLBACK / "sni-fallback" (coordinator narrowing: a port with
exactly one vhost still serves it); C-425 lejp '#' comments opt-in
(LEJP_FLAG_FEAT_COMMENTS, set by lwsws config and the SS policy parser, which the
live warmcat.com policy needed); C-436 resolver source-check api-test legs + adopt.c
comment (exclusion origin dacae3a95, possibly obsoleted by 6059d830f); C-450
consumer bounds; C-451 cgi list to lws_dll2; C-459 attach result enum
(LWS_AH_ATTACH_*, every caller audited); C-363 mbedtls cipher mapping + PSS tests;
C-406 TLS 1.2 floor / no renegotiation on every backend with the parity sweep
(C-408/409/410/411/412/413/417/359/362/343 equivalents), which also found C-463
(wolfSSL never checked hostname or chain result, critical, unbuildable here) and
C-462 (schannel partial write stall); C-262 closed by design (Andy: elevated users
or an lws_stub copy).  C-318 (cross-vhost CA on rebind), C-461 (h2 POST through the interceptor chain, plus
C-468 captcha POST-as-form bypass and C-469 lws-login non-GET bounce) and C-464 (SNI
selection on bearssl and schannel via a shared ClientHello parser in tls-server.c;
schannel unverified here) were then committed.  C-460 (ah early detach design) is
the one open design item; C-467 was allocated by Andy's other session (h3 TE).

Watch out: Andy's other session allocates C-NNN ids in commit subjects (C-465,
C-466 so far); placeholder records exist so audit.py new-id skips them.  That
session's C-011 request-body commits (0782e37e1, dec45dd50) currently fail the
h1 POST client tests in build-agy (server never answers the POST, client
"read failed"); it was running those tests itself at 12:15, so it is presumably
aware.  Do not run ctest in build-agy while another session is.

## C-460 early ah release (2026-09-11)

Audit report: security-audit/reports/C-460-ah-late-use-audit.md (13 late sites, 3
blockers).  Landed in order: B1 h2 hdrs_done bit (a94d25023), B2 proxy header
snapshot at proxy start + replay through the onward-header parser, with the 512 /
256-byte capacity defects that dropped browser Cookie headers (1bb85bc69), B3
interceptor redirect target captured at arm time (03d232c49), method snapshot
(0fd8d8f4d), lws-login host/scheme capture (465f93f05), the release itself via
lws_http_ah_release_after_dispatch() at the no-more-body exits of lws_http_action()
and after HTTP_BODY_COMPLETION on h1/h2/h3 (1150aec1a), docs (1cc29d4f8), cookie.c
guard.  Behaviour change for apps: request headers are readable up to
LWS_CALLBACK_HTTP, or HTTP_BODY_COMPLETION for a body-bearing request; later reads
answer "not present".  Open: C-470 (SS DIRECT_PROTO_STR metadata late read /
dangling pointer), cgi POST with Content-Length: 0 gets no empty body pair
(preserved deliberately), C-461-class interceptors done.

## 2026-09-11 production crash and C-460 revert

warmcat.com lwsws died with SIGSEGV (no trace: lwsws only installs its handler with -d,
and the unit has no core limit) at 40 min on ef0b2ae70 and 10 min on HEAD, the last
event each time a QUIC PTO death.  Two read-only audits:
security-audit/reports/quic-pto-death-crash-audit.md found C-471 (server frees the
network wsi on a peer CONNECTION_CLOSE then continues the coalesced-packet loop over
it: confirmed, fixed ac5067b4e) and C-472 (openssl-quic migration left the ex_data wsi
pointer on the freed h3 stream: fixed 8ccf51622, read-only).
security-audit/reports/C-460-post-release-crash-audit.md found the early ah release
unsafe on h1 (POLLIN re-attach clears hdr_parsing_completed and arms the 10s HOLDING_AH
timeout over a live transfer), dead h2 body framing guards, and the dangling
LWS_CALLBACK_HTTP `in`: the release and docs were reverted (65c736daf, f224dfdb2);
C-468 (captcha diverted-POST block) was a false positive (form posts to the gated url)
and was reverted (6b004539e).  NULL-ah assert fall-throughs hardened (52f2f9b73).
Suite 201/201 at HEAD.  Valgrind run by Andy pending.  Re-land C-460 for mux streams
only, with an h1 pipelining-during-transfer test first.
Root cause found: C-473 (5c8543f55) -- ALPN migration moved the evlib block before the racer teardown, so the parked TCP racer's libuv watcher outlived the wsi. Valgrind trace matched (lws_io_cb with reused memory).

## 2026-09-12 next phase: libuv parity and the lwsws fixture

C-473 stayed up 22h on warmcat.  Agreed plan with Andy, in order: (1) run the whole
ctest suite under libuv, (2) e2e tests for this week's regressions housed in a real
lwsws-on-libuv fixture, then object-lifetime audits, an evlib parity sweep, warmcat
plugin pass 2, stateful fuzzers.  Landed (committed by Andy from a script because the
session's auto mode started refusing every non-read-only action):
 - 96fd13fac evlib runtime selection: --uv/--event/--ev/--glib/--sd/--uloop in
   lws_cmdline_option_handle_builtin(), and LWS_EVLIB=uv etc applied inside
   lws_create_context() (examples overwrite info.options after the builtin call).
   Build tree: build-agy-evlib (libuv+libev evlib plugins, GnuTLS, HTTP3); run with
   LD_LIBRARY_PATH=build-agy-evlib/lib LWS_EVLIB=uv.
 - fa332e627 lws_service()/lws_service_tsi() return -1 once the evlib internal loop
   exited for a context destroy (previously every app looping on >= 0 spun forever
   after SIGINT/SIGTERM under --uv, or after lws_context_destroy() from a callback).
   NOT YET CHECKED: whether the app's final lws_context_destroy() on an internal loop
   ever reaches LWSCD_FINALIZATION ("waiting for internal loop exit" is logged last),
   ie whether the context leaks at exit: run valgrind --leak-check=full on an example
   under LWS_EVLIB=uv + SIGTERM, and on destroy-from-sul-callback and
   destroy-from-protocol-callback cases, poll vs uv.
 - 8a2bbf375 api-test-lwsws-uv: lwsws + plugins from the build tree on a generated
   JSON config (tls vhost alpn h3,h2,http/1.1 + QUIC on the same port, captcha
   interceptor on /gated, deaddrop, lws-status, /proxy to a cleartext vhost, 5s
   keepalive), cases captcha(-h2,-uv), pipeline(-uv), proxy(-uv), h3race-uv/-poll,
   quic-abort-uv/-poll.  Build tree: build-agy-lwsws-uv.  Passes ctest for Andy.
   README's "libuv note" about lws_context_destroy() from a callback wedging in
   uv_run() describes the spin fixed by fa332e627: correct it.

Fixture findings still to record and fix (next free id C-474; C-467 was the other
session's, C-468..C-473 mine; check `git log --grep` first):
 - C-474 lws h2 client does not deliver a POST request body (lwsws-uv-captcha-h2
   fails deterministically; stock lws-minimal-http-client-post h2 fails 2/8):
   client-http.c / http2.c client body write path.
 - C-475 lws h3 client POST puts two FINs on the request stream, server answers
   QUIC FINAL_SIZE_ERROR 0x6; no h3 POST ctest exists: ops-h3.c / quic stream FIN.
 - C-476 the libuv loop-exit spin (fixed by fa332e627, record it; leak check above).
Then item 1 proper: `LWS_EVLIB=uv LD_LIBRARY_PATH=.../build-agy-evlib/lib ctest -j1`
in build-agy-evlib (never while another tree runs ctest), failures become findings.
build-audit does not configure: minimal-secure-streams-testsfail/sstf.test.zone.in
is missing (Andy's other session's work in progress).  C-470 still open.

## 2026-09-12 afternoon: fixture regressions fixed, exit paths, suite under libuv

Committed: 7f120569b (C-474 h2 client POST: no body writeable without credit, nothing
after END_STREAM; captcha-h2 passes), e983397db (C-475 h3 client: no writeable / no
write after the stream's FIN).  Also committed: 4ee2ba62f (C-477/C-479
evlib destroy finalization: context.c, libuv.c, fixture README libuv note), 4d31955f4
(C-480 lws_default_loop_exit() on an internal evlib loop).  LWS_EVLIB=uv suite rerun in
build-agy-evlib: 16 passed then api-test-http-transfer hung after its cases (C-481: 139
examples exit via a private interrupted flag, 20 ctest api-tests among them; decision for
Andy, sweep to lws_default_loop_exit() or restrict the uv run); stopped at 17/142.  C-476 records fa332e627.  C-478
(quic client-server ctest fails on IPv6 hosts: server binds 0.0.0.0, client prefers ::1;
not a regression) is open for Andy.  Verified: build-agy (-Werror) clean, build-agy-lwsws-uv
full suite 161/162 (the C-478 one), lwsws-uv cases 13/13, valgrind exit paths under
uv/ev/poll (SIGTERM, destroy from sul and protocol callback, create failure).
First LWS_EVLIB=uv suite run (before C-480) timed out every SS example after completion;
rerun in progress.  Andy's other session's 464bcb3bc (hls trace) fails -O2 -Werror
builds (hls-av.c maybe-uninitialized start_time/end_time/has_index): told, not touched.
Next: Andy's C-481 decision, then the uv suite again; evlib parity sweep (event/glib/sd/uloop
have the same destroy_self hooks, untested here); h3 POST case for the fixture (C-475
follow-up); warmcat plugin pass 2; stateful fuzzers.

## 2026-09-12 evening: C-481 sweep (Andy's decision: teach the api)

Library: lws_service()/lws_service_tsi() return -1 once lws_default_loop_exit() was
called (lib/core-net/service.c, docs in lws-service.h / lws-context-vhost.h).  Examples:
~150 files, private "interrupted" flag gone, lws_default_loop_exit(cx) at sigint and
completion, loops `while (lws_service(cx, 0) >= 0)` / `while (n >= 0)`, context hoisted
to file scope where needed; details in findings/C-481.md.  Scripts in the session
scratchpad (sweep.py automatic part, manual-edits.py for the 37 hand cases).  Foreign
edits present in the tree at the time (NOT mine, do not commit): lib/misc/dht/dht.c,
minimal-examples-lowlevel/api-tests/api-test-dht-msg-parse/main.c.  Build: all three trees
ok (build-agy-lwsws-uv with make -k because of 464bcb3bc hls-av.c).  Then: full poll
suite in build-agy-lwsws-uv, LWS_EVLIB=uv suite in build-agy-evlib, commit as two commits
(service.c + headers; the sweep), Andy takes stock after CI.

Committed: 489a38caa (lws_service returns -1 after lws_default_loop_exit, libuv run_pt
UV_RUN_ONCE, normal evlib turn returns 0, -1 only once an in-loop destroy reached
FINALIZATION), 364855eaf (the sweep, 156 files), 9fbab6898 (C-482 gnutls cert list leak
found by valgrind on the way).  Suites at that point: LWS_EVLIB=uv in build-agy-evlib
141/142, poll in build-agy-lwsws-uv 161/162, the one failure is C-478 both times.
Andy takes stock after CI (Sai).  Open: C-478; evlib parity for event/glib/sd/uloop
(run_pt still blocks forever there: event_base_dispatch, g_main_loop_run, uloop_run;
they need the same one-turn treatment, untested here); h3 POST fixture case.

## 2026-09-12 night: every event library, whole suite green

Andy: "get it back to passing every test with poll and with event libs".  Installed
libevent/glib/libsystemd dev packages (his ok), tree build-agy-evlibs (uv, ev, event, glib,
sd; run with LD_LIBRARY_PATH=build-agy-evlibs/lib LWS_EVLIB=<name>; uloop not packaged).
Commits: 9390b8fb5 C-478 (wildcard UDP bind :: first, falls back to 0.0.0.0), aa4a80726
(libevent/glib run_pt one turn per lws_service, like ev/uv/sd), 0b5a721f5 C-483
(event_loop_ops->migrate_wsi for the QUIC ALPN migration, every plugin), 8640fadae C-484
(libevent promote), 3c426bf02 C-485 (glib dispatch fd, quit guard, libev debug-log deref),
089fbdb79 C-486 (non-pollable stdin read synchronously; the POST ctests were passing
vacuously under uv/event/sd and hanging under ev/glib).  Result: build-agy-evlibs full
suite 145/145 on poll and under event, glib, sd, ev, uv (5-minute cap each, `ctest
--timeout 60`).  Final poll run in build-agy-lwsws-uv pending at the time of writing
(scratchpad ctest-final-lwsws-uv.log).  Open: QUIC client next-address fallback (C-478
note), uloop parity (untested), valgrind noise from glib's own worker thread (not lws).
Never run a ctest suite with a background timeout over ~6 minutes: 20s test timeouts add
up and Andy watches the clock.

## 2026-09-15: serializer sweep (encode-side class)

Private report: OOB write in lws_qpack_encode_literal_with_literal_name()
(unchecked name memcpy after a checked length prefix, then buf_len - pos
wraps).  Fixed d6b080dd4; adjacent prefix-reservation wrap fixed e7db1787d;
debug-log pre-check read fixed after.  Missed by pass 1 h3-qpack because the
unit framing and fuzz-qpack are decoder-only.

Sweep of cursor-style memcpy sites in qpack/hpack/header.c/mqtt/adns/dnssec:
all other sites bounded (hpack checks total up front at hpack.c:96, H1
by_name checks per piece, mqtt PUBLISH checks the total before
lws_mqtt_str_init so write-then-advance is safe, adns/dnssec check first).
No new findings outside qpack.

Regression fence: api-test-qpack section 7 shrink test, 14 encoders, every
length 0..n-1 on exact-size heap buffers under ASan.  New cross-cutting
`serializers` unit in units.txt; not yet given a full pass on jose/cose/dht
(only grep-swept for memcpy, raw *p++ writers not yet read).

### 2026-09-15 serializers unit, pass 1 complete

Raw-cursor writers read in jose (jose_key.c escaper + base64 export, jws.c
encode_section, jwe.c be32 + snprintf/jwk_export chain), cose (no raw
writes; lecp writer is the stall/scratch design), dht-bencode (decode-side
skips only): all bounded, 0 findings.  hpack read-verified (total check up
front).  H1 writers fenced by api-test-http-cookie s8 shrink test; note the
H1 writers deliberately refuse with a few bytes of headroom, so shrink
tests for them assert "never claims more than given", not exact fit.
h2 writers are not exported, so hpack has no api-test shrink fence; a
future fuzz/api harness needs a wsi.  Unit status: done, pass 1.
