# Static analysis and fuzzing

The maintainer keeps the Coverity, CodeQL and SonarCloud dashboards clean,
fixing even test-side false positives in code where that is reasonable.
One commit per issue, with the checker's id in the message (eg
"Coverity CID n").  Dispositions are: fix it, mark it false-positive with
a reason, or a documented rule ignore.  Never a silent accept.

## Coverity

 - **Taint follows arithmetic.**  After
   `if (o > len) fail; len -= o; memmove(buf, buf + o, len)` the length is
   still flagged, because `len -= o` re-taints it.  What passes: compute
   `rest = len - o`, bound `rest` itself (`if (rest > BUF_MAX - o) fail`),
   memmove `rest`, store it back.
 - A library return built from an unbounded int sum stays "might have
   overflowed" in callers even after the caller's range check, and
   bounding the sum inside the library didn't clear it.  What cleared it
   was not indexing by the return at all (eg `strlen()` the NUL-terminated
   copy).
 - `lws_snprintf()` returns the whole size on truncation, so `p + m` can
   be one past the end; check `m >= size - 1` before using it.
 - An `if (ptr)` guard on a pointer that cannot be NULL makes FORWARD_NULL
   flag every later unguarded use.  Refuse NULL up front instead.
 - INTEGER_OVERFLOW fires when a known-constant seed is shifted or
   multiplied past 32 bits; mask off what a left shift would discard
   (`(r & 0x7ffff) << 13`).
 - `n = f(); (void)n;` satisfies gcc's `warn_unused_result` but not
   Coverity's CHECKED_RETURN, which wants the value to reach control flow:
   `if (f()) lwsl_info(...);`.  `(void)f()` does not suppress
   `warn_unused_result` in gcc at all.
 - Fixes made without the numbered event trail miss CIDs.  Get the trail
   before fixing.

## CodeQL

It can be run locally with the CodeQL CLI bundle:

 - The C database must be built by tracing a clean build matching
   `.github/workflows/codeql.yml` (plain default cmake), then analysed
   with `cpp-security-and-quality.qls`.  The CLI does not read the action
   config: apply the `query-filters` excludes from `.github/codeql.yml`
   yourself when summarising.
 - In-source `lgtm[...]` suppressions only show if you run
   `AlertSuppression.ql` alongside.
 - JavaScript scans need no node as long as build directories (and any
   in-source `**/CMakeFiles/**` from a stray in-source configure) are in
   `paths-ignore`; otherwise CMake's `compiler_depend.ts` files trigger the
   TypeScript extractor.
 - For `js/xss` and client-side redirect alerts, the sanitizers CodeQL
   recognises are an inline `startsWith` / `indexOf(...) === 0` guard
   dominating the sink, or concatenating after `window.location.origin`.
   A helper returning the validated string is invisible to it.
 - `cpp/inconsistent-null-check` is cleared by making a never-NULL helper
   return void, not by adding checks.  Dropping a NULL guard before
   `free()` can produce `cpp/use-after-free` on free-then-reassign.
 - Re-run the suite after a batch of fixes rather than guessing what its
   heuristics accept.

## SonarCloud

 - Autoscan analyses the GitHub mirror, which can lag the canonical tree.
   Before triaging, compare the analysed revision with the fix commits:
   reported issues may already be fixed.
 - Automatic analysis does **not** read `sonar-project.properties`; that
   file is the versioned record, pushed into the project settings by
   `scripts/sonar-push-settings.py`.
 - Analyses have reopened issues against unchanged source, quoting
   pre-fix code, and evaluated the preprocessor differently between runs.
   Check the issue changelog (CLOSED → OPEN with no source change) before
   re-fixing anything.
 - S3519 "negative offset" on `container_of(&x->member)` round trips is
   fixed by a helper that takes the containing struct.  S2612 on test
   files: create with owner-only modes.  The api-test `mkdtemp` convention
   is marked `// NOSONAR`.

## Fuzzing

Harnesses live in `fuzz/fuzz-<name>/` and run via `fuzz/run.sh`.
Committed regression inputs live in `fuzz/fuzz-<name>/seeds/` and run as
ctests (`ctest -R fuzz-`); a crash artifact becomes a regression test by
copying it there as `regress-*`.

 - Replay one input with `LWS_FUZZ_VERBOSE=1 ./bin/fuzz-x <file>`.
 - Rule out harness bugs (wrong buffer sizes) first: symbolize the ASan
   offsets (`addr2line -f -C -e bin/fuzz-x` if there is no
   llvm-symbolizer) and confirm the mechanism by reading.
 - LSan leaks seen mid-campaign but not on single-file replay are usually
   state carried between inputs: replay the whole corpus dir with
   `-runs=0` (all seeds run in one process).
 - The evil-peer vhost is named "fuzz" to match the preludes'
   `Host: fuzz`.
 - The hl / md harnesses compare a one-shot reference pass with a
   fragmented, sink-deferring stress pass; `LWS_FUZZ_VERBOSE=1` prints the
   first divergence, `LWS_FUZZ_TRACE=1` dumps the stress pass.  Both
   parsers' OK return can leave input unconsumed (a held decision byte):
   callers loop while progress is made.  Any new hl content state must
   keep the restartability model (content runs emitted only between
   units, state snapshotted and restored on deferral) or the oracle flags
   it.

## Known external noise under ASan

 - Plugin-enabled contexts dlopen every protocol plugin in the plugin
   dirs; a plugin pulling in libgomp (eg via libavcodec) leaves a small
   "unknown module" leak per context that is not lws.  Identify such
   leaks with `LD_DEBUG=files` and match the PC against the link map.
 - libuv event-lib plugins can trip ASan's ODR check in fixture ctests;
   `ASAN_OPTIONS=detect_odr_violation=0`.
