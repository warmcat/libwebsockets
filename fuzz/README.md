# lws fuzzing

Coverage-guided fuzzing of lws' untrusted-input parsers, using clang's
libFuzzer + AddressSanitizer.  Everything runs locally with no dependency
on any external fuzzing infrastructure.

## Quick start

Requirements: `clang` and the libFuzzer runtime (Debian-ish:
`clang-19 libclang-rt-19-dev`), plus `libgnutls28-dev` if you want the
`qpack` target (it needs the h3 role, which needs a QUIC-capable TLS
provider; without gnutls that one target is silently skipped).

```sh
./fuzz/run.sh              # build + 60s per target against all targets
./fuzz/run.sh 3600         # an hour per target
./fuzz/run.sh 600 lejp qpack   # selected targets only
BUILD=~/fz ./fuzz/run.sh   # non-default build dir
```

Corpora accumulate per-target in `<build>/fuzz/corpus-<name>/` across runs
(so coverage keeps advancing between campaigns), seeded from the committed
inputs in `fuzz/fuzz-<name>/seeds/`.  Anything the fuzzer finds is written
to `<build>/fuzz/crash-<sha1>`; re-run it directly on the artifact file to
reproduce:

```sh
./build-fuzz/bin/fuzz-qpack build-fuzz/fuzz/crash-<sha1>   # repro under ASan
```

`clang` is autodetected if there is no `clang` binary (eg `clang-19`).
Additional cmake options can be passed via `FUZZ_CMAKE_OPTS`.

## Reading the output

- `Done N runs in Ts` for a target means its time slice completed with no
  findings.  Corpus (`corp: N/MKb`) and coverage (`cov:`) growing between
  runs is the normal steady state, not a problem.
- Parser error logs during fuzzing are the *expected* face of malformed
  input being rejected, not findings — the harnesses silence them to keep
  throughput.  Set `LWS_FUZZ_VERBOSE=1` to replay a specific input with
  logs, e.g. `LWS_FUZZ_VERBOSE=1 ./build-fuzz/bin/fuzz-qpack <artifact>`.
- An actual finding is an ASan/UBSan report on stderr plus a
  `crash-<sha1>` artifact in `<build>/fuzz/`, and `run.sh` exits nonzero.
- `Ctrl-C` mid-campaign is safe; corpora reached so far are kept, and each
  target also self-terminates at its `-max_total_time`.

## CI / ctest

The same build registers a fast smoke test per target (`-runs=0`, runs
each committed seed exactly once under ASan):

```sh
CC=clang-19 cmake .. --fresh -DLWS_WITH_FUZZERS=ON -DLWS_WITH_CBOR=ON
cmake --build . --parallel
ctest -R fuzz-       # seconds, deterministic
```

`LWS_WITH_FUZZERS` implies whole-lib `-fsanitize=fuzzer-no-link,address`
instrumentation, so it should stay OFF for normal builds and normal CI.
Long campaigns belong on a dedicated runner or a nightly job via
`./fuzz/run.sh`.

## Targets

| target | parser under test | notes |
|---|---|---|
| `fuzz-lejp` | lejp JSON parser (`lib/misc/lejp.c`) | policy, JOSE, RPC JSON; fed in two chunks to cover partial-input states |
| `fuzz-lecp` | lecp CBOR parser (`lib/misc/lecp.c`) | needs `-DLWS_WITH_CBOR=ON` |
| `fuzz-qpack` | native QPACK decoders (`lib/roles/h3/qpack.c`) | first byte selects encoder-stream vs header-block decode; needs h3 (`LWS_WITH_HTTP3` + gnutls) |
| `fuzz-upng` | stateful PNG decoder (`lib/misc/upng.c`) | seeds from `test-apps/*.png` |
| `fuzz-lhp` | HTML5 + CSS parser (`lib/misc/lhp.c`) | builds a dlo document per input and destroys it; leaks and heap errors in teardown are caught |
| `fuzz-h1` | h1 server header/body parser (`lib/roles/http/`) | evil-peer target, see below |
| `fuzz-h2` | h2 framing + hpack (`lib/roles/h2/`) | evil-peer: the fuzz input is h2 frames after a canned h2c upgrade + connection preface |
| `fuzz-ws` | ws server frame parser (`lib/roles/ws/`) | evil-peer: the fuzz input is client frames after a canned upgrade handshake |

The `fuzz-h1`, `fuzz-h2` and `fuzz-ws` targets use the shared evil-peer
helper in [peer.h](peer.h): one real, adopted server-side connection per
input over a socketpair, fed the fuzz bytes as if received from the peer,
serviced deterministically via `lws_service_fd()`, then hung up on so the
close paths run too.  This exercises the production wsi state machines,
not just the parsing functions in isolation.  The same pattern will work
for any other adoptable server-side parser (eg, mqtt).

When a crash is found: reproduce on the artifact, minimize it, fix, then
commit a minimized seed under the target's `seeds/` and add the same input
as a case to the corresponding api-test where one exists, so it stays
covered in normal CI.

## Survey: what to harness next

The wsi-bound h1, h2/hpack and ws parsers are covered via `peer.h`.  The
remaining untrusted-input surfaces, easiest first:

 - mqtt rx parser (`lib/roles/mqtt/mqtt.c`): an evil-peer target with a
   canned CONNECT prelude, same shape as `fuzz-ws`
 - JPEG decoder (`lib/misc/jpeg.c`, `LWS_WITH_JPEG`) — standalone, same
   shape as `fuzz-upng`
 - async DNS wire parser (`lib/system/async-dns/async-dns-parse.c`)
 - auth-dns zone parser (`lib/system/auth-dns/`)
 - COSE sign/validate (`lib/cose/`), jrpc (`lib/misc/jrpc/`),
   dht messages (`lib/misc/dht`), sshd userauth / bipacket
 - `lws_tokenize`, `lws_b64_decode`, iso8601 and friends — standalone,
   cheap to add
 - wt (WebTransport) and full h3/QUIC framing: these need the UDP/QUIC
   stack stood up, a larger project than a socketpair

Fault injection (`lws_fi`) can additionally be used from inside harnesses
to fail the Nth allocation during parsing, which is where most parser
lifetime bugs hide.
