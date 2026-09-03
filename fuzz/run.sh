#!/bin/sh
#
# lws local guided-fuzzing runner
#
# Usage:
#
#   fuzz/run.sh                      # 60s per target, all targets
#   fuzz/run.sh 600                  # 10 mins per target, all targets
#   fuzz/run.sh 600 lejp lecp        # only named targets
#   BUILD=~/fuzz-build fuzz/run.sh   # non-default build dir
#
# Requires clang with libFuzzer (Debian-ish: clang + libclang-rt-*-dev).
# Additional cmake options can be injected via FUZZ_CMAKE_OPTS.
#
# Corpora accumulate per-target in <build>/fuzz/corpus-<name>/ across runs,
# seeded from the committed inputs in fuzz/fuzz-<name>/seeds/.  Crash
# artifacts are written into <build>/fuzz/.
#
# The same build also provides fast smoke tests of every harness against its
# seeds:  ctest -R fuzz-smoke

set -e

REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BUILD="${BUILD:-$REPO/build-fuzz}"
SECS="${1:-60}"
if [ "$#" -gt 0 ]; then
	shift
fi
if [ "$#" -gt 0 ]; then
	TARGETS="$*"
else
	TARGETS="lejp lecp qpack upng lhp h1 h2 ws"
fi

if [ -z "$CC" ]; then
	for c in clang clang-19 clang-18 clang-17; do
		if command -v "$c" >/dev/null 2>&1; then
			CC="$c"
			break
		fi
	done
fi

# qpack fuzzing needs the h3 role, which needs a QUIC-capable TLS provider;
# with gnutls available we can bring it in, otherwise that one target is
# silently skipped and the rest still fuzz

FUZZ_SSL=-DLWS_WITH_SSL=OFF
if pkg-config --exists gnutls 2>/dev/null; then
	FUZZ_SSL=-DLWS_WITH_SSL=ON
fi

CC="$CC" cmake -S "$REPO" -B "$BUILD" --fresh -DCMAKE_BUILD_TYPE=Debug \
	-DLWS_WITH_FUZZERS=ON \
	$FUZZ_SSL \
	-DLWS_WITH_MINIMAL_EXAMPLES=OFF \
	-DLWS_WITHOUT_TESTAPPS=ON \
	-DLWS_WITH_CBOR=ON \
	-DLWS_WITH_HTTP3=ON \
	$FUZZ_CMAKE_OPTS

cmake --build "$BUILD" --parallel

mkdir -p "$BUILD/fuzz"

rc=0

for t in $TARGETS; do
	bin="$BUILD/bin/fuzz-$t"
	seeds="$REPO/fuzz/fuzz-$t/seeds"

	if [ ! -x "$bin" ]; then
		echo "fuzz-$t: not built (cmake option off?), skipping" >&2
		continue
	fi

	echo
	echo "=== fuzz-$t: ${SECS}s ==="
	mkdir -p "$BUILD/fuzz/corpus-$t"
	# first corpus dir receives new discoveries, the second is read-only seeds
	"$bin" "$BUILD/fuzz/corpus-$t" "$seeds" \
		-max_total_time="$SECS" \
		-print_final_stats=1 \
		-artifact_prefix="$BUILD/fuzz/" || rc=1
done

exit $rc
