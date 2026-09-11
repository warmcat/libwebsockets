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
#   CORPUS=~/fuzz-corpus fuzz/run.sh # keep corpora outside the build dir
#
# Requires clang with libFuzzer (Debian-ish: clang + libclang-rt-*-dev).
# Additional cmake options can be injected via FUZZ_CMAKE_OPTS.
#
# Corpora accumulate per-target in <corpus>/corpus-<name>/ across runs,
# seeded from the committed inputs in fuzz/fuzz-<name>/seeds/.  <corpus>
# defaults to <build>/fuzz; point CORPUS somewhere persistent when <build>
# is disposable (eg, a CI job dir) so coverage keeps advancing between jobs.
# Finding artifacts (crash-*, leak-*, timeout-*, oom-*) are written into
# <build>/fuzz/; any produced by this run are listed by absolute path at the
# end and make the script exit nonzero.
#
# The same build also provides fast smoke tests of every harness against its
# seeds:  ctest -R fuzz-smoke

set -e

REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BUILD="${BUILD:-$REPO/build-fuzz}"
CORPUS="${CORPUS:-$BUILD/fuzz}"
SECS="${1:-60}"
if [ "$#" -gt 0 ]; then
	shift
fi
if [ "$#" -gt 0 ]; then
	TARGETS="$*"
else
	TARGETS="lejp lecp qpack upng jpeg lhp tokenize jose cose adns h1 h2 ws ws-pmd"
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
# silently skipped and the rest still fuzz.  JOSE / COSE / DNSSEC need a
# crypto provider too, so they ride on the same condition.

FUZZ_SSL="-DLWS_WITH_SSL=OFF"
if pkg-config --exists gnutls 2>/dev/null; then
	FUZZ_SSL="-DLWS_WITH_SSL=ON -DLWS_WITH_GENCRYPTO=ON -DLWS_WITH_JOSE=ON \
		  -DLWS_WITH_COSE=ON -DLWS_WITH_SYS_ASYNC_DNS_DNSSEC=ON"
fi

# ws permessage-deflate needs zlib; without it ws-pmd is skipped

FUZZ_ZLIB="-DLWS_WITHOUT_EXTENSIONS=ON"
if pkg-config --exists zlib 2>/dev/null; then
	FUZZ_ZLIB="-DLWS_WITHOUT_EXTENSIONS=OFF -DLWS_WITH_ZLIB=ON"
fi

CC="$CC" cmake -S "$REPO" -B "$BUILD" --fresh -DCMAKE_BUILD_TYPE=Debug \
	-DLWS_WITH_FUZZERS=ON \
	$FUZZ_SSL \
	$FUZZ_ZLIB \
	-DLWS_WITH_MINIMAL_EXAMPLES=OFF \
	-DLWS_WITHOUT_TESTAPPS=ON \
	-DLWS_WITH_CBOR=ON \
	-DLWS_WITH_HTTP3=ON \
	-DLWS_WITH_JPEG=ON \
	-DLWS_WITH_SYS_ASYNC_DNS=ON \
	$FUZZ_CMAKE_OPTS

cmake --build "$BUILD" --parallel

mkdir -p "$BUILD/fuzz" "$CORPUS"

# so we can tell this run's findings apart from any earlier ones in $BUILD
STAMP="$BUILD/fuzz/.run-stamp"
touch "$STAMP"

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
	mkdir -p "$CORPUS/corpus-$t"
	# first corpus dir receives new discoveries, the second is read-only seeds
	"$bin" "$CORPUS/corpus-$t" "$seeds" \
		-max_total_time="$SECS" \
		-print_final_stats=1 \
		-artifact_prefix="$BUILD/fuzz/" || rc=1
done

# list what this run produced, by absolute path, so the evidence can be
# collected from the log even when the run happened somewhere else (eg, CI)

FOUND=$(find "$BUILD/fuzz" -maxdepth 1 -type f -newer "$STAMP" \
	\( -name 'crash-*' -o -name 'leak-*' -o -name 'timeout-*' \
	   -o -name 'oom-*' -o -name 'slow-unit-*' \) | sort)

echo
if [ -n "$FOUND" ]; then
	echo "=== FINDINGS: replay each with <build>/bin/fuzz-<target> <file> ==="
	echo "$FOUND"
	rc=1
else
	echo "=== no findings ==="
fi

exit $rc
