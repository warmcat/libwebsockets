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
# Additional cmake options can be injected via FUZZ_CMAKE_OPTS, and extra
# libFuzzer flags via FUZZ_OPTS (eg, FUZZ_OPTS=-verbosity=0 for CI logs).
#
# Corpora accumulate per-target in <corpus>/corpus-<name>/ across runs,
# seeded from the committed inputs in fuzz/fuzz-<name>/seeds/.  <corpus>
# defaults to <build>/fuzz; point CORPUS somewhere persistent when <build>
# is disposable (eg, a CI job dir) so coverage keeps advancing between jobs.
# Under a sai idle task (sai's READMEs/README-idle.md), sai sets SAI_IDLE_SECS
# to the length of the slice, which is the whole time we have, build included.
# Then that decides the time per target instead of the seconds argument: the
# time left after the build goes to as many targets as can each have at least
# IDLE_MIN_TARGET_SECS, taking turns in order across slices, so all of them
# are covered over a few slices.  Any target names given still limit the choice.
#
# Under a sai task whose configuration names a pool (sai's READMEs/README-
# pool.md), sai sets SAI_POOL_DIR to a dir the builder keeps synced with every
# other builder fuzzing the repo, and the corpora go there instead of CORPUS.
# The first time, whatever corpora CORPUS already had are copied in, so nothing
# found before is lost.
#
# With the pool, sai also gives us SAI_POOL_KNOWN, the reproducers of the bugs
# found so far (sai's READMEs/README-findings.md), and SAI_POOL_FINDINGS, where
# what we find goes to be sent to sai-server, which groups them into bugs.  A
# CI run (not an idle task) replays the known reproducers of each target before
# fuzzing it, and fails if any still crash, so a known bug keeps CI failing
# until it's fixed.  The sanitizer reports go only to sai-server, which only
# shows them to admins: they can be unfixed security bugs, and CI logs are
# public.  An idle task's findings are reported that way, but don't make it
# fail.
#
# Finding artifacts (crash-*, leak-*, timeout-*, oom-*) are written into
# <build>/fuzz/ along with each target's full output in log-<name>.txt; any
# findings produced by this run are listed by absolute path at the end and
# make the script exit nonzero.
#
# The same build also provides fast smoke tests of every harness against its
# seeds:  ctest -R fuzz-smoke

set -e

REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BUILD="${BUILD:-$REPO/build-fuzz}"
CORPUS="${CORPUS:-$BUILD/fuzz}"

if [ -n "$SAI_POOL_DIR" ] && [ -d "$SAI_POOL_DIR" ]; then
	if [ "$CORPUS" != "$SAI_POOL_DIR" ] && [ -d "$CORPUS" ] &&
	   [ ! -e "$CORPUS/.sai-pool-copied" ]; then
		for d in "$CORPUS"/corpus-*; do
			if [ -d "$d" ]; then
				mkdir -p "$SAI_POOL_DIR/${d##*/}"
				cp -Rn "$d/." "$SAI_POOL_DIR/${d##*/}/"
			fi
		done
		touch "$CORPUS/.sai-pool-copied"
	fi
	CORPUS="$SAI_POOL_DIR"
fi
SECS="${1:-60}"
if [ "$#" -gt 0 ]; then
	shift
fi
if [ "$#" -gt 0 ]; then
	TARGETS="$*"
else
	TARGETS="lejp lecp qpack upng jpeg gif lhp hl md tokenize jose cose adns h1 h2 ws ws-pmd"
fi

START=$(date +%s)
IDLE_SECS="${SAI_IDLE_SECS:-}"
case "$IDLE_SECS" in
	''|*[!0-9]*) IDLE_SECS="" ;;
esac
# least time a target gets in an idle slice, since each run begins by
# replaying the target's whole corpus
IDLE_MIN_TARGET_SECS=120
# time an idle slice keeps back for the fuzzer runs starting and stopping,
# and reporting at the end
IDLE_MARGIN_SECS=30
IDLE_PER_TARGET_OVERHEAD_SECS=5

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

if [ -n "$IDLE_SECS" ]; then
	# only the targets that got built can take a turn
	avail=""
	for t in $TARGETS; do
		if [ -x "$BUILD/bin/fuzz-$t" ]; then
			avail="$avail $t"
		fi
	done
	set -- $avail
	n=$#
	if [ "$n" -eq 0 ]; then
		echo "no fuzz targets built" >&2
		exit 1
	fi

	left=$(( IDLE_SECS - ($(date +%s) - START) - IDLE_MARGIN_SECS ))
	count=$(( left / (IDLE_MIN_TARGET_SECS + IDLE_PER_TARGET_OVERHEAD_SECS) ))
	if [ "$count" -gt "$n" ]; then
		count=$n
	fi
	if [ "$count" -lt 1 ]; then
		echo "idle slice of ${IDLE_SECS}s has no time left after the build"
		exit 0
	fi
	SECS=$(( left / count - IDLE_PER_TARGET_OVERHEAD_SECS ))

	# whose turn it is, kept with the corpora so it lasts between slices
	next=0
	if [ -r "$CORPUS/.idle-next" ]; then
		read -r next < "$CORPUS/.idle-next" || next=0
		case "$next" in
			''|*[!0-9]*) next=0 ;;
		esac
	fi
	next=$(( next % n ))
	echo $(( (next + count) % n )) > "$CORPUS/.idle-next"

	TARGETS=""
	i=0
	while [ "$i" -lt "$count" ]; do
		k=$(( (next + i) % n + 1 ))
		eval "TARGETS=\"\$TARGETS \${$k}\""
		i=$(( i + 1 ))
	done

	echo "idle slice of ${IDLE_SECS}s: ${SECS}s each for$TARGETS"
fi

# so we can tell this run's findings apart from any earlier ones in $BUILD
STAMP="$BUILD/fuzz/.run-stamp"
touch "$STAMP"

rc=0

# send a finding to sai-server through the pool: $1 target, $2 the input,
# $3 the name to give it, $4 the report.  Each is written under a hidden name
# first, so the builder never sends one half written.
sai_finding() {
	d="$SAI_POOL_FINDINGS/$1"
	mkdir -p "$d"
	tail -c 1048576 "$4" > "$d/.$3.log" && mv "$d/.$3.log" "$d/$3.log"
	cp "$2" "$d/.$3" && mv "$d/.$3" "$d/$3"
}

# replay the known reproducers of target $1, failing for any that still
# crash, and telling sai-server about those that don't any more
replay_known() {
	kdir="$SAI_POOL_KNOWN/$1"
	[ -d "$kdir" ] || return 0

	for f in "$kdir"/*; do
		h=${f##*/}
		case "$h" in
			*[!0-9a-f]*|'') continue ;;
		esac
		[ ${#h} -eq 40 ] || continue

		rlog="$BUILD/fuzz/replay-$1-$h.txt"
		if "$BUILD/bin/fuzz-$1" -timeout=60 "$f" > "$rlog" 2>&1; then
			mkdir -p "$SAI_POOL_FINDINGS/$1"
			: > "$SAI_POOL_FINDINGS/$1/.ok-$h" &&
				mv "$SAI_POOL_FINDINGS/$1/.ok-$h" \
				   "$SAI_POOL_FINDINGS/$1/ok-$h"
		else
			echo "fuzz-$1: known bug $h still crashes (report sent to sai)"
			sai_finding "$1" "$f" "replay-$h" "$rlog"
			rc=1
		fi
	done
}

# first corpus dir receives new discoveries, the second is read-only seeds
run_target() {
	"$BUILD/bin/fuzz-$1" "$CORPUS/corpus-$1" "$REPO/fuzz/fuzz-$1/seeds" \
		-max_total_time="$SECS" \
		-print_final_stats=1 \
		-artifact_prefix="$BUILD/fuzz/" \
		$FUZZ_OPTS
}

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
	log="$BUILD/fuzz/log-$t.txt"

	if [ -n "$SAI_POOL_KNOWN" ] && [ -n "$SAI_POOL_FINDINGS" ] &&
	   [ -z "$IDLE_SECS" ]; then
		replay_known "$t"
	fi

	TSTAMP="$BUILD/fuzz/.target-stamp"
	touch "$TSTAMP"

	if [ -t 1 ]; then
		# interactive: live output, plus a copy next to the artifacts
		{ run_target "$t"; echo $? > "$log.rc"; } 2>&1 | tee "$log"
		[ "$(cat "$log.rc")" = 0 ] || rc=1
		rm -f "$log.rc"
	else
		# not a terminal (CI log capture): libFuzzer emits each status
		# line as a dozen tiny unbuffered write()s, and collectors that
		# store per-read chunks (sai) count every one against a spew
		# limit; gather the target's output and emit it in one go
		run_target "$t" > "$log" 2>&1 || rc=1

		if [ -n "$SAI_POOL_FINDINGS" ]; then
			# the reports go to sai-server; the public log just
			# gets how it went
			grep -aE '^(#[0-9]+[[:space:]]+(INITED|DONE)|Done [0-9]+ runs|stat::)' \
				"$log" || true
		else
			cat "$log"
		fi
	fi

	if [ -n "$SAI_POOL_FINDINGS" ]; then
		for f in $(find "$BUILD/fuzz" -maxdepth 1 -type f \
				-newer "$TSTAMP" \( -name 'crash-*' \
				-o -name 'leak-*' -o -name 'timeout-*' \
				-o -name 'oom-*' -o -name 'slow-unit-*' \)); do
			echo "fuzz-$t: finding ${f##*/} (report sent to sai)"
			sai_finding "$t" "$f" "${f##*/}" "$log"
		done
	fi
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

if [ -n "$IDLE_SECS" ] && [ -n "$SAI_POOL_FINDINGS" ]; then
	# an idle task has reported what it found, it carries on next slice
	rc=0
fi

exit $rc
