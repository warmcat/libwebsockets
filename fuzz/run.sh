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
# It builds with as many compiles at once as there are cpus, or under sai,
# SAI_PARALLEL of them.
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
# Each target's share is worked out from the clock just before it starts, so
# one that ran long only takes time from the targets after it, and each one is
# stopped if it runs past its share (eg, if replaying its corpus took longer
# than that), so the slice is never overrun.  Targets that don't fit any more
# go first next slice.  The log says how long the build and each target took.
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
# libFuzzer keeps every input that reached anything new, and with value
# profiling that's a lot of them, so left alone the corpora only grow, and
# each target spends more and more of its time replaying its corpus before it
# fuzzes anything.  So before a target fuzzes, if its corpus has grown to more
# than twice the size it was last minimized to (or this machine has never
# minimized it, and it has at least MINIMIZE_MIN_FILES inputs), it's
# minimized with libFuzzer's -merge=1 first: only the inputs that add coverage
# are kept.  With a sai pool, the minimized corpus replaces the shared one
# through the pool (sai's READMEs/README-pool.md), so every builder gets it.
# FUZZ_MINIMIZE=off stops that, and FUZZ_MINIMIZE=only minimizes the targets'
# corpora (all of them, however big) without fuzzing, eg, by hand on a builder
# to bring corpora that have grown too big to minimize in an idle slice back
# under control:
#
#   SAI_POOL_DIR=~/pools/<pool>/corpus FUZZ_MINIMIZE=only fuzz/run.sh
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
	TARGETS="lejp lecp qpack upng jpeg gif lhp lhp-layout hl md svg tokenize jose cose adns h1 h2 ws ws-pmd srv-h1 srv-h2 cli-h1 cli-ws cli-h2 quic"
fi

# UBSan's reports are a line with no stack unless it's asked for one
UBSAN_OPTIONS="${UBSAN_OPTIONS:-print_stacktrace=1}"
export UBSAN_OPTIONS

START=$(date +%s)
IDLE_SECS="${SAI_IDLE_SECS:-}"
case "$IDLE_SECS" in
	''|*[!0-9]*) IDLE_SECS="" ;;
	*) ;;
esac
# least time a target gets in an idle slice, since each run begins by
# replaying the target's whole corpus
IDLE_MIN_TARGET_SECS=120
# time an idle slice keeps back for reporting at the end
IDLE_MARGIN_SECS=30
# time each target's share keeps back for the fuzzer starting and stopping
IDLE_PER_TARGET_OVERHEAD_SECS=10
# how long one input may run before libFuzzer calls it a hang (a timeout-*
# finding); its default of 20 minutes would just use up the slice
IDLE_UNIT_TIMEOUT_SECS=60
# a target with less of its share left than this after minimizing its corpus
# doesn't fuzz this slice, it'd only be replaying its corpus
IDLE_MIN_FUZZ_SECS=30

MINIMIZE="${FUZZ_MINIMIZE:-auto}"
case "$MINIMIZE" in
	auto|only|off) ;;
	*)
		echo "FUZZ_MINIMIZE must be auto, only or off" >&2
		exit 1
		;;
esac
# a corpus smaller than this isn't worth minimizing on a first look
MINIMIZE_MIN_FILES=1000
# a lock left by a minimize that was killed is taken as stale after this
MINIMIZE_STALE_MINS=1440

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

# ws permessage-deflate needs zlib; without it ws-pmd is skipped.  With it,
# http stream compression is on too, so a request asking for gzip has its
# answer go through the coder.

FUZZ_ZLIB="-DLWS_WITHOUT_EXTENSIONS=ON"
if pkg-config --exists zlib 2>/dev/null; then
	FUZZ_ZLIB="-DLWS_WITHOUT_EXTENSIONS=OFF -DLWS_WITH_ZLIB=ON \
		   -DLWS_WITH_HTTP_STREAM_COMPRESSION=ON"
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
	-DLWS_WITH_RANGES=ON \
	-DLWS_WITH_PEER_LIMITS=ON \
	$FUZZ_CMAKE_OPTS

# A bare --parallel is make -j with no limit: every compile at once, which
# with a few fuzz tasks on one builder means hundreds of clangs and the
# builder running out of memory.  Under sai, take the share of the builder
# it gives each task; by hand, the cpus.
JOBS=${SAI_PARALLEL:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}
cmake --build "$BUILD" --parallel "$JOBS"
BUILT=$(date +%s)

mkdir -p "$BUILD/fuzz" "$CORPUS"

# under an idle task, how to stop a target that runs past its share: an
# interrupt, which libFuzzer catches and exits with its final stats
CAP=""
UNIT_TIMEOUT=""

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

	# when the last target must have finished by
	DEADLINE=$(( START + IDLE_SECS - IDLE_MARGIN_SECS ))
	UNIT_TIMEOUT="-timeout=$IDLE_UNIT_TIMEOUT_SECS"

	left=$(( DEADLINE - $(date +%s) ))
	count=$(( left / (IDLE_MIN_TARGET_SECS + IDLE_PER_TARGET_OVERHEAD_SECS) ))
	if [ "$count" -gt "$n" ]; then
		count=$n
	fi
	if [ "$count" -lt 1 ]; then
		echo "idle slice of ${IDLE_SECS}s has no time left after the" \
		     "$(( BUILT - START ))s build"
		exit 0
	fi
	SECS=$(( left / count - IDLE_PER_TARGET_OVERHEAD_SECS ))
	# how many of the chosen targets haven't had their turn yet
	togo=$count

	# whose turn it is, kept with the corpora so it lasts between slices
	next=0
	if [ -r "$CORPUS/.idle-next" ]; then
		read -r next < "$CORPUS/.idle-next" || next=0
		case "$next" in
			''|*[!0-9]*) next=0 ;;
			*) ;;
		esac
	fi
	next=$(( next % n ))

	TARGETS=""
	i=0
	while [ "$i" -lt "$count" ]; do
		k=$(( (next + i) % n + 1 ))
		eval "TARGETS=\"\$TARGETS \${$k}\""
		i=$(( i + 1 ))
	done

	echo "idle slice of ${IDLE_SECS}s: build took $(( BUILT - START ))s," \
	     "about ${SECS}s each for$TARGETS"
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
			*) ;;
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

# the names of the inputs in corpus dir $1, sorted.  Corpus inputs are named
# by the sha1 of their content, by libFuzzer and by the sai pool, which only
# syncs names like that; anything else in there is left alone.
corpus_list() {
	ls "$1" | grep -E '^[0-9a-f]{40}$' | LC_ALL=C sort
}

# whether target $1's corpus should be minimized before it fuzzes
needs_minimize() {
	case "$MINIMIZE" in
	only)
		return 0
		;;
	off)
		return 1
		;;
	*)
		;;
	esac

	have=$(corpus_list "$CORPUS/corpus-$1" | wc -l)
	last=0
	if [ -r "$CORPUS/.minimized-$1" ]; then
		read -r last < "$CORPUS/.minimized-$1" || last=0
		case "$last" in
			''|*[!0-9]*) last=0 ;;
			*) ;;
		esac
	fi

	if [ "$last" -eq 0 ]; then
		[ "$have" -ge "$MINIMIZE_MIN_FILES" ]
		return
	fi

	[ "$have" -gt $(( last * 2 )) ]
}

# Minimize target $1's corpus: libFuzzer's -merge=1 copies into an empty dir
# just the inputs that add coverage, with value profiling as when fuzzing, so
# the progress it counted isn't thrown away.  Then the inputs we listed before
# the merge that it didn't keep are deleted.  Inputs that arrived during the
# merge, from a fuzzer sharing the corpus on this machine or a pool sync, are
# left alone: they weren't judged.  With a pool, the replace marker tells sai
# to drop the same inputs everywhere: everything it had synced up to the
# cursor we read before listing, that isn't in the corpus now.
#
# If the merge doesn't finish, eg, it's stopped at the end of the target's
# share of an idle slice, nothing is changed, but its control file is kept
# with the corpora: it says what coverage each input it got through had, so
# the next try only has to run the rest.  That only holds for the same
# binary, so it's thrown away when the binary changes.  (Hidden names in the
# pool dir aren't synced.)
minimize() {
	cdir="$CORPUS/corpus-$1"
	work="$BUILD/fuzz/minimize-$1"
	lock="$CORPUS/.minimizing-$1"
	control="$CORPUS/.minimize-$1.control"
	mstart=$(date +%s)

	# another task sharing the corpus on this machine may be at it
	find "$CORPUS" -maxdepth 1 -type d -name ".minimizing-$1" \
		-mmin +"$MINIMIZE_STALE_MINS" -exec rmdir {} \; 2>/dev/null || true
	if ! mkdir "$lock" 2>/dev/null; then
		echo "fuzz-$1: corpus is being minimized by another task"
		return 0
	fi

	seq=""
	if [ -n "$SAI_POOL_DIR" ] && [ "$CORPUS" = "$SAI_POOL_DIR" ]; then
		if [ -r "$CORPUS/.sai-pool-seq" ]; then
			read -r seq < "$CORPUS/.sai-pool-seq" || seq=""
		fi
		case "$seq" in
			''|*[!0-9]*)
				echo "fuzz-$1: no pool cursor, not minimizing"
				rmdir "$lock"
				return 0
				;;
			*) ;;
		esac
	fi

	bsum=$(cksum < "$BUILD/bin/fuzz-$1")
	osum=""
	if [ -r "$control.bin" ]; then
		read -r osum < "$control.bin" || osum=""
	fi
	if [ "$bsum" != "$osum" ]; then
		rm -f "$control"
		echo "$bsum" > "$control.bin"
	fi

	rm -rf "$work"
	mkdir -p "$work/new"
	corpus_list "$cdir" > "$work/before"

	# A merge stopped after it had run every input, while it was copying
	# out the ones it keeps, leaves a control file that says it's done:
	# carrying on from that copies nothing, and says so.  Then it has to
	# start again from scratch.
	tries=2
	while [ "$tries" -gt 0 ]; do
		tries=$(( tries - 1 ))
		st=0
		$CAP "$BUILD/bin/fuzz-$1" -merge=1 -use_value_profile=1 \
			-timeout="$IDLE_UNIT_TIMEOUT_SECS" \
			-merge_control_file="$control" \
			"$work/new" "$cdir" > "$work/log" 2>&1 || st=$?
		if [ "$st" -ne 0 ] ||
		   ! grep -aq 'MERGE-OUTER: nothing to do' "$work/log"; then
			break
		fi
		rm -f "$control"
	done

	# only a merge that says it wrote out the inputs it keeps is believed,
	# anything else would have us delete the corpus
	if [ "$st" -eq 0 ] &&
	   ! grep -aqE 'MERGE-OUTER: [0-9]+ new files with' "$work/log"; then
		echo "fuzz-$1: minimizing didn't say what it kept, corpus" \
		     "unchanged"
		rm -rf "$work" "$control" "$control.bin"
		rmdir "$lock"
		return 0
	fi

	if [ "$st" -ne 0 ]; then
		echo "fuzz-$1: minimizing stopped after" \
		     "$(( $(date +%s) - mstart ))s (exit $st), corpus" \
		     "unchanged, it carries on next time"
		rm -rf "$work"
		rmdir "$lock"
		return 0
	fi
	rm -f "$control" "$control.bin"

	corpus_list "$work/new" > "$work/kept"

	# the first input of a corpus always adds coverage, so nothing kept
	# from something means the merge went wrong
	if [ -s "$work/before" ] && [ ! -s "$work/kept" ]; then
		echo "fuzz-$1: minimizing kept nothing, corpus unchanged"
		rm -rf "$work"
		rmdir "$lock"
		return 0
	fi

	# an input kept under a name it didn't have in the corpus goes in
	# first, so nothing that adds coverage is ever missing
	LC_ALL=C comm -13 "$work/before" "$work/kept" |
		while read -r f; do
			[ -e "$cdir/$f" ] || cp "$work/new/$f" "$cdir/$f"
		done
	LC_ALL=C comm -23 "$work/before" "$work/kept" |
		(cd "$cdir" && xargs rm -f)

	if [ -n "$seq" ]; then
		echo "$seq" > "$CORPUS/.tmp-replace-$1"
		mv "$CORPUS/.tmp-replace-$1" "$CORPUS/.sai-replace-corpus-$1"
	fi

	kept=$(wc -l < "$work/kept")
	echo "$kept" > "$CORPUS/.minimized-$1"
	echo "fuzz-$1: minimized $(wc -l < "$work/before") inputs to $kept" \
	     "in $(( $(date +%s) - mstart ))s"
	rm -rf "$work"
	rmdir "$lock"
}

# first corpus dir receives new discoveries, the second is read-only seeds.
# A target with a dictionary of its format's tokens (fuzz-<name>/<name>.dict)
# gets it, so the mutator can splice in whole header names, keywords and
# magic values instead of having to hit on them a byte at a time.  Value
# profiling makes the operands of comparisons count as coverage, so getting
# closer to a magic constant or a length check is progress the fuzzer keeps.
run_target() {
	dict=""
	if [ -r "$REPO/fuzz/fuzz-$1/$1.dict" ]; then
		dict="-dict=$REPO/fuzz/fuzz-$1/$1.dict"
	fi

	$CAP "$BUILD/bin/fuzz-$1" "$CORPUS/corpus-$1" "$REPO/fuzz/fuzz-$1/seeds" \
		-max_total_time="$SECS" \
		-print_final_stats=1 \
		-artifact_prefix="$BUILD/fuzz/" \
		-use_value_profile=1 \
		$dict \
		$UNIT_TIMEOUT \
		$FUZZ_OPTS
}

# how target $1 went, from its exit code $2: being stopped at the end of its
# share isn't a failure, the corpus it built up so far is kept
target_done() {
	took=$(( $(date +%s) - TSTART ))
	case "$2" in
	0)
		;;
	124|137)
		if [ -n "$CAP" ]; then
			echo "fuzz-$1: stopped, it ran past its share of the slice"
		else
			rc=1
		fi
		;;
	*)
		rc=1
		;;
	esac
	if [ -n "$IDLE_SECS" ]; then
		echo "fuzz-$1: took ${took}s"
	fi
}

for t in $TARGETS; do
	bin="$BUILD/bin/fuzz-$t"
	seeds="$REPO/fuzz/fuzz-$t/seeds"

	if [ ! -x "$bin" ]; then
		echo "fuzz-$t: not built (cmake option off?), skipping" >&2
		continue
	fi

	if [ -n "$IDLE_SECS" ]; then
		# share out what's really left between the targets still to
		# go, as many as can each have the least time for a target
		left=$(( DEADLINE - $(date +%s) ))
		fit=$(( left / (IDLE_MIN_TARGET_SECS + \
				IDLE_PER_TARGET_OVERHEAD_SECS) ))
		if [ "$fit" -lt "$togo" ]; then
			togo=$fit
		fi
		if [ "$togo" -lt 1 ]; then
			echo
			echo "idle slice has ${left}s left, too little for" \
			     "fuzz-$t, it goes first next slice"
			break
		fi
		SECS=$(( left / togo - IDLE_PER_TARGET_OVERHEAD_SECS ))
		togo=$(( togo - 1 ))
		if command -v timeout >/dev/null 2>&1; then
			CAP="timeout -s INT -k 15 $(( SECS + \
					IDLE_PER_TARGET_OVERHEAD_SECS ))"
		fi
	fi

	if [ "$MINIMIZE" = only ]; then
		echo
		echo "=== fuzz-$t: minimizing ==="
		mkdir -p "$CORPUS/corpus-$t"
		minimize "$t"
		continue
	fi

	mkdir -p "$CORPUS/corpus-$t"
	if needs_minimize "$t"; then
		echo
		MSTART=$(date +%s)
		minimize "$t"
		if [ -n "$IDLE_SECS" ]; then
			# it came out of this target's share
			SECS=$(( SECS - ($(date +%s) - MSTART) ))
			if [ "$SECS" -lt "$IDLE_MIN_FUZZ_SECS" ]; then
				echo "fuzz-$t: no time left to fuzz this slice"
				next=$(( (next + 1) % n ))
				echo "$next" > "$CORPUS/.idle-next"
				continue
			fi
			if [ -n "$CAP" ]; then
				CAP="timeout -s INT -k 15 $(( SECS + \
					IDLE_PER_TARGET_OVERHEAD_SECS ))"
			fi
		fi
	fi

	echo
	echo "=== fuzz-$t: ${SECS}s ==="
	log="$BUILD/fuzz/log-$t.txt"

	if [ -n "$SAI_POOL_KNOWN" ] && [ -n "$SAI_POOL_FINDINGS" ] &&
	   [ -z "$IDLE_SECS" ]; then
		replay_known "$t"
	fi

	TSTAMP="$BUILD/fuzz/.target-stamp"
	touch "$TSTAMP"
	TSTART=$(date +%s)

	# sai runs build steps in a pty, so under sai with findings going to
	# sai-server, a tty doesn't mean someone is watching: the output is
	# the public task log, and must not get the sanitizer reports
	if [ -t 1 ] && [ -z "$SAI_POOL_FINDINGS" ]; then
		# interactive: live output, plus a copy next to the artifacts
		{ st=0; run_target "$t" || st=$?; echo $st > "$log.rc"; } 2>&1 |
			tee "$log"
		target_done "$t" "$(cat "$log.rc")"
		rm -f "$log.rc"
	else
		# not a terminal (CI log capture): libFuzzer emits each status
		# line as a dozen tiny unbuffered write()s, and collectors that
		# store per-read chunks (sai) count every one against a spew
		# limit; gather the target's output and emit it in one go
		st=0
		run_target "$t" > "$log" 2>&1 || st=$?

		if [ -n "$SAI_POOL_FINDINGS" ]; then
			# the reports go to sai-server; the public log just
			# gets how it went
			grep -aE '^(#[0-9]+[[:space:]]+(INITED|DONE)|Done [0-9]+ runs|stat::)' \
				"$log" || true
		else
			cat "$log"
		fi
		target_done "$t" "$st"
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

	if [ -n "$IDLE_SECS" ]; then
		# it had its turn, the next one goes first next slice
		next=$(( (next + 1) % n ))
		echo "$next" > "$CORPUS/.idle-next"
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

if [ -n "$IDLE_SECS" ]; then
	echo "idle slice: used $(( $(date +%s) - START ))s of ${IDLE_SECS}s"
fi

if [ -n "$IDLE_SECS" ] && [ -n "$SAI_POOL_FINDINGS" ]; then
	# an idle task has reported what it found, it carries on next slice
	rc=0
fi

exit $rc
