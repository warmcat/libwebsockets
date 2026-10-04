#!/bin/sh
#
# Which rows of the wsi state machine event table were never fired
#
# Build with -DLWS_WITH_STATE_TRACE=ON, then
#
#   rm -f /tmp/t ; LWS_STATE_TRACE_FILE=/tmp/t ctest
#   scripts/state-row-coverage.sh /tmp/t
#
# Each process appends an LRSROW line the first time it fires a row of
# lws_wsi_event_edges[] in lib/sansio/wsi-state.c, naming the row by its
# source line.  This prints every row no LRSROW line names, as
# file:line: role side from event, then the rows fired out of the rows
# present, per row role.  The trace must come from a build of the same
# wsi-state.c, since the rows are known by their line numbers.
#
# Usage: state-row-coverage.sh <trace file> [<trace file>...]
#
# $LWS_WSI_STATE_C overrides the table source, by default the one in the
# tree this script is in.

if [ $# -lt 1 ] ; then
	echo "Usage: $0 <trace file> [<trace file>...]" >&2
	exit 1
fi

SRC=${LWS_WSI_STATE_C:-$(dirname "$0")/../lib/sansio/wsi-state.c}

if [ ! -r "$SRC" ] ; then
	echo "$0: can't read $SRC" >&2
	exit 1
fi

for t in "$@" ; do
	if [ ! -r "$t" ] ; then
		echo "$0: can't read $t" >&2
		exit 1
	fi
done

# the table's rows first, then the trace files' LRSROW lines

awk -v src="$SRC" -v name="$(basename "$SRC")" '
FNR == 1 { file++ }

file == 1 && /^\tR\(/ {
	s = $0
	sub(/^\tR\(/, "", s)
	n = split(s, f, ",")
	if (n < 7)
		next
	for (i = 1; i <= 4; i++) {
		gsub(/[ \t"]/, "", f[i])
	}
	sub(/^LRS_/, "", f[3])
	sub(/^LWS_WSIEV_/, "", f[4])
	row[FNR] = f[1] " " f[2] " " f[3] " " f[4]
	role[FNR] = f[1]
	rows++
	next
}

file > 1 && $1 == "LRSROW" {
	if (!($2 in row)) {
		if (!($2 in stale))
			stale[$2] = $0
		next
	}
	fired[$2] = 1
}

END {
	if (!rows) {
		print "no event table rows found in " src > "/dev/stderr"
		exit 1
	}

	for (l in stale)
		print "warning: " name ":" l " is not a row; " \
		      "trace from a different wsi-state.c?" > "/dev/stderr"

	for (l in row) {
		tot[role[l]]++
		if (l in fired)
			hit[role[l]]++
		else
			unfired[l] = 1
	}

	cmd = "sort -n | cut -f2-"
	for (l in unfired)
		printf "%d\t%s:%d: %s\n", l, name, l, row[l] | cmd
	close(cmd)

	print ""
	printf "%-12s %6s %6s %6s\n", "role", "fired", "rows", "unfired"
	cmd = "sort"
	for (r in tot) {
		printf "%-12s %6d %6d %6d\n", r, hit[r], tot[r],
		       tot[r] - hit[r] | cmd
		all += tot[r]
		allhit += hit[r]
	}
	close(cmd)
	printf "%-12s %6d %6d %6d\n", "total", allhit, all, all - allhit
}
' "$SRC" "$@"
