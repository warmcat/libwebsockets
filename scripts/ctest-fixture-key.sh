#
# Sourced by ctest-background.sh and ctest-background-kill.sh: where a
# fixture's pid and log files live, and what they are called.
#
# The same test can run in several build trees on one box at once (Sai
# allows several builds per builder), so the files are keyed by the build
# tree, not just by the fixture's name: they live under the build tree's
# Testing/fixtures/.  The start and kill steps of a fixture do not share a
# working directory (the start of a tls server often runs in the example's
# source directory, for its certificates; the kill runs in the build tree),
# so the tree is found from the executable's path when the command names
# one, else by walking up from the working directory to the CMakeCache.txt.
#
# in:  $FIXTURE_NAME, $FIXTURE_EXE (basename), $SAI_INSTANCE_IDX, "$@" (the
#      fixture command)
# out: $FIX_PID, $FIX_LOG

lws_fixture_tree_from() {
	local d="$1"
	while [ -n "$d" ] && [ "$d" != "/" ] && [ "$d" != "." ]; do
		if [ -f "$d/CMakeCache.txt" ]; then
			echo "$d"
			return 0
		fi
		d=$(dirname "$d")
	done
	return 1
}

FIX_TREE=""
for arg in "$@"; do
	case "$arg" in
	*/*)
		if [ -f "$arg" ]; then
			FIX_TREE=$(lws_fixture_tree_from "$(cd "$(dirname "$arg")" && pwd)")
			[ -n "$FIX_TREE" ] && break
		fi
		;;
	esac
done
[ -z "$FIX_TREE" ] && FIX_TREE=$(lws_fixture_tree_from "$(pwd)")

J=$FIXTURE_EXE.$FIXTURE_NAME.$SAI_INSTANCE_IDX

if [ -n "$FIX_TREE" ]; then
	mkdir -p "$FIX_TREE/Testing/fixtures"
	FIX_PID="$FIX_TREE/Testing/fixtures/$J.pid"
	FIX_LOG="$FIX_TREE/Testing/fixtures/$J.log"
else
	echo "$0: no build tree found for fixture $J, using /tmp" >&2
	FIX_PID="/tmp/sai-ctest-$J"
	FIX_LOG="/tmp/ctest-background-$J"
fi
