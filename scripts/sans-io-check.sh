#!/usr/bin/env bash
#
# sans-io-check.sh: compile the sansIO sources with the IO half's private
# prototypes hidden (LWS_SANSIO_CHECK), so every place sansIO code calls into
# IO past the seam (lib/core-net/private-lib-sansio-seam.h, the requests in
# their private spellings) fails to compile and names its line.  See
# READMEs/README.sans-io-split.md.
#
# Usage: scripts/sans-io-check.sh <build-dir-with-compile_commands.json> [-v]
#
# -v also prints every offending line, as file:line: callee.
#
# The build dir needs CMAKE_EXPORT_COMPILE_COMMANDS=1.  Prints each error
# once per callee, then the count of distinct callees and of error lines.
# Exit 0 when clean.

cd "$(dirname "$0")/.." || exit 1
B=${1:?build dir}
CC=$B/compile_commands.json
[ -f "$CC" ] || { echo "no $CC (configure with -DCMAKE_EXPORT_COMPILE_COMMANDS=1)"; exit 2; }

# the sansIO sources, as scripts/sans-io-lint.sh lists them
FILTER='/lib/roles/(h1|h2|h3|http|ws|wt|quic|mqtt|raw-skt|raw-proxy)/|/lib/core-net/(wsi|wsi-state|close|state|vhost|socks5-client|dummy-callback)\.c'

LOG=$(mktemp)
python3 - "$CC" "$FILTER" <<'PY' | while IFS= read -r cmd; do
import json, re, sys, shlex
cc = json.load(open(sys.argv[1])); flt = re.compile(sys.argv[2])
seen = set()
for e in cc:
    f = e["file"]
    if not flt.search(f) or f in seen: continue
    seen.add(f)
    args = e.get("arguments") or shlex.split(e["command"])
    out = []
    skip = False
    for a in args:
        if skip: skip = False; continue
        if a == "-o": skip = True; continue
        if a.startswith("-o") and len(a) > 2 and not a.startswith("-O"): continue
        if a in ("-c",): continue
        out.append(a)
    out += ["-fsyntax-only", "-DLWS_SANSIO_CHECK", "-Wno-unused-function", "-Wno-error"]
    print(" ".join(shlex.quote(a) for a in out) + " ; cd " + shlex.quote(e["directory"]))
PY
	( eval "${cmd##*; cd }" 2>/dev/null; cd "$(echo "$cmd" | sed 's/.*; cd //' | tr -d "'")" && eval "${cmd%% ; cd *}" ) 2>&1 | grep -E 'error:' >> "$LOG"
done

if [ "$2" = "-v" ]; then
	sed -nE "s#^$(pwd)/(.*): error: (implicit declaration of function|call to undeclared function) ['‘]([a-z_0-9]+)['’].*#\1: \3#p" "$LOG" | sort
	echo
fi
sed -E "s/.*error: (implicit declaration of function|call to undeclared function) ['‘]([a-z_0-9]+)['’].*/\2/" "$LOG" | grep -E '^[a-z_0-9]+$' | sort | uniq -c | sort -rn
N=$(sed -E "s/.*error: (implicit declaration of function|call to undeclared function) ['‘]([a-z_0-9]+)['’].*/\2/" "$LOG" | grep -cE '^[a-z_0-9]+$')
D=$(sed -E "s/.*error: (implicit declaration of function|call to undeclared function) ['‘]([a-z_0-9]+)['’].*/\2/" "$LOG" | grep -E '^[a-z_0-9]+$' | sort -u | wc -l)
O=$(grep -vE "implicit declaration of function|call to undeclared function" "$LOG" | wc -l)
echo "sansIO -> IO calls: $N lines, $D distinct callees; other errors: $O"
[ "$O" -gt 0 ] && grep -vE "implicit declaration of function|call to undeclared function" "$LOG" | sort | uniq -c | sort -rn | head -20
rm -f "$LOG"
[ "$N" -eq 0 ] && [ "$O" -eq 0 ]
