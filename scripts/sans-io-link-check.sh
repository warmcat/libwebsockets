#!/usr/bin/env bash
#
# sans-io-link-check.sh: the link-level counterpart of sans-io-check.sh (see
# READMEs/README.sans-io-split.md).  That compiles the sansIO sources with
# IO's private prototypes hidden, so it cannot see a call to an IO function
# that is also declared in a header both halves include.  This looks at what
# the built objects actually reference: every symbol the sansIO objects need
# that only an IO object defines, and is neither public api (declared under
# include/) nor in the seam (lib/sansio/private-lib-sansio-seam.h).
#
# Usage: scripts/sans-io-link-check.sh <build-dir> [-v]
#
# -v also lists the public and seam symbols sansIO takes from IO.
# Needs nm.  Exit 0 when nothing private is referenced.

cd "$(dirname "$0")/.." || exit 1
B=${1:?build dir}
OBJ=$B/lib/CMakeFiles/websockets.dir
[ -d "$OBJ" ] || OBJ=$B/lib/CMakeFiles/websockets_shared.dir
[ -d "$OBJ" ] || { echo "no library objects under $B/lib/CMakeFiles"; exit 2; }

# the halves, by directory, as the README places them: lib/sansio, and
# lib/io with the other directories that are IO's
SANSIO='\.dir/sansio/'
IO='\.dir/(io|plat|tls|event-libs|system/async-dns)/'
# the generic crypto in lib/tls is not the transport's: neither half's
NEITHER='/tls/(.*/)?lws-gen|/tls/(chacha|poly1305)\.c\.o'

T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

find "$OBJ" -name '*.o' | grep -E "$SANSIO" > "$T/s.lst"
find "$OBJ" -name '*.o' | grep -E "$IO" | grep -vE "$NEITHER" > "$T/io.lst"

xargs nm -g --defined-only < "$T/io.lst" 2>/dev/null | awk 'NF==3{print $3}' | sort -u > "$T/io.def"
xargs nm -g --defined-only < "$T/s.lst" 2>/dev/null | awk 'NF==3{print $3}' | sort -u > "$T/s.def"
while read -r o; do
	nm -u "$o" | awk -v f="${o#"$OBJ"/}" '{sub(/\.o$/, "", f); print $NF, f}'
done < "$T/s.lst" | sort -u > "$T/uses"

awk '{print $1}' "$T/uses" | sort -u | comm -23 - "$T/s.def" | comm -12 - "$T/io.def" > "$T/fromio"

grep -ohE '\b[_a-z][a-z0-9_]*\b' lib/sansio/private-lib-sansio-seam.h | sort -u > "$T/seam"
P=0; S=0; N=0
: > "$T/priv"
while read -r s; do
	if grep -qx "$s" "$T/seam"; then
		S=$((S + 1)); [ "$2" = "-v" ] && echo "seam    $s"
	elif grep -rqwE "$s" include/; then
		P=$((P + 1)); [ "$2" = "-v" ] && echo "public  $s"
	else
		N=$((N + 1)); echo "$s" >> "$T/priv"
	fi
done < "$T/fromio"

while read -r s; do
	printf '%-44s %s\n' "$s" "$(awk -v s="$s" '$1 == s {printf "%s ", $2}' "$T/uses")"
done < "$T/priv"

echo "sansIO -> IO symbols: $N private, $S seam, $P public"
[ "$N" -eq 0 ]
