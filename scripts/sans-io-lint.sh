#!/usr/bin/env bash
#
# sans-io-lint.sh: count the places where sansIO code names something that
# belongs to IO.  See READMEs/README.sans-io-split.md for the rule.
#
# The sansIO directories and files are listed below, from that document.
# The forbidden identifiers are its corollary: a socket or fd, a poll flag,
# a TLS library object, an event-loop handle.
#
# Usage: scripts/sans-io-lint.sh [--update]
#
# Prints the count per file and the total, and compares the total with
# scripts/sans-io-lint.baseline: more than the baseline fails.  --update
# writes the current total as the new baseline, for when a step of the
# split has brought it down.

cd "$(dirname "$0")/.." || exit 1

SANSIO="lib/roles \
	lib/core-net/wsi.c lib/core-net/wsi-state.c lib/core-net/close.c \
	lib/core-net/state.c lib/core-net/vhost.c lib/core-net/socks5-client.c \
	lib/core-net/dummy-callback.c"

# one alternation, extended regex
FORBIDDEN='desc\.sockfd|\bsend\(|\brecv\(|\bsendto\(|\brecvfrom\(|\bpollfd\b|\brevents\b|\bLWS_POLL(IN|OUT|HUP)\b|\bSSL_[A-Za-z_]+\(|\bgnutls_[a-z_]+\(|\bmbedtls_[a-z_]+\(|\bbr_ssl_[a-z_]+\(|\bwolfSSL_[A-Za-z_]+\(|\buv_[a-z_]+\(|\bev_io_[a-z_]+\(|\bevent_base_[a-z_]+\(|\bg_main_[a-z_]+\(|\bsd_event_[a-z_]+\('

BASELINE_FILE=scripts/sans-io-lint.baseline

TOTAL=0
while read -r f n; do
	[ -z "$f" ] && continue
	printf '%6d %s\n' "$n" "$f"
	TOTAL=$((TOTAL + n))
done < <(grep -rEc "$FORBIDDEN" --include='*.c' --include='*.h' $SANSIO 2>/dev/null |
	 awk -F: '$2 > 0 { print $1, $2 }' | sort -k2 -n -r)

echo "total $TOTAL"

if [ "$1" = "--update" ]; then
	echo "$TOTAL" > $BASELINE_FILE
	echo "baseline updated"
	exit 0
fi

if [ -f $BASELINE_FILE ]; then
	B=$(cat $BASELINE_FILE)
	if [ "$TOTAL" -gt "$B" ]; then
		echo "FAIL: $TOTAL IO references in sansIO code, baseline $B"
		exit 1
	fi
	echo "ok: baseline $B"
fi

exit 0
