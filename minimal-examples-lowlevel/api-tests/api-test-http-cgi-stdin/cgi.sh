#!/bin/sh
#
# lws-api-test-http-cgi-stdin helper
#
# Counts the bytes arriving on stdin and answers with a tiny body of the
# form "bytes=<count>\n", so the test client can check the CGI received
# the complete POST body intact.

#
# The second line reports what a mount interceptor stamped on the request,
# as lws exports it to the CGI env (HTTP_ + the header name, RFC 3875
# style), so the test can check the stamped value got here and the
# client's own attempt at the same header did not.
#
# The third line is the QUERY_STRING as lws exported it, and the fourth the
# CONTENT_LENGTH.

# Some paths ask for a script that misbehaves instead:
#
#  /nohdr: exits without writing anything, not even its headers
#  /big:   answers with 32KB of 'x', and is gone before much of that can
#          have been sent on
#  /nolen: answers with no content-length, so its end is the script's exit
#  /linger: sends its headers and then takes its time, longer than its
#          client is going to wait for it
#  /linger-stubborn: the same, but ignoring SIGTERM, as the sleep it runs
#          then does too

case "$PATH_INFO" in
nohdr)
	exit 0 ;;
linger|linger-stubborn)
	if [ "$PATH_INFO" = linger-stubborn ]; then
		trap '' TERM
	fi
	printf 'content-type: text/plain\r\n'
	printf '\r\n'
	printf 'lingering\n'
	sleep 30
	exit 0 ;;
nolen)
	printf 'content-type: text/plain\r\n'
	printf '\r\n'
	printf 'no content-length here\n'
	exit 0 ;;
big)
	printf 'content-type: text/plain\r\n'
	printf 'content-length: 32768\r\n'
	printf '\r\n'
	dd if=/dev/zero bs=1024 count=32 2>/dev/null | tr '\000' x
	exit 0 ;;
*)
	# everything else is answered below
	;;
esac

# A request without a body has nothing on stdin to count.

case "$REQUEST_METHOD" in
GET|HEAD)
	n=0 ;;
*)
	n=$(wc -c | tr -d ' \t\r\n') ;;
esac
b="bytes=$n
stamp=$HTTP_X_TEST_STAMP
qs=$QUERY_STRING
clen=$CONTENT_LENGTH"

printf 'content-type: text/plain\r\n'
printf 'content-length: %d\r\n' "$(( ${#b} + 1 ))"
printf '\r\n'
printf '%s\n' "$b"
