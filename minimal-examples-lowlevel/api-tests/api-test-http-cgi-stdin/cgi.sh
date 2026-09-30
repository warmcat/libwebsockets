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

case "$PATH_INFO" in
nohdr)
	exit 0 ;;
big)
	printf 'content-type: text/plain\r\n'
	printf 'content-length: 32768\r\n'
	printf '\r\n'
	dd if=/dev/zero bs=1024 count=32 2>/dev/null | tr '\000' x
	exit 0 ;;
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
