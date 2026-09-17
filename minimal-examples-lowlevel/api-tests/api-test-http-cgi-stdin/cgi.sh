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

n=$(wc -c | tr -d ' \t\r\n')
b="bytes=$n
stamp=$HTTP_X_TEST_STAMP"

printf 'content-type: text/plain\r\n'
printf 'content-length: %d\r\n' "$(( ${#b} + 1 ))"
printf '\r\n'
printf '%s\n' "$b"
