#!/bin/sh
#
# lws-api-test-http-cgi-stdin helper
#
# Counts the bytes arriving on stdin and answers with a tiny body of the
# form "bytes=<count>\n", so the test client can check the CGI received
# the complete POST body intact.

n=$(wc -c | tr -d ' \t\r\n')
b="bytes=$n"

printf 'content-type: text/plain\r\n'
printf 'content-length: %d\r\n' "$(( ${#b} + 1 ))"
printf '\r\n'
printf '%s\n' "$b"
