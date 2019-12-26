#!/bin/bash
#
# $1: path to minimal example binaries...
#     if lws is built with -DLWS_WITH_MINIMAL_EXAMPLES=1
#     that will be ./bin from your build dir
#
# $2: path for logs and results.  The results will go
#     in a subdir named after the directory this script
#     is in
#
# $3: offset for test index count
#
# $4: total test count
#
# $5: path to ./minimal-examples dir in lws
#
# Test return code 0: OK, 254: timed out, other: error indication

. $5/selftests-library.sh

COUNT_TESTS=4

dotest $1 $2 warmcat
dotest $1 $2 warmcat-h1 --h1

spawn "" $5/http-server/minimal-http-server-tls $1/lws-minimal-http-server-tls
dotest $1 $2 localhost -l
spawn $SPID $5/http-server/minimal-http-server-tls $1/lws-minimal-http-server-tls
dotest $1 $2 localhost-h1 -l --h1

kill $SPID 2>/dev/null
wait $SPID 2>/dev/null
exit $FAILS
