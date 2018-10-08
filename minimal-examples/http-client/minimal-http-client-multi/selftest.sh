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

COUNT_TESTS=16

dotest $1 $2 warmcat
dotest $1 $2 warmcat-pipe -p
dotest $1 $2 warmcat-h1 --h1
dotest $1 $2 warmcat-h1-pipe --h1 -p
dotest $1 $2 warmcat-stag -s
dotest $1 $2 warmcat-pipe-stag -p -s
dotest $1 $2 warmcat-h1-stag --h1 -s
dotest $1 $2 warmcat-h1-pipe-stag --h1 -p -s

spawn "" $5/http-server/minimal-http-server-tls $1/lws-minimal-http-server-tls
dotest $1 $2 localhost -l
spawn $SPID $5/http-server/minimal-http-server-tls $1/lws-minimal-http-server-tls
dotest $1 $2 localhost-pipe -l -p
spawn $SPID $5/http-server/minimal-http-server-tls $1/lws-minimal-http-server-tls
dotest $1 $2 localhost-h1 -l --h1
spawn $SPID $5/http-server/minimal-http-server-tls $1/lws-minimal-http-server-tls
dotest $1 $2 localhost-h1-pipe -l --h1 -p
spawn $SPID $5/http-server/minimal-http-server-tls $1/lws-minimal-http-server-tls
dotest $1 $2 localhost-stag -l -s
spawn $SPID $5/http-server/minimal-http-server-tls $1/lws-minimal-http-server-tls
dotest $1 $2 localhost-pipe-stag -l -p -s
spawn $SPID $5/http-server/minimal-http-server-tls $1/lws-minimal-http-server-tls
dotest $1 $2 localhost-h1-stag -l --h1 -s
spawn $SPID $5/http-server/minimal-http-server-tls $1/lws-minimal-http-server-tls
dotest $1 $2 localhost-h1-pipe-stag -l --h1 -p -s

kill $SPID 2>/dev/null
wait $SPID 2>/dev/null
exit $FAILS

