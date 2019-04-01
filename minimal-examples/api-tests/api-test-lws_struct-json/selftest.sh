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

COUNT_TESTS=1

dotest $1 $2 apiselftest
exit $FAILS
