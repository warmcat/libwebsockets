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

FAILS=0

#
# let's make an index with just Dorian first
#
dotest $1 $2 apitest -c -i /tmp/lws-fts-dorian.index \
    "../minimal-examples/api-tests/api-test-fts/the-picture-of-dorian-gray.txt"

# and let's hear about autocompletes for "b"

dotest $1 $2 apitest -i /tmp/lws-fts-dorian.index b
cat $2/api-test-fts/apitest.log | cut -d' ' -f5- > /tmp/fts1
diff -urN /tmp/fts1 "../minimal-examples/api-tests/api-test-fts/canned-1.txt"
if [ $? -ne 0 ] ; then
	echo "Test 1 failed"
	FAILS=$(( $FAILS + 1 ))
fi

#
# let's make an index with Dorian + Les Mis in French (ie, UTF-8) as well
#
dotest $1 $2 apitest -c -i /tmp/lws-fts-both.index \
   "../minimal-examples/api-tests/api-test-fts/the-picture-of-dorian-gray.txt" \
   "../minimal-examples/api-tests/api-test-fts/les-mis-utf8.txt"

# and let's hear about "help", which appears in both

dotest $1 $2 apitest -i /tmp/lws-fts-both.index -f -l help
cat $2/api-test-fts/apitest.log | cut -d' ' -f5- > /tmp/fts2
diff -urN /tmp/fts2 "../minimal-examples/api-tests/api-test-fts/canned-2.txt"
if [ $? -ne 0 ] ; then
	echo "Test 1 failed"
	FAILS=$(( $FAILS + 1 ))
fi

exit $FAILS
