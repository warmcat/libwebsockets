#/bin/bash
#
# run this from your build dir having configured
# -DLWS_WITH_MINIMAL_EXAMPLES=1 to get all the examples
# that apply built into ./bin
#
# Eg,
#
# build $ ../minimal-examples/selftests.sh

echo
echo "----------------------------------------------"
echo "-------   tests: lws minimal example selftests"
echo

LOGGING_PATH=/tmp/logs

# for mebedtls, we need the CA certs in ./build where we run from

cp ../minimal-examples/http-client/minimal-http-client-multi/warmcat.com.cer .
cp ../minimal-examples/http-client/minimal-http-client-post/libwebsockets.org.cer .

MINEX=`dirname $0`
MINEX=`realpath $MINEX`
TESTS=0
for i in `find $MINEX -name selftest.sh` ; do
	C=`cat $i | grep COUNT_TESTS= | cut -d= -f2`
	TESTS=$(( $TESTS + $C ))
done

FAILS=0
WH=1

for i in `find $MINEX -name selftest.sh` ; do
	C=`cat $i | grep COUNT_TESTS= | cut -d= -f2`
	sh $i `pwd`/bin $LOGGING_PATH $WH $TESTS $MINEX
	FAILS=$(( $FAILS + $? ))

	L=`ps fax | grep lws- | cut -d' ' -f2`
	kill $L 2>/dev/null
	kill -9 $L 2>/dev/null
	wait $L 2>/dev/null

	WH=$(( $WH + $C ))
done

if [ $FAILS -eq 0 ] ; then
	echo "All $TESTS passed"
	exit 0
else
	echo "Failed: $FAILS / $TESTS"
	exit 1
fi


