#!/bin/bash
#
# $1: path to minimal example binaries...
#     if lws is built with -DLWS_WITH_MINIMAL_EXAMPLES=1
#     that will be ./bin from your build dir
#
# $2: path for logs and results.  The results will go
#     in a subdir named after the directory this script
#     is in

if [ -z "$1" -o -z "$2" ] ; then
	echo "required args missing"
	exit 1
fi

MYTEST=`echo $0 | sed "s/\/[^\/]*\$//g" |sed "s/.*\///g"`
mkdir -p $2/$MYTEST
rm -f $2/$MYTEST/*.log $2/$MYTEST/*.result
$1/lws-$MYTEST > $2/$MYTEST/1.log 2> $2/$MYTEST/1.log
echo $? > $2/$MYTEST/1.result

exit 0

