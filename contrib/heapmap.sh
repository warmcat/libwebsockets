#!/bin/sh
#
# Pass the the scraped compressed alloc metadata on stdin.
#
# $1 is the path to the elf file with the debugging info.
# $2 is the path to lws-api-test-backtrace, may be omitted if it's on the path
#
# Eg,
#
# cat /tmp/mydump |  ../../../../../contrib/heapmap.sh build/myapp.elf ../../../../../build/bin/

echo -n 0 > /tmp/_total_size

while read line ; do
	X=`echo -n $line | "$2"lws-api-test-backtrace 2>/dev/null`
	if [ "$X" != "" ] ; then
		S=`echo -n $X | cut -d' ' -f2 | sed "s/\,//g"`
		T=`cat /tmp/_total_size`
		echo -n $(( $T + $S )) > /tmp/_total_size
		echo "$S"
		addr2line -f -p -e $1 `echo $X | cut -d',' -f2-`
		echo
	fi
done

T=`cat /tmp/_total_size`

echo 
echo "# Total instrumented allocation $T"
