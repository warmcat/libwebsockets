#!/bin/sh

echo "lwstest script stdout"
>&2 echo "lwstest script stderr"

echo "REQUEST_METHOD=$REQUEST_METHOD"

if [ "$REQUEST_METHOD" = "POST" ] ; then
	read line
	echo "read=\"$line\""
else
	cat /proc/meminfo
fi

echo "done"

exit 0

