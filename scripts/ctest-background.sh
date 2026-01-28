#!/bin/bash
#
# $SAI_LIST_PORT - optional, if present the ipv4 port number to wait on existing
# $SAI_INSTANCE_IDX - which instance of sai, 0+
# $1 - background fixture name, unique within test space, like "multipostlocalserver"
# $2 - executable
# $3+ - args

J=`basename $2`.$1.$SAI_INSTANCE_IDX
$2 $3 $4 $5 $6 $7 $8 $9 2>/tmp/ctest-background-$J 1>/dev/null 0</dev/null &
echo $! > /tmp/sai-ctest-$J

# really we want to loop until the listen port is up
# on, eg, rpi it can be blocked at sd card and slow to start
# due to parallel tests and disc cache flush

# echo "runscript SAI_LIST_PORT ${SAI_LIST_PORT}" > /tmp/q

if [ -z "${SAI_LIST_PORT}" ] ; then

	if [ ! -z "`echo $2 | grep valgrind`" ] ; then
		sleep 5
	else
		sleep 1
	fi
else
	if [ "${VENDOR}" = "apple" ] ; then
		while [ -z "`lsof -iTCP -sTCP:LISTEN -P -n | grep -- ':${SAI_LIST_PORT}'`" ] ; do
			sleep 0.5
		done
	else
		CNT=0
		while [ -z "`netstat -ltun4 | tr -s ' ' | grep ":${SAI_LIST_PORT} "`" ] ; do
			if ! kill -0 $! 2>/dev/null ; then
				echo "Background process died while waiting for port ${SAI_LIST_PORT}" >&2
				echo "Background process logs:" >&2
				cat /tmp/ctest-background-$J >&2
				exit 1
			fi
			if [ $CNT -gt 60 ] ; then
				echo "Timed out waiting for port ${SAI_LIST_PORT}" >&2
				echo "Background process state:" >&2
				ps -fp $! >&2
				echo "Background process logs:" >&2
				cat /tmp/ctest-background-$J >&2
				echo "Netstat output:" >&2
				netstat -ltun4 >&2
				exit 1
			fi
			if [ $((CNT % 10)) -eq 0 ] ; then
				echo "Waiting for port ${SAI_LIST_PORT}..." >&2
			fi
			CNT=$((CNT + 1))
			sleep 0.5
		done
	fi

	sleep 1
fi

exit 0

