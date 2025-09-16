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
               while [ -z "`netstat -an | grep LISTEN | tr -s ' ' | cut -d' ' -f4| grep "\.${SAI_LIST_PORT}\$"`" ] ; do
                       sleep 0.5
               done
       else
               while [ -z "`netstat -ltn4 | grep LISTEN | tr -s ' ' | grep ":${SAI_LIST_PORT}\ "`" ] ; do
                       sleep 0.5
               done
       fi

	sleep 1
fi

exit 0

