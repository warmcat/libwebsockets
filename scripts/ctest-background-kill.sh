#!/bin/bash
#
# $SAI_INSTANCE_IDX - which instance of sai, 0+
# $1  - background fixture name, unique within test space, like "multipostlocalsrv"
# $2  - executable
# $3+ - args

echo "$0 $1 $2 $3 $4" >> /tmp/ctklog

J=`basename $2`.$1.$SAI_INSTANCE_IDX
PI=`cat /tmp/sai-ctest-$J`
echo "Stage 1 kill $J 'kill $PI'" >> /tmp/ctklog

#
# We expect our background process to still be around
#

set +e
set +E
kill -0 $PI 2>&1 >> /tmp/ctklog
GONESKI=$?

if [ $GONESKI -eq 0 ] ; then
	kill $PI 2>&1 >> /tmp/ctklog
	kill -9 $PI 2>&1 >> /tmp/ctklog

	kill -0 $PI 2>&1
	if [ $? -eq 0 ] ; then
		#
		# but in case it isn't enough, use ps to find the same executable started on the same port
		# and kill that
		#
		A1=$3
		if [ -z "$A1" ] ; then
			A1=$2
		fi
		A2=$4
		if [ -z "$A2" ] ; then
			A2=$2
		fi

		# sed is there to match up bsd/osx ps with linux
		KL=`ps -Af | grep -v ctest-background-kill | grep -v grep | grep $2 | grep $A1 | grep $A2 | tr -s ' ' | sed "s/^\ //g" | cut -d' ' -f2`
		if [ ! -z "$KL" ] ; then
			echo "Stage 2 kill $J 'kill $KL'" >> /tmp/ctklog
			kill $KL 2>&1 >> /tmp/ctklog
		fi
	fi
else
	echo "Process already dead" >> /tmp/ctklog
fi

exit $GONESKI

