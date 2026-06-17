#!/usr/bin/env bash
#
# $SAI_INSTANCE_IDX - which instance of sai, 0+
# $1  - background fixture name, unique within test space, like "multipostlocalsrv"
# $2  - executable
# $3+ - args

echo "$0 $1 $2 $3 $4"

J=`basename $2`.$1.$SAI_INSTANCE_IDX
PI=`cat /tmp/sai-ctest-$J`

#
# We expect our background process to initially still be around
#

kill -0 $PI
GONESKI=$?

echo "Background task $PI: $J"

if [ $GONESKI -eq 1 ] ; then
	echo "Background Process $PI unexpectedly dead already, their log"
	cat /tmp/ctest-background-$J
	exit 1
fi

echo "Background task $PI: $J logs before kill:"
cat /tmp/ctest-background-$J

echo "Trying SIGTERM..."

get_descendants() {
        local pid=$1
        local pids=""
        if command -v pgrep >/dev/null 2>&1; then
                local children=`pgrep -P $pid`
                for child in $children; do
                        pids="$pids $child `get_descendants $child`"
                done
        fi
        echo $pids
}

CPIDS=`get_descendants $PI`
ALL_PIDS="$PI $CPIDS"

kill $PI 2>/dev/null
for i in $CPIDS ; do
        kill $i 2>/dev/null
done

#
# 100ms intervals, 100 = 10s
# need to allow time for valgrind case
#
BUDGET=100
while [ $BUDGET -ne 0 ] ; do
        sleep 0.1
        STILL_ALIVE=0
        for i in $ALL_PIDS ; do
                if kill -0 $i 2>/dev/null ; then
                        STILL_ALIVE=1
                        break
                fi
        done
        if [ $STILL_ALIVE -eq 0 ] ; then
                echo "Went down OK"
                exit 0
        fi
        BUDGET=$(( $BUDGET - 1 ))
done

echo "Trying SIGKILL..."

kill -9 $PI 2>/dev/null
for i in $CPIDS ; do
        kill -9 $i 2>/dev/null
done

#
# 100ms intervals, 100 = 10s
# need to allow time for valgrind case
#
BUDGET=20
while [ $BUDGET -ne 0 ] ; do
        sleep 0.1
        STILL_ALIVE=0
        for i in $ALL_PIDS ; do
                if kill -0 $i 2>/dev/null ; then
                        STILL_ALIVE=1
                        break
                fi
        done
        if [ $STILL_ALIVE -eq 0 ] ; then
                echo "Went down OK after SIGKILL"
                exit 0
        fi
        BUDGET=$(( $BUDGET - 1 ))
done

echo "Couldn't kill it"
exit 1
