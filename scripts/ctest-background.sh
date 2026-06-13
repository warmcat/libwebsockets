#!/bin/bash
#
# $SAI_LIST_PORT - optional, if present the ipv4 port number to wait on existing
# $SAI_INSTANCE_IDX - which instance of sai, 0+
# $1 - background fixture name, unique within test space, like "multipostlocalserver"
# $2 - executable
# $3+ - args

J=`basename $2`.$1.$SAI_INSTANCE_IDX

EXE_PATH=""
for arg in "$@"; do
    if [[ "$arg" == *"test-server"* ]] || [[ "$arg" == *"minimal-"* ]]; then
        if [ -f "$arg" ]; then
            EXE_PATH="$arg"
            break
        fi
    fi
done

if [ ! -z "$EXE_PATH" ]; then
    BIN_DIR=`dirname "$EXE_PATH"`
    BUILD_DIR=`dirname "$BIN_DIR"`
    export LD_LIBRARY_PATH="$BUILD_DIR/lib:$LD_LIBRARY_PATH"
fi

# We shift off $1 (the background fixture name) so that "$@" contains only the executable and its args.
shift

"$@" -d1039 2>/tmp/ctest-background-$J 1>/dev/null 0</dev/null &
echo $! > /tmp/sai-ctest-$J

# really we want to loop until the listen port is up
# on, eg, rpi it can be blocked at sd card and slow to start
# due to parallel tests and disc cache flush

# echo "runscript SAI_LIST_PORT ${SAI_LIST_PORT}" > /tmp/q

if [ -z "${SAI_LIST_PORT}" ] ; then

	if [ ! -z "`echo "$1" | grep valgrind`" ] ; then
		sleep 15
	else
		sleep 1
	fi
else
	if [ "`uname -s`" = "Darwin" ] || [ "${VENDOR}" = "apple" ] ; then
		CNT=0
		while true ; do
			if [ -n "$SAI_LIST_IS_UDP" ] ; then
				lsof -P -n -iUDP:${SAI_LIST_PORT} >/dev/null 2>/dev/null && break
			else
				lsof -P -n -iTCP:${SAI_LIST_PORT} -sTCP:LISTEN >/dev/null 2>/dev/null && break
			fi
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
				if command -v pgrep >/dev/null 2>&1; then
					CPIDS=`pgrep -P $!`
					for i in $CPIDS ; do
						kill -9 $i 2>/dev/null
					done
				fi
				kill -9 $! 2>/dev/null
				exit 1
			fi
			if [ $((CNT % 10)) -eq 0 ] ; then
				echo "Waiting for port ${SAI_LIST_PORT}..." >&2
			fi
			CNT=$((CNT + 1))
			sleep 0.5
		done
	else
		CNT=0
		while true ; do
			if [ -n "$SAI_LIST_IS_UDP" ] ; then
				MATCH="`netstat -an | grep "^udp" | tr -s ' ' | grep "[\.:]${SAI_LIST_PORT} "`"
			else
				MATCH="`netstat -an | grep "^tcp" | tr -s ' ' | grep "[\.:]${SAI_LIST_PORT} " | grep LISTEN`"
			fi
			if [ -n "$MATCH" ] ; then break ; fi
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
				netstat -an >&2
				if command -v pgrep >/dev/null 2>&1; then
					CPIDS=`pgrep -P $!`
					for i in $CPIDS ; do
						kill -9 $i 2>/dev/null
					done
				fi
				kill -9 $! 2>/dev/null
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

