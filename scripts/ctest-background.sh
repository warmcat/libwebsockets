#!/usr/bin/env bash
#
# $SAI_LIST_PORT - optional, if present the ipv4 port number to wait on existing
# $SAI_INSTANCE_IDX - which instance of sai, 0+
# $1 - background fixture name, unique within test space, like "multipostlocalserver"
# $2 - executable
# $3+ - args

FIXTURE_NAME=$1
FIXTURE_EXE=`basename $2`
. "$(dirname "$0")/ctest-fixture-key.sh"

#
# Build-tree binaries carry a RUNPATH to the build's lib/, and CI exports
# LD_LIBRARY_PATH for the installed-to-destdir case, so this guess is only for
# callers that have neither.  Skip it when the caller already said where the
# libraries are, rather than prepending a guess in front of their answer.
#
if [ -z "$LD_LIBRARY_PATH" ] ; then
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
	    export LD_LIBRARY_PATH="$BUILD_DIR/lib"
	fi
fi

# We shift off $1 (the background fixture name) so that "$@" contains only the executable and its args.
shift

#
# $LWS_CTEST_BG_DEBUG - optional, the log-level argument to append.  The
# default is deliberately noisy: -d1039 is also what makes lwsws install its
# crash handler, so a SIGSEGV in a fixture prints a backtrace into its log
# instead of vanishing.  Set it empty to append nothing (a fixture whose own
# args already set a level, or one too chatty to run at info).
#
BG_DEBUG="${LWS_CTEST_BG_DEBUG--d1039}"

"$@" $BG_DEBUG 2>"$FIX_LOG" 1>/dev/null 0</dev/null &
echo $! > "$FIX_PID"

# really we want to loop until the listen port is up
# on, eg, rpi it can be blocked at sd card and slow to start
# due to parallel tests and disc cache flush


if [ -z "${SAI_LIST_PORT}" ] ; then

	if [ ! -z "`echo "$1" | grep valgrind`" ] ; then
		sleep 15
	else
		sleep 1
	fi

	# The port being listened on is not proof it is ours: a stale server on it
	# leaves our child dead of EADDRINUSE while the port looks up, and the tests
	# would then run against a stranger.  The child must still be alive.
	if ! kill -0 $! 2>/dev/null ; then
		echo "Background process $! died; its log:" >&2
		cat "$FIX_LOG" >&2
		exit 1
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
				cat "$FIX_LOG" >&2
				exit 1
			fi
			if [ $CNT -gt 60 ] ; then
				echo "Timed out waiting for port ${SAI_LIST_PORT}" >&2
				echo "Background process state:" >&2
				ps -fp $! >&2
				echo "Background process logs:" >&2
				cat "$FIX_LOG" >&2
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
					if command -v netstat >/dev/null 2>&1 ; then
						MATCH="`netstat -an | grep "^udp" | tr -s ' ' | grep "[\.:]${SAI_LIST_PORT} "`"
					else
						# "ss" is the modern netstat replacement and is all
						# that's available on some minimal/CI images
						MATCH="`ss -lun | tr -s ' ' | grep "[\.:]${SAI_LIST_PORT} "`"
					fi
				else
					if command -v netstat >/dev/null 2>&1 ; then
						MATCH="`netstat -an | grep "^tcp" | tr -s ' ' | grep "[\.:]${SAI_LIST_PORT} " | grep LISTEN`"
					else
						MATCH="`ss -ltn | tr -s ' ' | grep "[\.:]${SAI_LIST_PORT} "`"
					fi
				fi
				if [ -n "$MATCH" ] ; then break ; fi
			if ! kill -0 $! 2>/dev/null ; then
				echo "Background process died while waiting for port ${SAI_LIST_PORT}" >&2
				echo "Background process logs:" >&2
				cat "$FIX_LOG" >&2
				exit 1
			fi
			if [ $CNT -gt 60 ] ; then
				echo "Timed out waiting for port ${SAI_LIST_PORT}" >&2
				echo "Background process state:" >&2
				ps -fp $! >&2
				echo "Background process logs:" >&2
				cat "$FIX_LOG" >&2
				echo "Listen socket output:" >&2
				if command -v netstat >/dev/null 2>&1 ; then
					netstat -an >&2
				else
					ss -lntau >&2
				fi
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

	# The port being listened on is not proof it is ours: a stale server on it
	# leaves our child dead of EADDRINUSE while the port looks up, and the tests
	# would then run against a stranger.  The child must still be alive.
	if ! kill -0 $! 2>/dev/null ; then
		echo "Background process $! died; its log:" >&2
		cat "$FIX_LOG" >&2
		exit 1
	fi

	sleep 1
fi

exit 0

