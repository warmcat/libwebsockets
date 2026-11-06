#
# ctest driver: run a test against a background fixture, and if it fails,
# show what the fixture logged while it ran
#
# cmake -DFIX_LOG_STEM=<build>/Testing/fixtures/<fixture exe>.<fixture name>
#       -DCMD=<test command;args> [-DTIMEOUT=<secs>]
#       -P ctest-fixture-log-on-fail.cmake
#
# A fixture started by ctest-background.sh logs to
# <FIX_LOG_STEM>.<SAI_INSTANCE_IDX>.log for the whole ctest run, and the log
# is only seen if the fixture dies.  When a client test fails because of
# something on the server side, eg, a handshake the server stalled on and
# reset, the client's log can only say that it happened.  So this notes how
# long the fixture's log is before the test runs, and if the test fails, it
# shows the test's output followed by what the fixture logged after that
# point.  Tests sharing a fixture should take turns on it with RESOURCE_LOCK,
# so that is the fixture's side of this test alone.
#
# Each part shown is capped to its last part, so ctest's limit on the output
# of a failed test still leaves room for both.
#

if (NOT TIMEOUT)
	set(TIMEOUT 45)
endif()

set(FIX_LOG "${FIX_LOG_STEM}.$ENV{SAI_INSTANCE_IDX}.log")

set(fix_from 0)
if (EXISTS "${FIX_LOG}")
	file(SIZE "${FIX_LOG}" fix_from)
endif()

execute_process(COMMAND ${CMD}
		RESULT_VARIABLE r OUTPUT_VARIABLE log ERROR_VARIABLE log
		TIMEOUT ${TIMEOUT})

function(show_tail what text cap)
	string(LENGTH "${text}" len)
	if (len GREATER cap)
		math(EXPR from "${len} - ${cap}")
		string(SUBSTRING "${text}" ${from} -1 text)
		set(what "${what}, its last ${cap} bytes of ${len}")
	endif()
	message("---- ${what}:\n${text}")
endfunction()

if (r EQUAL 0)
	message("${log}")
	return()
endif()

show_tail("test output" "${log}" 160000)

if (EXISTS "${FIX_LOG}")
	file(SIZE "${FIX_LOG}" fix_to)
	if (fix_to GREATER fix_from)
		math(EXPR n "${fix_to} - ${fix_from}")
		file(READ "${FIX_LOG}" fix OFFSET ${fix_from} LIMIT ${n})
		show_tail("fixture log ${FIX_LOG} during the test" "${fix}" 96000)
	else()
		message("---- fixture log ${FIX_LOG}: nothing logged during the test")
	endif()
else()
	message("---- no fixture log at ${FIX_LOG}")
endif()

message(FATAL_ERROR "${CMD} failed (${r})")
