#
# ctest driver for lws-api-test-cache-blob
#
# Starts from a clean scratch dir each run, so the cache-creation and
# maintenance paths are exercised the same way every time.  The dir is
# unique per run, so concurrent runs in the same build tree cannot see
# each other's files, and it is removed again afterwards
#

string(RANDOM LENGTH 8 rnd)
set(SCRATCH "${SCRATCH}-${rnd}")
file(REMOVE_RECURSE ${SCRATCH})

execute_process(COMMAND ${TOOL} --scratch ${SCRATCH} -d 4
		RESULT_VARIABLE r OUTPUT_QUIET ERROR_QUIET TIMEOUT 120)
file(REMOVE_RECURSE ${SCRATCH})
if (NOT r EQUAL 0)
	message(FATAL_ERROR "lws-api-test-cache-blob failed (${r})")
endif()
