#
# ctest driver for lws-api-test-cache-blob
#
# Starts from a clean scratch dir each run, so the cache-creation and
# maintenance paths are exercised the same way every time
#

file(REMOVE_RECURSE ${SCRATCH})

execute_process(COMMAND ${TOOL} --scratch ${SCRATCH} -d 4
		RESULT_VARIABLE r OUTPUT_QUIET ERROR_QUIET TIMEOUT 120)
if (NOT r EQUAL 0)
	message(FATAL_ERROR "lws-api-test-cache-blob failed (${r})")
endif()
