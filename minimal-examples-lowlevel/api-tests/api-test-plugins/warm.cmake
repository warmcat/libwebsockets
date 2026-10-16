#
# ctest runs this before any test, see CMakeLists.txt.  It loads the plugins
# once, so later loads are quick.  It always succeeds, since ctest runs no
# tests at all if it fails; the api-test-plugins test reports any problem.
#

execute_process(COMMAND "${EXE}" --dir "${DIR}" --suffix "${SUFFIX}"
		RESULT_VARIABLE _r)

if (NOT _r EQUAL 0)
	message("plugins warm-up: ${_r}, see api-test-plugins")
endif()
