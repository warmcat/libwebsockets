project(lws-api-test-crash-backtrace C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-crash-backtrace)
set(SRCS main.c)

#
# Children that crash must print their backtrace and still die of the signal,
# and a handler the application installed first is left alone.  It forks, so
# posix only.
#
set(requirements 1)
require_lws_config(LWS_WITH_CRASH_BACKTRACE 1 requirements)

if (requirements AND NOT WIN32)

	add_executable(${SAMP} ${SRCS})
	add_test(NAME api-test-crash-backtrace COMMAND lws-api-test-crash-backtrace)
	set_tests_properties(api-test-crash-backtrace PROPERTIES TIMEOUT 30)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

endif()
