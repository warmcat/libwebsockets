project(lws-api-test-lws_stub C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)
include(CTest)

set(SAMP lws-api-test-lws_stub)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_WITH_STUB 1 requirements)
require_lws_config(LWS_UNIX_SOCK 1 requirements)

if (requirements)

	add_executable(${SAMP} ${SRCS})
	add_test(NAME api-test-lws_stub COMMAND lws-api-test-lws_stub)
	#
	# Every phase already bounds its own waits (5s per stub connect, 300ms
	# teardown settles), so a healthy run takes a few seconds; this is
	# only the backstop for a wedged process.  Without it ctest's default
	# of 1500s applies, which turns a hang into half an hour of dead time
	# on a builder.
	#
	set_tests_properties(api-test-lws_stub PROPERTIES TIMEOUT 30)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
