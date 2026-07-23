project(lws-minimal-http-client-timeout-h3 C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-minimal-http-client-timeout-h3)
set(SRCS minimal-http-client-timeout-h3.c)

set(requirements 1)
require_lws_config(LWS_ROLE_QUIC 1 requirements)
require_lws_config(LWS_WITH_HTTP3 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	if (LWS_WITH_MINIMAL_EXAMPLES)
		#
		# The test starts the blackhole QUIC server (-s) on a free port,
		# gives it a moment to bind, runs the client against it, then
		# kills the server.  The client's success condition is that it
		# times out awaiting the reply (the server never answers), which
		# exercises the H3 client reply timeout.  We bundle server +
		# client into a single ctest command with a tiny inline shell
		# wrapper so the test is self-contained and does not depend on
		# netstat/lsof-based port detection helpers.
		#
		# Expected exit codes: server (-s) always returns 0; the client
		# returns 0 if it saw the timeout and non-zero otherwise, so the
		# client exit code is the test result.
		lws_get_free_port(PORT_H3TO)

		add_test(NAME h3to COMMAND sh -c
			"$<TARGET_FILE:${SAMP}> -s -p ${PORT_H3TO} -d1039 2>/dev/null & SRV=$!; sleep 2; $<TARGET_FILE:${SAMP}> -p ${PORT_H3TO} -d1039; RC=$?; kill $SRV 2>/dev/null; wait $SRV 2>/dev/null; exit $RC")
		set_tests_properties(h3to PROPERTIES
				     WORKING_DIRECTORY .
				     TIMEOUT 40)
	endif()
endif()
