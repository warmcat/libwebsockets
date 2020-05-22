project(lws-minimal-http-client)
cmake_minimum_required(VERSION 2.8)
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-minimal-http-client)
set(SRCS minimal-http-client.c)

set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	#	if (LWS_CTEST_INTERNET_AVAILABLE)
	#	add_test(NAME http-client-warmcat COMMAND lws-minimal-http-client --ignore-sigterm)
	#	add_test(NAME http-client-warmcat-h1 COMMAND lws-minimal-http-client --ignore-sigterm --h1)
	#	set_tests_properties(http-client-warmcat
	#			     http-client-warmcat-h1
	#			     PROPERTIES
	#			     WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples/http-client/minimal-http-client
	#			     TIMEOUT 20)
	#
	#endif()

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared)
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets)
	endif()
endif()
