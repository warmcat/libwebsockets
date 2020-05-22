project(lws-minimal-ws-client-rx)
cmake_minimum_required(VERSION 2.8)
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-minimal-ws-client-rx)
set(SRCS minimal-ws-client.c)

set(requirements 1)
require_lws_config(LWS_ROLE_WS 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})
	if (LWS_CTEST_INTERNET_AVAILABLE)
		add_test(NAME ws-client-rx-warmcat COMMAND lws-minimal-ws-client-rx -t)
		set_tests_properties(ws-client-rx-warmcat
				     PROPERTIES
				     WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples/ws-client/minimal-ws-client-rx
				     TIMEOUT 20)

	endif()

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared)
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets)
	endif()
endif()
