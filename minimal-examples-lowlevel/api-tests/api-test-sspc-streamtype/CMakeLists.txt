project(lws-api-test-sspc-streamtype C)
cmake_minimum_required(VERSION 3.10)
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(requirements 1)
require_lws_config(LWS_WITH_SECURE_STREAMS_PROXY_API 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)

if (requirements)

	add_executable(${PROJECT_NAME} main.c)
	add_test(NAME api-test-sspc-streamtype COMMAND lws-api-test-sspc-streamtype)
	set_tests_properties(api-test-sspc-streamtype PROPERTIES
				TIMEOUT 20)

	if (websockets_shared)
		target_link_libraries(${PROJECT_NAME} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${PROJECT_NAME} websockets_shared)
	else()
		target_link_libraries(${PROJECT_NAME} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
