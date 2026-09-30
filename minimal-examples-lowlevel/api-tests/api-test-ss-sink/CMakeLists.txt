project(lws-api-test-ss-sink C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-ss-sink)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_WITH_SECURE_STREAMS 1 requirements)
require_lws_config(LWS_WITH_SECURE_STREAMS_STATIC_POLICY_ONLY 0 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)
require_lws_config(LWS_WITH_SYS_SMD 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	add_test(NAME api-test-ss-sink COMMAND lws-api-test-ss-sink)
	set_tests_properties(api-test-ss-sink
			     PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			     TIMEOUT 30)
endif()
