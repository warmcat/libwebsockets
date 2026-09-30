project(lws-api-test-sspc-link-retry C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-sspc-link-retry)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_WITH_SECURE_STREAMS_PROXY_API 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_UNIX_SOCK 1 requirements)

if (requirements)

	add_executable(${SAMP} ${SRCS})
	add_test(NAME api-test-sspc-link-retry COMMAND lws-api-test-sspc-link-retry)
	set_tests_properties(api-test-sspc-link-retry PROPERTIES TIMEOUT 20)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
