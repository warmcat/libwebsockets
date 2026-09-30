project(lws-api-test-ss-proxy C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-ss-proxy)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_WITH_SECURE_STREAMS_PROXY_API 1 requirements)
require_lws_config(LWS_WITH_SECURE_STREAMS_STATIC_POLICY_ONLY 0 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)
require_lws_config(LWS_WITH_UNIX_SOCK 1 requirements)

if (requirements)

	add_executable(${SAMP} ${SRCS})
	add_test(NAME api-test-ss-proxy COMMAND lws-api-test-ss-proxy)
	set_tests_properties(api-test-ss-proxy PROPERTIES TIMEOUT 30)
	add_test(NAME api-test-ss-proxy-refused
		 COMMAND lws-api-test-ss-proxy --refused)
	set_tests_properties(api-test-ss-proxy-refused PROPERTIES TIMEOUT 30)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
