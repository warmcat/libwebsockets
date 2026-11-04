project(lws-api-test-ss-destroy-in-connect C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-ss-destroy-in-connect)
set(SRCS main.c)

#
# a quic connection failing to make its tls session inside the connect, by
# fault injection
#
set(requirements 1)
require_lws_config(LWS_ROLE_H3 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_TLS 1 requirements)
require_lws_config(LWS_WITH_SECURE_STREAMS 1 requirements)
require_lws_config(LWS_WITH_SECURE_STREAMS_STATIC_POLICY_ONLY 0 requirements)
require_lws_config(LWS_WITH_SYS_FAULT_INJECTION 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})
	add_test(NAME api-test-ss-destroy-in-connect COMMAND ${SAMP})
	set_tests_properties(api-test-ss-destroy-in-connect PROPERTIES TIMEOUT 30)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
