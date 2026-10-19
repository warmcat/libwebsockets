project(lws-api-test-ss-redirect C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-ss-redirect)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_WITH_SECURE_STREAMS 1 requirements)
require_lws_config(LWS_WITH_SECURE_STREAMS_STATIC_POLICY_ONLY 0 requirements)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_ROLE_RAW 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)
require_lws_config(LWS_WITH_TLS 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	lws_get_free_port(PORT_SS_REDIRECT)
	lws_get_free_port(PORT_SS_REDIRECT_PLAIN)

	# single-stack builds pin the client to their family's address
	if (LWS_CTEST_SERVER_RESOLVE STREQUAL "localhost")
		set(SSR_SERVER srv.localhost)
	else()
		set(SSR_SERVER ${LWS_CTEST_SERVER_RESOLVE})
	endif()

	add_test(NAME api-test-ss-redirect
		 COMMAND lws-api-test-ss-redirect
			 -p ${PORT_SS_REDIRECT}
			 --port-plain ${PORT_SS_REDIRECT_PLAIN}
			 --cert ${CMAKE_CURRENT_SOURCE_DIR}/ss-redirect-100y.cert
			 --key ${CMAKE_CURRENT_SOURCE_DIR}/ss-redirect-100y.key
			 --server ${SSR_SERVER})
	set_tests_properties(api-test-ss-redirect
			     PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			     TIMEOUT 60)
endif()
