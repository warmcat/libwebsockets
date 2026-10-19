project(lws-api-test-oauth-peer-caps C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-oauth-peer-caps)
set(SRCS main.c)

set(requirements 1)
# PROXY v2 from loopback is how one process is clients on many addresses
require_lws_config(LWS_WITH_TLS_PASSTHROUGH 1 requirements)
require_lws_config(LWS_WITH_IPV6 1 requirements)
require_lws_config(LWS_WITH_JOSE 1 requirements)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_ROLE_WS 1 requirements)
require_lws_config(LWS_ROLE_RAW 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})
	# the two plugins under test, built in
	target_include_directories(${SAMP} PRIVATE
		${CMAKE_SOURCE_DIR}/plugins/protocol_lws_oauth2_client
		${CMAKE_SOURCE_DIR}/plugins/protocol_lws_oauth_preauth)

	# the server listens on a port the kernel picks, so no port to allocate
	add_test(NAME api-test-oauth-peer-caps
		 COMMAND lws-api-test-oauth-peer-caps
			 --server ${LWS_CTEST_SERVER_RESOLVE})
	set_tests_properties(api-test-oauth-peer-caps PROPERTIES TIMEOUT 60)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
