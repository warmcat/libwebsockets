project(lws-api-test-quic-session-dump C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-quic-session-dump)
set(SRCS main.c)

#
# An h3 server and quic clients in one process: a quic client session is
# saved and loaded through lws_tls_session_dump_save_flags() /
# lws_tls_session_dump_load_flags(), which mbedtls and schannel do not
# implement, and resumed with 0-RTT.
#
set(requirements 1)
require_lws_config(LWS_ROLE_H3 1 requirements)
require_lws_config(LWS_WITH_NETWORK 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITHOUT_SERVER 0 requirements)
require_lws_config(LWS_WITH_TLS_SESSIONS 1 requirements)
require_lws_config(LWS_WITH_MBEDTLS 0 requirements)
require_lws_config(LWS_WITH_SCHANNEL 0 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	lws_get_free_port(PORT_QUIC_SESSION_DUMP)

	add_test(NAME api-test-quic-session-dump
		 COMMAND lws-api-test-quic-session-dump
			 -p ${PORT_QUIC_SESSION_DUMP}
			 -s ${LWS_CTEST_SERVER_RESOLVE}
			 --certs ${CMAKE_CURRENT_SOURCE_DIR})
	set_tests_properties(api-test-quic-session-dump PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			     TIMEOUT 60)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
