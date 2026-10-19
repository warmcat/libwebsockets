project(lws-api-test-log-redact C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-log-redact)
set(SRCS main.c)

#
# Captures every log line at every level while credentials pass through
# h1 / h2 / h3, a followed redirect, the PEM key loader and a ws
# subprotocol offer, and fails if any of them reaches the log
#
set(requirements 1)
require_lws_config(LWS_WITH_TLS 1 requirements)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)

set(LRD_H2 1)
require_lws_config(LWS_ROLE_H2 1 LRD_H2)
set(LRD_H3 1)
require_lws_config(LWS_ROLE_H3 1 LRD_H3)
set(LRD_WS 1)
require_lws_config(LWS_ROLE_WS 1 LRD_WS)

if (requirements AND NOT WIN32)
	add_executable(${SAMP} ${SRCS})

	set(LRD_CERTS ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/api-tests/api-test-ws-close)

	set(LRD_CASES h1 redirect pem)
	if (LRD_WS)
		list(APPEND LRD_CASES ws)
	endif()
	if (LRD_H2)
		list(APPEND LRD_CASES h2)
		if (LRD_WS)
			list(APPEND LRD_CASES ws-h2)
		endif()
	endif()
	if (LRD_H3)
		list(APPEND LRD_CASES h3)
	endif()

	foreach(LRD_CASE ${LRD_CASES})
		lws_get_free_port(PORT_LRD_${LRD_CASE})

		add_test(NAME api-test-log-redact-${LRD_CASE}
			 COMMAND lws-api-test-log-redact
				 --case ${LRD_CASE}
				 -p ${PORT_LRD_${LRD_CASE}}
				 --cert ${LRD_CERTS}/localhost-100y.cert
				 --key ${LRD_CERTS}/localhost-100y.key)
		set_tests_properties(api-test-log-redact-${LRD_CASE} PROPERTIES
				     TIMEOUT 30)
	endforeach()

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
