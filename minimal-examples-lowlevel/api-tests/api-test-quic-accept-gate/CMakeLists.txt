project(lws-api-test-quic-accept-gate C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-quic-accept-gate)
set(SRCS main.c)

#
# An h3 server and client in one process: pausing the server's tcp accepts,
# for the tls restriction or a full fds table, must not stop its established
# QUIC connections, and new QUIC connections honour the tls restriction
# once their address is validated, not before
#
set(requirements 1)
require_lws_config(LWS_ROLE_H3 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITHOUT_SERVER 0 requirements)
# the idle tcp connects go to 127.0.0.1
require_lws_config(LWS_WITH_IPV4 1 requirements)

if (requirements AND NOT WIN32)
	add_executable(${SAMP} ${SRCS})

	set(CGA_CERTS ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/api-tests/api-test-ws-close)

	foreach(CGA_CASE handshakes sessions fds flood)
		# the server, and the flood case's udp relay
		lws_get_free_ports(PORT_CGA_${CGA_CASE} 2)
		math(EXPR PORT_CGA_RELAY_${CGA_CASE} "${PORT_CGA_${CGA_CASE}} + 1")

		add_test(NAME api-test-quic-accept-gate-${CGA_CASE}
			 COMMAND lws-api-test-quic-accept-gate
				 --case ${CGA_CASE}
				 -p ${PORT_CGA_${CGA_CASE}}
				 --relay-port ${PORT_CGA_RELAY_${CGA_CASE}}
				 --cert ${CGA_CERTS}/localhost-100y.cert
				 --key ${CGA_CERTS}/localhost-100y.key)
		set_tests_properties(api-test-quic-accept-gate-${CGA_CASE}
				     PROPERTIES TIMEOUT 40)
	endforeach()

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
