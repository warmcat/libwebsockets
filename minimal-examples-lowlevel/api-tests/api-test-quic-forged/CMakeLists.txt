project(lws-api-test-quic-forged C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-quic-forged)
set(SRCS main.c)

#
# an h3 server and client in this process, with a udp relay between them
# that can inject datagrams into the connection
#
set(requirements 1)
require_lws_config(LWS_ROLE_H3 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITHOUT_SERVER 0 requirements)
require_lws_config(LWS_WITH_IPV4 1 requirements)

if (requirements AND NOT WIN32)
	add_executable(${SAMP} ${SRCS})

	set(QFG_CERTS ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/api-tests/api-test-ws-close)

	# the server, and the relay the client dials
	lws_get_free_ports(PORT_QFG 2)

	add_test(NAME api-test-quic-forged
		 COMMAND lws-api-test-quic-forged
			 -p ${PORT_QFG}
			 --cert ${QFG_CERTS}/localhost-100y.cert
			 --key ${QFG_CERTS}/localhost-100y.key)
	set_tests_properties(api-test-quic-forged PROPERTIES TIMEOUT 30)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
