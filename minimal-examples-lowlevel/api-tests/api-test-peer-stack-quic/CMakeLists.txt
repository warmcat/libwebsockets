project(lws-api-test-peer-stack-quic C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-peer-stack-quic)
set(SRCS main.c)

#
# an h3 server and client in one process, and a udp "NAT" between them for
# the migration phase
#
set(requirements 1)
require_lws_config(LWS_ROLE_H3 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITHOUT_SERVER 0 requirements)
require_lws_config(LWS_WITH_IPV4 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	set(PQ_CERTS ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/api-tests/api-test-ws-close)
	lws_get_free_port(PORT_PEER_STACK_QUIC)

	add_test(NAME api-test-peer-stack-quic
		 COMMAND lws-api-test-peer-stack-quic
			 -p ${PORT_PEER_STACK_QUIC}
			 --cert ${PQ_CERTS}/localhost-100y.cert
			 --key ${PQ_CERTS}/localhost-100y.key
			 --access-log ${CMAKE_CURRENT_BINARY_DIR}/api-test-peer-stack-quic-access.log)
	set_tests_properties(api-test-peer-stack-quic PROPERTIES TIMEOUT 60)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
