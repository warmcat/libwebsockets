project(lws-api-test-quic-lost-probes C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-quic-lost-probes)
set(SRCS main.c)

#
# an h3 server and its clients in one process, with a udp "NAT" between them
# that drops the server's probes, and the server logging what it made of that
# by fault injection
#
set(requirements 1)
require_lws_config(LWS_ROLE_H3 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITHOUT_SERVER 0 requirements)
require_lws_config(LWS_WITH_IPV4 1 requirements)
require_lws_config(LWS_WITH_SYS_FAULT_INJECTION 1 requirements)
require_lws_config(LWS_WITH_NO_LOGS 0 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	set(QLP_CERTS ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/api-tests/api-test-ws-close)
	lws_get_free_port(PORT_QUIC_LOST_PROBES)

	add_test(NAME api-test-quic-lost-probes
		 COMMAND lws-api-test-quic-lost-probes
			 -p ${PORT_QUIC_LOST_PROBES}
			 --cert ${QLP_CERTS}/localhost-100y.cert
			 --key ${QLP_CERTS}/localhost-100y.key)
	set_tests_properties(api-test-quic-lost-probes PROPERTIES TIMEOUT 70)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
