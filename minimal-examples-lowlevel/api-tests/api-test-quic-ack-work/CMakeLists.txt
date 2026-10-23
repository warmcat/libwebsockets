project(lws-api-test-quic-ack-work C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-quic-ack-work)
set(SRCS main.c)

#
# an h3 server and client in this process, whose ACKs are made expensive by
# fault injection, and which log what that cost them
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

	set(QAW_CERTS ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/api-tests/api-test-ws-close)

	lws_get_free_port(PORT_QAW)
	add_test(NAME api-test-quic-ack-work
		 COMMAND lws-api-test-quic-ack-work -p ${PORT_QAW}
			 --cert ${QAW_CERTS}/localhost-100y.cert
			 --key ${QAW_CERTS}/localhost-100y.key)
	set_tests_properties(api-test-quic-ack-work PROPERTIES TIMEOUT 60)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
