project(lws-api-test-quic-destroy-close C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-quic-destroy-close)
set(SRCS main.c)

#
# an h3 server, and on a thread of its own with its own context, a client
# that destroys its context with its connection still open
#
set(requirements 1)
require_pthreads(requirements)
require_lws_config(LWS_ROLE_H3 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITHOUT_SERVER 0 requirements)
require_lws_config(LWS_WITH_IPV4 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	set(QDC_CERTS ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/api-tests/api-test-ws-close)

	lws_get_free_port(PORT_QDC)
	add_test(NAME api-test-quic-destroy-close
		 COMMAND lws-api-test-quic-destroy-close -p ${PORT_QDC}
			 --cert ${QDC_CERTS}/localhost-100y.cert
			 --key ${QDC_CERTS}/localhost-100y.key)
	set_tests_properties(api-test-quic-destroy-close PROPERTIES TIMEOUT 60)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${PTHREAD_LIB} ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${PTHREAD_LIB} ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
