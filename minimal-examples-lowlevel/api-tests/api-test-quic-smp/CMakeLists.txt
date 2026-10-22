project(lws-api-test-quic-smp C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-quic-smp)
set(SRCS main.c)

#
# h3 clients on two service threads (LWS_MAX_SMP > 1) fetching from an h3
# server vhost in the same process, and, with IPv6, from a dual stack one
# telling them to migrate to IPv4
#
set(requirements 1)
require_pthreads(requirements)
require_lws_config(LWS_ROLE_H3 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITHOUT_SERVER 0 requirements)
require_lws_config(LWS_WITH_IPV4 1 requirements)

if (requirements AND NOT WIN32)
	add_executable(${SAMP} ${SRCS})

	set(QSMP_CERTS ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/api-tests/api-test-ws-close)
	lws_get_free_port(PORT_QSMP)
	lws_get_free_port(PORT_QSMP_DUAL)

	add_test(NAME api-test-quic-smp
		 COMMAND lws-api-test-quic-smp
			 -p ${PORT_QSMP}
			 --port-dual ${PORT_QSMP_DUAL}
			 --cert ${QSMP_CERTS}/localhost-100y.cert
			 --key ${QSMP_CERTS}/localhost-100y.key)
	set_tests_properties(api-test-quic-smp PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
			     TIMEOUT 60)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${PTHREAD_LIB} ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${PTHREAD_LIB} ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
