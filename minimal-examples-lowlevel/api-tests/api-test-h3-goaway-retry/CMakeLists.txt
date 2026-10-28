project(lws-api-test-h3-goaway-retry C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-h3-goaway-retry)
set(SRCS main.c)

#
# an h3 server and its clients in this process, losing requests by fault
# injection
#
set(requirements 1)
require_lws_config(LWS_ROLE_H3 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITHOUT_SERVER 0 requirements)
require_lws_config(LWS_WITH_IPV4 1 requirements)
require_lws_config(LWS_WITH_SYS_FAULT_INJECTION 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	set(GRT_CERTS ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/api-tests/api-test-ws-close)

	lws_get_free_port(PORT_GRT)
	add_test(NAME api-test-h3-goaway-retry
		 COMMAND lws-api-test-h3-goaway-retry -p ${PORT_GRT}
			 --cert ${GRT_CERTS}/localhost-100y.cert
			 --key ${GRT_CERTS}/localhost-100y.key)
	set_tests_properties(api-test-h3-goaway-retry PROPERTIES TIMEOUT 60)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
