project(lws-api-test-h3-stream-reset C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-h3-stream-reset)
set(SRCS main.c)

#
# an h3 server and its clients in this process
#
set(requirements 1)
require_lws_config(LWS_ROLE_H3 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITHOUT_SERVER 0 requirements)
require_lws_config(LWS_WITH_IPV4 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	set(HSR_CERTS ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/api-tests/api-test-ws-close)

	lws_get_free_port(PORT_HSR)
	add_test(NAME api-test-h3-stream-reset
		 COMMAND lws-api-test-h3-stream-reset -p ${PORT_HSR}
			 --cert ${HSR_CERTS}/localhost-100y.cert
			 --key ${HSR_CERTS}/localhost-100y.key)
	set_tests_properties(api-test-h3-stream-reset PROPERTIES TIMEOUT 60)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
