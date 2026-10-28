project(lws-api-test-h3-qpack-blocked C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-h3-qpack-blocked)
set(SRCS main.c)

#
# an h3 server and its client in this process, the client's encoder stream
# inserting what its requests refer to by fault injection
#
set(requirements 1)
require_lws_config(LWS_ROLE_H3 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITHOUT_SERVER 0 requirements)
require_lws_config(LWS_WITH_IPV4 1 requirements)
require_lws_config(LWS_WITH_SYS_FAULT_INJECTION 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	set(HQB_CERTS ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/api-tests/api-test-ws-close)

	lws_get_free_port(PORT_HQB)
	lws_get_free_port(PORT_HQB_NB)
	add_test(NAME api-test-h3-qpack-blocked
		 COMMAND lws-api-test-h3-qpack-blocked -p ${PORT_HQB}
			 --nb-port ${PORT_HQB_NB}
			 --cert ${HQB_CERTS}/localhost-100y.cert
			 --key ${HQB_CERTS}/localhost-100y.key)
	set_tests_properties(api-test-h3-qpack-blocked PROPERTIES TIMEOUT 60)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
