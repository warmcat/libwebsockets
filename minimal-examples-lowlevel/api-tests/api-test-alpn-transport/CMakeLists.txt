project(lws-api-test-alpn-transport C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-alpn-transport)
set(SRCS main.c)

#
# Five server vhosts on tcp and quic, and a client in the same process: h3 is
# never negotiated on tcp, and a request only h3 may carry goes on quic, also
# when it is redirected
#
set(requirements 1)
require_lws_config(LWS_ROLE_H3 1 requirements)
require_lws_config(LWS_ROLE_H2 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITHOUT_SERVER 0 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	set(ALPNT_CERTS ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/api-tests/api-test-ws-close)

	lws_get_free_port(PORT_ALPNT0)
	lws_get_free_port(PORT_ALPNT1)
	lws_get_free_port(PORT_ALPNT2)
	lws_get_free_port(PORT_ALPNT3)
	lws_get_free_port(PORT_ALPNT4)

	add_test(NAME api-test-alpn-transport
		 COMMAND lws-api-test-alpn-transport
			 --port0 ${PORT_ALPNT0} --port1 ${PORT_ALPNT1}
			 --port2 ${PORT_ALPNT2} --port3 ${PORT_ALPNT3}
			 --port4 ${PORT_ALPNT4}
			 --cert ${ALPNT_CERTS}/localhost-100y.cert
			 --key ${ALPNT_CERTS}/localhost-100y.key)
	set_tests_properties(api-test-alpn-transport PROPERTIES TIMEOUT 60)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
