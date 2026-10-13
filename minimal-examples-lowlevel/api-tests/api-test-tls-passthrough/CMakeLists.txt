project(lws-api-test-tls-passthrough C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-tls-passthrough)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_WITH_TLS_PASSTHROUGH 1 requirements)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_ROLE_RAW 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)
require_lws_config(LWS_WITH_TLS 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	# the front, the backend, the ClientHello capture listener, and the udp
	# "NAT" the h3 migration step goes through
	lws_get_free_ports(PORT_TLSPT 4)

	add_test(NAME api-test-tls-passthrough
		 COMMAND lws-api-test-tls-passthrough -p ${PORT_TLSPT}
			 --certs ${CMAKE_CURRENT_SOURCE_DIR})
	set_tests_properties(api-test-tls-passthrough PROPERTIES TIMEOUT 90)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
