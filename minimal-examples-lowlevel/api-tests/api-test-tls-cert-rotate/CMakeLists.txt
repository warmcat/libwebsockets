project(lws-api-test-tls-cert-rotate C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-tls-cert-rotate)
set(SRCS main.c)

#
# A tls server vhost's cert renewed under it with lws_tls_cert_updated(), and
# a client of the same process connecting after each renewal
#
set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_WITH_NETWORK 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITHOUT_SERVER 0 requirements)
require_lws_config(LWS_WITH_TLS 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	lws_get_free_port(PORT_TLS_CERT_ROTATE)
	lws_get_free_port(PORT_TLS_CERT_ROTATE_GRACED)

	#
	# The live cert and key files the test rewrites are made in the build
	# dir, the certs it copies into them are read from the source dir
	#
	add_test(NAME api-test-tls-cert-rotate
		 COMMAND lws-api-test-tls-cert-rotate
			 -p ${PORT_TLS_CERT_ROTATE}
			 --port-graced ${PORT_TLS_CERT_ROTATE_GRACED}
			 --server ${LWS_CTEST_SERVER_RESOLVE}
			 --certs ${CMAKE_CURRENT_SOURCE_DIR})
	set_tests_properties(api-test-tls-cert-rotate PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
			     TIMEOUT 120)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
