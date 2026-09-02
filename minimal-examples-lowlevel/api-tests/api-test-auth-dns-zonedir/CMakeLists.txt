project(lws-api-test-auth-dns-zonedir C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-auth-dns-zonedir)
set(SRCS main.c
	 ../../../plugins/protocol_lws_auth_dns/protocol_lws_auth_dns.c)

set(requirements 1)
require_lws_config(LWS_WITH_SERVER 1 requirements)
require_lws_config(LWS_WITH_AUTHORITATIVE_DNS 1 requirements)

if (requirements)

	add_executable(${SAMP} ${SRCS})

	# two unique ports; the sequential phases alternate between them
	lws_get_free_port(PORT_AUTH_DNS_A)
	lws_get_free_port(PORT_AUTH_DNS_B)

	add_test(NAME api-test-auth-dns-zonedir COMMAND lws-api-test-auth-dns-zonedir
		 -p ${PORT_AUTH_DNS_A} -b ${PORT_AUTH_DNS_B})
	set_tests_properties(api-test-auth-dns-zonedir PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/api-tests/api-test-auth-dns-zonedir
			     TIMEOUT 90)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

endif()
