project(lws-api-test-auth-dns-dnsbl C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-auth-dns-dnsbl)
set(SRCS main.c
	 ../../../plugins/protocol_lws_auth_dns/protocol_lws_auth_dns.c)

set(requirements 1)
require_lws_config(LWS_WITH_SERVER 1 requirements)
require_lws_config(LWS_WITH_AUTHORITATIVE_DNS 1 requirements)
# the plugin drives the internal async resolver
require_lws_config(LWS_WITH_SYS_ASYNC_DNS 1 requirements)

if (requirements)

	add_executable(${SAMP} ${SRCS})

	# two unique ports: the auth dns server under test, and the
	# blackholed DNSBL resolver stub
	lws_get_free_port(PORT_AUTH_DNS)
	lws_get_free_port(PORT_DNSBL_STUB)

	add_test(NAME api-test-auth-dns-dnsbl COMMAND lws-api-test-auth-dns-dnsbl
		 -p ${PORT_AUTH_DNS} -b ${PORT_DNSBL_STUB})
	set_tests_properties(api-test-auth-dns-dnsbl PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/api-tests/api-test-auth-dns-dnsbl
			     TIMEOUT 60)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

endif()
