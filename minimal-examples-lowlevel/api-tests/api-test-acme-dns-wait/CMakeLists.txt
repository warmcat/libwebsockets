project(lws-api-test-acme-dns-wait C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-acme-dns-wait)
# the dns-01 wait from the acme plugin, and the auth dns plugin it asks
set(SRCS main.c
	 ../../../plugins/protocol_lws_acme_client/acme-dns-wait.c
	 ../../../plugins/protocol_lws_auth_dns/protocol_lws_auth_dns.c)

set(requirements 1)
require_lws_config(LWS_WITH_ACME 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)
require_lws_config(LWS_WITH_SYS_ASYNC_DNS 1 requirements)
require_lws_config(LWS_WITH_AUTHORITATIVE_DNS 1 requirements)

if (requirements AND NOT WIN32)

	add_executable(${SAMP} ${SRCS})
	target_include_directories(${SAMP} PRIVATE
		${CMAKE_SOURCE_DIR}/plugins/protocol_lws_acme_client)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	# the name server's port, and one that takes questions and never answers
	lws_get_free_port(PORT_ACME_DNS_WAIT_SRV)
	lws_get_free_port(PORT_ACME_DNS_WAIT_SILENT)

	add_test(NAME api-test-acme-dns-wait COMMAND lws-api-test-acme-dns-wait
		 -p ${PORT_ACME_DNS_WAIT_SRV}
		 --port-silent ${PORT_ACME_DNS_WAIT_SILENT})
	set_tests_properties(api-test-acme-dns-wait PROPERTIES
		WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
		TIMEOUT 40)

endif()
