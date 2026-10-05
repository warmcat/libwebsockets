project(lws-api-test-adns-direct C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-adns-direct)
# the authoritative server it asks is the auth dns plugin, built in
set(SRCS main.c
	 ../../../plugins/protocol_lws_auth_dns/protocol_lws_auth_dns.c)

set(requirements 1)
require_lws_config(LWS_WITH_SERVER 1 requirements)
require_lws_config(LWS_WITH_SYS_ASYNC_DNS 1 requirements)
require_lws_config(LWS_WITH_AUTHORITATIVE_DNS 1 requirements)

if (requirements AND NOT WIN32)

	add_executable(${SAMP} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	# the server's port, one that never answers, one nothing is bound to
	lws_get_free_port(PORT_ADNS_DIRECT_SRV)
	lws_get_free_port(PORT_ADNS_DIRECT_DEAD)
	lws_get_free_port(PORT_ADNS_DIRECT_REFUSED)

	add_test(NAME api-test-adns-direct COMMAND lws-api-test-adns-direct
		 -p ${PORT_ADNS_DIRECT_SRV} --port-dead ${PORT_ADNS_DIRECT_DEAD}
		 --port-refused ${PORT_ADNS_DIRECT_REFUSED})
	set_tests_properties(api-test-adns-direct PROPERTIES
		WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
		TIMEOUT 40)

endif()
