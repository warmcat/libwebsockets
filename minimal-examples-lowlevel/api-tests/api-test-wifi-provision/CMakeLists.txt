project(lws-api-test-wifi-provision C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-wifi-provision)
set(SRCS main.c)

#
# The wifi settings served by a device that is an AP of its own, to be given
# credentials, here by a pretend wifi netdev whose AP is this host, fetched
# by an http client in the same process
#
set(requirements 1)
require_lws_config(LWS_WITH_DRIVERS 1 requirements)
require_lws_config(LWS_WITH_NETWORK 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SYS_SMD 1 requirements)
require_lws_config(LWS_ROLE_H1 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	lws_get_free_port(PORT_WIFIPROV)
	lws_get_free_port(PORT_WIFIPROV_DNS)

	add_test(NAME api-test-wifi-provision
		 COMMAND lws-api-test-wifi-provision --port ${PORT_WIFIPROV}
			 --dns-port ${PORT_WIFIPROV_DNS})
	set_tests_properties(api-test-wifi-provision
			     PROPERTIES
			     WORKING_DIRECTORY .
			     TIMEOUT 30)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
