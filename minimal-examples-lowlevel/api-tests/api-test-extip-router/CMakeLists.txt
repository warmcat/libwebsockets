project(lws-api-test-extip-router C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-extip-router)

set(requirements 1)
require_lws_config(LWS_WITH_NETWORK 1 requirements)
require_lws_config(LWS_WITH_EXTIP 1 requirements)
require_lws_config(LWS_WITH_JOSE 1 requirements)
require_lws_config(LWS_WITH_LEJP 1 requirements)
require_lws_config(LWS_WITH_SYS_SMD 1 requirements)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)
require_lws_config(LWS_WITH_IPV4 1 requirements)

# the plugin takes interface addresses from getifaddrs()
if (requirements AND NOT WIN32)
	# the plugin is built into the test
	add_executable(${SAMP} main.c)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	lws_get_free_port(PORT_EXTIP_ROUTER)
	lws_get_free_port(PORT_EXTIP_ROUTER_WK)

	# the test writes its generated keys into the build dir
	add_test(NAME api-test-extip-router
		 COMMAND ${SAMP} -p ${PORT_EXTIP_ROUTER})
	add_test(NAME api-test-extip-router-wrong-key
		 COMMAND ${SAMP} -p ${PORT_EXTIP_ROUTER_WK} --wrong-key)
	set_tests_properties(api-test-extip-router
			     api-test-extip-router-wrong-key
			     PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
			     TIMEOUT 30)
endif()
