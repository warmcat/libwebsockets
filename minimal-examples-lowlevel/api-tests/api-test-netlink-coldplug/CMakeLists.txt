project(lws-api-test-netlink-coldplug C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)
include(CTest)

set(SAMP lws-api-test-netlink-coldplug)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_ROLE_RAW 1 requirements)
require_lws_config(LWS_WITH_UDP 1 requirements)
require_lws_config(LWS_WITH_NETWORK 1 requirements)
require_lws_config(LWS_WITH_NETLINK 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)

# netlink, where the routing table comes from, is Linux-only
if (requirements AND CMAKE_SYSTEM_NAME STREQUAL "Linux")

	add_executable(${SAMP} ${SRCS})

	lws_get_free_port(PORT_NETLINK_COLDPLUG)

	add_test(NAME api-test-netlink-coldplug
		 COMMAND lws-api-test-netlink-coldplug -p ${PORT_NETLINK_COLDPLUG})
	set_tests_properties(api-test-netlink-coldplug PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			     TIMEOUT 30)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
