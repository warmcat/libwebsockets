project(lws-api-test-proxy-hdr C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-proxy-hdr)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_ROLE_WS 1 requirements)
require_lws_config(LWS_WITH_NETWORK 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)
require_lws_config(LWS_WITH_HTTP_PROXY 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	# backend vhost and the proxying vhost in front of it listen on
	# adjacent ports from the CI port allocator
	lws_get_free_ports(PORT_PROXYHDR 2)

	add_test(NAME api-test-proxy-hdr
		 COMMAND lws-api-test-proxy-hdr -p ${PORT_PROXYHDR})
	set_tests_properties(api-test-proxy-hdr PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			     TIMEOUT 60)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
