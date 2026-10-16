project(lws-api-test-h2-client-peer C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)
include(CTest)

set(SAMP lws-api-test-h2-client-peer)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_ROLE_H2 1 requirements)
require_lws_config(LWS_WITH_NETWORK 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITHOUT_SERVER 0 requirements)

if (requirements)

	add_executable(${SAMP} ${SRCS})

	lws_get_free_port(PORT_H2_CLIENT_PEER)

	add_test(NAME api-test-h2-client-peer
		 COMMAND lws-api-test-h2-client-peer -p ${PORT_H2_CLIENT_PEER})
	set_tests_properties(api-test-h2-client-peer PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			     TIMEOUT 120)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
