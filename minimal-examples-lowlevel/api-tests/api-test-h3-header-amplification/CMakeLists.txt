project(lws-api-test-h3-header-amplification C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-h3-header-amplification)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_ROLE_H3 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	lws_get_free_port(PORT_HAMP_H3)
	lws_get_free_port(PORT_HAMP_H3_SMALL)

	add_test(NAME api-test-h3-header-amplification
		 COMMAND lws-api-test-h3-header-amplification
			 --server ${LWS_CTEST_SERVER_RESOLVE}
			 -p ${PORT_HAMP_H3} --small-port ${PORT_HAMP_H3_SMALL})
	set_tests_properties(api-test-h3-header-amplification PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			     TIMEOUT 120)
endif()
