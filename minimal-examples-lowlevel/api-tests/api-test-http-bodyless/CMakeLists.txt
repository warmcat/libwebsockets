project(lws-api-test-http-bodyless C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-http-bodyless)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_ROLE_RAW 1 requirements)
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

	lws_get_free_port(PORT_BL_h1)

	add_test(NAME api-test-http-bodyless-h1
		 COMMAND lws-api-test-http-bodyless
			 -p ${PORT_BL_h1}
			 --server ${LWS_CTEST_SERVER_RESOLVE})
	set_tests_properties(api-test-http-bodyless-h1
			     PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
			     TIMEOUT 40)
endif()
