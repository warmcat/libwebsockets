project(lws-api-test-h2-stream-reset C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-h2-stream-reset)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_ROLE_H2 1 requirements)
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

	foreach(case ping hpack ignored reset)
		lws_get_free_port(PORT_H2_STREAM_RESET_${case})

		add_test(NAME api-test-h2-stream-reset-${case}
			 COMMAND lws-api-test-h2-stream-reset --case ${case}
				 -p ${PORT_H2_STREAM_RESET_${case}}
				 --server ${LWS_CTEST_SERVER_RESOLVE})
		set_tests_properties(api-test-h2-stream-reset-${case} PROPERTIES
				     WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
				     TIMEOUT 30)
	endforeach()

endif()
