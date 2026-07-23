project(lws-minimal-http-client-h3 C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-minimal-http-client-h3)
set(SRCS minimal-http-client-h3.c)

set(requirements 1)
require_lws_config(LWS_ROLE_H3 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SYS_STATE 1 requirements)
require_lws_config(LWS_WITH_TLS 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	lws_get_free_port(PORT_H3_SRV)

	if (NOT WIN32 AND LWS_WITH_SERVER AND LWS_WITH_TLS)
		add_test(NAME st_hc_h3_srv COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh
					hc_h3_srv
					$<TARGET_FILE:test-server>
					-r ${CMAKE_BINARY_DIR}/share/libwebsockets-test-server/
					-s --port ${PORT_H3_SRV} )
		add_test(NAME ki_hc_h3_srv COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh hc_h3_srv
					$<TARGET_FILE_NAME:test-server> --port ${PORT_H3_SRV})

		set_tests_properties(st_hc_h3_srv PROPERTIES
							 WORKING_DIRECTORY .
							 FIXTURES_SETUP hc_h3_srv
							 TIMEOUT 800)
		set_tests_properties(ki_hc_h3_srv PROPERTIES
							 FIXTURES_CLEANUP hc_h3_srv)

		add_test(NAME minimal-http-client-h3 COMMAND lws-minimal-http-client-h3 -l --server ${LWS_CTEST_SERVER_RESOLVE} -p ${PORT_H3_SRV})
		set_tests_properties(minimal-http-client-h3
				     PROPERTIES
				     WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/http-client/minimal-http-client-h3
				     FIXTURES_REQUIRED "hc_h3_srv"
				     TIMEOUT 30)
	endif()
	target_include_directories(lws-minimal-http-client-h3 PRIVATE /lib)
endif()
