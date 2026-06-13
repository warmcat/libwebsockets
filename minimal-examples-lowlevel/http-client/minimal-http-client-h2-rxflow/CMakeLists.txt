project(lws-minimal-http-client-h2-rxflow C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-minimal-http-client-h2-rxflow)
set(SRCS minimal-http-client.c)

set(requirements 1)
require_lws_config(LWS_ROLE_H2 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SYS_STATE 1 requirements)
require_lws_config(LWS_WITH_TLS 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})
	set(PORT_HC_RXFLOW_SRV "10020")
	if ("$ENV{SAI_INSTANCE_IDX}")
		math(EXPR PORT_HC_RXFLOW_SRV "10021 + ($ENV{SAI_INSTANCE_IDX} * 1000)")
	endif()

	if (NOT WIN32 AND LWS_WITH_SERVER AND LWS_WITH_TLS)
		add_test(NAME st_hc_rxflow_srv COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh
					hc_rxflow_srv
					$<TARGET_FILE:test-server>
					-r ${CMAKE_BINARY_DIR}/share/libwebsockets-test-server/
					-s --port ${PORT_HC_RXFLOW_SRV} )
		add_test(NAME ki_hc_rxflow_srv COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh hc_rxflow_srv
					$<TARGET_FILE_NAME:test-server> --port ${PORT_HC_RXFLOW_SRV})

		set_tests_properties(st_hc_rxflow_srv PROPERTIES
							 WORKING_DIRECTORY .
							 FIXTURES_SETUP hc_rxflow_srv
							 TIMEOUT 800)
		set_tests_properties(ki_hc_rxflow_srv PROPERTIES
							 FIXTURES_CLEANUP hc_rxflow_srv)

		add_test(NAME http-client-h2-rxflow-warmcat COMMAND lws-minimal-http-client-h2-rxflow -l --server localhost -p ${PORT_HC_RXFLOW_SRV})
		add_test(NAME http-client-h2-rxflow-warmcat-h1 COMMAND lws-minimal-http-client-h2-rxflow -l --server localhost -p ${PORT_HC_RXFLOW_SRV} --h1)
		set_tests_properties(http-client-h2-rxflow-warmcat
				     http-client-h2-rxflow-warmcat-h1
				     PROPERTIES
				     WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/http-client/minimal-http-client-h2-rxflow
				     FIXTURES_REQUIRED "hc_rxflow_srv"
				     TIMEOUT 30)
	endif()

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
