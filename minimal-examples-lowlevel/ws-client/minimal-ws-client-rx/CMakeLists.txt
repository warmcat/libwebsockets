project(lws-minimal-ws-client-rx C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-minimal-ws-client-rx)
set(SRCS minimal-ws-client.c)

set(requirements 1)
require_lws_config(LWS_ROLE_WS 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})
	set(PORT_WSC_RX_SRV "10120")
	if ("$ENV{SAI_INSTANCE_IDX}")
		math(EXPR PORT_WSC_RX_SRV "10121 + ($ENV{SAI_INSTANCE_IDX} * 1000)")
	endif()

	if (NOT WIN32 AND LWS_WITH_SERVER AND LWS_WITH_TLS)
		add_test(NAME st_wsc_rx_srv COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh
					wsc_rx_srv
					$<TARGET_FILE:test-server>
					-r ${CMAKE_BINARY_DIR}/share/libwebsockets-test-server/
					-s --port ${PORT_WSC_RX_SRV} )
		add_test(NAME ki_wsc_rx_srv COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh wsc_rx_srv
					$<TARGET_FILE_NAME:test-server> --port ${PORT_WSC_RX_SRV})

		set_tests_properties(st_wsc_rx_srv PROPERTIES
							 WORKING_DIRECTORY .
							 FIXTURES_SETUP wsc_rx_srv
							 TIMEOUT 800)
		set_tests_properties(ki_wsc_rx_srv PROPERTIES
							 FIXTURES_CLEANUP wsc_rx_srv)

		add_test(NAME ws-client-rx-warmcat COMMAND lws-minimal-ws-client-rx -t -l --server localhost -p ${PORT_WSC_RX_SRV})
		set_tests_properties(ws-client-rx-warmcat
				     PROPERTIES
				     WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/ws-client/minimal-ws-client-rx
				     FIXTURES_REQUIRED "wsc_rx_srv"
				     TIMEOUT 20)

	endif()

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
