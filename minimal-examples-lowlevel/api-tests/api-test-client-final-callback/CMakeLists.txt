project(lws-api-test-client-final-callback C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-client-final-callback)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_WITH_NETWORK 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITHOUT_SERVER 0 requirements)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_ROLE_WS 1 requirements)
require_lws_config(LWS_ROLE_RAW 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	lws_get_free_port(PORT_FCB_SILENT)
	lws_get_free_port(PORT_FCB_WS)
	# the silent nameserver, the only one lws's async dns may ask
	lws_get_free_port(PORT_FCB_DNS)

	add_test(NAME api-test-client-final-callback
		 COMMAND lws-api-test-client-final-callback
			 --port-silent ${PORT_FCB_SILENT}
			 --port-ws ${PORT_FCB_WS}
			 --server ${LWS_CTEST_SERVER_RESOLVE})
	set_tests_properties(api-test-client-final-callback
			     PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			     ENVIRONMENT "LWS_ASYNCDNS_PORT=${PORT_FCB_DNS}"
			     TIMEOUT 30)

	#
	# libuv finishes the closes later, from its own close callbacks
	#

	set(uv_requirements 1)
	require_lws_config(LWS_WITH_LIBUV 1 uv_requirements)

	if (uv_requirements)
		lws_get_free_port(PORT_FCB_SILENT_UV)
		lws_get_free_port(PORT_FCB_WS_UV)
		lws_get_free_port(PORT_FCB_DNS_UV)

		add_test(NAME api-test-client-final-callback-libuv
			 COMMAND lws-api-test-client-final-callback --uv
				 --port-silent ${PORT_FCB_SILENT_UV}
				 --port-ws ${PORT_FCB_WS_UV}
				 --server ${LWS_CTEST_SERVER_RESOLVE})
		set_tests_properties(api-test-client-final-callback-libuv
				     PROPERTIES
				     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
				     ENVIRONMENT "LD_LIBRARY_PATH=${CMAKE_BINARY_DIR}/lib;LWS_ASYNCDNS_PORT=${PORT_FCB_DNS_UV}"
				     TIMEOUT 30)
	endif()
endif()
