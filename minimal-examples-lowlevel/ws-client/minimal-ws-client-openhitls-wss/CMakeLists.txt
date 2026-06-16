project(lws-minimal-ws-client-wss C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-minimal-ws-client-wss)
set(SRCS minimal-ws-client-openhitls-wss.c)

set(requirements 1)
require_lws_config(LWS_ROLE_WS 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)
require_lws_config(LWS_WITH_OPENHITLS 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	set(PORT_OHWSS_SRV "7720")
	if ("$ENV{SAI_INSTANCE_IDX}")
		math(EXPR PORT_OHWSS_SRV "7721 + $ENV{SAI_INSTANCE_IDX}")
	endif()

	if (NOT WIN32)
		add_test(NAME ws-client-wss-positive COMMAND
			lws-minimal-ws-client-wss
				--port ${PORT_OHWSS_SRV})
		set_tests_properties(ws-client-wss-positive PROPERTIES
			WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
			TIMEOUT 20)
	endif()

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
