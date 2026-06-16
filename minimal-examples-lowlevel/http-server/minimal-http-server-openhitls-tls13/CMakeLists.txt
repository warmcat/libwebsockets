project(lws-minimal-http-server-tls13 C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-minimal-http-server-tls13)
set(SRCS minimal-http-server-openhitls-tls13.c)

set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_TLS 1 requirements)
require_lws_config(LWS_WITH_OPENHITLS 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	#
	# CTest configuration
	#
	if (NOT WIN32)
		set(PORT_OH_TLS13 "7782")
		if ("$ENV{SAI_INSTANCE_IDX}")
			math(EXPR PORT_OH_TLS13 "7783 + $ENV{SAI_INSTANCE_IDX}")
		endif()

		add_test(NAME http-server-tls13 COMMAND
			${SAMP} --port ${PORT_OH_TLS13})
		set_tests_properties(http-server-tls13 PROPERTIES
			WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/http-server/minimal-http-server-openhitls-tls13
			TIMEOUT 30)
	endif()
endif()
