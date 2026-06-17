project(lws-minimal-http-server-sni-mismatch C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-minimal-http-server-sni-mismatch)
set(SRCS minimal-http-server-openhitls-sni-mismatch.c)

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
		lws_get_free_port(PORT_OH_SNI_MISMATCH)

		add_test(NAME http-server-sni-mismatch COMMAND
			${SAMP} --port ${PORT_OH_SNI_MISMATCH})
		set_tests_properties(http-server-sni-mismatch PROPERTIES
			WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/http-server/minimal-http-server-openhitls-sni-mismatch
			TIMEOUT 30)
	endif()
endif()
