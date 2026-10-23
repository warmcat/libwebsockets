project(lws-api-test-webrtc-session-caps C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

#
# The lws-webrtc protocol is built into the test from the plugin's source,
# so it runs whether or not plugins are built as shared objects
#

set(SAMP lws-api-test-webrtc-session-caps)
set(SRCS main.c
	 ../../../plugins/protocol_lws_webrtc/protocol_lws_webrtc.c)

set(requirements 1)
require_lws_config(LWS_WITH_WEBRTC 1 requirements)
require_lws_config(LWS_ROLE_WS 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)

if (requirements)

	add_executable(${SAMP} ${SRCS})
	target_include_directories(${SAMP} PRIVATE
		${CMAKE_SOURCE_DIR}/plugins/protocol_lws_webrtc)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared
			${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets
			${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	foreach(case host total)
		lws_get_free_port(PORT_WEBRTC_CAPS_${case})
		lws_get_free_port(PORT_WEBRTC_CAPS_UDP_${case})

		add_test(NAME api-test-webrtc-session-caps-${case}
			 COMMAND lws-api-test-webrtc-session-caps --case ${case}
				 -p ${PORT_WEBRTC_CAPS_${case}}
				 -u ${PORT_WEBRTC_CAPS_UDP_${case}})
		set_tests_properties(api-test-webrtc-session-caps-${case}
				     PROPERTIES
				     WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
				     TIMEOUT 30)
	endforeach()

endif()
