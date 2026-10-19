project(lws-api-test-deaddrop C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-deaddrop)
set(SRCS main.c)

#
# The deaddrop plugin is built into this test, so it needs what the plugin
# needs (plugins/protocol_deaddrop/CMakeLists.txt), plus a client and basic
# auth to drive it as several users
#
set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_ROLE_WS 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)
require_lws_config(LWS_WITH_JOSE 1 requirements)
require_lws_config(LWS_WITH_LEJP 1 requirements)
require_lws_config(LWS_WITH_HTTP_BASIC_AUTH 1 requirements)
require_lws_config(LWS_WITH_FILE_OPS 1 requirements)

if (requirements AND UNIX AND LWS_HAVE_PTHREAD_H)
	add_executable(${SAMP} ${SRCS})
	target_include_directories(${SAMP} PRIVATE
		${CMAKE_SOURCE_DIR}/plugins/protocol_deaddrop)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	lws_get_free_port(PORT_DEADDROP)

	add_test(NAME api-test-deaddrop
		 COMMAND lws-api-test-deaddrop
			 --server ${LWS_CTEST_SERVER_RESOLVE}
			 -p ${PORT_DEADDROP}
			 --upload-dir ${CMAKE_CURRENT_BINARY_DIR}/upload
			 --passwords ${CMAKE_CURRENT_SOURCE_DIR}/ba-passwords)
	set_tests_properties(api-test-deaddrop PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
			     TIMEOUT 60)
endif()
