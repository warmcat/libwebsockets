project(lws-api-test-http-h2c-mount C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-http-h2c-mount)
set(SRCS main.c)

#
# An h1 request upgrading to h2c lands in the mount its path does, even if
# that mount is passed over for websocket upgrades
#
set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_ROLE_H2 1 requirements)
require_lws_config(LWS_ROLE_RAW 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)
require_lws_config(LWS_WITH_FILE_OPS 1 requirements)

if (requirements AND NOT WIN32)
	add_executable(${SAMP} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	# the test files are made in the working directory
	add_test(NAME api-test-http-h2c-mount
		 COMMAND lws-api-test-http-h2c-mount
			 --server ${LWS_CTEST_SERVER_RESOLVE})
	set_tests_properties(api-test-http-h2c-mount
			     PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
			     TIMEOUT 30)
endif()
