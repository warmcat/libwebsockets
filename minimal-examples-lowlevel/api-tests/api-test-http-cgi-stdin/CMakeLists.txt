project(lws-api-test-http-cgi-stdin C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)
include(CTest)

set(SAMP lws-api-test-http-cgi-stdin)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_WITH_NETWORK 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITHOUT_SERVER 0 requirements)
require_lws_config(LWS_WITH_CGI 1 requirements)
require_lws_config(LWS_WITH_SPAWN 1 requirements)

if (requirements)

	#
	# bake the absolute path of the posix cgi helper script in next to
	# this test into the test binary, so it is independent of cwd
	#

	if (WIN32)
		string(REPLACE "\\" "/" CGI_SCRIPT_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cgi.sh")
	else()
		set(CGI_SCRIPT_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cgi.sh")
	endif()

	add_executable(${SAMP} ${SRCS})
	target_compile_definitions(${SAMP} PRIVATE
				    CGI_SCRIPT_PATH="${CGI_SCRIPT_PATH}")

	if (NOT WIN32)
		# the cgi helper script needs a posix sh
		lws_get_free_port(PORT_HTTP_CGI_STDIN)

		add_test(NAME api-test-http-cgi-stdin
			 COMMAND lws-api-test-http-cgi-stdin -p ${PORT_HTTP_CGI_STDIN})
		set_tests_properties(api-test-http-cgi-stdin PROPERTIES
				     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
				     TIMEOUT 60)
	endif()

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
