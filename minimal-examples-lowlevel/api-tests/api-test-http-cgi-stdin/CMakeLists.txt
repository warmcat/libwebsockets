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

		lws_get_free_port(PORT_HTTP_CGI_STDIN_CHUNKED)

		add_test(NAME api-test-http-cgi-stdin-chunked
			 COMMAND lws-api-test-http-cgi-stdin --chunked
				 -p ${PORT_HTTP_CGI_STDIN_CHUNKED})
		set_tests_properties(api-test-http-cgi-stdin-chunked PROPERTIES
				     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
				     TIMEOUT 60)

		lws_get_free_port(PORT_HTTP_CGI_NO_HEADERS)

		add_test(NAME api-test-http-cgi-no-headers
			 COMMAND lws-api-test-http-cgi-stdin --no-headers
				 -p ${PORT_HTTP_CGI_NO_HEADERS})
		set_tests_properties(api-test-http-cgi-no-headers PROPERTIES
				     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
				     TIMEOUT 60)

		set(has_h2 1)
		require_lws_config(LWS_ROLE_H2 1 has_h2)
		if (has_h2)
			lws_get_free_port(PORT_HTTP_CGI_H2_STARVE)

			add_test(NAME api-test-http-cgi-h2-starve
				 COMMAND lws-api-test-http-cgi-stdin --h2-starve
					 -p ${PORT_HTTP_CGI_H2_STARVE})
			set_tests_properties(api-test-http-cgi-h2-starve PROPERTIES
					     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
					     TIMEOUT 60)
		endif()

		lws_get_free_port(PORT_HTTP_CGI_FD_BUDGET)

		add_test(NAME api-test-http-cgi-fd-budget
			 COMMAND lws-api-test-http-cgi-stdin --fd-budget
				 -p ${PORT_HTTP_CGI_FD_BUDGET})
		set_tests_properties(api-test-http-cgi-fd-budget PROPERTIES
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
