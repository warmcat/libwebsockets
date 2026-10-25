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

		set(has_put 1)
		require_lws_config(LWS_WITH_HTTP_UNCOMMON_HEADERS 1 has_put)
		if (has_put)
			# a PUT with a body, and one saying Content-Length: 0
			foreach(CGI_CASE put put-cl0)
				lws_get_free_port(PORT_HTTP_CGI_${CGI_CASE})

				add_test(NAME api-test-http-cgi-${CGI_CASE}
					 COMMAND lws-api-test-http-cgi-stdin
						 --${CGI_CASE}
						 -p ${PORT_HTTP_CGI_${CGI_CASE}})
				set_tests_properties(api-test-http-cgi-${CGI_CASE}
						     PROPERTIES
						     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
						     TIMEOUT 60)
			endforeach()
		endif()

		lws_get_free_port(PORT_HTTP_CGI_PIPELINED)

		add_test(NAME api-test-http-cgi-pipelined
			 COMMAND lws-api-test-http-cgi-stdin --pipelined
				 -p ${PORT_HTTP_CGI_PIPELINED})
		set_tests_properties(api-test-http-cgi-pipelined PROPERTIES
				     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
				     TIMEOUT 60)

		lws_get_free_port(PORT_HTTP_CGI_QUERY)

		add_test(NAME api-test-http-cgi-query
			 COMMAND lws-api-test-http-cgi-stdin --query
				 -p ${PORT_HTTP_CGI_QUERY})
		set_tests_properties(api-test-http-cgi-query PROPERTIES
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

			lws_get_free_port(PORT_HTTP_CGI_H2_POST)

			add_test(NAME api-test-http-cgi-h2-post
				 COMMAND lws-api-test-http-cgi-stdin --h2-post
					 -p ${PORT_HTTP_CGI_H2_POST})
			set_tests_properties(api-test-http-cgi-h2-post PROPERTIES
					     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
					     TIMEOUT 60)

			lws_get_free_port(PORT_HTTP_CGI_H2_POST_STREAM)

			add_test(NAME api-test-http-cgi-h2-post-stream
				 COMMAND lws-api-test-http-cgi-stdin --h2-post-stream
					 -p ${PORT_HTTP_CGI_H2_POST_STREAM})
			set_tests_properties(api-test-http-cgi-h2-post-stream PROPERTIES
					     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
					     TIMEOUT 60)

			lws_get_free_port(PORT_HTTP_CGI_H2_POST_CL0)

			add_test(NAME api-test-http-cgi-h2-post-cl0
				 COMMAND lws-api-test-http-cgi-stdin --h2-post-cl0
					 -p ${PORT_HTTP_CGI_H2_POST_CL0})
			set_tests_properties(api-test-http-cgi-h2-post-cl0 PROPERTIES
					     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
					     TIMEOUT 60)

			if (has_put)
				lws_get_free_port(PORT_HTTP_CGI_H2_PUT_CL0)

				add_test(NAME api-test-http-cgi-h2-put-cl0
					 COMMAND lws-api-test-http-cgi-stdin
						 --h2-put-cl0
						 -p ${PORT_HTTP_CGI_H2_PUT_CL0})
				set_tests_properties(api-test-http-cgi-h2-put-cl0
						     PROPERTIES
						     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
						     TIMEOUT 60)
			endif()

			lws_get_free_port(PORT_HTTP_CGI_H2_SLOW_POST)

			add_test(NAME api-test-http-cgi-h2-slow-post
				 COMMAND lws-api-test-http-cgi-stdin --h2-slow-post
					 -p ${PORT_HTTP_CGI_H2_SLOW_POST})
			set_tests_properties(api-test-http-cgi-h2-slow-post PROPERTIES
					     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
					     TIMEOUT 60)

			# the same, ended by an empty DATA after the body
			lws_get_free_port(PORT_HTTP_CGI_H2_POST_STREAM_END)

			add_test(NAME api-test-http-cgi-h2-post-stream-end
				 COMMAND lws-api-test-http-cgi-stdin
					 --h2-post-stream-end
					 -p ${PORT_HTTP_CGI_H2_POST_STREAM_END})
			set_tests_properties(api-test-http-cgi-h2-post-stream-end
					     PROPERTIES
					     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
					     TIMEOUT 60)
		endif()

		# a POST saying Content-Length: 0, an h1 POST that waits
		# for the 100 Continue its Expect: 100-continue asks for, a
		# script answer with no Content-Length, and a script that is
		# quiet for longer than the context's timeout_secs before it
		# answers
		foreach(CGI_CASE post-cl0 expect-continue nolen slow-post)
			lws_get_free_port(PORT_HTTP_CGI_${CGI_CASE})

			add_test(NAME api-test-http-cgi-${CGI_CASE}
				 COMMAND lws-api-test-http-cgi-stdin --${CGI_CASE}
					 -p ${PORT_HTTP_CGI_${CGI_CASE}})
			set_tests_properties(api-test-http-cgi-${CGI_CASE}
					     PROPERTIES
					     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
					     TIMEOUT 60)
		endforeach()

		# the same over h3, with the server on a test cert
		set(has_h3 1)
		require_lws_config(LWS_ROLE_H3 1 has_h3)
		if (has_h3)
			set(CGI_CERTS ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/api-tests/api-test-ws-close)

			foreach(CGI_CASE h3-post h3-nolen)
				lws_get_free_port(PORT_HTTP_CGI_${CGI_CASE})

				add_test(NAME api-test-http-cgi-${CGI_CASE}
					 COMMAND lws-api-test-http-cgi-stdin
						 --${CGI_CASE}
						 -p ${PORT_HTTP_CGI_${CGI_CASE}}
						 --cert ${CGI_CERTS}/localhost-100y.cert
						 --key ${CGI_CERTS}/localhost-100y.key)
				set_tests_properties(api-test-http-cgi-${CGI_CASE}
						     PROPERTIES
						     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
						     TIMEOUT 60)
			endforeach()
		endif()

		lws_get_free_port(PORT_HTTP_CGI_ABANDON)

		add_test(NAME api-test-http-cgi-abandon
			 COMMAND lws-api-test-http-cgi-stdin --abandon
				 -p ${PORT_HTTP_CGI_ABANDON})
		set_tests_properties(api-test-http-cgi-abandon PROPERTIES
				     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
				     TIMEOUT 120)

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
