project(lws-api-test-ws-close C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-ws-close)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_ROLE_WS 1 requirements)
require_lws_config(LWS_ROLE_H2 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)
require_lws_config(LWS_WITH_TLS 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	lws_get_free_port(PORT_WS_CLOSE)

	#
	# direct legs: h1 and ws-over-h2, client- and server-initiated close
	#
	add_test(NAME api-test-ws-close COMMAND lws-api-test-ws-close --server ${LWS_CTEST_SERVER_RESOLVE} -p ${PORT_WS_CLOSE})
	set_tests_properties(api-test-ws-close
			     PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/api-tests/api-test-ws-close
			     TIMEOUT 60)

	#
	# proxied legs: the same through an http CONNECT proxy and socks5
	# (no auth, and username/password), served by proxy-fixture.py
	#
	find_program(PYTHON3_FOR_FIXTURE python3)
	if (PYTHON3_FOR_FIXTURE AND NOT WIN32)
		lws_get_free_port(PORT_WS_CLOSE_PX)
		lws_get_free_port(PORT_WS_CLOSE_PROXY)
		lws_get_free_port(PORT_WS_CLOSE_PROXY_AUTH)

		add_test(NAME st_wsclose_proxy COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh
			wsclose_proxy ${PYTHON3_FOR_FIXTURE}
			${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/api-tests/api-test-ws-close/proxy-fixture.py
			--port ${PORT_WS_CLOSE_PROXY} --auth-port ${PORT_WS_CLOSE_PROXY_AUTH})
		add_test(NAME ki_wsclose_proxy COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh
			wsclose_proxy ${PYTHON3_FOR_FIXTURE})
		set_tests_properties(st_wsclose_proxy PROPERTIES
				     WORKING_DIRECTORY . FIXTURES_SETUP wsclose_proxy TIMEOUT 60
				     ENVIRONMENT "SAI_LIST_PORT=${PORT_WS_CLOSE_PROXY}")
		set_tests_properties(ki_wsclose_proxy PROPERTIES FIXTURES_CLEANUP wsclose_proxy)

		add_test(NAME api-test-ws-close-proxied COMMAND lws-api-test-ws-close
			 --server 127.0.0.1 -p ${PORT_WS_CLOSE_PX}
			 --proxy 127.0.0.1:${PORT_WS_CLOSE_PROXY}
			 --socks 127.0.0.1:${PORT_WS_CLOSE_PROXY}
			 --socks-auth 127.0.0.1:${PORT_WS_CLOSE_PROXY_AUTH})
		set_tests_properties(api-test-ws-close-proxied
				     PROPERTIES
				     WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/api-tests/api-test-ws-close
				     FIXTURES_REQUIRED "wsclose_proxy"
				     TIMEOUT 60)
	endif()
endif()
