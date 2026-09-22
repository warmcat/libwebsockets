project(lws-api-test-raw-close C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)
include(CTest)

set(SAMP lws-api-test-raw-close)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_ROLE_RAW 1 requirements)
require_lws_config(LWS_WITH_NETWORK 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITHOUT_SERVER 0 requirements)

if (requirements)

	add_executable(${SAMP} ${SRCS})

	lws_get_free_port(PORT_RAW_CLOSE)

	add_test(NAME api-test-raw-close
		 COMMAND lws-api-test-raw-close -p ${PORT_RAW_CLOSE})

	# the same again through a socks5 proxy, served by
	# api-test-ws-close's proxy-fixture.py
	find_program(PYTHON3_FOR_FIXTURE python3)
	if (PYTHON3_FOR_FIXTURE AND NOT WIN32 AND LWS_WITH_SOCKS5)
		lws_get_free_port(PORT_RAW_CLOSE_S)
		lws_get_free_port(PORT_RAW_CLOSE_SOCKS)

		add_test(NAME st_rawclose_proxy COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh
			rawclose_proxy ${PYTHON3_FOR_FIXTURE}
			${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/api-tests/api-test-ws-close/proxy-fixture.py
			--port ${PORT_RAW_CLOSE_SOCKS})
		add_test(NAME ki_rawclose_proxy COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh
			rawclose_proxy ${PYTHON3_FOR_FIXTURE})
		set_tests_properties(st_rawclose_proxy PROPERTIES
				     WORKING_DIRECTORY . FIXTURES_SETUP rawclose_proxy TIMEOUT 60
				     ENVIRONMENT "SAI_LIST_PORT=${PORT_RAW_CLOSE_SOCKS}")
		set_tests_properties(ki_rawclose_proxy PROPERTIES FIXTURES_CLEANUP rawclose_proxy)

		add_test(NAME api-test-raw-close-socks COMMAND lws-api-test-raw-close
			 -p ${PORT_RAW_CLOSE_S} --socks 127.0.0.1:${PORT_RAW_CLOSE_SOCKS})
		set_tests_properties(api-test-raw-close-socks PROPERTIES
				     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
				     FIXTURES_REQUIRED "rawclose_proxy"
				     TIMEOUT 60)
	endif()
	set_tests_properties(api-test-raw-close PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			     TIMEOUT 60)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
