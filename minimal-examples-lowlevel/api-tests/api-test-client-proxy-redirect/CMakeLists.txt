project(lws-api-test-client-proxy-redirect C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-client-proxy-redirect)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)
require_lws_config(LWS_CLIENT_HTTP_PROXYING 1 requirements)

#
# The proxies are api-test-ws-close's proxy-fixture.py: an http CONNECT and
# SOCKS5 proxy in one process
#
find_program(PYTHON3_FOR_FIXTURE python3)

if (requirements AND PYTHON3_FOR_FIXTURE AND NOT WIN32)
	add_executable(${SAMP} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	lws_get_free_port(PORT_CPR)
	lws_get_free_port(PORT_CPR2)
	lws_get_free_port(PORT_CPR_PROXY)
	lws_get_free_port(PORT_CPR_RAW)
	lws_get_free_port(PORT_CPR_RAW_TLS)

	add_test(NAME st_cprx_proxy COMMAND
		${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh
		cprx_proxy ${PYTHON3_FOR_FIXTURE}
		${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/api-tests/api-test-ws-close/proxy-fixture.py
		--port ${PORT_CPR_PROXY})
	add_test(NAME ki_cprx_proxy COMMAND
		${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh
		cprx_proxy ${PYTHON3_FOR_FIXTURE})
	set_tests_properties(st_cprx_proxy PROPERTIES
			     WORKING_DIRECTORY . FIXTURES_SETUP cprx_proxy TIMEOUT 60
			     ENVIRONMENT "SAI_LIST_PORT=${PORT_CPR_PROXY}")
	set_tests_properties(ki_cprx_proxy PROPERTIES FIXTURES_CLEANUP cprx_proxy)

	#
	# The raw origin's tls uses api-test-ws-close's test certificate too
	#
	set(CPRX_CERTS ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/api-tests/api-test-ws-close)

	add_test(NAME api-test-client-proxy-redirect
		 COMMAND lws-api-test-client-proxy-redirect
			 -p ${PORT_CPR} --port2 ${PORT_CPR2}
			 --port-raw ${PORT_CPR_RAW}
			 --port-raw-tls ${PORT_CPR_RAW_TLS}
			 --cert ${CPRX_CERTS}/localhost-100y.cert
			 --key ${CPRX_CERTS}/localhost-100y.key
			 --proxy 127.0.0.1:${PORT_CPR_PROXY})
	set_tests_properties(api-test-client-proxy-redirect
			     PROPERTIES
			     WORKING_DIRECTORY .
			     FIXTURES_REQUIRED "cprx_proxy"
			     TIMEOUT 60)
endif()
