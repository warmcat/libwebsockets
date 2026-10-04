project(lws-api-test-raw-proxy C)
cmake_minimum_required(VERSION 3.10)
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(requirements 1)
require_lws_config(LWS_ROLE_RAW_PROXY 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)
require_lws_config(LWS_WITH_TLS 1 requirements)

if (requirements)
	add_executable(${PROJECT_NAME} main.c)
	# the raw proxy protocol plugin, built in
	target_include_directories(${PROJECT_NAME} PRIVATE
		${CMAKE_SOURCE_DIR}/plugins/protocol_lws_raw_proxy)

	if (websockets_shared)
		target_link_libraries(${PROJECT_NAME} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${PROJECT_NAME} websockets_shared)
	else()
		target_link_libraries(${PROJECT_NAME} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	lws_get_free_port(PORT_RAWPX_ORIGIN)
	lws_get_free_port(PORT_RAWPX_ORIGIN_TLS)
	lws_get_free_port(PORT_RAWPX_PROXY)
	lws_get_free_port(PORT_RAWPX_FALLBACK)

	# the origin's tls uses api-test-ws-close's test certificate
	set(RAWPX_CERTS ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/api-tests/api-test-ws-close)

	add_test(NAME api-test-raw-proxy
		 COMMAND lws-api-test-raw-proxy
			 -p ${PORT_RAWPX_ORIGIN}
			 --port-tls ${PORT_RAWPX_ORIGIN_TLS}
			 --port-proxy ${PORT_RAWPX_PROXY}
			 --port-fallback ${PORT_RAWPX_FALLBACK}
			 --cert ${RAWPX_CERTS}/localhost-100y.cert
			 --key ${RAWPX_CERTS}/localhost-100y.key)
	set_tests_properties(api-test-raw-proxy PROPERTIES
			     WORKING_DIRECTORY . TIMEOUT 30)
endif()
