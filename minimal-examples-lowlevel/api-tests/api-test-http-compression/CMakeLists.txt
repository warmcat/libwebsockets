project(lws-api-test-http-compression C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)
include(CTest)

set(SAMP lws-api-test-http-compression)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_WITH_NETWORK 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITHOUT_SERVER 0 requirements)
require_lws_config(LWS_WITH_HTTP_STREAM_COMPRESSION 1 requirements)
# lws_genhash, for the digest, comes from the tls library
require_lws_config(LWS_WITH_TLS 1 requirements)
require_lws_config(LWS_WITH_GENCRYPTO 1 requirements)

if (requirements AND NOT WIN32)

	add_executable(${SAMP} ${SRCS})

	#
	# the client side decodes what the server compressed with the same
	# libraries lws used to compress it
	#

	find_package(ZLIB REQUIRED)
	set(EXTRA_INCS ${ZLIB_INCLUDE_DIRS})
	set(EXTRA_LIBS ${ZLIB_LIBRARIES})

	set(has_brotli 1)
	require_lws_config(LWS_WITH_HTTP_BROTLI 1 has_brotli)
	if (has_brotli)
		list(APPEND EXTRA_LIBS brotlidec)
	endif()

	target_include_directories(${SAMP} PRIVATE ${EXTRA_INCS})

	#
	# with h3, the h3 cases get a tls vhost of their own
	#
	set(has_h3 1)
	require_lws_config(LWS_ROLE_H3 1 has_h3)
	set(HTTP_COMP_CERTS ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/api-tests/api-test-ws-close)

	lws_get_free_port(PORT_HTTP_COMP_H1)
	lws_get_free_port(PORT_HTTP_COMP_H2)
	lws_get_free_port(PORT_HTTP_COMP_NC_H1)
	lws_get_free_port(PORT_HTTP_COMP_NC_H2)
	set(HTTP_COMP_H3_ARGS)
	if (has_h3)
		lws_get_free_port(PORT_HTTP_COMP_H3)
		set(HTTP_COMP_H3_ARGS --h3-port ${PORT_HTTP_COMP_H3}
			--cert ${HTTP_COMP_CERTS}/localhost-100y.cert
			--key ${HTTP_COMP_CERTS}/localhost-100y.key)
	endif()

	add_test(NAME api-test-http-compression
		 COMMAND lws-api-test-http-compression -p ${PORT_HTTP_COMP_H1}
			 --h2-port ${PORT_HTTP_COMP_H2}
			 --nc-port ${PORT_HTTP_COMP_NC_H1}
			 --nc-h2-port ${PORT_HTTP_COMP_NC_H2}
			 ${HTTP_COMP_H3_ARGS}
			 --tmpdir ${CMAKE_CURRENT_BINARY_DIR})
	set_tests_properties(api-test-http-compression PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			     TIMEOUT 120)

	#
	# an empty file: nothing for the compressor but the end of the
	# stream, which must still end the body (the last chunk on h1)
	#
	lws_get_free_port(PORT_HTTP_COMP_E_H1)
	lws_get_free_port(PORT_HTTP_COMP_E_H2)
	lws_get_free_port(PORT_HTTP_COMP_E_NC_H1)
	lws_get_free_port(PORT_HTTP_COMP_E_NC_H2)
	set(HTTP_COMP_E_H3_ARGS)
	if (has_h3)
		lws_get_free_port(PORT_HTTP_COMP_E_H3)
		set(HTTP_COMP_E_H3_ARGS --h3-port ${PORT_HTTP_COMP_E_H3}
			--cert ${HTTP_COMP_CERTS}/localhost-100y.cert
			--key ${HTTP_COMP_CERTS}/localhost-100y.key)
	endif()

	add_test(NAME api-test-http-compression-empty
		 COMMAND lws-api-test-http-compression -p ${PORT_HTTP_COMP_E_H1}
			 --h2-port ${PORT_HTTP_COMP_E_H2}
			 --nc-port ${PORT_HTTP_COMP_E_NC_H1}
			 --nc-h2-port ${PORT_HTTP_COMP_E_NC_H2} --size 0
			 ${HTTP_COMP_E_H3_ARGS}
			 --tmpdir ${CMAKE_CURRENT_BINARY_DIR})
	set_tests_properties(api-test-http-compression-empty PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			     TIMEOUT 120)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared
				      ${LIBWEBSOCKETS_DEP_LIBS} ${EXTRA_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets
				      ${LIBWEBSOCKETS_DEP_LIBS} ${EXTRA_LIBS})
	endif()
endif()
