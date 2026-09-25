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

	lws_get_free_port(PORT_HTTP_COMP_H1)
	lws_get_free_port(PORT_HTTP_COMP_H2)

	add_test(NAME api-test-http-compression
		 COMMAND lws-api-test-http-compression -p ${PORT_HTTP_COMP_H1}
			 --h2-port ${PORT_HTTP_COMP_H2}
			 --tmpdir ${CMAKE_CURRENT_BINARY_DIR})
	set_tests_properties(api-test-http-compression PROPERTIES
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
