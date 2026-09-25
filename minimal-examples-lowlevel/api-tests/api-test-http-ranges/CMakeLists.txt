project(lws-api-test-http-ranges C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)
include(CTest)

set(SAMP lws-api-test-http-ranges)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_WITH_NETWORK 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_FILE_OPS 1 requirements)
require_lws_config(LWS_WITH_RANGES 1 requirements)
require_lws_config(LWS_WITHOUT_SERVER 0 requirements)

if (requirements)

	add_executable(${SAMP} ${SRCS})

	lws_get_free_port(PORT_HTTP_RANGES_H1)
	lws_get_free_port(PORT_HTTP_RANGES_H2)
	lws_get_free_port(PORT_HTTP_RANGES_SB_H1)
	lws_get_free_port(PORT_HTTP_RANGES_SB_H2)

	add_test(NAME api-test-http-ranges
		 COMMAND lws-api-test-http-ranges -p ${PORT_HTTP_RANGES_H1}
			 --h2-port ${PORT_HTTP_RANGES_H2}
			 --tmpdir ${CMAKE_CURRENT_BINARY_DIR})
	set_tests_properties(api-test-http-ranges PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			     TIMEOUT 300)

	#
	# The same cases with the pt serv_buf at its floor: the part header,
	# the payload and the close delimiter are then up against the end of
	# the buffer on every write of a multipart response
	#

	add_test(NAME api-test-http-ranges-small-buf
		 COMMAND lws-api-test-http-ranges -p ${PORT_HTTP_RANGES_SB_H1}
			 --h2-port ${PORT_HTTP_RANGES_SB_H2}
			 --serv-buf 1280
			 --tmpdir ${CMAKE_CURRENT_BINARY_DIR})
	set_tests_properties(api-test-http-ranges-small-buf PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			     TIMEOUT 300)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
