project(lws-api-test-http-tls-ah C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-http-tls-ah)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_ROLE_RAW 1 requirements)
require_lws_config(LWS_WITH_TLS 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)

set(TAH_H2 1)
require_lws_config(LWS_ROLE_H2 1 TAH_H2)

if (requirements)

	add_executable(${SAMP} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	set(TAH_CERTS ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/api-tests/api-test-ws-close)

	set(TAH_ROLES h1)
	if (TAH_H2)
		list(APPEND TAH_ROLES h2)
	endif()

	foreach(TAH_ROLE ${TAH_ROLES})
		set(TAH_ARGS)
		if (TAH_ROLE STREQUAL "h2")
			set(TAH_ARGS --h2)
		endif()

		lws_get_free_port(PORT_TAH_${TAH_ROLE})

		add_test(NAME api-test-http-tls-ah-${TAH_ROLE}
			 COMMAND lws-api-test-http-tls-ah ${TAH_ARGS}
				 -p ${PORT_TAH_${TAH_ROLE}}
				 --server ${LWS_CTEST_SERVER_RESOLVE}
				 --cert ${TAH_CERTS}/localhost-100y.cert
				 --key ${TAH_CERTS}/localhost-100y.key)
		set_tests_properties(api-test-http-tls-ah-${TAH_ROLE}
				     PROPERTIES
				     WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
				     TIMEOUT 30)
	endforeach()
endif()
