project(lws-api-test-http-basic-auth C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-http-basic-auth)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)
require_lws_config(LWS_WITH_FILE_OPS 1 requirements)
require_lws_config(LWS_WITH_HTTP_BASIC_AUTH 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	lws_get_free_port(PORT_BA_H1)
	lws_get_free_port(PORT_BA_H2C)
	lws_get_free_port(PORT_BA_TLS)
	lws_get_free_port(PORT_BA_H3)

	add_test(NAME api-test-http-basic-auth
		 COMMAND lws-api-test-http-basic-auth
			 --server ${LWS_CTEST_SERVER_RESOLVE}
			 -p ${PORT_BA_H1} --h2c-port ${PORT_BA_H2C}
			 --tls-port ${PORT_BA_TLS} --h3-port ${PORT_BA_H3})
	set_tests_properties(api-test-http-basic-auth PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			     TIMEOUT 60)
endif()
