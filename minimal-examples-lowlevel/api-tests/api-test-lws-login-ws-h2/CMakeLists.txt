project(lws-api-test-lws-login-ws-h2 C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-lws-login-ws-h2)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_ROLE_H2 1 requirements)
require_lws_config(LWS_ROLE_WS 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)
require_lws_config(LWS_WITH_TLS 1 requirements)
require_lws_config(LWS_WITH_JOSE 1 requirements)
# the real lws-login plugin protocol must be in the vhost protocol table
require_lws_config(LWS_WITH_PLUGINS_BUILTIN 1 requirements)
# protocol_lws_login only builds with lws_struct JSON, for the auth feed
require_lws_config(LWS_WITH_STRUCT_JSON 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	lws_get_free_port(PORT_LOGIN_WS_H2)

	add_test(NAME api-test-lws-login-ws-h2
		 COMMAND lws-api-test-lws-login-ws-h2
			 --server ${LWS_CTEST_SERVER_RESOLVE} -p ${PORT_LOGIN_WS_H2})
	set_tests_properties(api-test-lws-login-ws-h2 PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			     TIMEOUT 60)
endif()
