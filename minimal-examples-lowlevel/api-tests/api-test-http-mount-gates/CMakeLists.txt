project(lws-api-test-http-mount-gates C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-http-mount-gates)
set(SRCS main.c)

#
# Every request for a mount's path meets its gates, and a mount whose gates
# would not be applied is refused when the vhost is created
#
set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_ROLE_WS 1 requirements)
require_lws_config(LWS_ROLE_RAW 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)
# interceptor_path is only in lws_http_mount with JOSE
require_lws_config(LWS_WITH_JOSE 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	add_test(NAME api-test-http-mount-gates
		 COMMAND lws-api-test-http-mount-gates
			 --server ${LWS_CTEST_SERVER_RESOLVE})
	set_tests_properties(api-test-http-mount-gates
			     PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
			     TIMEOUT 30)
endif()
