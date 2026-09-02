project(lws-api-test-auth-admin-js C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-auth-admin-js)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_WITHOUT_SERVER 0 requirements)
require_lws_config(LWS_WITH_AUTH_SERVER 1 requirements)

if (requirements)

	add_executable(${SAMP} ${SRCS})

	# the fence is asserted against the actual served asset bytes
	target_compile_definitions(${SAMP} PRIVATE
		AUTH_ADMIN_JS_ASSET="${CMAKE_CURRENT_SOURCE_DIR}/../../../plugins/protocol_lws_auth_server/assets/admin.js")

	add_test(NAME api-test-auth-admin-js COMMAND lws-api-test-auth-admin-js)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

endif()
