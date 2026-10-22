project(lws-api-test-auth-dns-names C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-auth-dns-names)
# main.c builds the plugin in itself, to look at what it would send
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_WITH_SERVER 1 requirements)
require_lws_config(LWS_WITH_AUTHORITATIVE_DNS 1 requirements)

if (requirements)

	add_executable(${SAMP} ${SRCS})

	add_test(NAME api-test-auth-dns-names COMMAND lws-api-test-auth-dns-names)
	set_tests_properties(api-test-auth-dns-names PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
			     TIMEOUT 20)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

endif()
