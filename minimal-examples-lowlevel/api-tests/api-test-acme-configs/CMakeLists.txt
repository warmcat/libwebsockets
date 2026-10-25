project(lws-api-test-acme-configs C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-acme-configs)
set(SRCS main.c
	 ../../../plugins/protocol_lws_acme_client/acme-configs.c)

set(requirements 1)
require_lws_config(LWS_WITH_ACME 1 requirements)
require_lws_config(LWS_WITH_DIR 1 requirements)
require_lws_config(LWS_WITH_STRUCT_JSON 1 requirements)

# the plugin, like the test's scratch tree, is POSIX only
if (requirements AND NOT WIN32)

	add_executable(${SAMP} ${SRCS})
	target_include_directories(${SAMP} PRIVATE
		${CMAKE_SOURCE_DIR}/plugins/protocol_lws_acme_client)

	add_test(NAME api-test-acme-configs COMMAND lws-api-test-acme-configs)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared
			${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets
			${LIBWEBSOCKETS_DEP_LIBS})
	endif()

endif()
