project(lws-api-test-session-dump C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-session-dump)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_WITH_OPENHITLS 1 requirements)
require_lws_config(LWS_WITH_TLS_SESSIONS 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})
	target_include_directories(${SAMP} PRIVATE ${LWS_LIB_BUILD_INC_PATHS})

	add_test(NAME api-test-session-dump COMMAND ${SAMP}
		WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
	set_tests_properties(api-test-session-dump PROPERTIES
		TIMEOUT 30)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
