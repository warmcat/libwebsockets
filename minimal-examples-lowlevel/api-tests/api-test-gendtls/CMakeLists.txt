project(lws-api-test-gendtls C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-gendtls)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_WITH_GENCRYPTO 1 requirements)
require_lws_config(LWS_WITH_SSL 1 requirements)
require_lws_config(LWS_WITH_DTLS 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	set(GENDTLS_PORT "7890")
	if ("$ENV{SAI_INSTANCE_IDX}")
		math(EXPR GENDTLS_PORT "7890 + $ENV{SAI_INSTANCE_IDX}")
	endif()

	add_test(NAME api-test-gendtls COMMAND ${SAMP})
	add_test(NAME api-test-gendtls-udp COMMAND ${SAMP} --udp --port ${GENDTLS_PORT})
	set_tests_properties(api-test-gendtls api-test-gendtls-udp PROPERTIES
	                     WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
	                     TIMEOUT 20)
endif()
