project(lws-api-test-gendtls C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-gendtls)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_WITH_OPENHITLS 1 requirements)
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

	add_test(NAME api-test-dtls COMMAND ${SAMP})
	add_test(NAME api-test-dtls-udp
		 COMMAND ${SAMP} --udp --port 0)
	set_tests_properties(api-test-dtls
			      api-test-dtls-udp PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
			     TIMEOUT 20)
endif()
