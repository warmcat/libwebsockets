project(lws-api-test-http-transfer C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)
include(CTest)

set(SAMP lws-api-test-http-transfer)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_WITH_NETWORK 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITHOUT_SERVER 0 requirements)

if (requirements)

	add_executable(${SAMP} ${SRCS})

	lws_get_free_port(PORT_HTTP_TRANSFER_H1)
	lws_get_free_port(PORT_HTTP_TRANSFER_H2)

	add_test(NAME api-test-http-transfer
		 COMMAND lws-api-test-http-transfer -p ${PORT_HTTP_TRANSFER_H1}
			 --h2-port ${PORT_HTTP_TRANSFER_H2})
	set_tests_properties(api-test-http-transfer PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			     TIMEOUT 300)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
