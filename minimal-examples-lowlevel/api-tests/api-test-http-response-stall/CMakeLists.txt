project(lws-api-test-http-response-stall C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-http-response-stall)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_WITH_NETWORK 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITHOUT_SERVER 0 requirements)
require_lws_config(LWS_WITH_FILE_OPS 1 requirements)

# the fixture file is made with mkdtemp() and ftruncate()
if (requirements AND NOT WIN32)

	add_executable(${SAMP} ${SRCS})

	lws_get_free_port(PORT_HTTP_RESPONSE_STALL)

	add_test(NAME api-test-http-response-stall
		 COMMAND lws-api-test-http-response-stall
			 -p ${PORT_HTTP_RESPONSE_STALL})
	set_tests_properties(api-test-http-response-stall PROPERTIES TIMEOUT 90)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
