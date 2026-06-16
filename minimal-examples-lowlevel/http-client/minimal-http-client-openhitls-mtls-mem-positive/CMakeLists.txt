project(lws-minimal-http-client-mtls-mem-positive C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-minimal-http-client-mtls-mem-positive)
set(SRCS minimal-http-client-openhitls-mtls-mem-positive.c)

set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)
require_lws_config(LWS_WITH_OPENHITLS 1 requirements)
require_lws_config(LWS_WITH_FILE_OPS 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	lws_get_free_port(PORT_OHMTLS_MEM)

	add_test(NAME http-client-mtls-mem-positive COMMAND
		lws-minimal-http-client-mtls-mem-positive
			--port ${PORT_OHMTLS_MEM})
	set_tests_properties(http-client-mtls-mem-positive PROPERTIES
		WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
		TIMEOUT 20)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
