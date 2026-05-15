project(lws-minimal-quic-client-server C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-minimal-quic-client-server)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_ROLE_QUIC 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	if (LWS_WITH_MINIMAL_EXAMPLES)
		set(PORT_QCS "7681")
		if ("$ENV{SAI_INSTANCE_IDX}")
			math(EXPR PORT_QCS "7681 + $ENV{SAI_INSTANCE_IDX}")
		endif()

		add_test(NAME ${SAMP} COMMAND ${SAMP} -p ${PORT_QCS})
		set_tests_properties(${SAMP} PROPERTIES
					     WORKING_DIRECTORY .
					     TIMEOUT 20)
	endif()
endif()
