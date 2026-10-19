project(lws-api-test-aws-credentials C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-aws-credentials)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_WITH_SECURE_STREAMS 1 requirements)
require_lws_config(LWS_WITH_SECURE_STREAMS_AUTH_SIGV4 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	# the test writes its credentials files into its build dir
	add_test(NAME api-test-aws-credentials
		 COMMAND lws-api-test-aws-credentials
			 --dir ${CMAKE_CURRENT_BINARY_DIR})
	set_tests_properties(api-test-aws-credentials PROPERTIES TIMEOUT 20)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
