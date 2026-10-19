project(lws-api-test-sul-wait C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-sul-wait)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_WITH_NETWORK 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	#
	# 60 timers of 0.2 - 6ms take well under a second; the timeout is only
	# the backstop for a wedged process
	#

	add_test(NAME api-test-sul-wait COMMAND lws-api-test-sul-wait)
	set_tests_properties(api-test-sul-wait
			     PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			     TIMEOUT 30)

	#
	# libuv takes its waits in whole ms too
	#

	set(uv_requirements 1)
	require_lws_config(LWS_WITH_LIBUV 1 uv_requirements)

	if (uv_requirements)
		add_test(NAME api-test-sul-wait-libuv
			 COMMAND lws-api-test-sul-wait --uv)
		set_tests_properties(api-test-sul-wait-libuv
				     PROPERTIES
				     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
				     ENVIRONMENT "LD_LIBRARY_PATH=${CMAKE_BINARY_DIR}/lib"
				     TIMEOUT 30)
	endif()
endif()
