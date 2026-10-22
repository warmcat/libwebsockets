project(lws-api-test-ws-server-threads-smp C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckIncludeFile)
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-ws-server-threads-smp)
set(SRCS main.c)

#
# The minimal-ws-server-threads-smp example's protocol under connection
# churn on two service threads (one in builds with LWS_MAX_SMP 1)
#
set(requirements 1)
require_pthreads(requirements)
require_lws_config(LWS_ROLE_WS 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)

if (requirements AND NOT WIN32)
	add_executable(${SAMP} ${SRCS})

	add_test(NAME api-test-ws-server-threads-smp
		 COMMAND lws-api-test-ws-server-threads-smp
			 --server ${LWS_CTEST_SERVER_RESOLVE})
	set_tests_properties(api-test-ws-server-threads-smp PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
			     TIMEOUT 60)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${PTHREAD_LIB} ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${PTHREAD_LIB} ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
