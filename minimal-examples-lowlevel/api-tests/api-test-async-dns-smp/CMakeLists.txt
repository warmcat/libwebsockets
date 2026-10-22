project(lws-api-test-async-dns-smp C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckIncludeFile)
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-async-dns-smp)
set(SRCS main.c)

set(requirements 1)
require_pthreads(requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)
require_lws_config(LWS_WITH_SYS_ASYNC_DNS 1 requirements)
require_lws_config(LWS_WITH_IPV4 1 requirements)
require_lws_config(LWS_ROLE_RAW 1 requirements)

# its fake nameserver is a thread of its own on a POSIX socket
if (requirements AND NOT WIN32)
	add_executable(${SAMP} ${SRCS})

	add_test(NAME api-test-async-dns-smp COMMAND lws-api-test-async-dns-smp)
	set_tests_properties(api-test-async-dns-smp PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
			     TIMEOUT 60)

	# the same with the small fd lookup scheme (G-635): it is only used
	# when the limit times the threads is below the process fd limit, so
	# keep it well under the usual soft limit of 1024
	add_test(NAME api-test-async-dns-smp-fd-limit
		 COMMAND lws-api-test-async-dns-smp --fd-limit-per-thread 256)
	set_tests_properties(api-test-async-dns-smp-fd-limit PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
			     TIMEOUT 60)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${PTHREAD_LIB} ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${PTHREAD_LIB} ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
