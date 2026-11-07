project(lws-api-test-epd-direct C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(CheckIncludeFile)
include(LwsCheckRequirements)

set(SAMP lws-api-test-epd-direct)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_WITH_DRIVERS 1 requirements)
require_lws_config(LWS_WITH_SYS_SMD 1 requirements)

if (requirements)

	add_executable(${SAMP} ${SRCS})
	add_test(NAME api-test-epd-direct COMMAND lws-api-test-epd-direct)

	# with pthreads, it also runs the passes on a thread of their own
	set(PTHREAD_LIB "")
	CHECK_INCLUDE_FILE(pthread.h LWS_HAVE_PTHREAD_H)
	if (LWS_HAVE_PTHREAD_H)
		if (WIN32)
			set(PTHREAD_LIB ${LWS_EXT_PTHREAD_LIBRARIES})
		elseif (NOT ${CMAKE_SYSTEM_NAME} MATCHES "QNX")
			set(PTHREAD_LIB pthread)
		endif()
	endif()

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${PTHREAD_LIB} ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${PTHREAD_LIB} ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

endif()
