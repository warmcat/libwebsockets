project(lws-minimal-http-server-eventlib-smp)
cmake_minimum_required(VERSION 2.8)
include(CheckIncludeFile)
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-minimal-http-server-eventlib-smp)
set(SRCS minimal-http-server-eventlib-smp.c)

set(requirements 1)
require_pthreads(requirements)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${PTHREAD_LIB})
		add_dependencies(${SAMP} websockets_shared ${PTHREAD_LIB})
	else()
		target_link_libraries(${SAMP} websockets ${PTHREAD_LIB})
	endif()
endif()
