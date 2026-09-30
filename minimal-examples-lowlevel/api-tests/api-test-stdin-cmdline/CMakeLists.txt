project(lws-api-test-stdin-cmdline C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-stdin-cmdline)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_WITH_NETWORK 1 requirements)

#
# The test puts its stdin content in a regular file on fd 0, which lws reads
# synchronously inside lws_system_adopt_stdin() on POSIX platforms only
#

if (requirements AND NOT WIN32)
	add_executable(${SAMP} ${SRCS})
	add_test(NAME api-test-stdin-cmdline COMMAND lws-api-test-stdin-cmdline)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
