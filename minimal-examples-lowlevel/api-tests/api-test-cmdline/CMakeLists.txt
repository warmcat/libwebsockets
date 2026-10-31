project(lws-api-test-cmdline C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-cmdline)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_WITH_NETWORK 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	add_test(NAME api-test-cmdline COMMAND lws-api-test-cmdline)

	#
	# The builtin -h and --help print the usage and exit(0): the test
	# fails if it gets past the builtins with either
	#

	add_test(NAME api-test-cmdline-help-h COMMAND lws-api-test-cmdline -h)
	add_test(NAME api-test-cmdline-help COMMAND lws-api-test-cmdline --help)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
