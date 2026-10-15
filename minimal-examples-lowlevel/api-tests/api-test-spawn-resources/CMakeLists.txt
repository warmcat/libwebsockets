project(lws-api-test-spawn-resources C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-spawn-resources)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_WITH_SPAWN 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	# the helpers it spawns are itself, run with --hog and --tree
	add_test(NAME api-test-spawn-resources COMMAND lws-api-test-spawn-resources)
	set_tests_properties(api-test-spawn-resources
			     PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/api-tests/api-test-spawn-resources
			     TIMEOUT 120)
endif()
