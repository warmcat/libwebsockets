project(lws-api-test-backtrace C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_WITH_COMPRESSED_BACKTRACES 1 requirements)

if (requirements)

	add_executable(${PROJECT_NAME} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${PROJECT_NAME} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${PROJECT_NAME} websockets_shared)
	else()
		target_link_libraries(${PROJECT_NAME} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()

