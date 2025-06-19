project(lws-api-test-lhp C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(requirements 1)
require_lws_config(LWS_WITH_LHP 1 requirements)
require_lws_config(LWS_WITH_SECURE_STREAMS 1 requirements)

if (requirements)

	add_executable(${PROJECT_NAME} main.c)
	add_test(NAME api-test-lhp COMMAND lws-api-test-lhp)

	if (websockets_shared)
		target_link_libraries(${PROJECT_NAME} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${PROJECT_NAME} websockets_shared)
	else()
		target_link_libraries(${PROJECT_NAME} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
