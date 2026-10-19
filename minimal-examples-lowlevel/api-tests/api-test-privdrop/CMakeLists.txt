project(lws-api-test-privdrop C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(requirements 1)
require_lws_config(LWS_WITH_NETWORK 1 requirements)

# uid / gid privilege drop only exists on unix platforms
if (requirements AND NOT WIN32)

	add_executable(${PROJECT_NAME} main.c)

	add_test(NAME api-test-privdrop COMMAND lws-api-test-privdrop)
	set_tests_properties(api-test-privdrop PROPERTIES TIMEOUT 30)

	if (websockets_shared)
		target_link_libraries(${PROJECT_NAME} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${PROJECT_NAME} websockets_shared)
	else()
		target_link_libraries(${PROJECT_NAME} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
