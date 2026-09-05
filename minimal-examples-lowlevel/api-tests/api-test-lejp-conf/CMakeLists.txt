project(lws-api-test-lejp-conf C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(requirements 1)
require_lws_config(LWS_WITH_LEJP_CONF 1 requirements)
# the ctest also creates a vhost with a listen port
require_lws_config(LWS_WITH_SERVER 1 requirements)

if (requirements)

	add_executable(${PROJECT_NAME} main.c)

	# pick a unique port at configure time, so parallel ctest is safe
	lws_get_free_port(LEJP_CONF_VH_PORT)
	target_compile_definitions(${PROJECT_NAME} PRIVATE
				   LEJP_CONF_VH_PORT=${LEJP_CONF_VH_PORT})

	add_test(NAME api-test-lejp-conf COMMAND lws-api-test-lejp-conf)

	if (websockets_shared)
		target_link_libraries(${PROJECT_NAME} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${PROJECT_NAME} websockets_shared)
	else()
		target_link_libraries(${PROJECT_NAME} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
