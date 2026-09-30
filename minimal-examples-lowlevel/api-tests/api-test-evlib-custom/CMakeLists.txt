project(lws-api-test-evlib-custom C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(requirements 1)
require_lws_config(LWS_WITH_NETWORK 1 requirements)

if (requirements)

	add_executable(${PROJECT_NAME} main.c)

	add_test(NAME api-test-evlib-custom COMMAND lws-api-test-evlib-custom)

	# LWS_EVLIB must not displace an event lib the app chose itself
	add_test(NAME api-test-evlib-custom-env
		 COMMAND lws-api-test-evlib-custom)
	set_tests_properties(api-test-evlib-custom-env PROPERTIES
			     ENVIRONMENT "LWS_EVLIB=uv")

	set_tests_properties(api-test-evlib-custom api-test-evlib-custom-env
			     PROPERTIES TIMEOUT 20)

	if (websockets_shared)
		target_link_libraries(${PROJECT_NAME} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${PROJECT_NAME} websockets_shared)
	else()
		target_link_libraries(${PROJECT_NAME} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
