project(lws-api-test-mqtt-fragment C)
cmake_minimum_required(VERSION 3.10)
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(requirements 1)
require_lws_config(LWS_ROLE_MQTT 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)

message("api-test-mqtt-fragment requirements: ${requirements}")

if (requirements)
	add_executable(${PROJECT_NAME} main.c)

	lws_get_free_port(PORT_MQTT_FRAGMENT)

	add_test(NAME api-test-mqtt-fragment
		  COMMAND lws-api-test-mqtt-fragment -p ${PORT_MQTT_FRAGMENT})
	set_tests_properties(api-test-mqtt-fragment PROPERTIES TIMEOUT 40)

	if (websockets_shared)
		target_link_libraries(${PROJECT_NAME} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${PROJECT_NAME} websockets_shared)
	else()
		target_link_libraries(${PROJECT_NAME} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
