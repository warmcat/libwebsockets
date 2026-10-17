project(lws-api-test-mqtt-inflight C)
cmake_minimum_required(VERSION 3.10)
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(requirements 1)
require_lws_config(LWS_ROLE_MQTT 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)

message("api-test-mqtt-inflight requirements: ${requirements}")

if (requirements)
	add_executable(${PROJECT_NAME} main.c)

	lws_get_free_port(PORT_MQTT_INFLIGHT)

	add_test(NAME api-test-mqtt-inflight
		  COMMAND lws-api-test-mqtt-inflight -p ${PORT_MQTT_INFLIGHT})
	set_tests_properties(api-test-mqtt-inflight PROPERTIES TIMEOUT 30)

	if (websockets_shared)
		target_link_libraries(${PROJECT_NAME} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${PROJECT_NAME} websockets_shared)
	else()
		target_link_libraries(${PROJECT_NAME} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
