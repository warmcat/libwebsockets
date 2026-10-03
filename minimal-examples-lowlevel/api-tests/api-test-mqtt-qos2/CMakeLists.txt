project(lws-api-test-mqtt-qos2 C)
cmake_minimum_required(VERSION 3.10)
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(requirements 1)
require_lws_config(LWS_ROLE_MQTT 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)

message("api-test-mqtt-qos2 requirements: ${requirements}")

if (requirements)
	add_executable(${PROJECT_NAME} main.c)

	lws_get_free_port(PORT_MQTT_QOS2)

	add_test(NAME api-test-mqtt-qos2
		  COMMAND lws-api-test-mqtt-qos2 -p ${PORT_MQTT_QOS2})
	# glibc fills fresh allocations with junk, so state the library
	# forgets to initialize is not quietly zero; other libcs ignore it
	set_tests_properties(api-test-mqtt-qos2 PROPERTIES
			     ENVIRONMENT "MALLOC_PERTURB_=165"
			     TIMEOUT 30)

	if (websockets_shared)
		target_link_libraries(${PROJECT_NAME} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${PROJECT_NAME} websockets_shared)
	else()
		target_link_libraries(${PROJECT_NAME} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
