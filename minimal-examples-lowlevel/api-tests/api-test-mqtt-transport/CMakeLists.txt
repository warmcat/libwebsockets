project(lws-api-test-mqtt-transport C)
cmake_minimum_required(VERSION 3.10)
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(requirements 1)
require_lws_config(LWS_ROLE_MQTT 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)
require_lws_config(LWS_WITH_TLS 1 requirements)
require_lws_config(LWS_CLIENT_HTTP_PROXYING 1 requirements)

#
# The proxies are api-test-ws-close's proxy-fixture.py: an http CONNECT and
# SOCKS5 proxy on one port; the broker's tls uses its test certificate too
#
find_program(PYTHON3_FOR_FIXTURE python3)

if (requirements AND PYTHON3_FOR_FIXTURE AND NOT WIN32)
	add_executable(${PROJECT_NAME} main.c)

	if (websockets_shared)
		target_link_libraries(${PROJECT_NAME} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${PROJECT_NAME} websockets_shared)
	else()
		target_link_libraries(${PROJECT_NAME} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	lws_get_free_port(PORT_MQTT_XPORT)
	lws_get_free_port(PORT_MQTT_XPORT_TLS)
	lws_get_free_port(PORT_MQTT_XPORT_PROXY)

	add_test(NAME st_mqttx_proxy COMMAND
		${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh
		mqttx_proxy ${PYTHON3_FOR_FIXTURE}
		${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/api-tests/api-test-ws-close/proxy-fixture.py
		--port ${PORT_MQTT_XPORT_PROXY})
	add_test(NAME ki_mqttx_proxy COMMAND
		${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh
		mqttx_proxy ${PYTHON3_FOR_FIXTURE})
	set_tests_properties(st_mqttx_proxy PROPERTIES
			     WORKING_DIRECTORY . FIXTURES_SETUP mqttx_proxy TIMEOUT 60
			     ENVIRONMENT "SAI_LIST_PORT=${PORT_MQTT_XPORT_PROXY}")
	set_tests_properties(ki_mqttx_proxy PROPERTIES FIXTURES_CLEANUP mqttx_proxy)

	set(MQTTX_CERTS ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/api-tests/api-test-ws-close)

	add_test(NAME api-test-mqtt-transport
		 COMMAND lws-api-test-mqtt-transport
			 -p ${PORT_MQTT_XPORT} --port-tls ${PORT_MQTT_XPORT_TLS}
			 --cert ${MQTTX_CERTS}/localhost-100y.cert
			 --key ${MQTTX_CERTS}/localhost-100y.key
			 --proxy 127.0.0.1:${PORT_MQTT_XPORT_PROXY}
			 --socks 127.0.0.1:${PORT_MQTT_XPORT_PROXY})
	set_tests_properties(api-test-mqtt-transport
			     PROPERTIES
			     WORKING_DIRECTORY .
			     FIXTURES_REQUIRED "mqttx_proxy"
			     TIMEOUT 60)
endif()
