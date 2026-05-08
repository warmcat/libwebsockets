project(lws-minimal-mqtt-client-qos2 C)
cmake_minimum_required(VERSION 3.10)
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-minimal-mqtt-client-qos2)
set(SRCS minimal-mqtt-client-qos2.c)

set(requirements 1)
require_lws_config(LWS_ROLE_MQTT 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SYS_STATE 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	#
	# requires mosquitto running locally
	#
	# add_test(NAME mqtt-client-qos2 COMMAND lws-minimal-mqtt-client-qos2 -f)
	# set_tests_properties(mqtt-client-qos2 PROPERTIES
	#	WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/mqtt-client/minimal-mqtt-client-qos2
	#	TIMEOUT 20)
endif()
