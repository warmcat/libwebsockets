project(lws-api-test-compose-in-rx C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)
include(CTest)

set(SAMP lws-api-test-compose-in-rx)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_ROLE_RAW 1 requirements)
require_lws_config(LWS_WITH_NETWORK 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITHOUT_SERVER 0 requirements)

if (requirements)

	add_executable(${SAMP} ${SRCS})

	lws_get_free_port(PORT_COMPOSE_IN_RX_H1)
	lws_get_free_port(PORT_COMPOSE_IN_RX_H2)
	lws_get_free_port(PORT_COMPOSE_IN_RX_MQTT)

	add_test(NAME api-test-compose-in-rx
		 COMMAND lws-api-test-compose-in-rx -p ${PORT_COMPOSE_IN_RX_H1}
			 --h2-port ${PORT_COMPOSE_IN_RX_H2}
			 --mqtt-port ${PORT_COMPOSE_IN_RX_MQTT})
	set_tests_properties(api-test-compose-in-rx PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			     TIMEOUT 30)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
