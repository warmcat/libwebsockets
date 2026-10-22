project(lws-api-test-dht-seq-flood C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-dht-seq-flood)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_WITH_DHT 1 requirements)

if (requirements)

	add_executable(${SAMP} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	if (NOT WIN32)
		#
		# pick unique loopback UDP ports at build time so parallel CI
		# instances cannot collide.  The fan port is never listened on:
		# the test sends to it at 127.0.1.x
		#
		lws_get_free_port(PORT_DHT_FL_DHT)
		lws_get_free_port(PORT_DHT_FL_FAN)
		lws_get_free_port(PORT_DHT_FL_P)

		add_test(NAME api-test-dht-seq-flood COMMAND
			 $<TARGET_FILE:${SAMP}>
			 --port-dht ${PORT_DHT_FL_DHT}
			 --port-fan ${PORT_DHT_FL_FAN}
			 --port-p ${PORT_DHT_FL_P})
		set_tests_properties(api-test-dht-seq-flood PROPERTIES
			TIMEOUT 75
			WORKING_DIRECTORY .
			ENVIRONMENT "LD_LIBRARY_PATH=${CMAKE_BINARY_DIR}/lib")
	endif()

endif()
