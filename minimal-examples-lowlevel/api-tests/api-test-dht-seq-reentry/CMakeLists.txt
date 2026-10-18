project(lws-api-test-dht-seq-reentry C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-dht-seq-reentry)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_WITH_DHT 1 requirements)
require_lws_config(LWS_WITH_DHT_BACKEND 1 requirements)

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
		# instances cannot collide.  The fan-out port is never listened
		# on: B sends to it at 127.0.0.2.. and 127.0.1.2..
		#
		lws_get_free_port(PORT_DHT_SR_B)
		lws_get_free_port(PORT_DHT_SR_Q)
		lws_get_free_port(PORT_DHT_SR_R)
		lws_get_free_port(PORT_DHT_SR_FAN)

		add_test(NAME api-test-dht-seq-reentry COMMAND
			 $<TARGET_FILE:${SAMP}>
			 --port-b ${PORT_DHT_SR_B}
			 --port-q ${PORT_DHT_SR_Q}
			 --port-r ${PORT_DHT_SR_R}
			 --port-fan ${PORT_DHT_SR_FAN})
		set_tests_properties(api-test-dht-seq-reentry PROPERTIES
			TIMEOUT 60
			WORKING_DIRECTORY .
			ENVIRONMENT "LD_LIBRARY_PATH=${CMAKE_BINARY_DIR}/lib")
	endif()

endif()
