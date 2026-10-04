project(lws-api-test-dht-dnssec-publish-queue C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-dht-dnssec-publish-queue)
# main.c builds the plugin in itself, with shortened upload timings
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_WITH_DHT 1 requirements)
require_lws_config(LWS_WITH_JOSE 1 requirements)
require_lws_config(LWS_WITH_GENCRYPTO 1 requirements)
require_lws_config(LWS_WITH_SYS_ASYNC_DNS_DNSSEC 1 requirements)
require_lws_config(LWS_WITH_AUTHORITATIVE_DNS 1 requirements)
# it counts the CAP_REQs the plugin logs
require_lws_config(LWS_WITH_NO_LOGS 0 requirements)

if (requirements AND NOT WIN32)

	add_executable(${SAMP} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	#
	# The upload target is a port nobody listens on, so no publication
	# can ever be answered.  Pick it at build time so parallel CI
	# instances cannot collide.
	#
	lws_get_free_port(PORT_DHT_PUBQ_DEAD)

	add_test(NAME api-test-dht-dnssec-publish-queue COMMAND
		 $<TARGET_FILE:${SAMP}> --port-dead ${PORT_DHT_PUBQ_DEAD})
	set_tests_properties(api-test-dht-dnssec-publish-queue PROPERTIES
		TIMEOUT 30
		WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
		ENVIRONMENT "LD_LIBRARY_PATH=${CMAKE_BINARY_DIR}/lib")

endif()
