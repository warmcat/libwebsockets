project(lws-api-test-dht-dnssec-fetch-fanout C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-dht-dnssec-fetch-fanout)
# main.c builds the plugin in itself, to reach its fetch requests
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_WITH_DHT 1 requirements)
require_lws_config(LWS_WITH_JOSE 1 requirements)
require_lws_config(LWS_WITH_GENCRYPTO 1 requirements)
require_lws_config(LWS_WITH_SYS_ASYNC_DNS_DNSSEC 1 requirements)
require_lws_config(LWS_WITH_AUTHORITATIVE_DNS 1 requirements)

if (requirements AND NOT WIN32)

	add_executable(${SAMP} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	# loopback UDP ports picked at build time, so parallel CI can't collide:
	# our DHT node, a bootstrap target nobody answers on, and the port of
	# the routing table nodes, where nothing listens either
	lws_get_free_port(PORT_DHT_FF)
	lws_get_free_port(PORT_DHT_FF_T)
	lws_get_free_port(PORT_DHT_FF_D)

	add_test(NAME api-test-dht-dnssec-fetch-fanout COMMAND
		 $<TARGET_FILE:${SAMP}> --port ${PORT_DHT_FF}
					--target-port ${PORT_DHT_FF_T}
					--dead-port ${PORT_DHT_FF_D})
	set_tests_properties(api-test-dht-dnssec-fetch-fanout PROPERTIES
		TIMEOUT 20
		WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
		ENVIRONMENT "LD_LIBRARY_PATH=${CMAKE_BINARY_DIR}/lib")

endif()
