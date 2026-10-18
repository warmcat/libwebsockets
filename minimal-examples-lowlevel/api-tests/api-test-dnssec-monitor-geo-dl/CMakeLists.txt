project(lws-api-test-dnssec-monitor-geo-dl C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-dnssec-monitor-geo-dl)
set(SRCS main.c
	 ../../../plugins/protocol_lws_dht_dnssec_monitor/monitor-geo.c)

set(requirements 1)
# the monitor plugin itself is only built with these
require_lws_config(LWS_WITH_AUTHORITATIVE_DNS 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_TLS 1 requirements)
# the fake nameserver
require_lws_config(LWS_WITH_SYS_ASYNC_DNS 1 requirements)
require_lws_config(LWS_WITH_UDP 1 requirements)
require_lws_config(LWS_WITH_IPV4 1 requirements)

if (requirements)

	add_executable(${SAMP} ${SRCS})
	target_include_directories(${SAMP} PRIVATE
		${CMAKE_SOURCE_DIR}/plugins/protocol_lws_dht_dnssec_monitor)

	# the port the fake nameserver answers on
	lws_get_free_port(PORT_GEODL_DNS)

	# the test lays its <base-dir> in the build tree
	add_test(NAME api-test-dnssec-monitor-geo-dl
		 COMMAND lws-api-test-dnssec-monitor-geo-dl)
	set_tests_properties(api-test-dnssec-monitor-geo-dl PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
			     ENVIRONMENT "LWS_ASYNCDNS_PORT=${PORT_GEODL_DNS}"
			     TIMEOUT 30)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared
			${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets
			${LIBWEBSOCKETS_DEP_LIBS})
	endif()

endif()
