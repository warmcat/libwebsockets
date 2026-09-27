project(lws-api-test-dnssec-monitor-extip C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-dnssec-monitor-extip)
set(SRCS main.c
	 ../../../plugins/protocol_lws_dht_dnssec_monitor/monitor-extip.c)

set(requirements 1)
require_lws_config(LWS_WITH_AUTHORITATIVE_DNS 1 requirements)
require_lws_config(LWS_WITH_LEJP 1 requirements)
require_lws_config(LWS_WITH_JOSE 1 requirements)
require_lws_config(LWS_WITH_DIR 1 requirements)

if (requirements)

	add_executable(${SAMP} ${SRCS})
	target_include_directories(${SAMP} PRIVATE
		${CMAKE_SOURCE_DIR}/plugins/protocol_lws_dht_dnssec_monitor)

	# the test lays out its scratch base-dir in the build tree
	add_test(NAME api-test-dnssec-monitor-extip
		 COMMAND lws-api-test-dnssec-monitor-extip)
	set_tests_properties(api-test-dnssec-monitor-extip PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
			     TIMEOUT 60)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared
			${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets
			${LIBWEBSOCKETS_DEP_LIBS})
	endif()

endif()
