project(lws-api-test-dnssec-monitor-whois C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)
include(CTest)

set(SAMP lws-api-test-dnssec-monitor-whois)
set(SRCS main.c
	 ../../../plugins/protocol_lws_dht_dnssec_monitor/monitor-whois.c)

set(requirements 1)
require_lws_config(LWS_WITH_AUTHORITATIVE_DNS 1 requirements)
require_lws_config(LWS_WITH_SYS_WHOIS 1 requirements)
require_lws_config(LWS_WITH_LEJP 1 requirements)
require_lws_config(LWS_WITH_JOSE 1 requirements)
require_lws_config(LWS_WITH_DIR 1 requirements)
require_lws_config(LWS_ROLE_RAW 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITHOUT_SERVER 0 requirements)
require_lws_config(LWS_UNIX_SOCK 1 requirements)

if (requirements)

	add_executable(${SAMP} ${SRCS})
	target_include_directories(${SAMP} PRIVATE
		${CMAKE_SOURCE_DIR}/plugins/protocol_lws_dht_dnssec_monitor)

	lws_get_free_port(PORT_DNSSEC_MONITOR_WHOIS)

	# the test lays out its scratch base-dir and UDS in the build tree
	add_test(NAME api-test-dnssec-monitor-whois
		 COMMAND lws-api-test-dnssec-monitor-whois
			 -p ${PORT_DNSSEC_MONITOR_WHOIS})
	set_tests_properties(api-test-dnssec-monitor-whois PROPERTIES
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
