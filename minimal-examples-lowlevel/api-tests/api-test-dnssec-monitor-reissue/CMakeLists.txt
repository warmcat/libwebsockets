project(lws-api-test-dnssec-monitor-reissue C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-dnssec-monitor-reissue)
set(SRCS main.c
	 ../../../plugins/protocol_lws_dht_dnssec_monitor/monitor-acme.c)

set(requirements 1)
require_lws_config(LWS_WITH_AUTHORITATIVE_DNS 1 requirements)
require_lws_config(LWS_WITH_LEJP 1 requirements)
require_lws_config(LWS_WITH_JOSE 1 requirements)
require_lws_config(LWS_WITH_DIR 1 requirements)
require_lws_config(LWS_WITH_SYS_SMD 1 requirements)

if (requirements)

	add_executable(${SAMP} ${SRCS})
	target_include_directories(${SAMP} PRIVATE
		${CMAKE_SOURCE_DIR}/plugins/protocol_lws_dht_dnssec_monitor)

	add_test(NAME api-test-dnssec-monitor-reissue
		 COMMAND lws-api-test-dnssec-monitor-reissue)
	set_tests_properties(api-test-dnssec-monitor-reissue PROPERTIES
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
