project(lws-api-test-dnssec-monitor-inventory C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-dnssec-monitor-inventory)
set(SRCS main.c
	 ../../../plugins/protocol_lws_dht_dnssec_monitor/monitor-inventory.c)

set(requirements 1)
require_lws_config(LWS_WITH_AUTHORITATIVE_DNS 1 requirements)
# the inventory cache is only built when sqlite3 was enabled for lws
require_lws_config(LWS_WITH_SQLITE3 1 requirements)

find_path(INV_SQLITE3_INC NAMES sqlite3.h)
find_library(INV_SQLITE3_LIB NAMES sqlite3)
if (NOT INV_SQLITE3_INC OR NOT INV_SQLITE3_LIB)
	set(requirements 0)
endif()

if (requirements)

	add_executable(${SAMP} ${SRCS})
	target_include_directories(${SAMP} PRIVATE
		${INV_SQLITE3_INC}
		${CMAKE_SOURCE_DIR}/plugins/protocol_lws_dht_dnssec_monitor)

	# the test builds its zonefile corpus in the build tree, not the
	# source tree
	add_test(NAME api-test-dnssec-monitor-inventory
		 COMMAND lws-api-test-dnssec-monitor-inventory)
	set_tests_properties(api-test-dnssec-monitor-inventory PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
			     TIMEOUT 60)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared
			${LIBWEBSOCKETS_DEP_LIBS} ${INV_SQLITE3_LIB})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets
			${LIBWEBSOCKETS_DEP_LIBS} ${INV_SQLITE3_LIB})
	endif()

endif()
