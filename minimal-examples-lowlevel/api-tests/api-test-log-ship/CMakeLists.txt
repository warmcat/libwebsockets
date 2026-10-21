project(lws-api-test-log-ship C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-log-ship)
set(SRCS main.c
	 ../../../plugins/protocol_lws_log_ingest/ingest-store.c
	 ../../../plugins/protocol_lws_log_ingest/ingest-api.c)

#
# The lws-log-ingest plugin is built into this test, so it needs what the
# plugin needs (plugins/protocol_lws_log_ingest/CMakeLists.txt), plus a client
# to drive its api, and custom headers to stamp the login state a trusted
# front end would
#
set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_ROLE_WS 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)
require_lws_config(LWS_WITH_LOG_SHIP 1 requirements)
require_lws_config(LWS_WITH_STRUCT_SQLITE3 1 requirements)
require_lws_config(LWS_WITH_LEJP 1 requirements)
require_lws_config(LWS_WITH_CUSTOM_HEADERS 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})
	target_include_directories(${SAMP} PRIVATE
		${CMAKE_SOURCE_DIR}/plugins/protocol_lws_log_ingest)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	lws_get_free_port(PORT_LOG_SHIP)

	add_test(NAME api-test-log-ship
		 COMMAND lws-api-test-log-ship
			 --server ${LWS_CTEST_SERVER_RESOLVE}
			 -p ${PORT_LOG_SHIP})
	set_tests_properties(api-test-log-ship PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
			     TIMEOUT 60)

	#
	# The ingestor keeping our kind always in a window, a shipper only told
	# where to go after it was made, and one changing its name.  It has a
	# working dir of its own, since each run starts its db afresh.
	#
	lws_get_free_port(PORT_LOG_SHIP_ALWAYS)
	file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/always)

	add_test(NAME api-test-log-ship-always
		 COMMAND lws-api-test-log-ship --always
			 --server ${LWS_CTEST_SERVER_RESOLVE}
			 -p ${PORT_LOG_SHIP_ALWAYS})
	set_tests_properties(api-test-log-ship-always PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/always
			     TIMEOUT 60)
endif()
