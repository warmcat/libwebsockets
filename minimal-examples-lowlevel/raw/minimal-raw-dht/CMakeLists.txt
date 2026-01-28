project(lws-minimal-raw-dht C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include_directories(BEFORE ../../../../include)
include_directories(BEFORE ../../../../build-dht/include)
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-minimal-raw-dht)
set(SRCS minimal-raw-dht.c ../../../../plugins/protocol_lws_dht_object_store.c)

set(requirements 1)
require_lws_config(LWS_WITH_DHT 1 requirements)

include_directories(${CMAKE_SOURCE_DIR}/plugins)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	if (NOT WIN32)
		set(PORT_DHT_SRV "15000")
		if ("$ENV{SAI_INSTANCE_IDX}")
			math(EXPR PORT_DHT_SRV "15000 + $ENV{SAI_INSTANCE_IDX}")
		endif()

		add_test(NAME st_raw_dht_srv COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background.sh
			raw_dht_srv
			$<TARGET_FILE:lws-minimal-raw-dht>
			-s dht-store-srv -p ${PORT_DHT_SRV})
		set_tests_properties(st_raw_dht_srv PROPERTIES
			WORKING_DIRECTORY .
			FIXTURES_SETUP raw_dht_srv
			TIMEOUT 800
			ENVIRONMENT "SAI_LIST_PORT=${PORT_DHT_SRV}")

		add_test(NAME ki_raw_dht_srv COMMAND
			${CMAKE_SOURCE_DIR}/scripts/ctest-background-kill.sh
			raw_dht_srv
			$<TARGET_FILE_NAME:lws-minimal-raw-dht> --port ${PORT_DHT_SRV})
		set_tests_properties(ki_raw_dht_srv PROPERTIES FIXTURES_CLEANUP raw_dht_srv)

		#
		# Client part: PUT data, then verify it exists in srv dir
		# We use a dummy file for testing
		#

		add_test(NAME raw_dht_cli COMMAND
			$<TARGET_FILE:lws-minimal-raw-dht>
			-s dht-store-cli -p 15001 --put test-data.txt --target-ip 127.0.0.1 --target-port ${PORT_DHT_SRV})

		set_tests_properties(raw_dht_cli PROPERTIES
			FIXTURES_REQUIRED "raw_dht_srv"
			WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			TIMEOUT 20)

		add_test(NAME raw_dht_bulk COMMAND
			$<TARGET_FILE:lws-minimal-raw-dht>
			-s dht-store-bulk -p 15002 --bulk --target-ip 127.0.0.1 --target-port ${PORT_DHT_SRV})

		set_tests_properties(raw_dht_bulk PROPERTIES
			FIXTURES_REQUIRED "raw_dht_srv"
			WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			TIMEOUT 60)

		# 1. Generate Manifest (Sender)
		add_test(NAME raw_dht_gen_manifest COMMAND
			${CMAKE_COMMAND}
			"-DCMD=$<TARGET_FILE:lws-minimal-raw-dht>;-s;dht-store-upl;-p;15003;--bulk;--gen-manifest;--target-ip;127.0.0.1;--target-port;${PORT_DHT_SRV}"
			"-DOUTPUT=${CMAKE_CURRENT_BINARY_DIR}/manifest.txt"
			-P "${CMAKE_SOURCE_DIR}/scripts/ctest-redirect.cmake")

		# 2. Consume Manifest (Receiver)
		add_test(NAME raw_dht_manifest COMMAND
			${CMAKE_COMMAND}
			"-DCMD=$<TARGET_FILE:lws-minimal-raw-dht>;-s;dht-store-man;-p;15004;--receiver;--target-ip;127.0.0.1;--target-port;${PORT_DHT_SRV}"
			"-DINPUT=${CMAKE_CURRENT_BINARY_DIR}/manifest.txt"
			-P "${CMAKE_SOURCE_DIR}/scripts/ctest-redirect.cmake")

		set_tests_properties(raw_dht_gen_manifest PROPERTIES
			FIXTURES_SETUP "raw_dht_gen"
			FIXTURES_REQUIRED "raw_dht_srv"
			WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			TIMEOUT 60)

		set_tests_properties(raw_dht_manifest PROPERTIES
			FIXTURES_REQUIRED "raw_dht_gen;raw_dht_srv"
			WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			TIMEOUT 20)
	endif()
endif()
