project(lws-api-test-http-ah-lifetime C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-http-ah-lifetime)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_ROLE_RAW 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)

set(AHL_H2 1)
require_lws_config(LWS_ROLE_H2 1 AHL_H2)
set(AHL_H3 1)
require_lws_config(LWS_ROLE_H3 1 AHL_H3)
set(AHL_FILE 1)
require_lws_config(LWS_WITH_FILE_OPS 1 AHL_FILE)

if (requirements)

	add_executable(${SAMP} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	#
	# One test per case and role, so ctest -j runs them side by side and a
	# failure names both
	#
	set(AHL_TESTS pipeline-depth:h1 slow-cl:h1 slow-stream:h1 late-spa:h1)
	if (AHL_FILE AND NOT WIN32)
		# the file it serves is made at runtime, with posix file apis
		list(APPEND AHL_TESTS file-stall:h1)
	endif()
	if (AHL_H2)
		list(APPEND AHL_TESTS slow-cl:h2 slow-stream:h2 late-spa:h2)
	endif()
	if (AHL_H3)
		list(APPEND AHL_TESTS slow-cl:h3 slow-stream:h3 late-spa:h3)
	endif()

	set(AHL_CERTS ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/api-tests/api-test-ws-close)

	foreach(AHL_T ${AHL_TESTS})
		string(REPLACE ":" ";" AHL_CR ${AHL_T})
		list(GET AHL_CR 0 AHL_CASE)
		list(GET AHL_CR 1 AHL_ROLE)
		set(AHL_NAME ${AHL_CASE}-${AHL_ROLE})

		lws_get_free_port(PORT_AHL_${AHL_NAME})

		add_test(NAME api-test-http-ah-lifetime-${AHL_NAME}
			 COMMAND lws-api-test-http-ah-lifetime
				 --case ${AHL_CASE} --role ${AHL_ROLE}
				 -p ${PORT_AHL_${AHL_NAME}}
				 --server ${LWS_CTEST_SERVER_RESOLVE}
				 --cert ${AHL_CERTS}/localhost-100y.cert
				 --key ${AHL_CERTS}/localhost-100y.key)
		set_tests_properties(api-test-http-ah-lifetime-${AHL_NAME}
				     PROPERTIES
				     WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
				     TIMEOUT 60)
	endforeach()
endif()
