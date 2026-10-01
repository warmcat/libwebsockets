project(lws-api-test-x509-info C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-x509-info)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_WITH_TLS 1 requirements)

if (requirements)

	add_executable(${SAMP} ${SRCS})
	add_test(NAME api-test-x509-info COMMAND lws-api-test-x509-info)

	set_tests_properties(api-test-x509-info PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			     TIMEOUT 30)

	# The same under a zone well away from UTC: the certificate times
	# are UTC and must not pick up the process's local offset (C-407)
	add_test(NAME api-test-x509-info-tz COMMAND lws-api-test-x509-info)
	set_tests_properties(api-test-x509-info-tz PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			     ENVIRONMENT "TZ=Asia/Tokyo"
			     TIMEOUT 30)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
