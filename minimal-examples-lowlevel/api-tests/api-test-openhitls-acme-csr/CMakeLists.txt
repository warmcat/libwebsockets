project(lws-api-test-acme-csr C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-acme-csr)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_WITH_OPENHITLS 1 requirements)
require_lws_config(LWS_WITH_ACME 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})
	target_include_directories(${SAMP} PRIVATE
		${LWS_LIB_BUILD_INC_PATHS}
		${CMAKE_SOURCE_DIR}/lib/core
		${CMAKE_SOURCE_DIR}/lib/core-net
		${CMAKE_SOURCE_DIR}/lib/misc
		${CMAKE_SOURCE_DIR}/lib/system
		${CMAKE_SOURCE_DIR}/lib/drivers
		${CMAKE_SOURCE_DIR}/lib/event-libs
		${CMAKE_SOURCE_DIR}/lib/event-libs/poll
		${CMAKE_SOURCE_DIR}/lib/jose
		${CMAKE_SOURCE_DIR}/lib/jose/jwe
		${CMAKE_SOURCE_DIR}/lib/cose
		${CMAKE_SOURCE_DIR}/lib/roles
		${CMAKE_SOURCE_DIR}/lib/roles/dbus
		${CMAKE_SOURCE_DIR}/lib/roles/http
		${CMAKE_SOURCE_DIR}/lib/roles/http/compression
		${CMAKE_SOURCE_DIR}/lib/roles/h1
		${CMAKE_SOURCE_DIR}/lib/roles/h2
		${CMAKE_SOURCE_DIR}/lib/roles/ws
		${CMAKE_SOURCE_DIR}/lib/roles/mqtt
		${CMAKE_SOURCE_DIR}/lib/roles/cgi
		${CMAKE_SOURCE_DIR}/lib/roles/raw-proxy
		${CMAKE_SOURCE_DIR}/lib/roles/listen
		${CMAKE_SOURCE_DIR}/lib/secure-streams
		${CMAKE_SOURCE_DIR}/lib/secure-streams/serialized/client
		${CMAKE_SOURCE_DIR}/lib/system/metrics
		${CMAKE_SOURCE_DIR}/lib/system/async-dns
		${CMAKE_SOURCE_DIR}/lib/system/smd
		${CMAKE_SOURCE_DIR}/lib/system/fault-injection
		${CMAKE_SOURCE_DIR}/lib/tls
		${CMAKE_SOURCE_DIR}/lib/tls/openhitls)

	add_test(NAME api-test-acme-csr COMMAND ${SAMP}
		WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
	set_tests_properties(api-test-acme-csr PROPERTIES TIMEOUT 60)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
