project(lws-api-test-dnssec-root-anchors C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-dnssec-root-anchors)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_WITH_SYS_ASYNC_DNS 1 requirements)
require_lws_config(LWS_WITH_SYS_ASYNC_DNS_DNSSEC 1 requirements)
require_lws_config(LWS_WITH_GENCRYPTO 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	# the built-in anchors are in a private header of the library
	target_include_directories(${SAMP} PRIVATE
		${CMAKE_SOURCE_DIR}/lib/system/async-dns)

	add_test(NAME api-test-dnssec-root-anchors
		 COMMAND lws-api-test-dnssec-root-anchors)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
