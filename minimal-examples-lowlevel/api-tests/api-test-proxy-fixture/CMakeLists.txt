project(lws-api-test-proxy-fixture C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

#
# Not a test itself: the http CONNECT / SOCKS5 proxy that api-test-ws-close,
# api-test-raw-close, api-test-client-proxy-redirect and
# api-test-mqtt-transport run as a ctest fixture, as
# $<TARGET_FILE:lws-api-test-proxy-fixture>.  A test using it needs the same
# requirements as here, plus NOT WIN32 for the fixture scripts.
#

set(SAMP lws-api-test-proxy-fixture)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_ROLE_RAW 1 requirements)
require_lws_config(LWS_WITH_NETWORK 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITHOUT_SERVER 0 requirements)

if (requirements AND NOT WIN32)
	add_executable(${SAMP} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
