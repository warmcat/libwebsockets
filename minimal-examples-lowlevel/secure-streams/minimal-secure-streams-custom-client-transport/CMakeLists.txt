project(lws-minimal-secure-streams-custom-client-transport C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckIncludeFile)
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-minimal-secure-streams-custom-client-transport)
set(SRCS main.c binance-ss.c transport-serial.c app-event-loop.c system.c)

set(requirements 1)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SECURE_STREAMS 1 requirements)
require_lws_config(LWS_WITH_SECURE_STREAMS_PROXY_API 1 requirements)
require_lws_config(LWS_ONLY_SSPC 1 requirements)
require_lws_config(USE_WOLFSSL 0 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})
	add_compile_options(-DLWS_SS_USE_SSPC)

	target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
endif()
