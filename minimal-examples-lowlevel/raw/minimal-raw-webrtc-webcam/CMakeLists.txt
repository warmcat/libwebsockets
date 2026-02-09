project(lws-minimal-raw-webrtc-webcam C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(LwsCheckRequirements)

set(SAMP lws-minimal-raw-webrtc-webcam)
set(SRCS minimal-raw-webrtc-webcam.c)

set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_ROLE_WS 1 requirements)
require_lws_config(LWS_WITH_DTLS 1 requirements)
require_lws_config(LWS_WITH_EXTERNAL_POLL 0 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})
	target_link_libraries(${SAMP} websockets asound opus)
endif()
