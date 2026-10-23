project(lws-minimal-raw-webrtc-webcam C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(LwsCheckRequirements)

set(SAMP lws-minimal-raw-webrtc-webcam)
set(SRCS minimal-raw-webrtc-webcam.c webcam-media.c)

set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_ROLE_WS 1 requirements)
require_lws_config(LWS_WITH_DTLS 1 requirements)
require_lws_config(LWS_WITH_TRANSCODE 1 requirements)
require_lws_config(LWS_WITH_V4L2 1 requirements)
# it uses the lws-webrtc protocol from the webrtc plugin
require_lws_config(LWS_WITH_PLUGINS 1 requirements)
require_lws_config(LWS_WITH_WEBRTC 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	# the media libraries (v4l2, ffmpeg, opus, alsa) are lws' own deps
	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
