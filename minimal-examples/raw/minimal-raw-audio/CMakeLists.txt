project(lws-minimal-raw-audio)
cmake_minimum_required(VERSION 2.8)
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-minimal-raw-audio)
set(SRCS audio.c)

set(requirements 1)
require_lws_config(LWS_WITH_ALSA 1 requirements)
require_lws_config(LWS_WITH_NETWORK 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared asound)
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets asound)
	endif()
endif()
