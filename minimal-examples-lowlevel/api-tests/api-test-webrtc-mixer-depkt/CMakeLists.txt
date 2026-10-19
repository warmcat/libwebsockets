project(lws-api-test-webrtc-mixer-depkt C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)

#
# mixer-depkt.c needs nothing from GStreamer, so this runs whether or not
# the mixer plugin itself can be built here
#

set(SAMP lws-api-test-webrtc-mixer-depkt)
set(SRCS main.c
	 ../../../plugins/protocol_lws_webrtc_mixer/mixer-depkt.c)

add_executable(${SAMP} ${SRCS})
target_include_directories(${SAMP} PRIVATE
	${CMAKE_SOURCE_DIR}/plugins/protocol_lws_webrtc_mixer)

add_test(NAME api-test-webrtc-mixer-depkt COMMAND lws-api-test-webrtc-mixer-depkt)

if (websockets_shared)
	target_link_libraries(${SAMP} websockets_shared
		${LIBWEBSOCKETS_DEP_LIBS})
	add_dependencies(${SAMP} websockets_shared)
else()
	target_link_libraries(${SAMP} websockets
		${LIBWEBSOCKETS_DEP_LIBS})
endif()
