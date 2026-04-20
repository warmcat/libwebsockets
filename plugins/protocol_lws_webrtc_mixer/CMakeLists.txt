set(PLUGIN_NAME protocol_lws_webrtc_mixer)
set(requirements 1)
require_lws_config(LWS_WITH_GSTREAMER 1 requirements)

if (requirements)
	find_package(PkgConfig QUIET)
	if (PKG_CONFIG_FOUND)
		pkg_check_modules(GSTREAMER QUIET gstreamer-1.0 gstreamer-app-1.0)
	endif()

	if (NOT GSTREAMER_FOUND)
		message(FATAL_ERROR "GStreamer 1.0 and gstreamer-app-1.0 are required for the WebRTC mixer plugin")
	endif()

	create_plugin(${PLUGIN_NAME} "." "protocol_lws_webrtc_mixer.c;mixer-media.c;mixer-wav.c;layout-quad.c;layout-speaker.c" "" "")
	if (NOT LWS_WITH_PLUGINS_BUILTIN)
		target_compile_definitions(${PLUGIN_NAME} PRIVATE LWS_BUILDING_SHARED)
		target_include_directories(${PLUGIN_NAME} PRIVATE .)
	endif()

	include_directories(SYSTEM ${GSTREAMER_INCLUDE_DIRS})
	target_link_libraries(${PLUGIN_NAME} ${GSTREAMER_LIBRARIES})

	if (NOT WIN32 AND LWS_WITH_PLUGINS AND NOT LWS_WITH_PLUGINS_BUILTIN)
		install(DIRECTORY assets/ DESTINATION share/libwebsockets-test-server/lws-webrtc-mixer COMPONENT plugins)
		install(DIRECTORY sounds/ DESTINATION share/libwebsockets-test-server/lws-webrtc-mixer/sounds COMPONENT plugins)
	endif()
endif()
