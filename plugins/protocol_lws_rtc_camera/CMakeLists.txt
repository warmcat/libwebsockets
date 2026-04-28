set(requirements 1)
require_lws_config(LWS_ROLE_WS 1 requirements)
require_lws_config(LWS_ROLE_RAW_FILE 1 requirements)
require_lws_config(LWS_WITH_PLUGINS 1 requirements)
require_lws_config(LWS_WITH_DRM 1 requirements)
require_lws_config(LWS_WITH_WEBRTC 1 requirements)

if (requirements STREQUAL "0")
	return()
endif()

set(PLUGIN_SRCS protocol_lws_rtc_camera.c media-v4l2.c)

if (LWS_WITH_MEDIA_RK_MPI)
	list(APPEND PLUGIN_SRCS media-rkmpi.c)
endif()

create_plugin(protocol_lws_rtc_camera "" "${PLUGIN_SRCS}" "" "")

if (NOT LWS_WITH_PLUGINS_BUILTIN)
	target_compile_definitions(protocol_lws_rtc_camera PRIVATE LWS_BUILDING_SHARED)
	if (LWS_WITH_MEDIA_RK_MPI)
		target_link_libraries(protocol_lws_rtc_camera ${ROCKCHIP_MPI_LIB} ${ROCKCHIP_MPP_LIB} ${ROCKCHIP_RGA_LIB})
	endif()
endif()

if (LWS_WITH_MEDIA_RK_MPI)
	enable_language(CXX)
	set_target_properties(protocol_lws_rtc_camera PROPERTIES LINKER_LANGUAGE CXX)
endif()
