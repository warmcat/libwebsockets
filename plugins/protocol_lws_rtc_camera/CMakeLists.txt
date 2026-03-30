require_lws_config(LWS_ROLE_WS 1 REQUIRE 1)
require_lws_config(LWS_ROLE_RAW_FILE 1 REQUIRE 1)
require_lws_config(LWS_WITH_PLUGINS 1 REQUIRE 1)
require_lws_config(LWS_WITH_DRM 1 REQUIRE 1)

if (REQUIRE_FAIL)
	return()
endif()

set(PLUGIN_SRCS protocol_lws_rtc_camera.c media-v4l2.c)

if (LWS_WITH_MEDIA_RK_MPI)
	list(APPEND PLUGIN_SRCS media-rkmpi.c)
endif()

create_plugin(protocol_lws_rtc_camera "" "${PLUGIN_SRCS}" "" "")

if (NOT LWS_WITH_PLUGINS_BUILTIN)
	target_compile_definitions(protocol_lws_rtc_camera PRIVATE LWS_BUILDING_SHARED)
endif()
