set(PLUGIN_NAME protocol_lws_latency)
set(requirements 1)
require_lws_config(LWS_WITH_LATENCY 1 requirements)

if (requirements)
	create_plugin(${PLUGIN_NAME} "" "protocol_lws_latency.c" "" "")
	if (NOT LWS_WITH_PLUGINS_BUILTIN)
		target_compile_definitions(${PLUGIN_NAME} PRIVATE LWS_BUILDING_SHARED)
	endif()

	if (NOT WIN32 AND LWS_WITH_PLUGINS AND NOT LWS_WITH_PLUGINS_BUILTIN)
		install(DIRECTORY assets/ DESTINATION share/libwebsockets-test-server/lws-latency COMPONENT plugins)
	endif()
endif()
