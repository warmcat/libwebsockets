set(PLUGIN_NAME protocol_lws_extip)
set(requirements 1)
require_lws_config(LWS_WITH_NETWORK 1 requirements)

require_lws_config(LWS_WITH_EXTIP 1 requirements)
require_lws_config(LWS_WITH_SYS_ASYNC_DNS 1 requirements)

if (requirements)
	create_plugin(${PLUGIN_NAME} "" "protocol_lws_extip.c" "" "")
	if (NOT LWS_WITH_PLUGINS_BUILTIN AND NOT WIN32)
		target_compile_definitions(${PLUGIN_NAME} PRIVATE LWS_BUILDING_SHARED)
	endif()
endif()
