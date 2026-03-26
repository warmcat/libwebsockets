if (LWS_ROLE_H1 AND NOT LWS_WITHOUT_SERVER AND LWS_WITH_JOSE)
	create_plugin(protocol_lws_oauth2_client ""
		      "protocol_lws_oauth2_client.c" "" "")
	if (NOT LWS_WITH_PLUGINS_BUILTIN)
		target_compile_definitions(protocol_lws_oauth2_client PRIVATE LWS_BUILDING_SHARED)
	endif()
endif()
