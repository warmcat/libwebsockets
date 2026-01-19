if (LWS_ROLE_H1 AND NOT LWS_WITHOUT_SERVER AND LWS_WITH_STRUCT_SQLITE3)
	create_plugin(protocol_lws_login ""
		      "protocol_lws_login.c" "" "")
	if (NOT LWS_WITH_PLUGINS_BUILTIN)
		target_compile_definitions(protocol_lws_login PRIVATE LWS_BUILDING_SHARED)
	endif()

	if (LWS_WITH_PLUGINS AND NOT LWS_WITH_PLUGINS_BUILTIN)
		if (NOT WIN32)
			install(DIRECTORY login-assets
				DESTINATION share/libwebsockets-test-server/lws-login
				COMPONENT plugins)
		endif()
	endif()
endif()
