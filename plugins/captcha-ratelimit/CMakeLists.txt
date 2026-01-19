if (LWS_ROLE_H1 AND NOT LWS_WITHOUT_SERVER)
	create_plugin(protocol_lws_captcha_ratelimit ""
		      "protocol_lws_captcha_ratelimit.c" "" "")
	if (NOT LWS_WITH_PLUGINS_BUILTIN)
		target_compile_definitions(protocol_lws_captcha_ratelimit PRIVATE LWS_BUILDING_SHARED)
	endif()

	if (LWS_WITH_PLUGINS AND NOT LWS_WITH_PLUGINS_BUILTIN)
		if (NOT WIN32)
			install(DIRECTORY captcha-assets
				DESTINATION share/libwebsockets-test-server/captcha-ratelimit
				COMPONENT plugins)
		endif()
	endif()
endif()
