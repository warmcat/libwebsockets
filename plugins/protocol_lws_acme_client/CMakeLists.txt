set(requirements 1)
require_lws_config(LWS_WITH_ACME 1 requirements)

if (requirements)
	create_plugin(protocol_lws_acme_client_core ""
		      "protocol_lws_acme_client_core.c" "" "")
	if (NOT LWS_WITH_PLUGINS_BUILTIN)
		target_compile_definitions(protocol_lws_acme_client_core PRIVATE LWS_BUILDING_SHARED)
	endif()

	set(req_dns 1)
	require_lws_config(LWS_ROLE_WS 1 req_dns)
	if (req_dns)
		create_plugin(protocol_lws_acme_client_dns ""
				  "protocol_lws_acme_client_dns.c" "" "")
		if (NOT LWS_WITH_PLUGINS_BUILTIN)
			target_compile_definitions(protocol_lws_acme_client_dns PRIVATE LWS_BUILDING_SHARED)
		endif()
	endif()

	create_plugin(protocol_lws_acme_client_http ""
		      "protocol_lws_acme_client_http.c" "" "")
	if (NOT LWS_WITH_PLUGINS_BUILTIN)
		target_compile_definitions(protocol_lws_acme_client_http PRIVATE LWS_BUILDING_SHARED)
	endif()
endif()
