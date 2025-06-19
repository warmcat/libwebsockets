project(lws-minimal-ss-server-hello_world C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)

set(SRCS main.c ss-server.c)

require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)
require_lws_config(LWS_WITH_SYS_SMD 1 requirements)
require_lws_config(LWS_WITH_SECURE_STREAMS 1 requirements)
require_lws_config(LWS_WITH_SECURE_STREAMS_STATIC_POLICY_ONLY 0 requirements)

require_lws_config(LWS_WITH_SECURE_STREAMS_PROXY_API 1 has_ss_proxy)

if (requirements)
	add_executable(${PROJECT_NAME} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${PROJECT_NAME}
					websockets_shared
					${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${PROJECT_NAME}
					websockets_shared)
	else()
		target_link_libraries(${PROJECT_NAME}
					websockets
					${LIBWEBSOCKETS_DEP_LIBS})
	endif()
	
	if (HAS_LWS_WITH_SECURE_STREAMS_PROXY_API OR has_ss_proxy OR
	    LWS_WITH_SECURE_STREAMS_PROXY_API)

		add_compile_options(-DLWS_SS_USE_SSPC)
		add_executable(${PROJECT_NAME}-client ${SRCS})

		if (websockets_shared)
			target_link_libraries(${PROJECT_NAME}-client
						websockets_shared
						${LIBWEBSOCKETS_DEP_LIBS})
			add_dependencies(${PROJECT_NAME}-client
						websockets_shared)
		else()
			target_link_libraries(${PROJECT_NAME}-client
						websockets
						${LIBWEBSOCKETS_DEP_LIBS})
		endif()
	endif()
endif()
