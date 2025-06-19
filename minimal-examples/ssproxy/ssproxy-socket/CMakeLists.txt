project(lws-minimal-ss-proxy C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)

set(SRCS main.c)

require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_WITHOUT_CLIENT 0 requirements)
require_lws_config(LWS_WITH_SECURE_STREAMS 1 requirements)
require_lws_config(LWS_WITH_SECURE_STREAMS_PROXY_API 1 requirements)
require_lws_config(LWS_WITH_SECURE_STREAMS_STATIC_POLICY_ONLY 0 requirements)
require_lws_config(LWS_WITH_SYS_STATE 1 requirements)

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
endif()
