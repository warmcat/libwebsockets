project(lws-minimal-secure-streams-binance C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckIncludeFile)
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-minimal-secure-streams-binance)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_ROLE_WS 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITHOUT_EXTENSIONS 0 requirements)
require_lws_config(LWS_WITH_SECURE_STREAMS 1 requirements)
require_lws_config(LWS_WITH_SECURE_STREAMS_STATIC_POLICY_ONLY 0 requirements)
require_lws_config(USE_WOLFSSL 0 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	if (HAS_LWS_WITH_SECURE_STREAMS_PROXY_API OR LWS_WITH_SECURE_STREAMS_PROXY_API)

		add_compile_options(-DLWS_SS_USE_SSPC)
		add_executable(${SAMP}-client ${SRCS})

		if (websockets_shared)
			target_link_libraries(${SAMP}-client websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
			add_dependencies(${SAMP}-client websockets_shared)
		else()
			target_link_libraries(${SAMP}-client websockets ${LIBWEBSOCKETS_DEP_LIBS})
		endif()
	endif()


endif()
