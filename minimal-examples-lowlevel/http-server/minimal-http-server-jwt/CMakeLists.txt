cmake_minimum_required(VERSION 3.10)
include(CheckIncludeFile)

find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-minimal-http-server-jwt)
set(SRCS minimal-http-server-jwt.c)

set(requirements 1)
require_lws_config(LWS_WITH_SQLITE3 1 requirements)
require_lws_config(LWS_WITH_JOSE 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)
require_lws_config(LWS_WITH_HTTP_UNCOMMON_HEADERS 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	#find_package(sqlite3 REQUIRED)
	#target_include_directories(${SAMP} PRIVATE ${SQLITE3_INCLUDE_DIRS})
	#target_link_libraries(${SAMP} ${SQLITE3_LIBRARIES})

endif()

