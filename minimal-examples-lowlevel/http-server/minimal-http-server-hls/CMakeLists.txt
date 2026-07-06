project(lws-minimal-http-server-hls C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-minimal-http-server-hls)
set(SRCS minimal-http-server.c)

set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)
require_lws_config(LWS_WITH_SERVER 1 requirements)
require_lws_config(LWS_WITH_PLUGINS 1 requirements)

find_package(PkgConfig QUIET)
if (PKG_CONFIG_FOUND)
        pkg_check_modules(PC_AVFORMAT libavformat)
        pkg_check_modules(PC_AVCODEC libavcodec)
        pkg_check_modules(PC_AVUTIL libavutil)
        pkg_check_modules(PC_SWSCALE libswscale)

        if (NOT PC_AVFORMAT_FOUND OR NOT PC_AVCODEC_FOUND OR NOT PC_AVUTIL_FOUND OR NOT PC_SWSCALE_FOUND)
                set(requirements 0)
        endif()
else()
        set(requirements 0)
endif()

if (requirements)
	add_executable(${SAMP} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	set_property(TARGET ${SAMP} APPEND PROPERTY COMPILE_DEFINITIONS
		INSTALL_DATADIR="${CMAKE_INSTALL_PREFIX}/share"
	)

	install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/media/"
		DESTINATION share/libwebsockets-test-server/hls
		COMPONENT examples)
	install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/mount-origin/"
		DESTINATION share/libwebsockets-test-server/hls/mount-origin
		COMPONENT examples)
endif()
