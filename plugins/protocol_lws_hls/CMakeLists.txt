#
# libwebsockets - small server side websockets and web server implementation
#
# Copyright (C) 2010 - 2026 Andy Green <andy@warmcat.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#

	find_package(PkgConfig QUIET)
	pkg_check_modules(PC_AVFORMAT libavformat)
	pkg_check_modules(PC_AVCODEC libavcodec)
	pkg_check_modules(PC_AVUTIL libavutil)
	pkg_check_modules(PC_SWSCALE libswscale)
	pkg_check_modules(PC_SWRESAMPLE libswresample)

	if (PC_AVFORMAT_FOUND AND PC_AVCODEC_FOUND AND PC_AVUTIL_FOUND AND PC_SWSCALE_FOUND AND PC_SWRESAMPLE_FOUND)
		set(PLUGIN_NAME "protocol_lws_hls")
		set(PLUGIN_SRCS
			protocol_lws_hls.c
			hls-av.c
			hls-dir.c
		)
		set(PLUGIN_HDR private-lws-hls.h)

		# Create the plugin target using the macro from plugins/CMakeLists.txt
		create_plugin(${PLUGIN_NAME}
			      ""
			      "${PLUGIN_SRCS}"
			      ""
			      ""
		)

		if (TARGET ${PLUGIN_NAME})
			target_compile_definitions(${PLUGIN_NAME} PRIVATE LWS_BUILDING_SHARED)
			target_include_directories(${PLUGIN_NAME} PRIVATE 
				${PC_AVFORMAT_INCLUDE_DIRS}
				${PC_AVCODEC_INCLUDE_DIRS}
				${PC_AVUTIL_INCLUDE_DIRS}
				${PC_SWSCALE_INCLUDE_DIRS}
				${PC_SWRESAMPLE_INCLUDE_DIRS})
			target_link_libraries(${PLUGIN_NAME} 
				${PC_AVFORMAT_LIBRARIES}
				${PC_AVCODEC_LIBRARIES}
				${PC_AVUTIL_LIBRARIES}
				${PC_SWSCALE_LIBRARIES}
				${PC_SWRESAMPLE_LIBRARIES})
		endif()
	endif()
