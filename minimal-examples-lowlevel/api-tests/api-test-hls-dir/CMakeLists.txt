project(lws-api-test-hls-dir C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-hls-dir)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_WITH_NETWORK 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITHOUT_SERVER 0 requirements)
require_lws_config(LWS_WITH_JOSE 1 requirements)

if (requirements)

	# the test folds the whole HLS plugin in statically, so it needs the
	# same ffmpeg dev libraries the plugin builds against
	find_package(PkgConfig QUIET)
	pkg_check_modules(PC_AVFORMAT libavformat)
	pkg_check_modules(PC_AVCODEC libavcodec)
	pkg_check_modules(PC_AVUTIL libavutil)
	pkg_check_modules(PC_SWSCALE libswscale)
	pkg_check_modules(PC_SWRESAMPLE libswresample)

	if (PC_AVFORMAT_FOUND AND PC_AVCODEC_FOUND AND PC_AVUTIL_FOUND AND
	    PC_SWSCALE_FOUND AND PC_SWRESAMPLE_FOUND)

		add_executable(${SAMP} ${SRCS})

		target_include_directories(${SAMP} PRIVATE
				"${CMAKE_SOURCE_DIR}/plugins/protocol_lws_hls/include")

		lws_get_free_port(PORT_HLS_DIR)

		add_test(NAME api-test-hls-dir
			 COMMAND lws-api-test-hls-dir -p ${PORT_HLS_DIR})
		set_tests_properties(api-test-hls-dir PROPERTIES TIMEOUT 60)

		if (websockets_shared)
			target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
			add_dependencies(${SAMP} websockets_shared)
		else()
			target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
		endif()

		target_include_directories(${SAMP} PRIVATE
				${PC_AVFORMAT_INCLUDE_DIRS}
				${PC_AVCODEC_INCLUDE_DIRS}
				${PC_AVUTIL_INCLUDE_DIRS}
				${PC_SWSCALE_INCLUDE_DIRS}
				${PC_SWRESAMPLE_INCLUDE_DIRS})
		target_link_libraries(${SAMP}
				${PC_AVFORMAT_LIBRARIES}
				${PC_AVCODEC_LIBRARIES}
				${PC_AVUTIL_LIBRARIES}
				${PC_SWSCALE_LIBRARIES}
				${PC_SWRESAMPLE_LIBRARIES})
	endif()

endif()
