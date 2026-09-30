project(lws-api-test-jpeg C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-jpeg)
set(SRCS main.c )

set(requirements 1)
require_lws_config(LWS_WITH_JPEG 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)

if (requirements)

	add_executable(${SAMP} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	# built-in images, cut up every way
	add_test(NAME api-test-jpeg COMMAND lws-api-test-jpeg --selftest)

	#
	# The in-tree JPEGs must decode completely: one of each MCU layout,
	# 4:4:4, 4:2:2 (leaf.jpg, big), 4:2:0 and grayscale
	#

	set(LWS_JPEG_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../../..)
	foreach(J	doc-assets/lhp-example-g4.jpg
			test-apps/leaf.jpg
			plugins/protocol_lws_captcha_ratelimit/captcha-assets/scrapers-1.jpg
			fuzz/fuzz-jpeg/seeds/splash-128-64.jpg)
		if (EXISTS ${LWS_JPEG_ROOT}/${J})
			get_filename_component(JN ${J} NAME_WE)
			add_test(NAME api-test-jpeg-${JN}
				 COMMAND lws-api-test-jpeg --no-output
					--stdin ${LWS_JPEG_ROOT}/${J})
		endif()
	endforeach()
endif()
