project(lws-api-test-mcufonts-plugin C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-mcufonts-plugin)
set(SRCS main.c)

# the plugin is built into the test, and runs the encoder built alongside

set(requirements 1)
require_lws_config(LWS_WITH_SERVER 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_WITH_SPAWN 1 requirements)
require_lws_config(LWS_WITH_DISKCACHE 1 requirements)
require_lws_config(LWS_WITH_STRUCT_JSON 1 requirements)
require_lws_config(LWS_WITH_MCUFONT_ENCODER 1 requirements)

if (requirements AND NOT WIN32)
	add_executable(${SAMP} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	#
	# The first run starts from an empty cache, so the faces and the page
	# have to be made; the second runs on what the first left in the cache
	#

	set(MCUF_CACHE ${CMAKE_CURRENT_BINARY_DIR}/mcufonts-cache)
	set(MCUF_ARGS --encoder $<TARGET_FILE:lws-mcufont-encoder>
		      --ttf-dir ${CMAKE_CURRENT_SOURCE_DIR}/../../../contrib/mcufont/fonts
		      --cache-dir ${MCUF_CACHE})

	add_test(NAME api-test-mcufonts-plugin-clean
		 COMMAND ${CMAKE_COMMAND} -E rm -rf ${MCUF_CACHE})
	set_tests_properties(api-test-mcufonts-plugin-clean PROPERTIES
			     FIXTURES_SETUP mcufonts_cache)

	add_test(NAME api-test-mcufonts-plugin COMMAND ${SAMP} ${MCUF_ARGS})
	add_test(NAME api-test-mcufonts-plugin-cached
		 COMMAND ${SAMP} ${MCUF_ARGS} --cached)
	set_tests_properties(api-test-mcufonts-plugin PROPERTIES
			     FIXTURES_REQUIRED mcufonts_cache
			     FIXTURES_SETUP mcufonts_made
			     WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
			     TIMEOUT 180)
	set_tests_properties(api-test-mcufonts-plugin-cached PROPERTIES
			     FIXTURES_REQUIRED "mcufonts_cache;mcufonts_made"
			     WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
			     TIMEOUT 60)
endif()
