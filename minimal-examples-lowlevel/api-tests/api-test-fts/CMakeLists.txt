project(lws-api-test-fts C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-fts)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_WITH_FTS 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	#
	# Index the two corpus files that ship with this test into one index,
	# then query it and confirm every match record against the original
	# files (line numbers, file offsets and quoted lines)
	#
	# (the index file is written as binary through a plain open(), so
	# this doesn't work on a platform where that means text mode)
	if (NOT WIN32)
		add_test(NAME api-test-fts COMMAND ${SAMP}
			 --selftest
			 --index ${CMAKE_CURRENT_BINARY_DIR}/lws-fts-selftest.index
			 ${CMAKE_CURRENT_SOURCE_DIR}/the-picture-of-dorian-gray.txt
			 ${CMAKE_CURRENT_SOURCE_DIR}/les-mis-utf8.txt)
	endif()

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
