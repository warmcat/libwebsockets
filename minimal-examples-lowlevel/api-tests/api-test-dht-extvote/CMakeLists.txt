project(lws-api-test-dht-extvote C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

#
# The external-address vote is pure logic over the public types: build it in
# directly and drive it with made-up witnesses and clock values
#

set(SAMP lws-api-test-dht-extvote)
set(SRCS main.c
	 ../../../lib/misc/dht/dht-extvote.c)

set(requirements 1)
require_lws_config(LWS_WITH_DHT 1 requirements)

if (requirements)

	add_executable(${SAMP} ${SRCS})
	target_include_directories(${SAMP} PRIVATE
		${CMAKE_CURRENT_SOURCE_DIR}/../../../lib/misc/dht)

	add_test(NAME api-test-dht-extvote COMMAND lws-api-test-dht-extvote)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared
			${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets
			${LIBWEBSOCKETS_DEP_LIBS})
	endif()

endif()
