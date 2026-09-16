project(lws-api-test-reclaim C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-reclaim)
set(SRCS main.c)

add_executable(${SAMP} ${SRCS})
add_test(NAME api-test-reclaim COMMAND lws-api-test-reclaim)

if (websockets_shared)
	target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
	add_dependencies(${SAMP} websockets_shared)
else()
	target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
endif()
