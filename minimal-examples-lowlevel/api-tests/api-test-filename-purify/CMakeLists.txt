project(lws-api-test-filename-purify C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-filename-purify)
set(SRCS main.c)

add_executable(${SAMP} ${SRCS})
add_test(NAME api-test-filename-purify COMMAND lws-api-test-filename-purify)

if (websockets_shared)
	target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
	add_dependencies(${SAMP} websockets_shared)
else()
	target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
endif()
