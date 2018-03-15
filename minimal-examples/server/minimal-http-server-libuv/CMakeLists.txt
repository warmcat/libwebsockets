cmake_minimum_required(VERSION 2.8)
include(CheckSymbolExists)

set(SAMP lws-minimal-http-server-libuv)
set(SRCS minimal-http-server.c)

if (UNIX)
      set(CMAKE_C_FLAGS "-Wall -Wsign-compare -Wignored-qualifiers -Wtype-limits -Wuninitialized -Werror -Wundef ${CMAKE_C_FLAGS}" )
endif()

CHECK_SYMBOL_EXISTS(LWS_WITH_LIBUV libwebsockets.h HAS_LIBUV)
if (HAS_LIBUV)
else()
	message(FATAL_ERROR "lws must have been built with LWS_WITH_LIBUV")
endif()

add_executable(${SAMP} ${SRCS})
target_link_libraries(${SAMP} -lwebsockets)

