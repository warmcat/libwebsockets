cmake_minimum_required(VERSION 2.8)

set(SAMP lws-minimal-http-server)
set(SRCS minimal-http-server.c)

if (UNIX)
      set(CMAKE_C_FLAGS "-Wall -Wsign-compare -Wignored-qualifiers -Wtype-limits -Wuninitialized -Werror -Wundef ${CMAKE_C_FLAGS}" )
endif()

add_executable(${SAMP} ${SRCS})
target_link_libraries(${SAMP} -lwebsockets)

