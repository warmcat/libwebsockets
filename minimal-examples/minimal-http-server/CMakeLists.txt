cmake_minimum_required(VERSION 2.8)

project(lws-minimal-http-server C)

set(SAMP lws-minimal-http-server)
set(SRCS minimal-http-server.c)

add_executable(${SAMP} ${SRCS})
target_link_libraries(${SAMP} -lwebsockets)

