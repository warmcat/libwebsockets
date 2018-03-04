cmake_minimum_required(VERSION 2.8)

project(lws-minimal-ws-server C)

set(SAMP lws-minimal-ws-server)
set(SRCS minimal-ws-server.c)

add_executable(${SAMP} ${SRCS})
target_link_libraries(${SAMP} -lwebsockets)
