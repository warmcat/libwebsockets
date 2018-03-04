cmake_minimum_required(VERSION 2.8)

project(lws-minimal-http-client C)

set(SAMP lws-minimal-http-client)
set(SRCS minimal-http-client.c)

add_executable(${SAMP} ${SRCS})
target_link_libraries(${SAMP} -lwebsockets)

