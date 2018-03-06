cmake_minimum_required(VERSION 2.8.9)
include(CheckFunctionExists)

set(SAMP lws-minimal-ws-server-pmd-bulk)
set(SRCS minimal-ws-server-pmd-bulk.c)

set(CMAKE_REQUIRED_LIBRARIES websockets)

CHECK_FUNCTION_EXISTS(lws_extension_callback_pm_deflate HAVE_PMD)
if (HAVE_PMD)
else()
	message(FATAL_ERROR "LWS need to have been built for extensions")
endif()

add_executable(${SAMP} ${SRCS})
target_link_libraries(${SAMP} -lwebsockets)
