cmake_minimum_required(VERSION 2.8.9)
include(CheckFunctionExists)

set(SAMP lws-minimal-ws-server-pmd)
set(SRCS minimal-ws-server-pmd.c)

set(CMAKE_REQUIRED_LIBRARIES websockets)

CHECK_FUNCTION_EXISTS(lws_extension_callback_pm_deflate HAVE_PMD)
if (HAVE_PMD)
else()
	message(FATAL_ERROR "LWS needs to have been built for extensions")
endif()

if (UNIX)
      set(CMAKE_C_FLAGS "-Wall -Wsign-compare -Wignored-qualifiers -Wtype-limits -Wuninitialized -Werror -Wundef ${CMAKE_C_FLAGS}" )
endif()

add_executable(${SAMP} ${SRCS})
target_link_libraries(${SAMP} -lwebsockets)
