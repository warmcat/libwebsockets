project(lws-api-test-mnemonic C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-mnemonic)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_WITH_MNEMONIC 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})
	add_test(NAME api-test-mnemonic COMMAND lws-api-test-mnemonic)

	if (LWS_WITH_STATIC)
		target_link_libraries(${SAMP} websockets)
	else()
		target_link_libraries(${SAMP} websockets_shared)
	endif()
endif()
