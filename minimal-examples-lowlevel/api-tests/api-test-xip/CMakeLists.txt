project(lws-api-test-xip C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-xip)
set(XIPDIR ${CMAKE_CURRENT_SOURCE_DIR}/../../../plugins/protocol_xip_clipboard)
set(SRCS main.c
	 ${XIPDIR}/chunk.c
	 ${XIPDIR}/hash.c
	 ${XIPDIR}/proto.c)

set(requirements 1)
require_lws_config(LWS_WITH_LEJP 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})
	add_test(NAME api-test-xip COMMAND lws-api-test-xip)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	target_include_directories(${SAMP} PRIVATE ${XIPDIR})
endif()
