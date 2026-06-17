project(lws-api-test-genrsa C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-genrsa)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_WITH_OPENHITLS 1 requirements)
require_lws_config(LWS_WITH_GENCRYPTO 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})
	target_include_directories(${SAMP} PRIVATE
		${LWS_LIB_BUILD_INC_PATHS}
		${CMAKE_SOURCE_DIR}/lib/core
		${CMAKE_SOURCE_DIR}/lib/core-net
		${CMAKE_SOURCE_DIR}/lib/misc
		${CMAKE_SOURCE_DIR}/lib/tls
		${CMAKE_SOURCE_DIR}/lib/tls/openhitls)
	add_test(NAME api-test-genrsa COMMAND ${SAMP}
		WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
	set_tests_properties(api-test-genrsa PROPERTIES TIMEOUT 60)
	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
