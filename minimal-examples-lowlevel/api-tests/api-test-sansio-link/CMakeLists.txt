project(lws-api-test-sansio-link C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)
include(CTest)

set(SAMP lws-api-test-sansio-link)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_ROLE_H1 1 requirements)

# the sansIO half linked alone exists (LWS_WITH_SANSIO_LINK_TEST): link a
# program against it, and nothing else of lws, and run it

if (requirements AND TARGET websockets-sansio)
	add_executable(${SAMP} ${SRCS})
	target_link_libraries(${SAMP} websockets-sansio)
	add_dependencies(${SAMP} websockets-sansio)

	add_test(NAME api-test-sansio-link COMMAND lws-api-test-sansio-link)
	set_tests_properties(api-test-sansio-link PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/minimal-examples-lowlevel/api-tests/api-test-sansio-link
			     TIMEOUT 20)
endif()
