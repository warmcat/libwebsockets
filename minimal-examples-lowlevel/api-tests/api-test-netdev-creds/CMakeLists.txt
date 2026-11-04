project(lws-api-test-netdev-creds C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-netdev-creds)
set(SRCS main.c)

#
# Storing wifi credentials for several APs in a settings store, here one in
# memory
#
set(requirements 1)
require_lws_config(LWS_WITH_DRIVERS 1 requirements)
require_lws_config(LWS_WITH_NETWORK 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})
	add_test(NAME api-test-netdev-creds COMMAND lws-api-test-netdev-creds)
	set_tests_properties(api-test-netdev-creds
			     PROPERTIES
			     WORKING_DIRECTORY .
			     TIMEOUT 20)

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()
endif()
