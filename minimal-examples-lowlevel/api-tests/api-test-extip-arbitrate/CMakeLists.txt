project(lws-api-test-extip-arbitrate C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-extip-arbitrate)
set(SRCS main.c)

set(requirements 1)
require_lws_config(LWS_WITH_NETWORK 1 requirements)
require_lws_config(LWS_WITH_SYS_SMD 1 requirements)
# an IPv6-only build keeps IPv4 addresses as v4-mapped IPv6 ones
require_lws_config(LWS_WITH_IPV4 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	add_test(NAME api-test-extip-arbitrate COMMAND lws-api-test-extip-arbitrate)
	set_tests_properties(api-test-extip-arbitrate
			     PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			     TIMEOUT 20)
endif()
