project(lws-api-test-client-no-vhost C)
cmake_minimum_required(VERSION 3.10)
find_package(libwebsockets CONFIG REQUIRED)
list(APPEND CMAKE_MODULE_PATH ${LWS_CMAKE_DIR})
include(CheckCSourceCompiles)
include(LwsCheckRequirements)

set(SAMP lws-api-test-client-no-vhost)
set(SRCS main.c)

#
# A client connect in a context with no vhost of the app's own (only lws's
# "system" one, or none) fails cleanly (G-694)
#
set(requirements 1)
require_lws_config(LWS_WITH_NETWORK 1 requirements)
require_lws_config(LWS_WITH_CLIENT 1 requirements)
require_lws_config(LWS_ROLE_H1 1 requirements)

if (requirements)
	add_executable(${SAMP} ${SRCS})

	if (websockets_shared)
		target_link_libraries(${SAMP} websockets_shared ${LIBWEBSOCKETS_DEP_LIBS})
		add_dependencies(${SAMP} websockets_shared)
	else()
		target_link_libraries(${SAMP} websockets ${LIBWEBSOCKETS_DEP_LIBS})
	endif()

	# nothing listens on it: the connection that is taken is refused
	lws_get_free_port(PORT_CNV)

	add_test(NAME api-test-client-no-vhost
		 COMMAND lws-api-test-client-no-vhost
			 --port ${PORT_CNV}
			 --server ${LWS_CTEST_SERVER_RESOLVE})
	set_tests_properties(api-test-client-no-vhost
			     PROPERTIES
			     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
			     TIMEOUT 30)
endif()
